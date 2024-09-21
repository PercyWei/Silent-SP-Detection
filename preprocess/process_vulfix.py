import os
import json
import re
import requests
import shutil
import pandas as pd

from typing import *
from pathlib import Path
from tqdm import tqdm
from collections import defaultdict

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from openai import OpenAI
from openai.types.chat.completion_create_params import ResponseFormat

from preprocess.util import is_commit_exist_in_repo
from utils import run_command


"""RAW DATASET"""


def read_raw_vulfix(ori_csv: str, output_root: str) -> Tuple[str, str]:
    all_commits = pd.read_csv(ori_csv)

    # Separate by language, since the Java commits are missing some info which we will add later on.
    py = all_commits[all_commits.PL == 'python']
    java = all_commits[all_commits.PL == 'java']

    # Java first: partition into train/val/test and check # of commits
    print("Java VF vs NVF for train/val/test")
    java_train = java[java.partition == "train"]
    java_val = java[java.partition == "val"]
    java_test = java[java.partition == "test"]
    print(java_train.drop_duplicates(subset='commit_id').label.value_counts())
    print(java_val.drop_duplicates(subset='commit_id').label.value_counts())
    print(java_test.drop_duplicates(subset='commit_id').label.value_counts())

    # Python: partition into train/val/test and check # of commits
    print("Py VF vs NVF for train/val/test")
    py_train = py[py.partition == "train"]
    py_val = py[py.partition == "val"]
    py_test = py[py.partition == "test"]
    print(py_train.drop_duplicates(subset='commit_id').label.value_counts())
    print(py_val.drop_duplicates(subset='commit_id').label.value_counts())
    print(py_test.drop_duplicates(subset='commit_id').label.value_counts())

    py_vulfix_fpath = os.path.join(output_root, "py_vulfix.json")
    with open(py_vulfix_fpath, 'w') as f:
        json.dump(py.hyp_to_dict(orient='records'), f, indent=4)

    java_vulfix_fpath = os.path.join(output_root, "java_vulfix.json")
    with open(java_vulfix_fpath, 'w') as f:
        json.dump(java.hyp_to_dict(orient='records'), f, indent=4)

    return py_vulfix_fpath, java_vulfix_fpath


"""DATASET SIMPLIFICATION"""


def build_simplified_dataset(dataset_fpath: str, output_root: str) -> str:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    pl = "Python" if "py" in dataset_fpath else "Java"

    # Select important attributes
    record_commit_ids = []
    updt_dataset: List[Dict] = []

    with tqdm(total=len(dataset)) as pb:
        for item in dataset:
            if item['commit_id'] not in record_commit_ids:
                record_commit_ids.append(item['commit_id'])
                updt_item = {
                    "cve_list": item["cve_list"],
                    "commit_type": item["label"],
                    "cwe_id": None,
                    "path_list": [],
                    "repo": item["repo"],
                    "commit_hash": item["commit_id"],
                    "PL_list": [pl]
                }
                updt_dataset.append(updt_item)
            pb.update(1)

    save_fpath = os.path.join(output_root, dataset_fpath.split('/')[-1])
    with open(save_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)

    return save_fpath


"""SEARCH CVE INFO"""


cwe_extract_msg = """You are a helpful assistant to extract information from the text containing the following information and output it in json format.
1. What CVE-ID is this commit addressing?

Extract CVE-ID from question 1 (leave empty if not specified).
Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

interface CVE {
    cve_id: `CVE-${number}-${number}` | '';
};

Now based on the given context, write a cve_id section that conforms to the CVE schema.
"""


def ask_gpt(client: OpenAI, commit_msg: str) -> str | None:
    messages = [
        {
            "role": "system",
            "content": cwe_extract_msg
        },
        {
            "role": "user",
            "content": commit_msg
        }
    ]

    response = client.chat.completions.create(
        model="gpt-4o-2024-05-13",
        messages=messages,
        temperature=0.2,
        response_format=ResponseFormat(type="json_object")
    ).choices[0].message

    if response.content is None:
        response = ""
    else:
        response = response.content

    print(response + "\n")

    json_response = json.loads(response)

    if isinstance(json_response, dict) and "cve_id" in json_response:
        cve_id = json_response["cve_id"]
        return cve_id
    return None


def refine_dataset_with_cve(dataset_fpath: str, log_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    with open(log_fpath, 'r') as f:
        log: Dict[str, Dict] = json.load(f)

    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    with tqdm(total=len(dataset)) as pb:
        for i, item in enumerate(dataset):
            if item["commit_type"] == 1:
                repo = item["repo"]
                commit_hash = item["commit_hash"]

                search_flag = True if commit_hash not in log else False

                if search_flag:
                    # Ask the LLM
                    commit_url = f'https://api.github.com/repos/{repo}/commits/{commit_hash}'
                    try:
                        commit_response = requests.get(commit_url, timeout=10)
                    except requests.exceptions.Timeout:
                        continue

                    if commit_response.status_code != 200:
                        continue

                    commit_msg = commit_response.json()["commit"]["message"]
                    cve_id = ask_gpt(client, commit_msg)

                    # Update log
                    if cve_id is not None and re.fullmatch(r"CVE-\d+-\d+", cve_id):
                        data = {"repo": repo, "commit_hash": commit_hash, "cve_id": cve_id, "msg": commit_msg}
                    else:
                        data = {"repo": repo, "commit_hash": commit_hash, "cve_id": None, "msg": commit_msg}
                    log[commit_hash] = data

            pb.update(1)

    with open(log_fpath, 'w') as f:
        json.dump(log, f, indent=4)


def clean_dataset_by_cve():
    simp_py_vulfix_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py.json"
    with open(simp_py_vulfix_fpath, 'r') as f:
        dataset = json.load(f)

    # cve id -> [data]
    vul_cve2item: Dict[str, Dict] = {}
    # [data]
    novul_items: List[Dict] = []

    for item in dataset:
        commit_type = item["commit_type"]

        if commit_type == 0:
            novul_items.append(item)
        else:
            cve_id = item["cve_id"]
            if cve_id is not None:
                if cve_id not in vul_cve2item:
                    vul_cve2item[cve_id] = {
                        "cve_id": cve_id,
                        "commit_type": 1,
                        "cwe_id": item["cwe_id"],
                        "path_list": [],
                        "commits": [
                            {
                                "repo": item["repo"],
                                "commit_hash": item["commit_hash"],
                                "PL_list": item["PL_list"]
                            }
                        ]
                    }
                else:
                    vul_cve2item[cve_id]["commits"].append(
                        {
                            "repo": item["repo"],
                            "commit_hash": item["commit_hash"],
                            "PL_list": item["PL_list"]
                        }
                    )

    novul_save_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_novul_cleaned.json"
    with open(novul_save_fpath, 'w') as f:
        json.dump(novul_items, f, indent=4)

    vul_save_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_vul_cleaned.json"
    with open(vul_save_fpath, 'w') as f:
        json.dump(list(vul_cve2item.values()), f, indent=4)


def count_clean_dataset():
    novul_save_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_novul_cleaned.json"
    with open(novul_save_fpath, 'r') as f:
        dataset = json.load(f)

    print(f"Novul commit number: {len(dataset)}")

    vul_save_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_vul_cleaned.json"
    with open(vul_save_fpath, 'r') as f:
        dataset = json.load(f)

    cve_num = len(dataset)
    commit_num = 0
    commit_num2cve_num: Dict[int, int] = {}
    for item in dataset:
        curr_commit_num = len(item["commits"])
        if curr_commit_num not in commit_num2cve_num:
            commit_num2cve_num[curr_commit_num] = 1
        else:
            commit_num2cve_num[curr_commit_num] += 1
        commit_num += curr_commit_num
    print(f"Vul CVE number: {cve_num}")
    print(f"Vul commit number: {commit_num}")
    print(f"Vul commit&cve: {json.dumps(commit_num2cve_num, indent=4)}")


"""SEARCH CWE INFO"""


def search_and_extract_cwe(driver, cve_id):
    nvd_url = 'https://nvd.nist.gov/vuln/search'
    driver.get(nvd_url)

    wait = WebDriverWait(driver, 10)
    search_box = wait.until(EC.presence_of_element_located((By.ID, 'Keywords')))
    search_box.clear()
    search_box.send_keys(cve_id)

    search_button = driver.find_element(By.ID, 'vuln-search-submit')
    search_button.click()

    try:
        result_xpath = f"//a[contains(@href, '/vuln/detail/{cve_id}')]"
        result_link = wait.until(EC.presence_of_element_located((By.XPATH, result_xpath)))
        result_link.click()
    except Exception as e:
        return None

    cve_detail = wait.until(EC.presence_of_element_located((By.ID, 'vulnTechnicalDetailsDiv')))
    cwe_xpath = "//div[@id='vulnTechnicalDetailsDiv']//a[contains(@href, 'cwe.mitre.org') and contains(text(), 'CWE-')]"
    cwe_elements = wait.until(EC.presence_of_all_elements_located((By.XPATH, cwe_xpath)))

    # 提取所有CWE-ID并输出
    cwe_ids = [element.text for element in cwe_elements]

    driver.back()

    return cwe_ids


def complete_log():
    log_fpath = "/root/projects/VDTest/output/dataset/log.json"
    with open(log_fpath, 'r') as f:
        log = json.load(f)

    driver_path = '/usr/local/bin/chromedriver'
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(service=Service(driver_path), options=chrome_options)

    try:
        nvd_not_found = []
        nvd_mul_cwe = {}
        for i, item in enumerate(log):
            print("=" * 50 + f" {i} " + "=" * 50)

            cve_id = item["cve_id"]

            print(f"CVE-ID: {cve_id}")

            try:
                cwe_ids = search_and_extract_cwe(driver, cve_id)
            except Exception as e:
                nvd_not_found.append(cve_id)
                continue

            print(f"CWE-IDS: {cwe_ids}")

            if cwe_ids is None or len(cwe_ids) == 0:
                nvd_not_found.append(cve_id)
                continue

            if len(cwe_ids) != 1:
                nvd_mul_cwe[cve_id] = cwe_ids
                continue

            item["cwe_id"] = cwe_ids[0]

        with open(log_fpath, 'w') as f:
            json.dump(log, f, indent=4)

        log_log_fpath = "/root/projects/VDTest/output/dataset/log_log.json"
        with open(log_log_fpath, 'w') as f:
            json.dump({"nvd_not_found": nvd_not_found, "nvd_mul_cwe": nvd_mul_cwe}, f, indent=4)
    finally:
        driver.quit()


def complete_sim_dataset():
    sim_py_vulfix_fpath = "/root/projects/VDTest/output/dataset/sim_py_vulfix.json"
    with open(sim_py_vulfix_fpath, 'r') as f:
        py_items = json.load(f)

    log_fpath = "/root/projects/VDTest/output/dataset/log.json"
    with open(log_fpath, 'r') as f:
        log = json.load(f)

    log_lookup = {}
    for item in log:
        repo = item["repo"]
        commit_hash = item["commit_hash"]
        log_lookup[repo + "_" + commit_hash] = (item["cve_id"], item["cwe_id"])

    for item in py_items:
        repo = item["repo"]
        commit_hash = item["commit_hash"]
        key = repo + "_" + commit_hash
        if key in log_lookup:
            item["cve_list"] = [log_lookup[key][0]]
            item["cwe_id"] = log_lookup[key][1]

    with open(sim_py_vulfix_fpath, 'w') as f:
        json.dump(py_items, f, indent=4)


def clone():
    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items.json"
    with open(py_items_fpath, 'r') as f:
        items = json.load(f)

    failed_repos = []
    for item in items:
        if item["commit_type"] == 1:
            repo = item["repo"]
            name = repo.replace("/", "_")

            clone_dpath = f"/root/projects/clone_projects/{name}"
            if not os.path.exists(clone_dpath):
                token = ""
                repo_url = f"https://{token}@github.com/{repo}.git"
                clone_command = ["git", "clone", repo_url, clone_dpath]

                res, _ = run_command(clone_command, print_log=False, print_stdout=False, raise_error=False, timeout=300)

                if res is None:
                    # Delete local dir for saving this repo
                    try:
                        shutil.rmtree(clone_dpath)
                    except Exception as e:
                        pass
                    failed_repos.append(repo)

    lof_fpath = "/root/projects/VDTest/output/dataset/clone_log.json"
    with open(lof_fpath, 'w') as f:
        json.dump(failed_repos, f, indent=4)


"""VULFIX NOVUL"""


pass


"""VULFIX VUL V1"""


def build_vulfix_vul_v1():
    simp_py_vulfix_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py.json"
    with open(simp_py_vulfix_file, 'r') as f:
        dataset = json.load(f)

    items = []
    for item in dataset:
        if item["commit_type"] == 1 and item["cve_id"] is None:
            items.append(item)

    save_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/py_cleaned_vul_v1.json"
    with open(save_file, 'w') as f:
        json.dump(items, f, indent=4)


def process_vulfix_vul_v1():
    repos_root = "/root/projects/clone_projects"
    dataset_v1_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/py_cleaned_vul_v1.json"
    with open(dataset_v1_file, 'r') as f:
        dataset = json.load(f)

    ## FUNCTION 1
    # noexist_repos = []
    # for item in dataset:
    #     repo = item["repo"]
    #     repo_dpath = os.path.join(repos_root, repo.replace("/", "_"))
    #     if not os.path.exists(repo_dpath) and repo not in noexist_repos:
    #         noexist_repos.append(repo)
    # print(json.dumps(noexist_repos, indent=4))


    ## FUNCTION 2
    # total_num = len(dataset)
    # repro_commit_num = 0
    # for item in dataset:
    #     if item["reproducibility"]:
    #         repro_commit_num += 1
    # print(f"{repro_commit_num} / {total_num}")


    ## FUNCTION 3
    # for i, item in enumerate(dataset):
    #     if item.get("reproducibility", None) is not None:
    #         continue
    #
    #     repo = item["repo"]
    #     repo_dpath = os.path.join(repos_root, repo.replace("/", "_"))
    #     if os.path.exists(repo_dpath):
    #         res = is_commit_exist_in_repo(repo_dpath, item["commit_hash"])
    #         dataset[i]["reproducibility"] = res
    #
    # with open(dataset_v1_file, 'w') as f:
    #     json.dump(dataset, f, indent=4)


    ## FUNCTION 4
    # updt_dataset = []
    # for item in dataset:
    #     if item["reproducibility"]:
    #         updt_dataset.append(item)
    #
    # with open(dataset_v1_file, 'w') as f:
    #     json.dump(updt_dataset, f, indent=4)


"""VULFIX VUL V2"""


pass


if __name__ == '__main__':
    output_dir = "/root/projects/VDTest/dataset/Intermediate"
    ori_vulfix_csv = "/root/projects/VDTest/dataset/VulFix/ase_dataset_sept_19_2021.csv"

    ## Step 1: Read original VulFix
    # py_vulfix_file, java_vulfix_file = read_raw_vulfix(ori_vulfix_csv, "/root/projects/VDTest/dataset/VulFix")
    py_vulfix_file = "/root/projects/VDTest/dataset/Original/VulFix/vulfix_py.json"
    java_vulfix_file = "/root/projects/VDTest/dataset/Original/VulFix/vulfix_java.json"

    ## Step 2: Simplify dataset
    # simp_py_vulfix_file = build_simplified_dataset(py_vulfix_file, output_dir)
    simp_py_vulfix_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py.json"
    # simp_java_vulfix_file = build_simplified_dataset(java_vulfix_file, output_dir)
    simp_java_vulfix_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_java.json"

    ## Step 3: Find CVE of dataset items (only for 'vulfix_py', cause 'vulfix_java' has CVE annotations)
    # log_file = "/root/projects/VDTest/dataset/Intermediate/log_vulfix_py.json"
    # refine_dataset_with_cve(simp_py_vulfix_file, log_file)

    ## Step 4: Find CWE of dataset items
    pass


    ############# Tree types of task dataset #############
    ## (1) vulfix_novul:
    #       - novul fix commit
    pass

    ## (2) vulfix_vul_v1:
    #       - vul fix commit;
    #       - Without CWE labels.
    # build_vulfix_vul_v1()
    # process_vulfix_vul_v1()

    ## (3) vulfix_vul_v2:
    #       - vul fix commit;
    #       - With CWE labels.
    pass
