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
from webdriver_manager.chrome import ChromeDriverManager

from openai import OpenAI
from openai.types.chat.completion_create_params import ResponseFormat

from preprocess.repo_manage import format_size, get_remote_repo_size
from preprocess.process_all import update_dataset_with_commit_file_count
from preprocess.util import clone_repo, is_commit_exist, is_commit_exist_in_repo


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

    json_response = json.loads(response)

    if isinstance(json_response, dict) and "cve_id" in json_response:
        cve_id = json_response["cve_id"]
        return cve_id
    return None


def find_dataset_missing_cve(dataset_fpath: str, log_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    log: Dict[str, Dict] = {}
    if os.path.exists(log_fpath):
        with open(log_fpath, 'r') as f:
            log = json.load(f)

    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    with tqdm(total=len(dataset)) as pb:
        for item in dataset:
            if item["commit_type"] == 1 and not re.fullmatch(r"CVE-\d+-\d+", item["cve_list"]):
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
                    except requests.exceptions.SSLError:
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


def refine_dataset_with_cve(dataset_fpath: str, log_fpath: str):
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    with open(log_fpath, 'r') as f:
        log = json.load(f)

    updt_dataset = []
    for item in dataset:
        if item["commit_type"] == 1 and not re.fullmatch(r"CVE-\d+-\d+", item["cve_list"]):
            repo = item["repo"]
            commit_hash = item["commit_hash"]

            if commit_hash not in log:
                print(f"https://github.com/{repo}/commit/{commit_hash}")
            else:
                item["cve_list"] = log[commit_hash]["cve_id"]

        updt_dataset.append(item)

    with open(dataset_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)


"""SEPARATE NOVUL AND VUL"""


def separate_dataset(lang: Literal["Python", "Java"], dataset_fpath: str, cwe_log_fpath:str, save_dpath: str):
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    with open(cwe_log_fpath, 'r') as f:
        cwe_log = json.load(f)

    nvd_with_cwe: Dict[str, List[str]] = cwe_log["nvd_with_cwe"]

    cve2items: Dict[str, Dict] = {}
    novul_items: List[Dict] = []

    for item in dataset:
        commit_type = item["commit_type"]

        if commit_type == 0:
            novul_items.append({
                "cve_id": None,
                "commit_type": commit_type,
                "cwe_list": None,
                "repo": item["repo"],
                "commit_hash": item["commit_hash"],
                "file_count": None
            })
        else:
            cve_id = item["cve_id"]
            if cve_id is not None:
                if cve_id not in cve2items and cve_id in nvd_with_cwe:
                    cve2items[cve_id] = {
                        "cve_id": cve_id,
                        "commit_type": commit_type,
                        "cwe_list": nvd_with_cwe[cve_id],
                        "commits": [
                            {
                                "repo": item["repo"],
                                "commit_hash": item["commit_hash"]
                            }
                        ]
                    }
                elif cve_id in nvd_with_cwe:
                    cve2items[cve_id]["commits"].append(
                        {
                            "repo": item["repo"],
                            "commit_hash": item["commit_hash"]
                        }
                    )

    vul_items = list(cve2items.values())

    if lang == "Python":
        novul_save_fpath = os.path.join(save_dpath, f"vulfix_py_novul_cleaned.json")
        vul_save_fpath = os.path.join(save_dpath, f"vulfix_py_vul_cleaned.json")
    elif lang == "Java":
        novul_save_fpath = os.path.join(save_dpath, f"vulfix_java_novul_cleaned.json")
        vul_save_fpath = os.path.join(save_dpath, f"vulfix_java_vul_cleaned.json")
    else:
        raise RuntimeError

    with open(novul_save_fpath, 'w') as f:
        json.dump(novul_items, f, indent=4)

    with open(vul_save_fpath, 'w') as f:
        json.dump(vul_items, f, indent=4)


"""SEARCH CWE"""


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


def search_cwe_for_dataset(dataset_fpath: str, log_fpath: str):
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

    try:
        nvd_not_found: List[str] = []
        nvd_no_cwe: List[str] = []
        nvd_with_cwe: Dict[str, List[str]] = {}

        searched_cves: List[str] = []

        with tqdm(total=len(dataset)) as pb:
            for item in dataset:

                cve_id = item["cve_list"]
                if cve_id is not None and re.fullmatch(r"CVE-\d+-\d+", cve_id) and cve_id not in searched_cves:
                    searched_cves.append(cve_id)

                    try:
                        cwe_ids = search_and_extract_cwe(driver, cve_id)
                    except Exception as e:
                        nvd_not_found.append(cve_id)
                        continue

                    if cwe_ids is None or len(cwe_ids) == 0:
                        nvd_no_cwe.append(cve_id)
                        continue

                    nvd_with_cwe[cve_id] = cwe_ids

                pb.update(1)

        nvd_with_cwe = dict(sorted(nvd_with_cwe.items(), key=lambda x: len(x[1]), reverse=True))

        with open(log_fpath, 'w') as f:
            json.dump({
                "nvd_not_found": nvd_not_found,
                "nvd_no_cwe": nvd_no_cwe,
                "nvd_with_cwe": nvd_with_cwe
            }, f, indent=4)
    finally:
        driver.quit()


"""COMMITS CHECKING"""


def check_commits_existence_by_fetching(dataset_fpath: str) -> None:
    """Check the commits existence through fetching."""
    token = os.getenv("TOKEN", "")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []

    with (tqdm(total=len(dataset)) as pb):
        for cve_data in dataset:
            for i, commit in enumerate(cve_data['commits']):
                is_exist = commit.get('existence', None)
                if is_exist is None:
                    is_exist, _ = is_commit_exist(commit["repo"], commit["commit_hash"], token)
                    # Update current cve data
                    # is_exist:
                    # - True: commit exists
                    # - False: commit does not exist
                    # - Null: check failed
                    cve_data['commits'][i]['existence'] = is_exist

            updt_dataset.append(cve_data)

            pb.update(1)

    with open(dataset_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)


def check_local_repos_and_clone(
        dataset_fpath: str,
        repos_root: str = '/root/projects/clone_projects'
) -> None:
    token = os.getenv("TOKEN", "")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    noexist_local_repos = []
    for cve_data in dataset:
        for commit in cve_data['commits']:
            auth_repo = commit["repo"]
            repo_dpath = os.path.join(repos_root, auth_repo.replace('/', '_'))
            if not os.path.exists(repo_dpath):
                noexist_local_repos.append(auth_repo)

    noexist_local_repos = list(set(noexist_local_repos))
    print(f"No exist local repo number: {len(noexist_local_repos)}")
    # print(json.dumps(noexist_local_repos, indent=4))

    # (2) Calculate the total size of all repos which need to be cloned
    # total_size = 0
    # success_num = 0
    # noexist_local_repo2size = {}
    # for auth_repo in noexist_local_repos:
    #     size = get_remote_repo_size(auth_repo)
    #     total_size += size
    #     if size > 0:
    #         success_num += 1
    #     noexist_local_repo2size[auth_repo] = size
    # noexist_local_repo2size = dict(sorted(noexist_local_repo2size.items(), key=lambda x: x[1], reverse=True))
    # noexist_local_repo2size = {repo: format_size(size) for repo, size in noexist_local_repo2size.items()}
    # print(f"Total size: {format_size(total_size)} ({success_num} / {len(noexist_local_repos)})")
    # print(json.dumps(noexist_local_repo2size, indent=4))

    # (3) Clone repos
    # for repo in noexist_local_repos:
    #     if repo in [
    #         "OpenNMS/opennms",
    #         "OpenOLAT/OpenOLAT",
    #         "apache/ofbiz-framework",
    #         "wuyouzhuguli/FEBS-Shiro",
    #         "keycloak/keycloak",
    #         "facebook/buck",
    #         "luchua-bc/GreenBrowser",
    #         "gradle/gradle",
    #         "igniterealtime/Openfire",
    #         "shopizer-ecommerce/shopizer",
    #         "jamesagnew/hapi-fhir",
    #         "eclipse/rdf4j",
    #         "xwiki/xwiki-platform",
    #         "OpenAPITools/openapi-generator",
    #         "bigbluebutton/bigbluebutton",
    #         "brianchandotcom/liferay-portal",
    #         "elastic/elasticsearch",
    #         "restlet/restlet-framework-java",
    #         "siacs/Conversations",
    #         "ballerina-platform/ballerina-lang",
    #         "hapifhir/hapi-fhir",
    #         "intranda/goobi-viewer-core",
    #         "dotCMS/dotCMS",
    #         "alkacon/opencms-core",
    #         "apache/camel",
    #         "SonarSource/sonarqube",
    #         "apache/hive",
    #         "eXist-db/exist",
    #         "javaserverfaces/mojarra",
    #         "apache/geronimo",
    #         "blynkkk/blynk-server",
    #         "dotCMS/core",
    #         "apache/ignite",
    #         "apache/ambari",
    #         "apache/hbase",
    #         "XIOGit/https-github.com-wuyouzhuguli-FEBS-Shiro",
    #         "JabRef/jabref"
    #     ]:
    #         continue
    #
    #     print("=" * 100 + "\n\n")
    #     repo_dpath = os.path.join(repos_root, repo.replace('/', '_'))
    #     clone_repo(repo, repo_dpath, token=token, timeout=60)


def check_commits_reproducibility_by_cloning(
        dataset_fpath: str,
        repos_root: str = '/root/projects/clone_projects'
) -> None:
    """Check the commits reproducibility through cloning."""
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []
    for cve_data in dataset:
        for i, commit in enumerate(cve_data['commits']):
            is_exist = commit['existence']
            is_repro = commit.get('reproducibility', None)

            if is_exist is False:
                is_repro = False
            else:
                repo_dpath = os.path.join(repos_root, commit['repo'].replace("/", "_"))
                if is_repro is None and os.path.exists(repo_dpath):
                    is_repro = is_commit_exist_in_repo(repo_dpath, commit['commit_hash'])

            # Update current cve data
            cve_data['commits'][i]['reproducibility'] = is_repro

        updt_dataset.append(cve_data)

    with open(dataset_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)


def final_check(dataset_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    for cve_data in dataset:
        for i, commit in enumerate(cve_data['commits']):
            is_exist = commit['existence']
            is_repro = commit.get('reproducibility', None)

            # 1. Commit with null existence
            if is_exist is None:
                if is_repro:
                    cve_data['commits'][i]['existence'] = True
                else:
                    print(f"Commit with null existence: {commit['commit_hash']}")

            # 2. Commit with null reproducibility
            if is_repro is None:
                print(f"Commit with null reproducibility: {commit['commit_hash']}")

            # 3. Commit with false existence
            if is_exist is False:
                print(f"Commit with false existence: {commit['commit_hash']}")


def count_repo_cve_commits(dataset_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    valid_cve_num = 0
    commit_num2cve_num: Dict[int, int] = {}

    invalid_cves = []
    invalid_commit_num = 0
    valid_commit_num = 0

    valid_single_commit_cve_repos = []

    for cve_data in dataset:
        valid_flag = True
        curr_invalid_commit_num = 0

        for commit in cve_data['commits']:
            if not commit["reproducibility"]:
                # As long as one of the commits involved in the CVE cannot be reproduced, we consider it invalid!
                valid_flag = False
                curr_invalid_commit_num += 1

        curr_commit_num = len(cve_data['commits'])
        if valid_flag:
            valid_cve_num += 1

            if curr_commit_num not in commit_num2cve_num:
                commit_num2cve_num[curr_commit_num] = 1
            else:
                commit_num2cve_num[curr_commit_num] += 1

            if curr_commit_num == 1:
                repo = cve_data['commits'][0]['repo']
                if repo not in valid_single_commit_cve_repos:
                    valid_single_commit_cve_repos.append(repo)
        else:
            invalid_cves.append(cve_data['cve_id'])
            valid_commit_num += curr_commit_num - curr_invalid_commit_num
            invalid_commit_num += curr_invalid_commit_num

    print(f"Valid CVE number: {valid_cve_num}")
    print(f"Repo of valid single commit CVE number: {len(valid_single_commit_cve_repos)}")

    commit_num2cve_num = dict(sorted(commit_num2cve_num.items(), key=lambda x: x[1], reverse=True))
    print("Mapping from commit number to cve number: \n" + json.dumps(commit_num2cve_num, indent=4))

    print("\n" + "-" * 100 + "\n")

    print(f"Invalid CVE number: {len(invalid_cves)}")
    print(f"Valid / Invalid commit number (in invalid CVEs): {valid_commit_num} / {invalid_commit_num}")
    print("Invalid CVEs: \n" + json.dumps(invalid_cves, indent=4))


"""DATASET FILTER"""


def build_dataset_containing_cves_with_valid_single_commit(
        lang: Literal['Python', 'Java'],
        dataset_fpath: str,
        output_root: str
) -> str:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    filtered_dataset: List[Dict] = []

    for data in dataset:
        commits = data["commits"]

        if len(commits) == 1 and commits[0]['existence'] is True and commits[0]['reproducibility'] is True:
            new_data = {
                "source": "vulfix",
                "task_id": f"vulfix-vul-{len(filtered_dataset)}",
                "cve_id": data["cve_id"],
                "commit_type": data["commit_type"],
                "cwe_list": data["cwe_list"],
                "repo": commits[0]['repo'],
                "commit_hash": commits[0]['commit_hash'],
                "file_count": None
            }
            filtered_dataset.append(new_data)

    output_fpath = os.path.join(output_root, f"{lang.lower()}_vul_tasks_vulfix.json")
    with open(output_fpath, 'w') as f:
        json.dump(filtered_dataset, f, indent=4)

    return output_fpath


if __name__ == '__main__':
    output_dir = "/root/projects/VDTest/dataset/Intermediate"
    ori_vulfix_csv = "/root/projects/VDTest/dataset/VulFix/ase_dataset_sept_19_2021.csv"

    ## Step 1: Read original VulFix
    # py_vulfix_file, java_vulfix_file = read_raw_vulfix(ori_vulfix_csv, "/root/projects/VDTest/dataset/VulFix")
    vulfix_py_file = "/root/projects/VDTest/dataset/Original/VulFix/vulfix_py.json"
    vulfix_java_file = "/root/projects/VDTest/dataset/Original/VulFix/vulfix_java.json"


    lang = 'Python'  # 'Java'


    ## Step 2: Simplify dataset
    if lang == 'Python':
        # vulfix_lang_simp_file = build_simplified_dataset(vulfix_py_file, output_dir)
        vulfix_lang_simp_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py.json"
    elif lang == 'Java':
        # vulfix_lang_simp_file = build_simplified_dataset(vulfix_java_file, output_dir)
        vulfix_lang_simp_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_java.json"
    else:
        raise RuntimeError


    ## Step 3: Find CVE of dataset items (NOTE: some data in 'vulfix_java' has CVE annotations)
    if lang == 'Python':
        lang_cve_log_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_cve.log"
    elif lang == 'Java':
        lang_cve_log_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_java_cve.log"
    else:
        raise RuntimeError
    # find_dataset_missing_cve(vulfix_lang_simp_file, lang_cve_log_file)
    # refine_dataset_with_cve(vulfix_lang_simp_file, lang_cve_log_file)


    ## Step 4: Find CWE of dataset items
    if lang == 'Python':
        lang_cwe_log_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_cwe.log"
    elif lang == 'Java':
        lang_cwe_log_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_java_cwe.log"
    else:
        raise RuntimeError
    # search_cwe_for_dataset(vulfix_lang_simp_file, lang_cwe_log_file)


    ## Step 5: Separate dataset to novul and vul sub dataset
    # separate_dataset(
    #     lang=lang,
    #     dataset_fpath=vulfix_lang_simp_file,
    #     cwe_log_fpath=lang_cwe_log_file,
    #     save_dpath="/root/projects/VDTest/dataset/Intermediate/VulFix"
    # )

    if lang == 'Python':
        vulfix_lang_novul_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_novul_cleaned.json"
        vulfix_lang_vul_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_py_vul_cleaned.json"
    elif lang == 'Java':
        vulfix_lang_novul_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_java_novul_cleaned.json"
        vulfix_lang_vul_file = "/root/projects/VDTest/dataset/Intermediate/VulFix/vulfix_java_vul_cleaned.json"
    else:
        raise RuntimeError

    ## Step 6: Check commits validity
    # check_commits_existence_by_fetching(vulfix_lang_vul_file)
    # check_local_repos_and_clone(vulfix_lang_vul_file)
    # check_commits_reproducibility_by_cloning(vulfix_lang_vul_file)
    # final_check(vulfix_lang_vul_file)
    count_repo_cve_commits(vulfix_lang_vul_file)


    ## Step 5: Build filtered dataset
    # final_vul_tasks_fpath = build_dataset_containing_cves_with_valid_single_commit(
    #     lang=lang,
    #     dataset_fpath=vulfix_lang_vul_file,
    #     output_root="/root/projects/VDTest/dataset/Final/VIEW_1000"
    # )


    ## Step 6: Update final dataset with file count
    if lang == 'Python':
        final_vul_tasks_fpath = "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_vulfix.json"
        # update_dataset_with_commit_file_count(vul_tasks_fpath, suffix=['.py'])
    elif lang == 'Java':
        final_vul_tasks_fpath = "/root/projects/VDTest/dataset/Final/VIEW_1000/java_vul_tasks_vulfix.json"
        # update_dataset_with_commit_file_count(vul_tasks_fpath, suffix=['.java'])
    else:
        raise RuntimeError
