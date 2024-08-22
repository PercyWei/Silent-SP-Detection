import os
import json
import re
import requests
import shutil
import pandas as pd

from typing import *
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from openai import OpenAI
from openai.types.chat.completion_create_params import ResponseFormat

from utils import run_command


def read_raw_vulfix():
    all_commits = pd.read_csv('/root/projects/VDTest/dataset/VulFix/ase_dataset_sept_19_2021.csv')

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

    py_vulfix_fpath = "/root/projects/VDTest/dataset/VulFix/py_vulfix.json"
    with open(py_vulfix_fpath, 'w') as f:
        json.dump(py.to_dict(orient='records'), f, indent=4)

    java_vulfix_fpath = "/root/projects/VDTest/dataset/VulFix/java_vulfix.json"
    with open(java_vulfix_fpath, 'w') as f:
        json.dump(java.to_dict(orient='records'), f, indent=4)


def build_sim_vulfix():
    py_vulfix_fpath = "/root/projects/VDTest/dataset/VulFix/py_vulfix.json"
    with open(py_vulfix_fpath, 'r') as f:
        py_items = json.load(f)

    record_commit_ids = []
    sim_py_dataset: List[Dict] = []
    for item in py_items:
        if item['commit_id'] not in record_commit_ids:
            record_commit_ids.append(item['commit_id'])

            sim_item = {
                "id": len(sim_py_dataset),
                "cve_list": item["cve_list"],
                "commit_type": item["label"],
                "cwe_id": None,
                "repo": item["repo"],
                "commit_hash": item["commit_id"],
                "file_counts": item["file_counts"],
                "PL_list": ["Python"]
            }
            sim_py_dataset.append(sim_item)

    sim_py_vulfix_fpath = "/root/projects/VDTest/output/dataset/sim_py_vulfix.json"
    with open(sim_py_vulfix_fpath, 'w') as f:
        json.dump(sim_py_dataset, f, indent=4)


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


def find_py_cve_id():
    sim_py_vulfix_fpath = "/root/projects/VDTest/output/dataset/sim_py_vulfix.json"
    with open(sim_py_vulfix_fpath, 'r') as f:
        py_items = json.load(f)

    api_key = os.getenv("OPENAI_KEY")
    api_base = os.getenv("OPENAI_API_BASE")
    client = OpenAI(api_key=api_key, base_url=api_base)

    find_cves = []
    no_connect_cvs = []
    i = 0
    try:
        for item in py_items:
            if item["commit_type"] == 1:
                i += 1
                print("=" * 50 + f" {i} " + "=" * 50)
                repo = item["repo"]
                commit_hash = item["commit_hash"]
                commit_url = f'https://api.github.com/repos/{repo}/commits/{commit_hash}'
                try:
                    commit_response = requests.get(commit_url, timeout=10)
                except requests.exceptions.Timeout:
                    no_connect_cvs.append({"repo": repo, "commit_hash": commit_hash})
                    continue

                if commit_response.status_code != 200:
                    no_connect_cvs.append({"repo": repo, "commit_hash": commit_hash})
                    continue

                commit_msg = commit_response.json()["commit"]["message"]

                print(commit_msg + "\n")

                cve_id = ask_gpt(client, commit_msg)
                if cve_id is not None and re.fullmatch(r"CVE-\d+-\d+", cve_id):
                    find_cves.append({
                        "repo": repo,
                        "commit_hash": commit_hash,
                        "cve_id": cve_id,
                        "msg": commit_msg
                    })

    except Exception as e:
        print(e)
    finally:
        log = Path("/root/projects/VDTest/output/dataset/log.json")
        log.write_text(json.dumps({"find": find_cves, "time_out": no_connect_cvs}, indent=4))


def find_py_cve_id_in_log():
    log_fpath = "/root/projects/VDTest/output/dataset/log.json"
    with open(log_fpath, 'r') as f:
        log = json.load(f)

    api_key = os.getenv("OPENAI_KEY")
    api_base = os.getenv("OPENAI_API_BASE")
    client = OpenAI(api_key=api_key, base_url=api_base)

    find_cves = []
    no_connect_cvs = []
    for i, item in enumerate(log["time_out"]):
        print("=" * 50 + f" {i} " + "=" * 50)
        repo = item["repo"]
        commit_hash = item["commit_hash"]
        commit_url = f'https://api.github.com/repos/{repo}/commits/{commit_hash}'
        try:
            commit_response = requests.get(commit_url, timeout=10)
        except requests.exceptions.Timeout:
            no_connect_cvs.append({"repo": repo, "commit_hash": commit_hash})
            continue
        except requests.exceptions.SSLError:
            no_connect_cvs.append({"repo": repo, "commit_hash": commit_hash})
            continue

        if commit_response.status_code != 200:
            no_connect_cvs.append({"repo": repo, "commit_hash": commit_hash})
            continue

        commit_msg = commit_response.json()["commit"]["message"]

        print(commit_msg + "\n")

        cve_id = ask_gpt(client, commit_msg)
        if cve_id is not None and re.fullmatch(r"CVE-\d+-\d+", cve_id):
            find_cves.append({
                "repo": repo,
                "commit_hash": commit_hash,
                "cve_id": cve_id,
                "msg": commit_msg
            })

    log["find"].extend(find_cves)
    log["time_out"] = no_connect_cvs

    with open(log_fpath, 'w') as f:
        json.dump(log, f, indent=4)


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


def count():
    sim_py_vulfix_fpath = "/root/projects/VDTest/output/dataset/sim_py_vulfix.json"
    with open(sim_py_vulfix_fpath, 'r') as f:
        py_items = json.load(f)

    record_cve_repo_commit = {}
    for item in py_items:
        if item["commit_type"] == 1 and isinstance(item["cve_list"], list):
            assert len(item["cve_list"]) == 1
            cve_id = item["cve_list"][0]
            if cve_id not in record_cve_repo_commit:
                record_cve_repo_commit[cve_id] = []

            repo_commit = item["repo"] + "_" + item["commit_hash"]
            assert repo_commit not in record_cve_repo_commit[cve_id]
            record_cve_repo_commit[cve_id].append(repo_commit)

    sc_cve_num = 0
    cve_commit_num = {}
    for cve_id, repo_commit in record_cve_repo_commit.items():
        if len(repo_commit) == 1:
            sc_cve_num += 1

        cve_commit_num[cve_id] = len(repo_commit)

    print(f"CVE number: {len(record_cve_repo_commit)}")
    print(f"CVE with single commit number: {sc_cve_num}")


def combine_vulfix_treevul():
    sim_py_vulfix_fpath = "/root/projects/VDTest/output/dataset/sim_py_vulfix.json"
    with open(sim_py_vulfix_fpath, 'r') as f:
        sim_py_vulfix = json.load(f)

    sim_treevul_fpath = "/root/projects/VDTest/output/dataset/sim_treevul.json"
    with open(sim_treevul_fpath, 'r') as f:
        sim_treevul = json.load(f)

    # NOTE: For security patches, this dataset only collects the original dataset (VulFix, TreeVul) entries
    #       with CVE-ID that have been found so far, and each CVE only contains single commit.
    record_cve_repo_commit = {}
    for item in sim_py_vulfix:
        if item["commit_type"] == 1 and isinstance(item["cve_list"], list):
            assert len(item["cve_list"]) == 1
            cve_id = item["cve_list"][0]
            if cve_id not in record_cve_repo_commit:
                record_cve_repo_commit[cve_id] = []

            repo_commit = item["repo"] + "_" + item["commit_hash"]
            assert repo_commit not in record_cve_repo_commit[cve_id]
            record_cve_repo_commit[cve_id].append(repo_commit)

    cve_commit_num = {}
    for cve_id, repo_commit in record_cve_repo_commit.items():
        cve_commit_num[cve_id] = len(repo_commit)

    commit_items = {}
    # VulFix
    for item in sim_py_vulfix:
        append_flag = False
        if item["commit_type"] == 0:
            append_flag = True
        else:
            if isinstance(item["cve_list"], list):
                cve_id = item["cve_list"][0]
                if cve_commit_num[cve_id] == 1:
                    append_flag = True

        if append_flag and item["commit_hash"] not in commit_items:
            item["source"] = "vulfix"
            commit_items[item["commit_hash"]] = item

    # TreeVul
    for item in sim_treevul:
        if item["PL_list"] == ["Python"] and item["commit_hash"] not in commit_items:
            item["source"] = "treevul"
            commit_items[item["commit_hash"]] = item

    items = list(commit_items.values())

    # Count
    vul_num = 0
    non_vul_num = 0
    for item in items:
        if item["commit_type"] == 1:
            vul_num += 1
        else:
            non_vul_num += 1

    print(f"Vul number: {vul_num}")
    print(f"Non-Vul number: {non_vul_num}")

    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items.json"
    with open(py_items_fpath, 'w') as f:
        json.dump(items, f, indent=4)


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

clone()
