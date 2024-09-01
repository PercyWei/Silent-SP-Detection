import os
import re
import json
import requests

from typing import *
from tqdm import tqdm


def find_github_relevant_ref(refs: List[Dict]) -> List[str]:
    """Only check if there is a github url in the ref."""
    github_urls = []
    for ref in refs:
        url = ref['url']
        if "https://github.com/" in url:
            github_urls.append(url)
    return github_urls


def build_new_dataset(nvdcve_fpath):
    with open(nvdcve_fpath, 'r') as f:
        content = json.load(f)

    cve_items = content["CVE_Items"]

    dateset_items = []

    with tqdm(total=len(cve_items)) as pb:
        for item in cve_items:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]

            # Find GitHub reference of CVE
            refs = item["cve"]["references"]["reference_data"]
            github_urls = find_github_relevant_ref(refs)

            if github_urls:
                # Get CWE-IDs of CVE
                cwe_list = []
                for cwe in item["cve"]["problemtype"]["problemtype_data"][0]["description"]:
                    cwe_id = cwe["value"]
                    if re.match(r"^CWE-\d+$", cwe_id):
                        cwe_list.append(cwe_id)

                if len(cwe_list) > 0:
                    sim_item = {"cve_id": cve_id, "cwe_list": cwe_list, "urls": github_urls}
                    dateset_items.append(sim_item)

            pb.update(1)

    ori_fname = nvdcve_fpath.split('/')[-1]

    v1_dataset_fpath = nvdcve_fpath[:-len(ori_fname)] + ori_fname.split('.')[0] + "_v1.json"
    with open(v1_dataset_fpath, 'w') as f:
        json.dump(dateset_items, f, indent=4)


def filter_dataset_v1(v1_dataset_fpath):
    """
    v1 -> v1-1 + v1-2
    - v1-1: url has '.py'
    - v1-2:

    We found that the majority of the github urls where '.py' appears are in blob mode (see below),
    based on which we select python items from the dataset v1.
    """
    with open(v1_dataset_fpath, 'r') as f:
        dateset_items = json.load(f)

    # ex: https://github.com/openstack/horizon/blob/master/horizon/workflows/views.py#L96-L102
    # - repo: openstack/horizon
    # - tag:  master
    # - file: horizon/workflows/views.py
    # - line range: #L96-L102
    blob_pattern = r"^https://github\.com/([\w-]+/[\w-]+)/blob/([^/]+)/(.*?)(#L\d+(-L\d+)?)?$"

    py_items = []
    unchecked_items = []

    for item in dateset_items:
        urls = item["urls"]

        py_flag = False
        not_py_flag = False

        for url in urls:
            match = re.match(blob_pattern, url)

            if match:
                repo = match.group(1)
                tag = match.group(2)
                file_path = match.group(3)

                if file_path.endswith(".py"):
                    py_flag = True
                    continue
                # We do not consider commits that contain files with the following suffixes
                elif any(file_path.endswith(suffix) for suffix in ['.c', '.h', '.cpp', '.java', '.php']):
                    py_flag = False
                    not_py_flag = True
                    break

        if py_flag:
            py_items.append(item)

        if not py_flag and not not_py_flag:
            unchecked_items.append(item)

    dpath = os.path.dirname(v1_dataset_fpath)

    v1_1_dataset_fpath = os.path.join(dpath, "v1-1.json")
    with open(v1_1_dataset_fpath, 'w') as f:
        json.dump(py_items, f, indent=4)

    v1_2_dataset_fpath = os.path.join(dpath, "v1-2.json")
    with open(v1_2_dataset_fpath, 'w') as f:
        json.dump(unchecked_items, f, indent=4)


def select_from_dataset_v1_2(v1_2_dataset_fpath):
    """
    v1-2 -> v1-2-1 + v1-2-2
    - v1-2-1: has commit url
    - v1-2-2: rest
    """
    with open(v1_2_dataset_fpath, 'r') as f:
        items = json.load(f)

    commit_pattern = r"^https://github\.com/([\w-]+/[\w-]+)/commit/([a-fA-F0-9]+)$"

    selected_items = []
    rest_items = []

    for item in items:
        add_flag = False
        for url in item["urls"]:
            match = re.match(commit_pattern, url)
            if match:
                add_flag = True
                break

        if add_flag:
            selected_items.append(item)
        else:
            rest_items.append(item)

    dpath = os.path.dirname(v1_2_dataset_fpath)

    v1_2_1_dataset_fpath = os.path.join(dpath, "v1-2-1.json")
    with open(v1_2_1_dataset_fpath, 'w') as f:
        json.dump(selected_items, f, indent=4)

    v1_2_2_dataset_fpath = os.path.join(dpath, "v1-2-2.json")
    with open(v1_2_2_dataset_fpath, 'w') as f:
        json.dump(rest_items, f, indent=4)


def test_request():
    token = os.getenv("TOKEN")

    url = f"https://api.github.com/repos/livehelperchat/livehelperchat/commits/fbed8728be59040a7218610e72f6eceb5f8bc152"
    headers = {
        "Authorization": token,
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(json.dumps(response.json(), indent=4))


def get_pl_list_for_dataset_v1_2_1(v1_2_1_dataset_fpath):
    with open(v1_2_1_dataset_fpath, 'r') as f:
        items = json.load(f)

    token = os.getenv("TOKEN")

    commit_pattern = r"^https://github\.com/([\w-]+/[\w-]+)/commit/([a-fA-F0-9]+)$"

    with tqdm(total=len(items)) as pb:
        for i, item in enumerate(items):

            if "PL_list" not in item:
                repo = None
                commit_hash = None

                for url in item["urls"]:
                    match = re.match(commit_pattern, url)
                    if match:
                        repo = match.group(1)
                        commit_hash = match.group(2)
                        break

                assert repo is not None and commit_hash is not None

                url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
                headers = {
                    "Authorization": token,
                    "Accept": "application/vnd.github.v3+json"
                }

                try:
                    response = requests.get(url, headers=headers, timeout=10)
                except requests.exceptions.SSLError as ssl_err:
                    continue
                except requests.exceptions.HTTPError as http_err:
                    continue
                except requests.exceptions.RequestException as req_err:
                    continue
                except Exception as e:
                    continue

                if response.status_code == 200:
                    commit_data = response.json()

                    pl_list = []

                    for file_info in commit_data["files"]:
                        fname = file_info["filename"]

                        if fname.endswith(".py") and "Python" not in pl_list:
                            pl_list.append("Python")
                        elif (fname.endswith(".c") or fname.endswith(".h")) and "C" not in pl_list:
                            pl_list.append("C")
                        elif (fname.endswith(".cpp") or fname.endswith(".cc")) and "C++" not in pl_list:
                            pl_list.append("C++")
                        elif fname.endswith(".java") and "Java" not in pl_list:
                            pl_list.append("Java")
                        elif (fname.endswith(".php") or fname.endswith(".phpt")) and "PHP" not in pl_list:
                            pl_list.append("PHP")
                        elif (fname.endswith(".js") or fname.endswith(".jsx")) and "JavaScript" not in pl_list:
                            pl_list.append("JavaScript")
                        elif fname.endswith(".cs") and "C#" not in pl_list:
                            pl_list.append("C#")
                        elif fname.endswith(".ts") and "TypeScript" not in pl_list:
                            pl_list.append("TypeScript")
                        elif fname.endswith(".rb") and "Ruby" not in pl_list:
                            pl_list.append("Ruby")
                        elif fname.endswith(".go") and "Go" not in pl_list:
                            pl_list.append("Go")
                        elif fname.endswith(".html") and "HTML" not in pl_list:
                            pl_list.append("HTML")
                        elif (fname.endswith(".pm") or fname.endswith(".t")) and "Perl" not in pl_list:
                            pl_list.append("Perl")
                        elif fname.endswith(".rs") and "Rust" not in pl_list:
                            pl_list.append("Rust")
                        elif fname.endswith(".cshtml"):
                            if "C#" not in pl_list:
                                pl_list.append("C#")
                            if "HTML" not in pl_list:
                                pl_list.append("HTML")
                        elif fname.endswith(".vue"):
                            if "JavaScript" not in pl_list:
                                pl_list.append("JavaScript")
                            if "HTML" not in pl_list:
                                pl_list.append("HTML")
                        else:
                            pass

                    item["PL_list"] = pl_list

            items[i] = item
            pb.update(1)

    with open(v1_2_1_dataset_fpath, 'w') as f:
        json.dump(items, f, indent=4)


# nvdcve_fpath = "/root/projects/VDTest/NVD/raw/nvdcve-2022.json"
# nvdcve_fpath = "/root/projects/VDTest/NVD/raw/nvdcve-2023.json"
# nvdcve_fpath = "/root/projects/VDTest/NVD/raw/nvdcve-2024.json"
# build_new_dataset(nvdcve_fpath)


# v1_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2022/v1.json"
# v1_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2023/v1.json"
# v1_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2024/v1.json"
# filter_dataset_v1(v1_dataset_fpath)


# v1_2_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2022/v1-2.json"
# v1_2_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2023/v1-2.json"
# v1_2_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2024/v1-2.json"
# select_from_dataset_v1_2(v1_2_dataset_fpath)

# v1_2_1_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2022/v1-2-1.json"
v1_2_1_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2023/v1-2-1.json"
# v1_2_1_dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve-2024/v1-2-1.json"
get_pl_list_for_dataset_v1_2_1(v1_2_1_dataset_fpath)

