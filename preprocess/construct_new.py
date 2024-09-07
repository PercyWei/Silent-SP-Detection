import os
import re
import json
import requests

from typing import *
from tqdm import tqdm
from collections import defaultdict

from preprocess.util import (
    extract_pull_info_from_url, is_pull_exist, get_commits_from_pull_request,
    extract_issue_info_from_url, is_issue_exist, get_related_commits_from_issue_events,
    extract_commit_info_from_url,
    is_commit_exist, is_commit_exist_in_repo,
    get_file_lang
)


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
    dpath = os.path.dirname(v1_2_dataset_fpath)

    with open(v1_2_dataset_fpath, 'r') as f:
        items = json.load(f)

    # selected_items = []
    # rest_items = []
    # for item in items:
    #     add_flag = False
    #     for url in item["urls"]:
    #         match = re.match(commit_pattern, url)
    #         if match:
    #             add_flag = True
    #             break
    #
    #     if add_flag:
    #         selected_items.append(item)
    #     else:
    #         rest_items.append(item)
    #
    #
    # v1_2_1_dataset_fpath = os.path.join(dpath, "v1-2-1.json")
    # with open(v1_2_1_dataset_fpath, 'w') as f:
    #     json.dump(selected_items, f, indent=4)
    #
    # v1_2_2_dataset_fpath = os.path.join(dpath, "v1-2-2.json")
    # with open(v1_2_2_dataset_fpath, 'w') as f:
    #     json.dump(rest_items, f, indent=4)

    v1_2_3_items = []
    for item in items:
        add_flag = False
        for url in item["urls"]:
            commit_match = extract_commit_info_from_url(url)
            pull_match = extract_pull_info_from_url(url)
            issue_match = extract_issue_info_from_url(url)
            if commit_match or pull_match or issue_match:
                add_flag = True
                break

        if add_flag:
            v1_2_3_items.append(item)

    v1_2_3_dataset_fpath = os.path.join(dpath, "v1-2-3.json")
    with open(v1_2_3_dataset_fpath, 'w') as f:
        json.dump(v1_2_3_items, f, indent=4)


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


def complete_dataset_v1_2_1(v1_2_1_dataset_fpath):
    with open(v1_2_1_dataset_fpath, 'r') as f:
        items = json.load(f)

    commit_pattern = r"^https://github\.com/([\w-]+/[\w-]+)/commit/([a-fA-F0-9]+)$"

    updt_items = []
    for item in items:
        repo = None
        commit_hash = None

        repo_commits: List[Tuple[str, str]] = []
        for url in item["urls"]:
            match = re.match(commit_pattern, url)
            if match:
                repo = match.group(1)
                commit_hash = match.group(2)
                repo_commits.append((repo, commit_hash))

        assert repo is not None and commit_hash is not None

        updt_item = {
            "cve_id": item["cve_id"],
            "commit_type": 1,
            "cwe_id": item["cwe_list"],
            "commits": {

            }
        }
        updt_items.append(updt_item)


"""DATASET V1-2-3"""


def refine_dataset_v1_2_3_by_searching_url(v1_2_3_dataset_fpath):
    """Search commits related to url (commit / pull / issue)."""
    token = os.getenv("TOKEN", "")

    with open(v1_2_3_dataset_fpath, 'r') as f:
        items = json.load(f)

    updt_items = []
    with tqdm(total=len(items)) as pb:
        for item in items:
            rest_urls: List[str] = []
            commits: List[Dict] = item.get("commits", [])

            for url in item["urls"]:
                ## (1) Commit
                res = extract_commit_info_from_url(url)
                if res is not None:
                    repo, commit_hash = res
                    commits.append({"repo": repo, "commit_hash": commit_hash})
                    continue

                ## (2) Issue
                res = extract_issue_info_from_url(url)
                if res is not None:
                    repo, issue_number = res

                    issue_exist = is_issue_exist(repo, issue_number, token)
                    if issue_exist is None:
                        rest_urls.append(url)
                        continue
                    elif issue_exist is False:
                        continue

                    # Issue exists
                    issue_commits = get_related_commits_from_issue_events(repo, issue_number, token)
                    if issue_commits is not None:
                        for commit_hash in issue_commits:
                            commits.append({"repo": repo, "commit_hash": commit_hash})
                    else:
                        rest_urls.append(url)
                    continue

                ## (3) Pull
                res = extract_pull_info_from_url(url)
                if res is not None:
                    repo, pull_number = res

                    pull_exist = is_pull_exist(repo, pull_number, token)
                    if pull_exist is None:
                        rest_urls.append(url)
                        continue
                    elif pull_exist is False:
                        continue

                    # Pull exists
                    pull_commits = get_commits_from_pull_request(repo, pull_number, token)
                    if pull_commits is not None:
                        for commit_hash in pull_commits:
                            commits.append({"repo": repo, "commit_hash": commit_hash})
                    else:
                        rest_urls.append(url)
                    continue

            if len(rest_urls) > 0:
                print(json.dumps(rest_urls, indent=4))

            updt_item = {
                "cve_id": item["cve_id"],
                "cwe_list": item["cwe_list"],
                "urls": rest_urls,
                "commits": commits,
                "PL_list": []
            }
            updt_items.append(updt_item)
            pb.update(1)

    with open(v1_2_3_dataset_fpath, 'w') as f:
        json.dump(updt_items, f, indent=4)


def refine_dataset_v1_2_3_by_filtering(v1_2_3_dataset_fpath):
    with open(v1_2_3_dataset_fpath, 'r') as f:
        items = json.load(f)

    updt_items = []

    for item in items:
        # (1) Delete empty urls of each item
        assert len(item["urls"]) == 0

        # (2) Delete duplicate commits of each item
        updt_commits = []
        for commit in item["commits"]:
            if commit not in updt_commits:
                updt_commits.append(commit)

        # (3) Delete items with empty commits
        if len(updt_commits) > 0:
            updt_item = {
                "cve_id": item["cve_id"],
                "cwe_list": item["cwe_list"],
                "commits": updt_commits,
                "PL_list": []
            }
            updt_items.append(updt_item)

    with open(v1_2_3_dataset_fpath, 'w') as f:
        json.dump(updt_items, f, indent=4)


def refine_dataset_v1_2_3_by_getting_commit_lang(v1_2_3_dataset_fpath):
    """Search commits related to url (commit / pull / issue)."""
    token = os.getenv("TOKEN", "")

    with open(v1_2_3_dataset_fpath, 'r') as f:
        items = json.load(f)

    root = os.path.dirname(v1_2_3_dataset_fpath)
    commit_info_save_fpath = os.path.join(root, "v1-2-3_commit_infos.json")
    if os.path.exists(commit_info_save_fpath):
        with open(commit_info_save_fpath, 'r') as f:
            commit_infos = json.load(f)
    else:
        commit_infos: Dict[str, Dict] = {}

    fail_num = 0

    with tqdm(total=len(items)) as pb:
        for item in items:
            for commit in item["commits"]:
                repo = commit["repo"]
                commit_hash = commit["commit_hash"]
                if commit_hash not in commit_infos:
                    is_exist, commit_json = is_commit_exist(repo, commit_hash, token)
                    if is_exist is not None:
                        pl_list: List[str] = []
                        if is_exist:
                            for file in commit_json["files"]:
                                file_name = file["filename"]
                                langs = get_file_lang(file_name)
                                pl_list.extend(langs)
                        pl_list = list(set(pl_list))

                        commit_info = {
                            "existence": is_exist,
                            "PL_list": pl_list
                        }
                        commit_infos[commit_hash] = commit_info
                    else:
                        tqdm.write(f"{repo} {commit_hash}")
                        fail_num += 1

            pb.update(1)

    print(fail_num)
    with open(commit_info_save_fpath, 'w') as f:
        json.dump(commit_infos, f, indent=4)


def refine_dataset_v1_2_3_by_filling_commit_lang(v1_2_3_dataset_fpath):
    root = os.path.dirname(v1_2_3_dataset_fpath)
    commit_info_save_fpath = os.path.join(root, "v1-2-3_commit_infos.json")
    with open(commit_info_save_fpath, 'r') as f:
        commit_infos = json.load(f)

    with open(v1_2_3_dataset_fpath, 'r') as f:
        items = json.load(f)

    updt_items = []
    for item in items:
        updt_commits: List[Dict] = []
        for commit in item["commits"]:
            repo = commit["repo"]
            commit_hash = commit["commit_hash"]
            assert commit_hash in commit_infos

            updt_commit = {
                "repo": repo,
                "commit_hash": commit_hash,
                "existence": commit_infos[commit_hash]["existence"],
                "PL_list": commit_infos[commit_hash]["PL_list"]
            }
            updt_commits.append(updt_commit)

        updt_item = {
            "cve_id": item["cve_id"],
            "cwe_list": item["cwe_list"],
            "commits": updt_commits,
            "PL_list": []
        }
        updt_items.append(updt_item)

    with open(v1_2_3_dataset_fpath, 'w') as f:
        json.dump(updt_items, f, indent=4)


def select_cve_item_from_dataset_v1_2_3(v1_2_3_dataset_fpath, v2_dataset_fpath):
    # TODO-1: Only select CVE items that have no non-existent commit.

    with open(v1_2_3_dataset_fpath, 'r') as f:
        items = json.load(f)

    selected_items = []
    for item in items:
        add_flag = True
        for commit in item["commits"]:
            # Ref to TODO-1
            if not commit["existence"]:
                add_flag = False
                break

        if add_flag:
            # NOTE: Since all commits of this CVE item exist, delete the 'existence' attribute of each commit.
            updt_commis = []
            for commit in item["commits"]:
                del commit["existence"]
                updt_commis.append(commit)
            item["commits"] = updt_commis
            selected_items.append(item)

    with open(v2_dataset_fpath, 'w') as f:
        json.dump(selected_items, f, indent=4)


"""DATASET v2"""


def refine_dataset_v2_by_filling_cve_lang(v2_dataset_fpath):
    with open(v2_dataset_fpath, 'r') as f:
        items = json.load(f)

    updt_items = []
    for item in items:
        # NOTE: Since the program languages of all commits under this CVE item is summarized and recorded,
        #       delete the "PL_list" attribute of each commit.
        updt_pl_list = []
        updt_commits = []

        for commit in item["commits"]:
            updt_pl_list.extend(commit["PL_list"])
            del commit["PL_list"]
            updt_commits.append(commit)
        updt_pl_list = list(set(updt_pl_list))

        item["commits"] = updt_commits
        item["PL_list"] = updt_pl_list

        updt_items.append(item)

    with open(v2_dataset_fpath, 'w') as f:
        json.dump(updt_items, f, indent=4)


def select_cve_items_from_dataset_v2(v2_dataset_fpath, save_fpath):
    # TODO-1: For now, we only care about commits related to Python.
    # TODO-2: For now, we only select CVE items with single commit.

    with open(v2_dataset_fpath, 'r') as f:
        cve_items = json.load(f)

    selected_items = []
    for item in cve_items:
        # Ref to TODO-1 TODO2
        if item["PL_list"] == ["Python"] and len(item["commits"]) == 1:
            # NOTE:
            #  - Since we only select CVE items in Python, delete the "PL_list" attribute of each CVE item.
            #  - Since we only select CVE items with single commit, delete the 'commits' attribute and add
            #       the 'repo' and 'commit_hash' attributes.
            #  - Add 'commit_type' attribute and its value is 1.
            updt_item = {
                "cve_id": item["cve_id"],
                "commit_type": 1,
                "cwe_list": item["cwe_list"],
                "repo": item["commits"][0]["repo"],
                "commit_hash": item["commits"][0]["commit_hash"]
            }
            selected_items.append(updt_item)

    with open(save_fpath, 'w') as f:
        json.dump(selected_items, f, indent=4)


def check_cve_items_with_single_commit(cve_with_single_commit_fpath):
    with open(cve_with_single_commit_fpath, 'r') as f:
        cve_items = json.load(f)

    ## FUNCTION 1
    # duplicate_commit2cwes: Dict[str, List[str]] = defaultdict(list)
    # all_commits: List[str] = []
    #
    # updt_cve_items = []
    # for cve_item in cve_items:
    #     commit_hash = cve_item["commit_hash"]
    #     if commit_hash not in all_commits:
    #         all_commits.append(commit_hash)
    #         updt_cve_items.append(cve_item)
    #     else:
    #         duplicate_commit2cwes[commit_hash].extend(cve_item["cwe_list"])
    #
    # print(duplicate_commit2cwes)
    #
    # for i, cve_item in enumerate(updt_cve_items):
    #     commit_hash = cve_item["commit_hash"]
    #     if commit_hash in duplicate_commit2cwes:
    #         updt_cwe_list = list(set(cve_item["cwe_list"] + duplicate_commit2cwes[commit_hash]))
    #         updt_cve_items[i]["cwe_list"] = updt_cwe_list
    #
    # with open(cve_with_single_commit_fpath, 'w') as f:
    #     json.dump(updt_cve_items, f, indent=4)

    ## FUNCTION 2
    for cve_item in cve_items:
        if len(cve_item["cwe_list"]) > 1:
            print(cve_item["cve_id"])



def combine_nvdvul_2022_2024_2024(v2_dataset_2022_fpath, v2_dataset_2023_fpath, v2_dataset_2024_fpath):
    all_items = []
    with open(v2_dataset_2022_fpath, 'r') as f:
        items = json.load(f)
        all_items.extend(items)

    with open(v2_dataset_2023_fpath, 'r') as f:
        items = json.load(f)
        all_items.extend(items)

    with open(v2_dataset_2024_fpath, 'r') as f:
        items = json.load(f)
        all_items.extend(items)

    save_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks.json"
    with open(save_fpath, 'w') as f:
        json.dump(all_items, f, indent=4)


def check_comb_cve_items_with_single_commit(comb_cve_with_single_commit_fpath):
    with open(comb_cve_with_single_commit_fpath, 'r') as f:
        items = json.load(f)

    checked_commits = []
    for item in items:
        commit = item["commit_hash"]
        if commit not in checked_commits:
            checked_commits.append(commit)
        else:
            print(commit)


if __name__ == "__main__":
    # nvdcve_fpath = "/root/projects/VDTest/NVD/raw/nvdcve-2022.json"
    # nvdcve_fpath = "/root/projects/VDTest/NVD/raw/nvdcve-2023.json"
    # nvdcve_fpath = "/root/projects/VDTest/NVD/raw/nvdcve-2024.json"
    # build_new_dataset(nvdcve_fpath)

    version = "2023"

    # v1_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2022/v1.json"
    # v1_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2023/v1.json"
    # v1_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2024/v1.json"
    # filter_dataset_v1(v1_dataset_fpath)

    #################### v1_2 -> v1_2_1, v1_2_3, v1_2_3 ####################
    # v1_2_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2022/v1-2.json"
    # v1_2_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2023/v1-2.json"
    # v1_2_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2024/v1-2.json"
    # select_from_dataset_v1_2(v1_2_dataset_fpath)

    #################### Process v1_2_1 ####################
    # v1_2_1_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2022/v1-2-1.json"
    # v1_2_1_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2023/v1-2-1.json"
    # v1_2_1_dataset_fpath = "/root/projects/VDTest/data/NVD/filter/nvdcve-2024/v1-2-1.json"
    # get_pl_list_for_dataset_v1_2_1(v1_2_1_dataset_fpath)

    #################### Process v1_2_3 ####################
    v1_2_3_dataset_fpath = f"/root/projects/VDTest/data/NVD/filter/nvdcve-{version}/v1-2-3.json"

    ## Step 1
    # refine_dataset_v1_2_3_by_searching_url(v1_2_3_dataset_fpath)
    # TODO: Ensure that all urls for each item are checked before proceeding to the next step!

    ## Step 2
    # refine_dataset_v1_2_3_by_filtering(v1_2_3_dataset_fpath)

    ## Step 3
    # refine_dataset_v1_2_3_by_getting_commit_lang(v1_2_3_dataset_fpath)
    # TODO: Ensure that program languages of all commits are extracted before proceeding to the next step!

    ## Step 4
    # refine_dataset_v1_2_3_by_filling_commit_lang(v1_2_3_dataset_fpath)

    ## Step 5
    v2_dataset_fpath = f"/root/projects/VDTest/data/NVD/filter/nvdcve-{version}/v2.json"
    cve_with_single_commit_fpath = f"/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_{version}.json"
    # select_cve_item_from_dataset_v1_2_3(v1_2_3_dataset_fpath, v2_dataset_fpath)
    # refine_dataset_v2_by_filling_cve_lang(v2_dataset_fpath)
    # select_cve_items_from_dataset_v2(v2_dataset_fpath, cve_with_single_commit_fpath)

    ## Step 6
    # check_cve_items_with_single_commit(cve_with_single_commit_fpath)

    ## Step 7
    # TODO: Ensure that all three datasets are processed before proceeding to this step!
    # cve_with_single_commit_2022_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_2022.json"
    # cve_with_single_commit_2023_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_2023.json"
    # cve_with_single_commit_2024_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_2024.json"
    # combine_nvdvul_2022_2024_2024(
    #     cve_with_single_commit_2022_fpath,
    #     cve_with_single_commit_2023_fpath,
    #     cve_with_single_commit_2024_fpath
    # )

    comb_cve_with_single_commit_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks.json"
    check_comb_cve_items_with_single_commit(comb_cve_with_single_commit_fpath)


