import re
import os
import json
import time
import shutil
import requests

from typing import *
from collections import defaultdict
from tqdm import tqdm

from loguru import logger

from preprocess.log import default_add_logger
from preprocess.util import (
    clone_repo,
    calculate_date_range, is_commit_exist, is_commit_reproducible, is_commit_exist_in_repo
)
from utils import make_hie_dirs


"""DATASET SIMPLIFICATION"""


def build_simplified_dataset(dataset_fpath: str, output_root: str) -> str:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    # Select important attributes
    updt_dataset: List[Dict] = []
    for item in dataset:
        updt_item = {
            "cve_list": item["cve_list"],
            "commit_type": 1,
            "cwe_id": item["cwe_list"],
            "path_list": item["path_list"],
            "repo": item["repo"],
            "commit_hash": item["commit_id"],
            "PL": item["PL"]
        }
        updt_dataset.append(updt_item)

    save_fpath = os.path.join(output_root, "treevul.json")
    with open(save_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)

    return save_fpath


"""DATASET CLEANING"""


def group_items_by_commit(dataset_fpath: str) -> None:
    """Group dataset items by commit"""
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    # By default, the input dataset is the simplified TreeVul, so we only need to consider the attribute 'PL'
    updt_dataset: Dict[str, Dict] = {}
    for item in dataset:
        commit_hash = item['commit_hash']
        pl = item['PL']
        if commit_hash not in updt_dataset:
            del item["PL"]
            item["PL_list"] = [pl]
            updt_dataset[commit_hash] = item
        else:
            assert item["repo"] == updt_dataset[commit_hash]["repo"]
            if pl not in updt_dataset[commit_hash]["PL_list"]:
                updt_dataset[commit_hash]["PL_list"].append(pl)

    with open(dataset_fpath, 'w') as f:
        json.dump(list(updt_dataset.values()), f, indent=4)


def process_item_with_multiple_cves(dataset_fpath: str) -> None:
    """Process dataset items with multiple cves"""
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    cve_2_commits: Dict[str, List[str]] = defaultdict(list)    # cve id      -> [commit hash]
    commits_2c_cves: Dict[str, List[str]] = defaultdict(list)  # commit hash -> [cve id]
    for item in dataset:
        cves = item['cve_list'].split(',')
        commit_hash = item['commit_hash']

        for cve in cves:
            if commit_hash not in cve_2_commits[cve]:
                cve_2_commits[cve].append(commit_hash)
            if cve not in commits_2c_cves[commit_hash]:
                commits_2c_cves[commit_hash].append(cve)

    # Bad case: different CVEs have overlapping but not identical commits
    # ex: CVE A -> [commit 1, commit 2]   CVE B -> [commit 1, commit 3]
    bad_cves: List[str] = []
    for cve, commits in cve_2_commits.items():

        bad_flag = False
        match_cves = None

        for commit_hash in commits:
            if match_cves is None:
                match_cves = commits_2c_cves[commit_hash]
            elif match_cves != commits_2c_cves[commit_hash]:
                bad_flag = True
                break

        if bad_flag:
            bad_cves.append(cve)

    bad_cves = sorted(bad_cves, key=lambda cve: (int(cve.split('-')[1]), int(cve.split('-')[2])))

    print(json.dumps(bad_cves, indent=4))


def delete_duplicate_cves(dataset_fpath: str, output_root: str) -> str:
    """For items that correspond to multiple CVEs, we only retain one of the CWE-IDs."""
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    cve_to_items: Dict[str, List[Dict]] = defaultdict(list)
    for item in dataset:
        cves = item['cve_list'].split(',')
        cves = sorted(cves, key=lambda cve: (int(cve.split('-')[1]), int(cve.split('-')[2])))
        repr_cve = cves[-1]
        item["cve_id"] = repr_cve
        cve_to_items[repr_cve].append(item)

    updt_dataset: List[Dict] = []
    for cve_id, items in cve_to_items.items():
        updt_item = {
            "cve_id": cve_id,
            "commit_type": items[0]['commit_type'],
            "cwe_id": items[0]['cwe_id'],
            "path_list": items[0]['path_list'],
            "commits": []
        }
        for item in items:
            assert updt_item['cve_id'] == item['cve_id']
            assert updt_item['commit_type'] == item['commit_type']
            assert updt_item['cwe_id'] == item['cwe_id']
            assert updt_item['path_list'] == item['path_list']
            updt_item['commits'].append(
                {
                    'repo': item['repo'],
                    'commit_hash': item['commit_hash'],
                    'PL_list': item['PL_list']
                }
            )
        updt_dataset.append(updt_item)

    save_fpath = os.path.join(output_root, "treevul_cleaned.json")
    with open(save_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)

    return save_fpath


"""COMMITS CHECKING"""


def check_commits_existence_by_fetching(dataset_fpath: str) -> None:
    """Check the commits existence through fetching."""
    token = os.getenv("TOKEN", "")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []

    with (tqdm(total=len(dataset)) as pb):
        for cve_data in dataset:
            # TODO: For now, we only care about commits related to Python.
            if cve_data['PL_list'] == ["Python"]:
                for i, commit in enumerate(cve_data['commits']):
                    is_exist = commit.get('existence', None)
                    if is_exist is None:
                        is_exist, response = is_commit_exist(commit["repo"], commit["commit_hash"], token)
                        # Update current cve data
                        cve_data['commits'][i]['existence'] = is_exist

            updt_dataset.append(cve_data)

            pb.update(1)

    with open(dataset_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)


def check_local_repos_and_clone(dataset_fpath: str, repos_root: str = '/root/projects/clone_projects') -> None:
    token = os.getenv("TOKEN", "")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    noexist_local_repos = []
    for cve_data in dataset:
        # TODO: For now, we only care about commits related to Python.
        if cve_data["PL_list"] == ["Python"]:
            for commit in cve_data['commits']:
                auth_repo = commit["repo"]
                repo_dpath = os.path.join(repos_root, auth_repo.replace('/', '_'))
                if not os.path.exists(repo_dpath):
                    noexist_local_repos.append(auth_repo)

    noexist_local_repos = list(set(noexist_local_repos))
    print(json.dumps(noexist_local_repos, indent=4))

    for repo in noexist_local_repos:
        print("=" * 100 + "\n\n")
        repo_dpath = os.path.join(repos_root, repo.replace('/', '_'))
        clone_repo(repo, repo_dpath, token=token)


def check_commits_reproducibility_by_cloning(dataset_fpath: str, repos_root: str = '/root/projects/clone_projects') -> None:
    """Check the commits reproducibility through cloning."""
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []
    for cve_data in dataset:
        # TODO: For now, we only care about commits related to Python.
        if cve_data['PL_list'] == ["Python"]:
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


"""Select Valid Commits to Construct Dataset"""


def build_dataset_from_validity_check_results(dataset_fpath: str, check_results_fpath: str, output_root: str) -> None:
    """
    Select valid commits to build a new TreeVul dataset from validity check results.

    Args:
        dataset_fpath (str): Path to the TreeVul dataset file in JSON format.
            Note: Need to reconstruct the TreeVul dataset before calling this function.
                  Use 'group_TreeVul_items_by_commit' and get 'TreeVul_rec.json'.
        check_results_fpath (str): Path to the validity check results file in JSON format.
        output_root (str): Path to the root for overall output.
    """
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    with open(check_results_fpath, 'r') as f:
        check_results = json.load(f)

    if len(check_results["Failed Commits"]) != 0:
        return

    all_commits_check_results = check_results["All Commits"]
    not_found_check_results = check_results["Not Found Commits"]

    # Obtained manually
    old_2_new_repos = {
        "rcook/rgpg": "eahanson/rgpg",
        "embedthis/goahead": "zoushipeng/goahead",
        "embedthis/appweb": "whoerau/appweb",
        "wuyouzhuguli/FEBS-Shiro": "XIOGit/https-github.com-wuyouzhuguli-FEBS-Shiro",
        "vintagedaddyo/MyBB_Plugin-Upcoming_Events": "MangaD/MyBB_Plugin-Upcoming_Events"
    }

    # Build new dataset
    new_dataset: Dict[str, List[Dict]] = {}

    for commit_id, commit_items in dataset.items():
        repo = commit_items[0]["repo"]
        if repo in old_2_new_repos:
            # After manually checking, all commits belonging to the renamed repository are valid
            for commit_item in commit_items:
                commit_item["repo"] = old_2_new_repos[repo]
            new_dataset[commit_id] = commit_items
        else:
            if all_commits_check_results[repo][commit_id] == "Valid":
                new_dataset[commit_id] = commit_items
            elif all_commits_check_results[repo][commit_id] == "Invalid":
                pass
            else:
                assert repo in not_found_check_results and commit_id in not_found_check_results[repo], \
                    f"Commit is unchecked - repo: {repo}, commit_id: {commit_id}"

    # Save dataset
    save_dpath = make_hie_dirs(output_root, "TreeVul")
    new_dataset_fpath = os.path.join(save_dpath, "TreeVul_valid.json")
    with open(new_dataset_fpath, 'w') as f:
        json.dump(new_dataset, f, indent=4)


"""Select CVEs with Single Commit (scCVE)"""


def _get_cve2commit_and_commit2cve(dataset: Dict[str, List[Dict]]) -> Tuple[Dict, Dict]:
    """
    Get a Dict from CVE-ID to commit_id and a Dict from commit_id to CVE-ID.

    Args:
        dataset (Dict): Dataset with valid commit.
            Note: Form like
                {
                    commit_id_1:
                        [
                            changed_file_1_info (Dict),
                            changed_file_2_info (Dict),
                            ...
                        ]
                    commit_id_2: ...
                    ...
                }

    Returns:
        Dict: key is CVE-ID, value is the list of commit_id.
        Dict: key is commit_id, value is the list of CVE-ID.
    """
    cve2commit: Dict[str, List[str]] = {}
    commit2cve: Dict[str, List[str]] = {}

    def _update_cve2commit(_cve_id, _commit_id):
        if _cve_id not in cve2commit:
            cve2commit[_cve_id] = [_commit_id]
        else:
            cve2commit[_cve_id].append(_commit_id)
            cve2commit[_cve_id] = list(set(cve2commit[_cve_id]))

    def _update_commit2cve(_cve_id, _commit_id):
        if _commit_id not in commit2cve:
            commit2cve[_commit_id] = [_cve_id]
        else:
            commit2cve[_commit_id].append(_cve_id)
            commit2cve[_commit_id] = list(set(commit2cve[_commit_id]))

    for commit_id, items in dataset.items():
        for item in items:
            cves_str = item["cve_list"]
            if len(cves_str.split(',')) > 1:
                cves = cves_str.split(',')
                for cve_id in cves:
                    _update_cve2commit(cve_id, commit_id)
                    _update_commit2cve(cve_id, commit_id)
            else:
                cve_id = cves_str
                _update_cve2commit(cve_id, commit_id)
                _update_commit2cve(cve_id, commit_id)

    return cve2commit, commit2cve


"""Select CVEs with Single Commit Single File (scsfCVE)"""


def select_scsfCVEs(dataset_fpath: str, output_root: str) -> None:
    """
    After selecting CVEs containing single valid commit,
    this method select CVEs containing single valid commit which changes single file and build new dataset.

    Args:
        dataset_fpath (str): 'TreeVul_valid_scCVE.json'
        output_root (str): Path to overall output root directory.
    """
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    # Select
    new_dataset: Dict[str, Dict] = {}
    for commit_id, items in dataset.items():
        if len(items) == 1:
            new_dataset[commit_id] = items

    # Save
    save_dpath = make_hie_dirs(output_root, "TreeVul")
    new_dataset_fpath = os.path.join(save_dpath, "TreeVul_valid_scsfCVE.json")
    with open(new_dataset_fpath, 'w') as f:
        json.dump(new_dataset, f, indent=4)


"""OTHER"""


def count_dataset_file_language(dataset_fpath: str) -> None:
    """
    Count the number of files in different languages in the dataset.

    Args:
        dataset_fpath (str): Dataset form like: key is commit_id, value is list of items in original TreeVul dataset.
            Datasets Meet the Requirements:
                1. 'TreeVul_rec.json'
                2. 'TreeVul_valid.json'
                3. 'TreeVul_valid_scCVE.json'
                4. 'TreeVul_valid_scsfCVE.json'
    """
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    language_count: Dict[str, int] = {}

    for _, items in dataset.items():
        for item in items:
            if "PL" in item:
                lang = item["PL"]
                if lang not in language_count:
                    language_count[lang] = 1
                else:
                    language_count[lang] += 1


def count_repro_cve_commits(dataset_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    valid_cve_num = 0
    commit_num2cve_num: Dict[int, int] = {}

    invalid_cves = []
    invalid_commit_num = 0
    valid_commit_num = 0

    for cve_data in dataset:
        # TODO: For now, we only care about commits related to Python.
        if cve_data['PL_list'] == ["Python"]:

            valid_flag = True
            curr_invalid_commit_num = 0

            for commit in cve_data['commits']:
                if not commit["reproducibility"]:
                    valid_flag = False
                    curr_invalid_commit_num += 1

            curr_commit_num = len(cve_data['commits'])
            if valid_flag:
                valid_cve_num += 1

                if curr_commit_num not in commit_num2cve_num:
                    commit_num2cve_num[curr_commit_num] = 1
                else:
                    commit_num2cve_num[curr_commit_num] += 1
            else:
                invalid_cves.append(cve_data['cve_id'])
                valid_commit_num += curr_commit_num - curr_invalid_commit_num
                invalid_commit_num += curr_invalid_commit_num

    print(f"Valid CVE number: {valid_cve_num}")

    commit_num2cve_num = dict(sorted(commit_num2cve_num.items(), key=lambda x: x[1], reverse=True))
    print(json.dumps(commit_num2cve_num, indent=4))

    print(f"Invalid CVE number: {len(invalid_cves)}")
    print(valid_commit_num, invalid_commit_num)
    print(json.dumps(invalid_cves, indent=4))


if __name__ == '__main__':
    output_dir = "/root/projects/VDTest/dataset/Intermediate"
    ori_treevul_file = "/root/projects/VDTest/dataset/TreeVul/dataset_cleaned.json"

    ## Step 1: Simplify original TreeVul
    # simp_treevul_file = build_simplified_dataset(ori_treevul_file, output_dir)
    simp_treevul_file = "/root/projects/VDTest/dataset/Intermediate/TreeVul/treevul.json"

    ## Step 2: Group dataset items by commit
    # group_items_by_commit(simp_treevul_file)

    ## Step 3: Handle special items in dataset
    # process_item_with_multiple_cves(simp_treevul_file)

    # TODO: Manual checking and operation is required here. Ideally, the printed 'bad_cves' is empty.

    # simp_treevul_cleaned_file = delete_duplicate_cves(simp_treevul_file, output_dir)
    simp_treevul_cleaned_file = "/root/projects/VDTest/dataset/Intermediate/TreeVul/treevul_cleaned.json"

    ## Step 3: Combine PL_list for CVE
    pass

    ## Step 4: Check commits validity
    # check_commits_existence_by_fetching(simp_treevul_cleaned_file)
    # check_local_repos_and_clone(simp_treevul_cleaned_file)
    # check_commits_reproducibility_by_cloning(simp_treevul_cleaned_file)

    count_repro_cve_commits(simp_treevul_cleaned_file)


    # another_v = "/root/projects/VDTest/dataset/Intermediate/TreeVul/sim_treevul.json"
    # with open(another_v, 'r') as f:
    #     a_dataset = json.load(f)
    #
    # with open(simp_treevul_cleaned_file, 'r') as f:
    #     dataset = json.load(f)
    #
    # valid_cves = []
    # for cve_data in dataset:
    #     if cve_data['PL_list'] == ["Python"]:
    #         valid_flag = True
    #         for commit in cve_data['commits']:
    #             if not commit["reproducibility"]:
    #                 valid_flag = False
    #                 break
    #
    #         if valid_flag:
    #             valid_cves.append(cve_data["cve_id"])
    #
    # for item in a_dataset:
    #     if item["PL_list"] == ["Python"]:
    #         cve_ids = item["cve_list"]
    #         for cve_id in cve_ids:
    #             if cve_id not in valid_cves:
    #                 print(cve_id)
    #             else:
    #                 valid_cves.remove(cve_id)
    #
    # print(valid_cves)

