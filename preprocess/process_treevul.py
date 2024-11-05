import re
import os
import json
import shutil
import requests

from typing import *
from collections import defaultdict
from tqdm import tqdm

from preprocess.repo_manage import format_size
from preprocess.process_all import update_dataset_with_commit_file_count
from preprocess.util import clone_repo, is_commit_exist, is_commit_exist_in_repo


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


def group_items_by_commit(dataset_fpath: str, output_fpath: str) -> None:
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

    with open(output_fpath, 'w') as f:
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


def check_commits_existence_by_fetching(lang: Literal['Python', 'Java'], dataset_fpath: str) -> None:
    """Check the commits existence through fetching."""
    token = os.getenv("TOKEN", "")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []

    with (tqdm(total=len(dataset)) as pb):
        for cve_data in dataset:
            if cve_data['PL_list'] == [lang]:
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


def get_repo_size(auth_repo) -> int:
    token = os.getenv("TOKEN", "")
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    url = f"https://api.github.com/repos/{auth_repo}"
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            repo_data = response.json()
            kb_size = repo_data['size']
            return kb_size * 1024
    except requests.exceptions.RequestException as e:
        pass
    return 0


def check_local_repos_and_clone(
        lang: Literal['Python', 'Java'],
        dataset_fpath: str,
        repos_root: str = '/root/projects/clone_projects'
) -> None:
    token = os.getenv("TOKEN", "")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    noexist_local_repos = []
    for cve_data in dataset:
        if cve_data["PL_list"] == [lang]:
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
    #     size = get_repo_size(auth_repo)
    #     total_size += size
    #     if size > 0:
    #         success_num += 1
    #     noexist_local_repo2size[auth_repo] = size
    # noexist_local_repo2size = dict(sorted(noexist_local_repo2size.items(), key=lambda x: x[1], reverse=True))
    # noexist_local_repo2size = {repo: format_size(size) for repo, size in noexist_local_repo2size.items()}
    # print(f"Total size: {format_size(total_size)} ({success_num} / {len(noexist_local_repos)})")
    # print(json.dumps(noexist_local_repo2size, indent=4))

    # (3) Clone repos
    for repo in noexist_local_repos:
        if repo in [
            "OpenNMS/opennms",
            "OpenOLAT/OpenOLAT",
            "apache/ofbiz-framework",
            "wuyouzhuguli/FEBS-Shiro",
            "keycloak/keycloak",
            "facebook/buck",
            "luchua-bc/GreenBrowser",
            "gradle/gradle",
            "dotCMS/core",
            "igniterealtime/Openfire",
            "shopizer-ecommerce/shopizer",
            "jamesagnew/hapi-fhir",
            "eclipse/rdf4j",
            "xwiki/xwiki-platform",
            "OpenAPITools/openapi-generator",
            "bigbluebutton/bigbluebutton",
            "brianchandotcom/liferay-portal",
            "elastic/elasticsearch",
            "restlet/restlet-framework-java",
            "siacs/Conversations",
            "ballerina-platform/ballerina-lang",
            "hapifhir/hapi-fhir",
            "intranda/goobi-viewer-core"
        ]:
            continue

        print("=" * 100 + "\n\n")
        repo_dpath = os.path.join(repos_root, repo.replace('/', '_'))
        clone_repo(repo, repo_dpath, token=token, timeout=60)


def check_commits_reproducibility_by_cloning(
        lang: Literal['Python', 'Java'],
        dataset_fpath: str,
        repos_root: str = '/root/projects/clone_projects'
) -> None:
    """Check the commits reproducibility through cloning."""
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []
    for cve_data in dataset:
        if cve_data['PL_list'] == [lang]:
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


def final_check(lang: Literal['Python', 'Java'], dataset_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    updt_dataset: List[Dict] = []
    for cve_data in dataset:
        if cve_data['PL_list'] == [lang]:
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

        updt_dataset.append(cve_data)

    with open(dataset_fpath, 'w') as f:
        json.dump(updt_dataset, f, indent=4)


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

        if data['PL_list'] == [lang] and len(commits) == 1 and \
                commits[0]['existence'] is True and commits[0]['reproducibility'] is True:
            new_data = {
                "source": "treevul",
                "task_id": f"{len(filtered_dataset)}-treevul",
                "cve_id": data["cve_id"],
                "commit_type": data["commit_type"],
                "cwe_id": data["cwe_id"],
                "cwe_depth": None,
                "repo": commits[0]['repo'],
                "commit_hash": commits[0]['commit_hash'],
                "file_count": None
            }
            filtered_dataset.append(new_data)

    output_fpath = os.path.join(output_root, f"{lang.lower()}_vul_tasks_treevul.json")
    with open(output_fpath, 'w') as f:
        json.dump(filtered_dataset, f, indent=4)

    return output_fpath


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


def count_repo_cve_commits(lang: Literal['Python', 'Java'], dataset_fpath: str) -> None:
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    valid_cve_num = 0
    commit_num2cve_num: Dict[int, int] = {}

    invalid_cves = []
    invalid_commit_num = 0
    valid_commit_num = 0

    valid_single_commit_cve_repos = []

    for cve_data in dataset:
        if cve_data['PL_list'] == [lang]:

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


def remove_local_repos(repos_root: str = '/root/projects/clone_projects') -> None:
    repos = []
    for repo in repos:
        repo_dpath = os.path.join(repos_root, repo.replace('/', '_'))
        if os.path.exists(repo_dpath):
            print(f"Removing dir {repo_dpath} ...")
            shutil.rmtree(repo_dpath)


if __name__ == '__main__':
    output_dir = "/root/projects/VDTest/dataset/Intermediate"
    ori_treevul_file = "/root/projects/VDTest/dataset/TreeVul/dataset_cleaned.json"

    ## Step 1: Simplify original TreeVul
    # simp_treevul_file = build_simplified_dataset(ori_treevul_file, output_dir)
    simp_treevul_file = "/root/projects/VDTest/dataset/Intermediate/TreeVul/treevul.json"

    ## Step 2: Group dataset items by commit
    # group_items_by_commit(simp_treevul_file, )

    ## Step 3: Handle special items in dataset
    # process_item_with_multiple_cves(simp_treevul_file)

    # TODO: Manual checking and operation is required here. Ideally, the printed 'bad_cves' is empty.

    # simp_treevul_cleaned_file = delete_duplicate_cves(simp_treevul_file, output_dir)
    simp_treevul_cleaned_file = "/root/projects/VDTest/dataset/Intermediate/TreeVul/treevul_cleaned.json"

    ## Step 3: Combine PL_list for CVE
    pass

    ## Step 4: Check commits validity
    # check_commits_existence_by_fetching(lang='Java', simp_treevul_cleaned_file)
    # check_local_repos_and_clone(lang='Java', dataset_fpath=simp_treevul_cleaned_file)
    # check_commits_reproducibility_by_cloning(lang='Java', dataset_fpath=simp_treevul_cleaned_file)
    # final_check(lang='Java', dataset_fpath=simp_treevul_cleaned_file)
    # count_repo_cve_commits(lang='Java', dataset_fpath=simp_treevul_cleaned_file)

    ## Step 5: Build filtered dataset
    # vul_tasks_fpath = build_dataset_containing_cves_with_valid_single_commit(
    #     lang='Java',
    #     dataset_fpath=simp_treevul_cleaned_file,
    #     output_root="/root/projects/VDTest/dataset/Final/VIEW_1000"
    # )
    vul_tasks_fpath = "/root/projects/VDTest/dataset/Final/VIEW_1000/java_vul_tasks_treevul.json"

    update_dataset_with_commit_file_count(vul_tasks_fpath, suffix=['.java'])


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

