import json
import argparse
import os
import re
import requests
import time
import subprocess
import shutil
from typing import *

from utils.logging import start_with_logger, log_debug
from utils.commit import clone_repo, checkout_commit
from utils.utils import calculate_date_range


def get_api_rate_limit(logger, token):
    url = "https://api.github.com/rate_limit"
    headers = {'Authorization': f'token {token}'}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            rate_limit_info = response.json()
            remaining = rate_limit_info['rate']['remaining']
            reset_timestamp = rate_limit_info['rate']['reset']
            return remaining, reset_timestamp
        else:
            logger.info("Failed to retrieve rate limit information:", response.status_code)
            return None, None
    except requests.exceptions.Timeout as e:
        logger.error("Failed to retrieve rate limit information: " + str(e))
    except requests.exceptions.RequestException as e:
        logger.error("Failed to retrieve rate limit information: " + str(e))

    return None, None


def wait_for_rate_limit_reset(reset_timestamp):
    current_time = time.time()
    reset_time = reset_timestamp
    wait_time = reset_time - current_time
    if wait_time > 0:
        print(f"Rate limit exceeded. Waiting for {int(wait_time)} seconds until reset...")
        time.sleep(wait_time + 10)


def check_commits_validity_by_fetching(logger, dataset_jpath: str, save_dpath='./data', token=''):
    log_debug(logger, ">>>> Checking items with commit by fetching ...")

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)
    logger.info(f"Initial dataset items number: {len(dataset)}.")

    validity_check_info = {}
    checked_results = {}
    failed_results = {}
    validity_check_jpath = os.path.join(save_dpath, 'TreeVul-valid_check.json')
    if os.path.exists(validity_check_jpath):
        logger.info("Previous checked results of dataset exists.")
        logger.info(f"Dataset previous checked results file path: {validity_check_jpath}.")
        with open(validity_check_jpath, 'r') as f:
            validity_check_info = json.load(f)
        checked_results = validity_check_info["Checked Results"]
        failed_results = validity_check_info["Failed Results"]
    else:
        logger.info("Previous checked results of dataset does not exist.")

    valid_items_number = 0
    invalid_items_number = 0
    failed_items_number = 0
    for i, item in enumerate(dataset):
        cve_id = item['cve_list']
        auth_repo = item["repo"]
        commit_id = item["commit_id"]
        commit_date = item["commit_date"]

        logger.info(f">>> [Item {i}] {cve_id}")
        logger.info(f">>> Repo: {auth_repo}, commit_id: {commit_id}.")

        result = None
        current_item_checked_result = {
            "cve_id": cve_id,
            "repo": auth_repo,
            "commit_id": commit_id,
            "result": None
        }

        # Check if it has been checked before
        if str(i) not in checked_results:
            # Checking the first time
            logger.info("The first time checking.")
        else:
            # Checking after the first time
            if (checked_results[str(i)]["cve_id"] == cve_id
                    and checked_results[str(i)]["repo"] == auth_repo
                    and checked_results[str(i)]["commit_id"] == commit_id):
                logger.info("Already checked in previous checking.")

                if checked_results[str(i)]["result"] != "Failed":
                    result = checked_results[str(i)]["result"]
                    current_item_checked_result = checked_results[str(i)]
                    logger.info(f"Previous checked result is '{result}', do not need to re-check.")
                else:
                    logger.info("Previous checked result is 'Failed', need to re-check.")
            else:
                logger.info("CVE_id/repo/commit_id conflicts with previous checking, need to re-check.")

        # Check with fetch
        if result is None:
            # Items need to re-check or Unchecked items
            if type(commit_date) is str:
                start_date, end_date = calculate_date_range(commit_date)

                if auth_repo not in failed_results:
                    remaining, reset = get_api_rate_limit(logger, token)
                    if remaining == 0:
                        wait_for_rate_limit_reset(reset)

                    result = _check_commit_validity_by_fetching(logger=logger,
                                                                author=auth_repo.split('/')[0],
                                                                repo=auth_repo.split('/')[1],
                                                                commit_id=commit_id,
                                                                start_date=start_date, end_date=end_date,
                                                                token=token)
                    if result is True:
                        result = "Valid"
                    elif result is False:
                        result = "Invalid"
            else:
                logger.info("Invalid commit date!")

        if result is None:
            logger.info(">>> Check result: Failed.")
            failed_items_number += 1
            if auth_repo not in failed_results:
                failed_results[auth_repo] = [commit_id]
            else:
                failed_results[auth_repo].append(commit_id)
                failed_results[auth_repo] = list(set(failed_results[auth_repo]))
        elif result == "Valid":
            logger.info(">>> Check result: Valid.")
            valid_items_number += 1
        else:
            logger.info(f">>> Check result: Invalid.")
            invalid_items_number += 1

        current_item_checked_result["result"] = result if result is not None else "Failed"
        checked_results[str(i)] = current_item_checked_result

    failed_repo2commit_num = {repo: len(commits) for repo, commits in failed_results.items()}

    logger.info("-" * 40 + "Count" + "-" * 40)
    logger.info(f"Valid items number: {valid_items_number}.")
    logger.info(f"Invalid items number: {invalid_items_number}.")
    logger.info(f"Failed items number: {failed_items_number}.")
    logger.info(f"Fetched failed repo and commit number: {json.dumps(failed_repo2commit_num, indent=4)}.")
    logger.info(f"Detailed fetched failed repo and commits: {json.dumps(failed_results, indent=4)}")
    logger.info("-" * 85)

    # Save dataset validity check results
    if len(validity_check_info) == 0:
        validity_check_info["Checked Results"] = checked_results
        validity_check_info["Failed Results"] = failed_results

    with open(validity_check_jpath, 'w') as f:
        json.dump(validity_check_info, f, indent=4)
        logger.info(f"Dataset validity check results file path: {validity_check_jpath}.")


def _check_commit_validity_by_fetching(logger, author, repo, commit_id, start_date, end_date, token) -> Optional[bool]:
    """
        Check if a given commit ID is valid for a specific GitHub repository.

        Args:
        author (str): GitHub username or organization name.
        repo (str): GitHub repository name.
        commit_id (str): The commit ID to check.
        token (str): Personal Access Token for GitHub.

        Returns:
                True: Given commit ID is valid.
                False: Given commit ID is not valid.
                None: Given commit ID checked failed.
    """
    commits = _fetch_commits_with_date(logger, author, repo, start_date, end_date, token)
    if commits is not None:
        return _check_commit_in_list(commits, commit_id)
    else:
        return None


def _fetch_commits_with_date(logger, author, repo, start_date, end_date, token):
    url = f"https://api.github.com/repos/{author}/{repo}/commits"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {
        'since': start_date,
        'until': end_date,
        'per_page': 100
    }

    retries = 0
    max_retries = 5
    commits = []
    while retries < max_retries:
        current_url = url
        try:
            while current_url:
                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    commits.extend(response.json())
                    if 'next' in response.links:
                        current_url = response.links['next']['url']
                    else:
                        current_url = None
                else:
                    retries += 1
                    logger.warning(
                        f"Failed to fetch {retries}/{max_retries} due to non-200 status: {response.content}.")
                    time.sleep(2)
                    break
            if current_url is None:
                break
        except requests.exceptions.RequestException as e:
            retries += 1
            logger.warning(f"Failed to fetch {retries}/{max_retries}: {str(e)}.")
            time.sleep(2)
            continue

    if retries >= max_retries:
        logger.error(f"Max retries reached, commit still fails to fetch.")
        return None
    else:
        logger.info(f"Successfully fetched commits number: {len(commits)}.")
        return commits


def _check_commit_in_list(commits: List, commit_id: str):
    for commit in commits:
        if commit['sha'] == commit_id:
            return True
    return False


def check_failed_commits_by_cloning(logger, check_results_jpath: str,
                                    clone_repos_dpath='/root/projects/clone_projects',
                                    repo_exists=False):
    log_debug(logger, ">>>> Checking items with commit which checked failed previously by cloning ...")
    logger.info(f">>>> Dir for saving cloned repos: {clone_repos_dpath}.")

    if not os.path.exists(clone_repos_dpath):
        os.makedirs(clone_repos_dpath, exist_ok=True)

    with open(check_results_jpath, 'r') as f:
        check_info = json.load(f)

    # Get old checked results
    old_checked_results = check_info["Checked Results"]
    old_failed_results = check_info["Failed Results"]
    old_not_found_results = {}
    if "Not Found Results" in check_info:
        old_not_found_results = check_info["Not Found Results"]

    # Utilize cloning repo to check failed cve items (commit_id)
    new_check_success_results = {}
    new_check_failed_results = {}
    new_not_found_results = {}

    for repo, commit_list in old_failed_results.items():
        assert repo not in old_not_found_results

        commit_list = list(set(commit_list))
        check_flag, commits_result = _check_commits_validity_by_cloning(logger=logger,
                                                                        auth=repo.split('/')[0],
                                                                        repo=repo.split('/')[1],
                                                                        commit_list=commit_list,
                                                                        repos_dpath=clone_repos_dpath,
                                                                        repo_exists=repo_exists)

        if check_flag:
            new_check_success_results[repo] = commits_result
        elif check_flag is None:
            new_not_found_results[repo] = commit_list
        else:
            new_check_failed_results[repo] = commit_list

    # Update results
    update_checked_failed_results = {}

    # Update `old_not_found_results` with `new_not_found_results`
    for repo, commit_list in new_not_found_results.items():
        assert repo not in old_not_found_results
        old_not_found_results[repo] = commit_list

    # Update failed items in `old_checked_results` with `new_check_success_results`
    for item_id, item in old_checked_results.items():
        if item["result"] == "Failed":
            repo = item["repo"]
            commit_id = item["commit_id"]
            if repo in new_check_success_results:
                assert commit_id in new_check_success_results[repo]
                old_checked_results[item_id]["result"] = new_check_success_results[repo][commit_id]

    # Update `old_failed_results` with `new_check_success_results`
    for repo, commit_list in old_failed_results.items():
        if repo in new_check_success_results:
            assert len(new_check_success_results[repo]) == len(commit_list)
        elif repo in old_not_found_results:
            assert len(old_not_found_results[repo]) == len(commit_list)
        else:
            update_checked_failed_results[repo] = commit_list

    update_check_info = {
        "Checked Results": old_checked_results,
        "Failed Results": update_checked_failed_results,
        "Not Found Results": old_not_found_results
    }

    # Save
    with open(check_results_jpath, 'w') as f:
        json.dump(update_check_info, f, indent=4)


def _check_commits_validity_by_cloning(
        logger, auth, repo, commit_list,
        repos_dpath='/root/projects/clone_projects', repo_exists=False
) -> Tuple[Optional[bool], Dict[str, str]]:
    """
        First clone the repository to local, then check the validity of the commit.

        Args:
        logger:
        auth:
        repo:
        commit_list: commit ids to be checked in this repo
        repos_dpath: dir path for saving clone repos
        repo_exists: whether the repo exists

        Returns:
            check_flag:
                True: repo clone successful, check successful
                False: repo clone failed, check failed
                None: repo not found and clone failed, check failed
            Dict[commit_id: "Valid" / "Invalid"]:
                if return dict is empty, which means the check failed.
    """
    repo_dpath = os.path.join(repos_dpath, f'{auth}_{repo}')
    logger.info(f">>> Local repo dpath: {repo_dpath}.")

    if not repo_exists:
        if os.path.exists(repo_dpath):
            shutil.rmtree(repo_dpath)
    else:
        if not os.path.exists(repo_dpath):
            logger.error(f"Repo existing required but not actually!")
            return False, {}

    if not repo_exists:
        auth_repo = f"{auth}/{repo}"
        clone_result = clone_repo(logger, auth_repo, repo_dpath, 180)
    else:
        clone_result = True

    commits_result = {}
    if clone_result:
        check_flag = True

        commit_list = list(set(commit_list))
        for commit_id in commit_list:
            # Checkout commit
            checkout_result = checkout_commit(logger, repo_dpath, commit_id)
            # Save result
            if checkout_result:
                commits_result[commit_id] = "Valid"
                logger.info(f"Commit exist: True")
            else:
                commits_result[commit_id] = "Invalid"
                logger.info(f"Commit exist: False")
    elif clone_result is None:
        check_flag = None
    else:
        check_flag = False

    return check_flag, commits_result


def build_dataset_from_validity_check_results(logger, dataset_jpath: str, check_results_jpath: str, save_dpath: str):
    log_debug(logger, ">>>> Building dataset from validity check results ...")
    logger.info(f">>>> Dateset path: {dataset_jpath}, check results path: {check_results_jpath}.")

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)
    logger.info(f"Dataset size: {len(dataset)}.")

    with open(check_results_jpath, 'r') as f:
        check_results = json.load(f)

    if len(check_results["Failed Results"]) != 0:
        logger.error("Failed items in check results should be zero!")
        return

    old_and_new_repos = {
        "rcook/rgpg": "eahanson/rgpg",
        "embedthis/goahead": "zoushipeng/goahead",
        "embedthis/appweb": "whoerau/appweb",
        "wuyouzhuguli/FEBS-Shiro": "XIOGit/https-github.com-wuyouzhuguli-FEBS-Shiro",
        "vintagedaddyo/MyBB_Plugin-Upcoming_Events": "MangaD/MyBB_Plugin-Upcoming_Events"
    }

    new_dataset = []
    for item_id, item in check_results["Checked Results"].items():
        if item["cve_id"] != dataset[int(item_id)]["cve_list"]:
            assert item["cve_id"] in dataset[int(item_id)]["cve_list"]
            check_results["Checked Results"][item_id]["cve_id"] = dataset[int(item_id)]["cve_list"]
        assert (item["repo"] == dataset[int(item_id)]["repo"]
                or old_and_new_repos[dataset[int(item_id)]["repo"]] == item["repo"])
        assert item["commit_id"] == dataset[int(item_id)]["commit_id"]
        if item["result"] == "Valid":
            new_dataset.append(dataset[int(item_id)])
        elif item["result"] == "Failed":
            assert item["repo"] in check_results["Not Found Results"]

    logger.info(f"New dataset size: {len(new_dataset)}.")
    new_dataset_jpath = os.path.join(save_dpath, "TreeVul-valid.json")
    with open(new_dataset_jpath, 'w') as f:
        json.dump(new_dataset, f, indent=4)

    with open(check_results_jpath, 'w') as f:
        json.dump(check_results, f, indent=4)


def select_single_file_commit_items(logger, dataset_jpath: str, save_dpath: str):
    """
        Cleaning Step 2.
        Select CVE items with commit which changes only one file.
        Dataset format: List[Dict],
        while the key attributes of CVE items are as follows
            "cve_list": CVE-ID
            "cwe_list": CWE-ID
            "repo": author/repo
            "commit_id": commit_id
            "commit_date": like "1999-11-10T02:42:49Z"
            "file_name": relative file path

        :param logger:
        :param dataset_jpath:
        :param save_dpath:
    """
    log_debug(logger, f">>>> Selecting CVE items with commit which changes only single file from dataset ...")
    logger.info(f">>>> Dataset path: {dataset_jpath}.")

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)

    commit_id2file_num_dict = _count_commit_changed_files(dataset)

    logger.info(f"Commit number: {len(commit_id2file_num_dict)}.")
    logger.info(f"Max file changed by commit number: {max(commit_id2file_num_dict.values())}.")

    # Select commit with single changed file (referred as `single_file_commit`)
    single_file_commit_id_list = []
    for commit_id, file_num in commit_id2file_num_dict.items():
        if file_num == 1:
            single_file_commit_id_list.append(commit_id)

    logger.info(f"Single_file_commit number: {len(single_file_commit_id_list)}.")

    # Select CVE items with single_file_commit
    single_commit_list = []
    for item in dataset:
        if item["commit_id"] in single_file_commit_id_list:
            single_commit_list.append(item)

    # Save CVE items with single_file_commit
    single_file_commit_items_save_fpath = os.path.join(save_dpath, "TreeVul-valid-single.json")
    with open(single_file_commit_items_save_fpath, 'w') as f:
        json.dump(single_commit_list, f, indent=4)

    logger.info(f"Saved file path: {single_file_commit_items_save_fpath}.")


def process_multiple_files_commit_items(logger, dataset_source: str, dataset: List[Dict], save_dpath: str):
    """
        Cleaning Step 3.
        Process CVE items with commit which changes multiple files (>1).
        Dataset format: List[Dict],
        while the key attributes of CVE items are as follows
            "cve_list": CVE-ID
            "cwe_list": CWE-ID
            "repo": author/repo
            "commit_id": commit_id
            "commit_date": like "1999-11-10T02:42:49Z"
            "file_name": relative file path

        :param logger:
        :param dataset_source: original / valid
        :param dataset:
        :param save_dpath:
    """
    log_debug(logger,
              f"Processing CVE items with commit which changes multiple files from {dataset_source} dataset ...")

    commit_id2file_num_dict = _count_commit_changed_files(dataset)

    logger.info(f"Commit number: {len(commit_id2file_num_dict)}.")
    logger.info(f"Max file changed by commit number: {max(commit_id2file_num_dict.values())}.")

    # Select commit with multiple changed files (referred as `multiple_files_commit`)
    multiple_files_commit_id_list = []
    for commit_id, file_num in commit_id2file_num_dict.items():
        if file_num > 1:
            multiple_files_commit_id_list.append(commit_id)

    logger.info(f"Multiple_files_commit number: {multiple_files_commit_id_list}.")

    # TODO: How tp process


def _count_commit_changed_files(dataset: List[Dict]) -> Dict[str, int]:
    commit_id2file_num_dict = {}
    for item in dataset:
        if item["commit_id"] not in commit_id2file_num_dict:
            commit_id2file_num_dict[item["commit_id"]] = 1
        else:
            commit_id2file_num_dict[item["commit_id"]] += 1

    commit_id2file_num_dict = dict(sorted(commit_id2file_num_dict.items(), key=lambda x: x[1], reverse=True))

    return commit_id2file_num_dict


def _reassign_cve2commit_and_commit2cve_with_special_cases(cve2commit, commit2cve):
    """
        Special cases are CVEs with intersecting but not identical commits
    """
    # 1. CVE-2014-2235, CVE-2014-2236
    # cve_s_commit_dict["CVE-2014-2235"] = "876e3662ff6b78cc6241338c15e3a0cb49edf4e2"
    # cve_s_commit_dict["CVE-2014-2236"] = "a676a86b6b7a5737d4da4f59f71e037406f88d29"
    cve2commit["CVE-2014-2235"] = ["876e3662ff6b78cc6241338c15e3a0cb49edf4e2"]
    cve2commit["CVE-2014-2236"] = ["a676a86b6b7a5737d4da4f59f71e037406f88d29"]
    commit2cve["876e3662ff6b78cc6241338c15e3a0cb49edf4e2"] = ["CVE-2014-2235"]
    commit2cve["a676a86b6b7a5737d4da4f59f71e037406f88d29"] = ["CVE-2014-2236"]

    # 2. CVE-2016-10060, CVE-2016-10061, CVE-2016-10062
    # cve_s_commit_dict["CVE-2016-10060"] = "933e96f01a8c889c7bf5ffd30020e86a02a046e7"
    # cve_s_commit_dict["CVE-2016-10061"] = "4e914bbe371433f0590cefdf3bd5f3a5710069f9"
    # cve_s_commit_dict["CVE-2016-10062"] = "8ed56f49e4eb858c26420324d74882a22089fe3d"
    cve2commit["CVE-2016-10060"] = ["933e96f01a8c889c7bf5ffd30020e86a02a046e7"]
    cve2commit["CVE-2016-10061"] = ["4e914bbe371433f0590cefdf3bd5f3a5710069f9"]
    cve2commit["CVE-2016-10062"] = ["8ed56f49e4eb858c26420324d74882a22089fe3d"]
    commit2cve["933e96f01a8c889c7bf5ffd30020e86a02a046e7"] = ["CVE-2016-10060"]
    commit2cve["4e914bbe371433f0590cefdf3bd5f3a5710069f9"] = ["CVE-2016-10061"]
    commit2cve["8ed56f49e4eb858c26420324d74882a22089fe3d"] = ["CVE-2016-10062"]

    # 3. CVE-2016-5429, CVE-2016-5430, CVE-2016-5431
    # cve_s_commit_dict["CVE-2016-5429"] = None
    # cve_s_commit_dict["CVE-2016-5430"] = "f03b986b4439e20b0fd635109b48afe96cf0099b"
    # cve_s_commit_dict["CVE-2016-5431"] = "1cce55e27adf0274193eb1cd74b927a398a3df4b"
    cve2commit["CVE-2016-5430"] = ["f03b986b4439e20b0fd635109b48afe96cf0099b"]
    cve2commit["CVE-2016-5431"] = ["1cce55e27adf0274193eb1cd74b927a398a3df4b"]
    commit2cve["f03b986b4439e20b0fd635109b48afe96cf0099b"] = ["CVE-2016-5430"]
    commit2cve["1cce55e27adf0274193eb1cd74b927a398a3df4b"] = ["CVE-2016-5431"]
    del cve2commit["CVE-2016-5429"]

    # 4. CVE-2016-7515, CVE-2016-7516, CVE-2016-7517, CVE-2016-7518
    # TODO: Although CVE-2016-7516, 7517, 7518 have the same commit id, the files involved are different
    # cve_s_commit_dict["CVE-2016-7515"] = "2ad6d33493750a28a5a655d319a8e0b16c392de1"
    # cve_s_commit_dict["CVE-2016-7516"] = "2174484dfa68a594e2f9ad17f46217b6120db18d"
    # cve_s_commit_dict["CVE-2016-7517"] = "2174484dfa68a594e2f9ad17f46217b6120db18d"
    # cve_s_commit_dict["CVE-2016-7518"] = "2174484dfa68a594e2f9ad17f46217b6120db18d"
    cve2commit["CVE-2016-7515"] = ["2ad6d33493750a28a5a655d319a8e0b16c392de1"]
    cve2commit["CVE-2016-7516"] = ["2174484dfa68a594e2f9ad17f46217b6120db18d"]
    cve2commit["CVE-2016-7517"] = ["2174484dfa68a594e2f9ad17f46217b6120db18d"]
    cve2commit["CVE-2016-7518"] = ["2174484dfa68a594e2f9ad17f46217b6120db18d"]
    commit2cve["2ad6d33493750a28a5a655d319a8e0b16c392de1"] = ["CVE-2016-7515"]
    commit2cve["2174484dfa68a594e2f9ad17f46217b6120db18d"] = ["CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518"]

    # 5. CVE-2017-1000508, CVE-2017-18217
    # TODO: Although CVE-2017-18217 contains 2 commits, only change in `echo_helper.php` of commit 3fc256c related
    # cve_s_commit_dict["CVE-2017-1000508"] = "3fc256ccef403f5be9982f02ef340d9e01daabb2"
    # cve_m_commit_dict["CVE-2017-18217"] = ["3fc256ccef403f5be9982f02ef340d9e01daabb2", "f7dcddcf2a81492c55e8cc1ce5dbb3634baba037"]
    cve2commit["CVE-2017-1000508"] = ["3fc256ccef403f5be9982f02ef340d9e01daabb2"]
    cve2commit["CVE-2017-18217"] = ["f7dcddcf2a81492c55e8cc1ce5dbb3634baba037"]
    commit2cve["3fc256ccef403f5be9982f02ef340d9e01daabb2"] = ["CVE-2017-1000508"]
    commit2cve["f7dcddcf2a81492c55e8cc1ce5dbb3634baba037"] = ["CVE-2017-18217"]

    # 6. CVE-2017-9438, CVE-2017-9304
    # cve_s_commit_dict["CVE-2017-9438"] = "10e8bd3071677dd1fa76beeef4bc2fc427cea5e7"
    # cve_m_commit_dict["CVE-2017-9304"] = ["58f72d4d57c8a431c3b05df9f02150faf4323fe5", "1aaac7ba91101da0112a7365a05ef6f6281f8739"]
    cve2commit["CVE-2017-9438"] = ["10e8bd3071677dd1fa76beeef4bc2fc427cea5e7"]
    cve2commit["CVE-2017-9304"] = ["58f72d4d57c8a431c3b05df9f02150faf4323fe5",
                                   "1aaac7ba91101da0112a7365a05ef6f6281f8739"]
    commit2cve["10e8bd3071677dd1fa76beeef4bc2fc427cea5e7"] = ["CVE-2017-9438"]
    commit2cve["58f72d4d57c8a431c3b05df9f02150faf4323fe5"] = ["CVE-2017-9304"]
    commit2cve["1aaac7ba91101da0112a7365a05ef6f6281f8739"] = ["CVE-2017-9304"]

    # 7. CVE-2018-12023, CVE-2018-12022
    # cve_s_commit_dict["CVE-2018-12023"] = "28badf7ef60ac3e7ef151cd8e8ec010b8479226a"
    # cve_s_commit_dict["CVE-2018-12022"] = None
    cve2commit["CVE-2018-12023"] = ["28badf7ef60ac3e7ef151cd8e8ec010b8479226a"]
    commit2cve["28badf7ef60ac3e7ef151cd8e8ec010b8479226a"] = ["CVE-2018-12023"]
    del cve2commit["CVE-2018-12022"]
    del commit2cve["7487cf7eb14be2f65a1eb108e8629c07ef45e0a1"]

    # 8. CVE-2018-17568, CVE-2018-17569, CVE-2018-17570
    # TODO: Although CVE-2018-17568, 17569, 17570 have the same commit id, the files involved are different
    # cve_s_commit_dict["CVE-2018-17568"] = "4a7c27bfe98f409623d4d857894d017ff0672cc9"
    # cve_s_commit_dict["CVE-2018-17569"] = "4a7c27bfe98f409623d4d857894d017ff0672cc9"
    # cve_s_commit_dict["CVE-2018-17570"] = "4a7c27bfe98f409623d4d857894d017ff0672cc9"
    cve2commit["CVE-2018-17568"] = ["4a7c27bfe98f409623d4d857894d017ff0672cc9"]
    cve2commit["CVE-2018-17569"] = ["4a7c27bfe98f409623d4d857894d017ff0672cc9"]
    cve2commit["CVE-2018-17570"] = ["4a7c27bfe98f409623d4d857894d017ff0672cc9"]
    commit2cve["4a7c27bfe98f409623d4d857894d017ff0672cc9"] = ["CVE-2018-17568", "CVE-2018-17569", "CVE-2018-17570"]
    del commit2cve["5c2dc2b7856a66338e2f113540fd2e8fcb847f9e"]

    # 9. CVE-2018-20755, CVE-2018-20756, CVE-2018-20757, CVE-2018-20758
    # cve_s_commit_dict["CVE-2018-20755"] = "a12920f1698d3be8e6ba07d746da46e511b911b6"
    # cve_s_commit_dict["CVE-2018-20756"] = "20049805dad576250185e4317c4ded1d21871219"
    # cve_s_commit_dict["CVE-2018-20757"] = "489b13c61673ea0b19124e18cf1f3e7673f8aa64"
    # cve_s_commit_dict["CVE-2018-20758"] = "c08fb7c7a1f5979ff1241a7b28ae0f7690756ad3"
    cve2commit["CVE-2018-20755"] = ["a12920f1698d3be8e6ba07d746da46e511b911b6"]
    cve2commit["CVE-2018-20756"] = ["20049805dad576250185e4317c4ded1d21871219"]
    cve2commit["CVE-2018-20757"] = ["489b13c61673ea0b19124e18cf1f3e7673f8aa64"]
    cve2commit["CVE-2018-20758"] = ["c08fb7c7a1f5979ff1241a7b28ae0f7690756ad3"]
    commit2cve["a12920f1698d3be8e6ba07d746da46e511b911b6"] = ["CVE-2018-20755"]
    commit2cve["20049805dad576250185e4317c4ded1d21871219"] = ["CVE-2018-20756"]
    commit2cve["489b13c61673ea0b19124e18cf1f3e7673f8aa64"] = ["CVE-2018-20757"]
    commit2cve["c08fb7c7a1f5979ff1241a7b28ae0f7690756ad3"] = ["CVE-2018-20758"]
    del commit2cve["71f894ee55dc4eed10538979761d6c94e8cd1078"]

    # 10. CVE-2020-10672, CVE-2020-24616, CVE-2020-11111, CVE-2020-11112, CVE-2020-10968, CVE-2020-14061, CVE-2020-11619, CVE-2020-14062, CVE-2020-24750, CVE-2021-20190, CVE-2020-11113, CVE-2020-14060
    # cve_s_commit_dict["CVE-2020-10672"] = "32ab266118407e763d7875a555551780540b5ef5"
    # cve_s_commit_dict["CVE-2020-24616"] = "3d97153944f7de9c19c1b3637b33d3cf1fbbe4d7"
    # cve_s_commit_dict["CVE-2020-11111"] = "05d7e0e13f43e12db6a51726df12c8b4d8040676"
    # cve_s_commit_dict["CVE-2020-11112"] = None
    # cve_s_commit_dict["CVE-2020-10968"] = None
    # cve_s_commit_dict["CVE-2020-14061"] = "5c8642aeae9c756b438ab7637c90ef3c77966e6e"
    # cve_s_commit_dict["CVE-2020-11619"] = "113e89fb08b1b6b072d60b3e4737ed407c13db9a"
    # cve_s_commit_dict["CVE-2020-14062"] = "840eae2ca81c597a0010b2126f32dce17d384b7"
    # cve_s_commit_dict["CVE-2020-24750"] = "6cc9f1a1af323cd156f5668a47e43bab324ae16f"
    # cve_s_commit_dict["CVE-2021-20190"] = "7dbf51bf78d157098074a20bd9da39bd48c18e4a"
    # cve_s_commit_dict["CVE-2020-11113"] = "e2ba12d5d60715d95105e3e790fc234cfb59893d"
    # cve_s_commit_dict["CVE-2020-14060"] = "d1c67a0396e84c08d0558fbb843b5bd1f26e1921"
    cve2commit["CVE-2020-10672"] = ["32ab266118407e763d7875a555551780540b5ef5"]
    cve2commit["CVE-2020-24616"] = ["3d97153944f7de9c19c1b3637b33d3cf1fbbe4d7"]
    cve2commit["CVE-2020-11111"] = ["05d7e0e13f43e12db6a51726df12c8b4d8040676"]
    cve2commit["CVE-2020-14061"] = ["5c8642aeae9c756b438ab7637c90ef3c77966e6e"]
    cve2commit["CVE-2020-11619"] = ["113e89fb08b1b6b072d60b3e4737ed407c13db9a"]
    cve2commit["CVE-2020-14062"] = ["840eae2ca81c597a0010b2126f32dce17d384b7"]
    cve2commit["CVE-2020-24750"] = ["6cc9f1a1af323cd156f5668a47e43bab324ae16f"]
    cve2commit["CVE-2021-20190"] = ["7dbf51bf78d157098074a20bd9da39bd48c18e4a"]
    cve2commit["CVE-2020-11113"] = ["e2ba12d5d60715d95105e3e790fc234cfb59893d"]
    cve2commit["CVE-2020-14060"] = ["d1c67a0396e84c08d0558fbb843b5bd1f26e1921"]
    commit2cve["32ab266118407e763d7875a555551780540b5ef5"] = ["CVE-2020-10672"]
    commit2cve["3d97153944f7de9c19c1b3637b33d3cf1fbbe4d7"] = ["CVE-2020-24616"]
    commit2cve["05d7e0e13f43e12db6a51726df12c8b4d8040676"] = ["CVE-2020-11111"]
    commit2cve["5c8642aeae9c756b438ab7637c90ef3c77966e6e"] = ["CVE-2020-14061"]
    commit2cve["113e89fb08b1b6b072d60b3e4737ed407c13db9a"] = ["CVE-2020-11619"]
    commit2cve["840eae2ca81c597a0010b2126f32dce17d384b7"] = ["CVE-2020-14062"]
    commit2cve["6cc9f1a1af323cd156f5668a47e43bab324ae16f"] = ["CVE-2020-24750"]
    commit2cve["7dbf51bf78d157098074a20bd9da39bd48c18e4a"] = ["CVE-2021-20190"]
    commit2cve["e2ba12d5d60715d95105e3e790fc234cfb59893d"] = ["CVE-2020-11113"]
    commit2cve["d1c67a0396e84c08d0558fbb843b5bd1f26e1921"] = ["CVE-2020-14060"]
    del cve2commit["CVE-2020-11112"]
    del cve2commit["CVE-2020-10968"]
    del commit2cve["08fbfacf89a4a4c026a6227a1b470ab7a13e2e88"]

    # 11. CVE-2020-24265, CVE-2020-24266
    # cve_s_commit_dict["CVE-2020-24265"] = "8323a7fe1e47d562ebf384aa99633e3df74a01c4"
    # cve_s_commit_dict["CVE-2020-24266"] = "61db8adae55e246e0bc9442fbe977fff46154970"
    # cve_s_commit_dict["CVE-2020-24265,CVE-2020-24266"] = "d3110859064b15408dbca1294dc7e31c2208504d"
    cve2commit["CVE-2020-24265"] = ["8323a7fe1e47d562ebf384aa99633e3df74a01c4"]
    cve2commit["CVE-2020-24266"] = ["61db8adae55e246e0bc9442fbe977fff46154970"]
    cve2commit["CVE-2020-24265,CVE-2020-24266"] = ["d3110859064b15408dbca1294dc7e31c2208504d"]
    commit2cve["8323a7fe1e47d562ebf384aa99633e3df74a01c4"] = ["CVE-2020-24265"]
    commit2cve["61db8adae55e246e0bc9442fbe977fff46154970"] = ["CVE-2020-24266"]
    commit2cve["d3110859064b15408dbca1294dc7e31c2208504d"] = ["CVE-2020-24265,CVE-2020-24266"]
    del commit2cve["6fb578d20feccffd4bae9f3d0216d1c3507bd805"]
    del commit2cve["9f6f3d525a5a5a682b4caaf95df366b4dfe0602d"]

    # 12. CVE-2021-39530, CVE-2021-39522
    # cve_s_commit_dict["CVE-2021-39522"] = "4b99edb0ea26e99ef65c5fe68670e6b1f9382d44"
    # cve_s_commit_dict["CVE-2021-39530"] = "dac8fcc4be1007ccf4412ae5e90303e335fdb412"
    cve2commit["CVE-2021-39522"] = ["4b99edb0ea26e99ef65c5fe68670e6b1f9382d44"]
    cve2commit["CVE-2021-39530"] = ["dac8fcc4be1007ccf4412ae5e90303e335fdb412"]
    commit2cve["4b99edb0ea26e99ef65c5fe68670e6b1f9382d44"] = ["CVE-2021-39522"]
    commit2cve["dac8fcc4be1007ccf4412ae5e90303e335fdb412"] = ["CVE-2021-39530"]


def check_dataset_items(logger, dataset_jpath: str):
    log_debug(logger, ">>>> Checking CVE-ID, commit_id and changed files of dataset items ...")
    logger.info(f">>>> Dataset path: {dataset_jpath}.")

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)

    # Check CVE-ID with commit_id
    cve2commit, commit2cve = _get_cve2commit_and_commit2cve(dataset)

    # Reassign `cve2commit` and `commit2cve`
    _reassign_cve2commit_and_commit2cve_with_special_cases(cve2commit, commit2cve)

    print(f"Number of CVEs: {len(cve2commit)}.")
    print(f"Number of commits: {len(commit2cve)}.")

    # Separate CVEs with one commit and CVEs with multiple commits
    cve_s_commit_dict = {}
    cve_m_commit_dict = {}
    for cve, commits in cve2commit.items():
        if len(commits) == 1:
            assert cve not in cve_s_commit_dict
            cve_s_commit_dict[cve] = commits[0]
        else:
            assert cve not in cve_m_commit_dict
            cve_m_commit_dict[cve] = commits

    print(f"Number of CVEs with single commit: {len(cve_s_commit_dict)}.")
    print(f"Number of CVEs with multiple commits: {len(cve_m_commit_dict)}.")

    # Filter CVEs with the same single commit
    duplicated_cve_with_same_s_commit_num = 0
    duplicated_cve_with_same_s_commit_commits = []
    for cve, commit in cve_s_commit_dict.items():
        if len(commit2cve[commit]) != 1 and commit not in duplicated_cve_with_same_s_commit_commits:
            duplicated_cve_with_same_s_commit_num += len(commit2cve[commit]) - 1
            duplicated_cve_with_same_s_commit_commits.append(commit)

    print(f"Number of duplicated CVEs with the same single commit: {duplicated_cve_with_same_s_commit_num}.")

    # Filter CVEs with the same multiple commits
    duplicated_cve_with_same_m_commit_num = 0
    duplicated_cve_with_same_m_commit_commits = []
    for cve, commits in cve_m_commit_dict.items():
        checked_cves = commit2cve[commits[0]]
        # for commit in commits:
        #     assert commit2cve[commit] == checked_cves
        if len(commits) != 1 and commits not in duplicated_cve_with_same_m_commit_commits:
            duplicated_cve_with_same_m_commit_num += len(checked_cves) - 1
            duplicated_cve_with_same_m_commit_commits.append(commits)

    print(f"Number of duplicated CVEs with the same multiple commits: {duplicated_cve_with_same_m_commit_num}.")


def select_cves_with_single_commit(logger, dataset_jpath: str, save_dpath: str) -> str:
    """
        Select dataset items which belongs to CVEs containing single commit to build new dataset.

        New dataset form:
        repo_1:
            commit_id_1:
                cve_list: [cve_1, cve_2, ...]
                file_1: qualified dataset item (Dict)
                file_2: qualified dataset item (Dict)
                ...

            commit_id_2:
                ...
            ...

        repo_2:
            ...
        ...

        Args:
            logger
            dataset_jpath: TreeVul-valid.json
            save_dpath
        Returns:
            cve_s_commit_dataset_jpath:
                Dataset path to CVEs containing single valid commit.
    """
    log_debug(logger, ">>>> Selecting dataset items which belongs to CVEs containing single commit ...")
    logger.info(f">>>> Dataset path: {dataset_jpath}.")

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)
    logger.info(f"Number of dataset items: {len(dataset)}.")

    # Check CVE-ID with commit_id
    cve2commit, commit2cve = _get_cve2commit_and_commit2cve(dataset)

    # Reassign `cve2commit` and `commit2cve`
    _reassign_cve2commit_and_commit2cve_with_special_cases(cve2commit, commit2cve)

    logger.info(f"Number of CVEs: {len(cve2commit)}.")
    logger.info(f"Number of commits: {len(commit2cve)}.")

    # Separate CVEs with one commit and CVEs with multiple commits
    cve_s_commit_dict = {}
    cve_m_commit_dict = {}
    for cve, commits in cve2commit.items():
        if len(commits) == 1:
            assert cve not in cve_s_commit_dict
            cve_s_commit_dict[cve] = commits[0]
        else:
            assert cve not in cve_m_commit_dict
            cve_m_commit_dict[cve] = commits

    logger.info(f"Number of CVEs with single commit: {len(cve_s_commit_dict)}.")
    logger.info(f"Number of CVEs with multiple commits: {len(cve_m_commit_dict)}.")

    # Select qualified dataset items
    def _add_qualified_item(_item, _cve_list: List, _commit_id: str, _repo: str, _file_name: str):
        if _repo not in cve_s_commit_dataset:
            _commit_info = {
                "cve_list": _cve_list,
                _file_name: _item}
            _repo_commits_dict = {_commit_id: _commit_info}
            cve_s_commit_dataset[_repo] = _repo_commits_dict
        else:
            if _commit_id in cve_s_commit_dataset[_repo]:
                assert _file_name not in cve_s_commit_dataset[_repo][_commit_id]
                cve_s_commit_dataset[_repo][_commit_id][_file_name] = _item

                cve_s_commit_dataset[_repo][_commit_id]["cve_list"] += _cve_list
                cve_s_commit_dataset[_repo][_commit_id]["cve_list"] = \
                    list(set(cve_s_commit_dataset[_repo][_commit_id]["cve_list"]))
            else:
                _commit_info = {
                    "cve_list": _cve_list,
                    _file_name: _item}
                cve_s_commit_dataset[_repo][_commit_id] = _commit_info

    cve_s_commit_dataset = {}
    qualified_item_num = 0
    for item in dataset:
        cve_list = item["cve_list"]
        commit_id = item["commit_id"]
        repo = item["repo"]
        file_name = item["file_name"]

        cves = cve_list.split(',')

        # Special case 1: assign new CVE-ID (CVE-2016-10062) to commit 8ed56f49
        if cve_list == "CVE-2016-10060" and commit_id == "8ed56f49e4eb858c26420324d74882a22089fe3d":
            qualified_item_num += 1
            new_cve = "CVE-2016-10062"
            item["cve_list"] = new_cve
            _add_qualified_item(item, _cve_list=[new_cve], _commit_id=commit_id, _repo=repo, _file_name=file_name)
            continue

        # Special case 2: assign new commit 32ab266 (not in original dataset) to CVE-2020-10672
        if "CVE-2020-10672" in cves:
            qualified_item_num += 1
            new_cve = "CVE-2020-10672"
            new_commit_id = "32ab266118407e763d7875a555551780540b5ef5"
            new_file_name = "src/mapper/java/org/codehaus/jackson/map/jsontype/impl/SubTypeValidator.java"
            new_item = {
                "cve_list": new_cve,
                "cwe_list": item["cwe_list"],
                "path_list": item["path_list"],
                "repo": repo,
                "commit_id": new_commit_id,
                "file_name": new_file_name
            }
            _add_qualified_item(new_item, _cve_list=[new_cve], _commit_id=new_commit_id, _repo=repo, _file_name=new_file_name)
            continue

        # Special case 3: retain the composite CVE-ID (CVE-2020-24265,CVE-2020-24266) as the new ID for this commit
        if len(cves) == 1 or cve_list == "CVE-2020-24265,CVE-2020-24266":
            cve = cve_list
            if cve in cve_s_commit_dict and commit_id == cve_s_commit_dict[cve]:
                qualified_item_num += 1
                _add_qualified_item(item, _cve_list=[cve], _commit_id=commit_id, _repo=repo, _file_name=file_name)
        else:
            accepted_cves = []
            for cve in cves:
                if cve in cve_s_commit_dict and commit_id == cve_s_commit_dict[cve]:
                    accepted_cves.append(cve)
                    qualified_item_num += 1

            if len(accepted_cves) > 0:
                _add_qualified_item(item, _cve_list=accepted_cves, _commit_id=commit_id, _repo=repo, _file_name=file_name)

    logger.info(f"Number of qualified dataset items: {qualified_item_num}.")

    # Check and re-edit selected items
    cve_s_commit_exist = {}
    for cve, _ in cve_s_commit_dict.items():
        cve_s_commit_exist[cve] = False

    for repo, repo_item in cve_s_commit_dataset.items():
        for commit_id, commit_item in repo_item.items():
            # Check
            assert "cve_list" in commit_item

            cve_list = commit_item["cve_list"]
            assert len(set(cve_list)) == len(cve_list)
            assert len(set(commit2cve[commit_id])) == len(commit2cve[commit_id])
            assert set(cve_list) == set(commit2cve[commit_id])

            # Re-edit
            for file_name, original_dataset_item in commit_item.items():
                if file_name != "cve_list":
                    cve_s_commit_dataset[repo][commit_id][file_name]["cve_list"] = cve_list

    # Save
    cve_s_commit_dataset_jpath = os.path.join(save_dpath, "TreeVul-valid-cve_s_commit.json")
    logger.info(f"Dataset for saving CVEs with single valid commit: {cve_s_commit_dataset_jpath}.")
    with open(cve_s_commit_dataset_jpath, 'w') as f:
        json.dump(cve_s_commit_dataset, f, indent=4)

    return cve_s_commit_dataset_jpath


def select_cves_with_single_commit_with_single_file(logger, dataset_jpath: str, save_dpath: str) -> str:
    """
        After selecting dataset items which belongs to CVEs containing single commit,
        select CVEs containing single valid commit which changes single file to build new dataset.

        Returns:
            cve_s_commit_s_file_dataset_jpath:
                Dataset path to CVEs containing single valid commit which changes a single file.
    """
    log_debug(logger, ">>>> Selecting CVEs containing single valid commit which changes single file ...")
    logger.info(f"Dataset for saving CVEs with single valid commit: {dataset_jpath}.")

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)

    # Select
    cve_s_commit_s_file_num = 0
    cve_s_commit_s_file_dataset = {}
    for repo, repo_item in dataset.items():
        new_repo_item = {}
        for commit_id, commit_item in repo_item.items():
            if len(commit_item) == 2:
                new_repo_item[commit_id] = commit_item
                cve_s_commit_s_file_num += 1

        if len(new_repo_item) > 0:
            cve_s_commit_s_file_dataset[repo] = new_repo_item

    logger.info(f"Number of CVEs containing single valid commit which changes single file: {cve_s_commit_s_file_num}.")

    # Save
    cve_s_commit_s_file_dataset_jpath = os.path.join(save_dpath, "TreeVul-valid-cve_s_commit_s_file.json")
    logger.info(f"Dataset for saving CVEs containing single valid commit which changes single file: {cve_s_commit_s_file_dataset_jpath}.")
    with open(cve_s_commit_s_file_dataset_jpath, 'w') as f:
        json.dump(cve_s_commit_s_file_dataset, f, indent=4)

    return cve_s_commit_s_file_dataset_jpath


def _get_cve2commit_and_commit2cve(dataset: List[Dict]) -> Tuple[Dict, Dict]:
    cve2commit = {}
    commit2cve = {}

    def _update_cve2commit(_cve, _commit):
        if _cve not in cve2commit:
            cve2commit[_cve] = [_commit]
        else:
            cve2commit[_cve].append(_commit)
            cve2commit[_cve] = list(set(cve2commit[_cve]))

    def _update_commit2cve(_cve, _commit):
        if _commit not in commit2cve:
            commit2cve[_commit] = [_cve]
        else:
            commit2cve[_commit].append(_cve)
            commit2cve[_commit] = list(set(commit2cve[_commit]))

    for item in dataset:
        cve = item["cve_list"]
        commit = item["commit_id"]
        if len(cve.split(',')) > 1:
            cves = cve.split(',')
            for cve in cves:
                _update_cve2commit(cve, commit)
                _update_commit2cve(cve, commit)
        else:
            _update_cve2commit(cve, commit)
            _update_commit2cve(cve, commit)

    return cve2commit, commit2cve


def CWE_count(logger, dataset_source: str, dataset: List[Dict],
              cwe_view_id: str, cwe_jpath: str,
              save_dpath: str):
    log_debug(logger, f"Count CWE types of commits in {dataset_source} dataset under CWE view {cwe_view_id} ...")
    # Read CWE items (1003)
    with open(cwe_jpath, 'r') as f:
        view_cwe_items = json.load(f)

    # Check whether CWE-ID of commit is under specified CWE view (1003)
    in_commit_number = 0
    not_in_commit_number = 0
    in_cwe_list = []
    not_in_cwe_list = []

    cwe_commit_dict = {}
    for item in dataset:
        cwe_id = item["cwe_list"].split("-")[-1]
        if cwe_id in view_cwe_items:
            in_commit_number += 1
            if cwe_id not in in_cwe_list:
                in_cwe_list.append(cwe_id)
        else:
            not_in_commit_number += 1
            if cwe_id not in not_in_cwe_list:
                not_in_cwe_list.append(cwe_id)

        if cwe_id in cwe_commit_dict:
            cwe_commit_dict[cwe_id] += 1
        else:
            cwe_commit_dict[cwe_id] = 1

    cwe_commit_dict = dict(sorted(cwe_commit_dict.items(), key=lambda x: x[1], reverse=True))

    view_cwe_commit_dict = {}
    for cwe_id, commit_num in cwe_commit_dict.items():
        if cwe_id in view_cwe_items:
            if len(view_cwe_items[cwe_id]["VIEW-" + cwe_view_id]["father"]) == 0:
                if cwe_id in view_cwe_commit_dict:
                    view_cwe_commit_dict[cwe_id]["commit_num"] = commit_num
                else:
                    view_cwe_commit_dict[cwe_id] = {"commit_num": commit_num}
            else:
                for father in view_cwe_items[cwe_id]["VIEW-" + cwe_view_id]["father"]:
                    if father in view_cwe_commit_dict:
                        if "children_commit_num" in view_cwe_commit_dict[father]:
                            view_cwe_commit_dict[father]["children_commit_num"] += commit_num
                        else:
                            view_cwe_commit_dict[father]["children_commit_num"] = commit_num
                    else:
                        view_cwe_commit_dict[father] = {"children_commit_num": commit_num}

    count = {
        "Number of CWE types": len(cwe_commit_dict),
        "Number of CWE types in VIEW " + cwe_view_id: len(in_cwe_list),
        "Number of CWE types not in VIEW " + cwe_view_id: len(not_in_cwe_list),
        "Number of commit in VIEW " + cwe_view_id: in_commit_number,
        "Number of commit not in VIEW " + cwe_view_id: not_in_commit_number,
        "Detailed CWE items": cwe_commit_dict,
        "Detailed CWE items in VIEW " + cwe_view_id: view_cwe_commit_dict
    }

    # Save complete dataset count
    count_save_fpath = os.path.join(save_dpath, f"TreeVul-{dataset_source}-CWECount.json")
    with open(count_save_fpath, 'w') as f:
        json.dump(count, f, indent=4)

    logger.info(f"Saved file path: {count_save_fpath}.")


def TreeVulCleaning(step: int, dataset_source: str, dataset_jpath: str,
                    cwe_view_id: str, cwe_jpath: str,
                    save_dpath: str = "./data", token: str = ''):
    """
        Clean TreeVul dataset.

        Args:
            step:
                1: check validity of commit in CVE items by fetching (`check_commits_validity_by_fetching`)
                2: check validity of commit in CVE items by cloning (`check_commits_validity_by_cloning`)
                    and build dataset containing CVE items with valid commit (`build_dataset_from_validity_check_results`)
                3: select CVE items with valid commit which changes single file (`select_single_file_commit_items`)
                4: process CVE items with valid commit which changes multiple files (`process_multiple_files_commit_items`)
                5: get the attributes of the dataset related to CWE (`CWE_count`)
            dataset_source:
                original:       original dataset from TreeVul project, available for step 1 - 2 / 4
                valid:          dataset obtained after cleaning in step 1 and step 2, available for step  3 / 4 / 5
                valid-single:   dataset obtained after cleaning in step 1 and step 3, available for step 5
                valid-multiple: dataset obtained after cleaning in step 1 and step 4, available for step 5
            dataset_jpath: TreeVul dataset file path
                original:       TreeVul-original.json (= dataset_cleaned.json)
                valid:          TreeVul-valid.json
                valid-single:   TreeVul-valid-single.json
                valid-multiple: TreeVul-valid-multiple.json
            cwe_view_id:
            cwe_jpath:
            save_dpath: Saving dir path
            token
    """
    logger, _ = start_with_logger(__name__, log_fname=f"TreeVulCleaning-{step}")
    logger.info(">>>> Cleaning TreeVul dataset ...")
    logger.info(f">>>> Dataset source: {dataset_source}.")
    logger.info(f">>>> Dataset path: {dataset_jpath}.")
    logger.info(f">>>> Save dir path: {save_dpath}.")

    if not os.path.exists(save_dpath):
        os.makedirs(save_dpath, exist_ok=True)

    with open(dataset_jpath, 'r') as f:
        dataset = json.load(f)

    if step == 1:
        # Dataset source: original
        if dataset_source == "original":
            check_commits_validity_by_fetching(logger=logger, dataset_jpath=dataset_jpath, save_dpath=save_dpath, token=token)
        else:
            logger.warning(f"Cleaning step 1 only support dataset whose source is 'original', but gets {dataset_source}!")
    elif step == 2:
        check_result_jpath = "./data/TreeVul-valid_check.json"
        # step I
        # check_failed_commits_by_cloning(logger, check_result_jpath, repo_exists=False)
        # step II
        # check_failed_commits_by_cloning(logger, check_result_jpath, repo_exists=True)
        # step III
        build_dataset_from_validity_check_results(logger, dataset_jpath, check_result_jpath, save_dpath)
    elif step == 3:
        # Dataset source: valid
        if dataset_source == "valid":
            # Step I
            cve_s_commit_dataset_jpath = select_cves_with_single_commit(logger, dataset_jpath, save_dpath)
            # Step II
            select_cves_with_single_commit_with_single_file(logger, cve_s_commit_dataset_jpath, save_dpath)
        else:
            logger.warning(f"Cleaning step 2 only support dataset whose source is 'valid', but gets {dataset_source}!")
    elif step == 4:
        # Dataset source: valid
        if dataset_source == "valid":
            process_multiple_files_commit_items(logger=logger, dataset_source=dataset_source, dataset=dataset,
                                                save_dpath=save_dpath)
        else:
            logger.warning(f"Cleaning step 3 only support dataset whose source is 'valid', but gets {dataset_source}!")
    elif step == 5:
        # Dataset source: valid, valid-single, valid-multiple
        CWE_count(logger, dataset_source, dataset, cwe_view_id, cwe_jpath, save_dpath)
    else:
        logger.warning(f"Step {step} not implemented.")
        # check_dataset_items(logger, dataset_jpath)
        


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Clean dataset.')
    parser.add_argument('-dn', '--datasetName',
                        type=str, required=True, help='Dataset name.')
    parser.add_argument('-dp', '--datasetFilepath',
                        type=str, required=True, help='Dataset file path.')
    parser.add_argument('-cv', '--cweViewId',
                        type=str, default='1003', help='CWE VIEW ID, 1003 by default.')
    parser.add_argument('-cp', '--viewCWEFilepath',
                        type=str, required=True, help='CWE items under specific view file path.')
    parser.add_argument('-s', '--step',
                        type=int, required=True, help='Step in data cleansing.')
    parser.add_argument('-t', '--token',
                        type=str, default='', help='GitHub token.')

    args = parser.parse_args()
    dn = args.datasetName
    dp = args.datasetFilepath
    view_id = args.cweViewId
    vp = args.viewCWEFilepath
    s = args.step
    t = args.token

    data_sources = dp.split('/')[-1].split('.')[0].split('-')
    assert data_sources[0] == dn
    for source in data_sources[1:]:
        assert source in ('original', 'valid', 'single', 'multiple')
    ds = '-'.join(data_sources[1:])

    if dn == 'TreeVul':
        TreeVulCleaning(step=s, dataset_source=ds, dataset_jpath=dp, cwe_view_id=view_id, cwe_jpath=vp, token=t)

