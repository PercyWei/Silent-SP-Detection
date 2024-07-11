import os
import json
import time
import shutil
import requests

from typing import *
from datetime import datetime, timedelta

from loguru import logger

from preprocess.log import default_add_logger, log_banner, log_and_print, log_and_cprint, cprint
from preprocess.util import make_hie_dirs, clone_repo, checkout_commit


def get_api_rate_limit(token: str):
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


def calculate_date_range(commit_date) -> Tuple[str, str]:
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    commit_datetime = datetime.strptime(commit_date, date_format)

    start_date = commit_datetime - timedelta(hours=12)
    end_date = commit_datetime + timedelta(hours=12)

    start_date_str = datetime.strftime(start_date, date_format)
    end_date_str = datetime.strftime(end_date, date_format)

    return start_date_str, end_date_str


"""Cleaning Functions for TreeVul Dataset"""


def group_TreeVul_items_by_commit(data_fpath: str, output_root: str) -> None:
    """
    Group items from the same commit in original TreeVul dataset together and resave.

    Args:
        data_fpath (str): Path to original TreeVul dataset file in JSON format.
        output_root (str): Path to overall output root directory.
    """
    with open(data_fpath, 'r') as f:
        dataset = json.load(f)

    rec_dataset = {}

    for item in dataset:
        commit_id = item['commit_id']
        if commit_id not in rec_dataset:
            rec_dataset[commit_id] = [item]
        else:
            assert item["repo"] == rec_dataset[commit_id][0]["repo"]
            rec_dataset[commit_id].append(item)

    output_dpath = make_hie_dirs(output_root, "TreeVul")

    res_dataset_fpath = os.path.join(output_dpath, "TreeVul_rec.json")
    with open(res_dataset_fpath, 'w') as f:
        json.dump(rec_dataset, f, indent=4)


"""Check Commits Validity"""


def _fetch_commits_with_date(auth_repo: str, start_date: str, end_date: str, token: str) -> Optional[List]:
    url = f"https://api.github.com/repos/{auth_repo}/commits"
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
        cprint(f"Try fetching {retries + 1}/{max_retries}")
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
                    time.sleep(2)
                    break
            if current_url is None:
                break
        except requests.exceptions.Timeout as e:
            retries += 1
            time.sleep(2)
            continue
        except requests.exceptions.RequestException as e:
            retries += 1
            time.sleep(2)
            continue

    if retries >= max_retries:
        cprint(f"Max retries reached, still failed to fetch commits.", style="red")
        return None
    else:
        return commits


def _check_commit_validity_by_fetching(
        auth_repo: str,
        commit_id: str,
        start_date: str,
        end_date: str,
        token: str
) -> Optional[bool]:
    """
    Check if the given commit ID is valid for a specific GitHub repository.

    Args:
        auth_repo (str): Form like - username name/repository name
        commit_id (str): The commit ID to check.
        token (str): Personal Access Token for GitHub.

    Returns:
        True: Given commit ID is valid.
        False: Given commit ID is invalid.
        None: Given commit ID checked failed.
    """
    commits = _fetch_commits_with_date(auth_repo, start_date, end_date, token)
    if commits is not None:
        for commit in commits:
            if commit['sha'] == commit_id:
                return True
        return False
    else:
        return None


def check_commits_validity_by_fetching(
        dataset_fpath: str,
        output_root: str,
        token: str = ''
) -> bool:
    """
    Check commits in the TreeVul dataset through fetching.

    Args:
        dataset_fpath (str): Path to the TreeVul dataset file in JSON format.
            Note: Need to reconstruct the TreeVul dataset before calling this function.
                  Use 'group_TreeVul_items_by_commit' and get 'TreeVul_rec.json'.
        output_root (str): Path to the root for overall output.
        token (str): GitHub personal access token.
    """
    log_banner("Checking Commit Validity through Fetching")

    with open(dataset_fpath, 'r') as f:
        dataset: Dict = json.load(f)
    log_and_print(f"Initial commits number: {len(dataset)}.")

    output_dpath = make_hie_dirs(output_root, "TreeVul")

    prev_check_info = {}
    prev_all_results: Dict[str, Dict[str, bool]] = {}
    prev_failed_results: Dict[str, List] = {}
    validity_check_jpath = os.path.join(output_dpath, 'commit_val_check.json')
    log_and_print(f"Checked results save path: {validity_check_jpath}")
    if os.path.exists(validity_check_jpath):
        log_and_print("It has been checked before.")

        with open(validity_check_jpath, 'r') as f:
            prev_check_info = json.load(f)
        prev_all_results = prev_check_info["All Commits"]
        prev_failed_results = prev_check_info["Failed Commits"]
    else:
        log_and_print("This is the first time to check.")

    remaining, reset = get_api_rate_limit(token)
    api_rate_check_gap = remaining or 60
    api_rate_check_step = 0

    new_all_results: Dict[str, Dict[str, bool]] = {}
    new_failed_results: Dict[str, List] = {}

    valid_commits_number = 0
    invalid_commits_number = 0
    failed_commits_number = 0

    for i, (commit_id, items) in enumerate(dataset.items()):
        auth_repo = items[0]["repo"]
        commit_date = items[0]["commit_date"]
        cprint(f"- {i+1}/{len(dataset)} - repo: {auth_repo}, commit: {commit_id}", style="bold")

        result = None
        # Get prev check result
        if auth_repo in prev_all_results and commit_id in prev_all_results[auth_repo]:
            result = prev_all_results[auth_repo][commit_id]

        # Check with fetch
        if result is None or result == "Failed":
            # Current commit is checked failed before or is unchecked
            if type(commit_date) is str:
                # Can not fetch without an exact time (commit time)
                if auth_repo not in new_failed_results:
                    # In case API access is out of limits
                    api_rate_check_step += 1
                    if api_rate_check_step % api_rate_check_gap == 0:
                        remaining, reset = get_api_rate_limit(token)
                        if remaining == 0:
                            wait_for_rate_limit_reset(reset)

                    # Fetch and check
                    start_date, end_date = calculate_date_range(commit_date)

                    result = _check_commit_validity_by_fetching(auth_repo=auth_repo,
                                                                commit_id=commit_id,
                                                                start_date=start_date, end_date=end_date,
                                                                token=token)
                    if result is True:
                        result = "Valid"
                    elif result is False:
                        result = "Invalid"
                    else:
                        result = "Failed"

        # Count check result
        if result == "Valid":
            cprint("Result: Valid", style="green")
            valid_commits_number += 1
        elif result == "InValid":
            cprint("Result: Invalid", style="red")
            invalid_commits_number += 1
        else:
            cprint("Result: Failed", style="yellow")
            result = "Failed"
            failed_commits_number += 1
            # If a fetch failed, the corresponding repository will not attempt it again
            if auth_repo not in new_failed_results:
                new_failed_results[auth_repo] = [commit_id]
            else:
                new_failed_results[auth_repo].append(commit_id)
                new_failed_results[auth_repo] = list(set(new_failed_results[auth_repo]))

        # Recode new check result
        if auth_repo not in new_all_results:
            new_all_results[auth_repo] = {}
        new_all_results[auth_repo][commit_id] = result

    # Whether we need re-check through fetching
    continue_flag = False
    if not prev_failed_results:
        for auth_repo in prev_failed_results:
            prev_failed_commits = prev_failed_results[auth_repo]
            new_failed_commits = new_failed_results[auth_repo] if auth_repo in new_failed_results else []

            if len(prev_failed_commits) > len(new_failed_commits):
                continue_flag = True
                break
    else:
        continue_flag = True

    # log
    failed_repo2commit_num = {repo: len(commits) for repo, commits in new_failed_results.items()}

    log_and_print("-" * 40 + " COUNT " + "-" * 40)
    log_and_print(f"Valid commits number: {valid_commits_number}.")
    log_and_print(f"Invalid commits number: {invalid_commits_number}.")
    log_and_print(f"Failed commits number: {failed_commits_number}.")
    log_and_print(f"Fetched failed repo and commit number: {json.dumps(failed_repo2commit_num, indent=4)}.")
    log_and_print(f"Detailed fetched failed repo and commits: {json.dumps(new_failed_results, indent=4)}")
    log_and_print(f"Need re-check: {continue_flag}")
    log_and_print("-" * 87)

    # Save check results
    new_check_info = {
        "All Commits": new_all_results,
        "Failed Commits": new_failed_results,
    }

    with open(validity_check_jpath, 'w') as f:
        json.dump(new_check_info, f, indent=4)

    return continue_flag


# log_file = "./logs/clean.log"
# default_add_logger(log_file)

# dataset_file = "/root/projects/VDTest/output/TreeVul/TreeVul_rec.json"
# output_dir = "/root/projects/VDTest/output"
# git_token = ""
# check_commits_validity_by_fetching(dataset_file, output_dir, git_token)


def _check_commits_validity_by_cloning(
        auth_repo: str,
        commit_list: List[str],
        local_repos_root: str = '/root/projects/clone_projects',
        repo_exists: bool = False,
        token: str = ''
) -> Tuple[Optional[bool], Dict[str, str]]:
    """
    Clone the repository to local first, then check the validity of the commits.

    Args:
        auth_repo (str): Form like 'author_name/repo_name'.
        commit_list (List(str)): List of commit ids to be checked in this repo.
        local_repos_root (str): dir path for saving clone repos.
        repo_exists (bool): Whether the repo exists.
        token (str): GitHub personal access token.

    Returns:
        check_flag (bool | None):
            True: repo clone successful, check successful
            False: repo clone failed, check failed
            None: repo not found and clone failed, check failed
        Dict[commit_id: "Valid" / "Invalid"]:
            if return dict is empty, which means the check failed.
    """
    assert len(auth_repo.split('/')) == 2
    repo_dpath = os.path.join(local_repos_root, f'{auth_repo.replace("/", "_")}')
    cprint(f"Local repo dpath: {repo_dpath}")

    if not repo_exists:
        if os.path.exists(repo_dpath):
            shutil.rmtree(repo_dpath)
    else:
        if not os.path.exists(repo_dpath):
            logger.error(f"Repo existing required but not actually!")
            return False, {}

    if not repo_exists:
        clone_result = clone_repo(auth_repo=auth_repo,
                                  repo_dpath=repo_dpath,
                                  timeout=30,
                                  token=token)
    else:
        clone_result = True

    commits_result = {}
    if clone_result:
        check_flag = True

        commit_list = list(set(commit_list))
        for commit_id in commit_list:
            # Checkout commit
            checkout_result = checkout_commit(repo_dpath, commit_id)
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


def check_failed_commits_by_cloning(check_results_fpath: str,
                                    local_repos_root: str = '/root/projects/clone_projects',
                                    repo_exists: bool = False,
                                    token: str = ''):
    """
    Check commits, which were checked failed through fetching previously, through cloning.

    Args:
        check_results_fpath (str): Path to the file containing previous check results.
        local_repos_root (str): Path to the local root for saving all cloned repos.
        repo_exists (bool): True if the repos have been cloned to local, False otherwise.
        token (str): GitHub personal access token.
    """
    log_banner("Checking Commit Validity through Cloning")
    log_and_print(f"Dir for saving cloned repos: {local_repos_root}")

    if not os.path.exists(local_repos_root):
        os.makedirs(local_repos_root, exist_ok=True)

    with open(check_results_fpath, 'r') as f:
        prev_check_info = json.load(f)

    # Get old checked results
    all_results: Dict[str, Dict[str, str]] = prev_check_info["All Commits"]
    failed_results: Dict[str, List[str]] = prev_check_info["Failed Commits"]
    not_found_results: Dict[str, List[str]] = prev_check_info["Not Found Commits"] \
        if "Not Found Commits" in prev_check_info else {}

    log_and_print(f"Previously check failed repos number: {len(failed_results)}")
    log_and_print(f"Previously check failed commits number: {sum([len(c) for c in failed_results.values()])}")

    # Utilize cloning repo to check failed commit_id
    new_check_success_results: Dict[str, Dict[str, str]] = {}
    new_check_failed_results: Dict[str, List[str]] = {}
    new_not_found_results: Dict[str, List[str]] = {}

    for i, repo, commit_list in enumerate(failed_results.items()):
        assert repo not in not_found_results
        cprint(f"- {i + 1}/{len(failed_results)} - repo: {repo}")

        commit_list = list(set(commit_list))
        check_flag, commits_result = _check_commits_validity_by_cloning(auth_repo=repo,
                                                                        commit_list=commit_list,
                                                                        local_repos_root=local_repos_root,
                                                                        repo_exists=repo_exists,
                                                                        token=token)

        if check_flag:
            new_check_success_results[repo] = commits_result
        elif check_flag is None:
            new_not_found_results[repo] = commit_list
        else:
            new_check_failed_results[repo] = commit_list

    log_and_print("-" * 40 + " COUNT " + "-" * 40)
    log_and_print(f"Successfully checked repos number: {len(new_check_success_results)}")
    log_and_print(f"Successfully checked commits number: {sum([len(c) for c in new_check_success_results.values()])}")
    log_and_print(f"Unsuccessfully checked repos number: {len(new_check_failed_results)}")
    log_and_print(f"Unsuccessfully checked commits number: {sum([len(c) for c in new_check_failed_results.values()])}")
    log_and_print(f"Not found repos number: {len(not_found_results)}")
    log_and_print(f"Not found commits number: {sum([len(c) for c in not_found_results.values()])}")
    log_and_print("-" * 87)

    ## Update results
    # Not found commits
    for repo, commit_list in new_not_found_results.items():
        assert repo not in not_found_results
        not_found_results[repo] = commit_list

    # All commits
    for repo, commit_list in all_results.items():
        for commit_id, result in commit_list.items():
            if result == "Failed" and repo in new_check_success_results:
                assert commit_id in new_check_success_results[repo]
                all_results[repo][commit_id] = new_check_success_results[repo][commit_id]

    # Failed commits
    for repo, commit_list in failed_results.items():
        if repo in new_check_success_results:
            assert len(new_check_success_results[repo]) == len(commit_list)
            failed_results[repo] = []
        elif repo in not_found_results:
            assert len(not_found_results[repo]) == len(commit_list)
            failed_results[repo] = []

    failed_results = {k: v for k, v in failed_results.items() if v != []}

    update_check_info = {
        "All Commits": all_results,
        "Failed Commits": failed_results,
        "Not Found Commits": not_found_results
    }

    # Save
    with open(check_results_fpath, 'w') as f:
        json.dump(update_check_info, f, indent=4)


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
    log_banner("Build Valid Dataset")
    log_and_cprint("Dateset: TreeVul", style="bold")
    log_and_cprint(f"Dateset path: {dataset_fpath}", style="bold")
    log_and_cprint(f"Check results path: {check_results_fpath}", style="bold")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)
    log_and_print(f"Init commit number: {len(dataset)}")

    with open(check_results_fpath, 'r') as f:
        check_results = json.load(f)

    if len(check_results["Failed Commits"]) != 0:
        log_and_cprint("Failed commits in check results should be zero!", style='red')
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

    log_and_print(f"Valid commit number: {len(new_dataset)}")

    # Save dataset
    save_dpath = make_hie_dirs(output_root, "TreeVul")
    new_dataset_fpath = os.path.join(save_dpath, "TreeVul_valid.json")
    log_and_print(f"Valid dataset path: {new_dataset_fpath}")
    with open(new_dataset_fpath, 'w') as f:
        json.dump(new_dataset, f, indent=4)


# log_file = "./logs/build_valid_TreeVul.log"
# default_add_logger(log_file)
# treevul = "/root/projects/VDTest/output/TreeVul/TreeVul_rec.json"
# check = "/root/projects/VDTest/output/TreeVul/commit_valid_check.json"
# output_dir = "/root/projects/VDTest/output"
# build_dataset_from_validity_check_results(treevul, check, output_dir)


"""Select CVEs with Single Commit (scCVE)"""


def check_commits_of_cves(
        cve2commit: Dict[str, List[str]],
        commit2cve: Dict[str, List[str]]
) -> bool:
    """
    Check whether the commits of different CVEs in the dataset meet the requirements.

    Args:
        cve2commit (Dict): key is CVE-ID, value is the list of commit_id.
        commit2cve (Dict): key is commit_id, value is the list of CVE-ID.

    Returns:
        bool: Ture if different CVEs in the dataset have either exact the same or completely different commits,
              False otherwise.
    """

    # Filter CVEs with the same single commit

    cves_with_intersecting_commits = []
    cves_with_intersecting_commits_groups: List[Dict[str, List[str]]] = []

    for cve, commits in cve2commit.items():
        if cve not in cves_with_intersecting_commits:
            current_group = {cve: commits}

            related_cves = []
            for commit in commits:
                related_cves.extend(commit2cve[commit])
            related_cves = list(set(related_cves))

            for related_cve in related_cves:
                if related_cve != cve \
                        and set(cve2commit[related_cve]) != set(commits):
                    current_group[related_cve] = commits

            if len(current_group) > 1:
                cves_with_intersecting_commits_groups.append(current_group)
                cves_with_intersecting_commits.extend(list(current_group.keys()))

    if len(cves_with_intersecting_commits_groups) != 0:
        log_and_cprint(f"There are CVEs in the dataset that have not exactly the same commits!", style="red")
        logger.info("CVEs which do not meet the requirements:\n" +
                    json.dumps(cves_with_intersecting_commits_groups, indent=4))
        return False
    else:
        log_and_cprint("Different CVEs in the dataset have either exact the same or completely different commits.",
                       style="green")
        return True


def _reassign_cve2commit_and_commit2cve_with_special_cases(
        cve2commit: Dict[str, List[str]],
        commit2cve: Dict[str, List[str]]
) -> None:
    """
    Here special cases indicate CVEs with intersecting but not identical commits.
    All obtained by manual check.
    After calling this method, the commits belonging to different CVEs:
        1. Totally different -> Totally different CVEs
        2. Totally same -> a. Duplicate CVEs
                           b. The CVEs correspond to different parts of the changes in the commit

    Args:
        cve2commit (Dict): key is CVE-ID, value is the list of commit_id.
        commit2cve (Dict): key is commit_id, value is the list of CVE-ID.
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
    cve2commit["CVE-2020-14062"] = ["840eae2ca81c597a0010b2126f32dce17d384b70"]
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
    cve2commit["CVE-2020-24265+CVE-2020-24266"] = ["d3110859064b15408dbca1294dc7e31c2208504d"]
    commit2cve["8323a7fe1e47d562ebf384aa99633e3df74a01c4"] = ["CVE-2020-24265"]
    commit2cve["61db8adae55e246e0bc9442fbe977fff46154970"] = ["CVE-2020-24266"]
    commit2cve["d3110859064b15408dbca1294dc7e31c2208504d"] = ["CVE-2020-24265+CVE-2020-24266"]
    del commit2cve["6fb578d20feccffd4bae9f3d0216d1c3507bd805"]
    del commit2cve["9f6f3d525a5a5a682b4caaf95df366b4dfe0602d"]

    # 12. CVE-2021-39530, CVE-2021-39522
    # cve_s_commit_dict["CVE-2021-39522"] = "4b99edb0ea26e99ef65c5fe68670e6b1f9382d44"
    # cve_s_commit_dict["CVE-2021-39530"] = "dac8fcc4be1007ccf4412ae5e90303e335fdb412"
    cve2commit["CVE-2021-39522"] = ["4b99edb0ea26e99ef65c5fe68670e6b1f9382d44"]
    cve2commit["CVE-2021-39530"] = ["dac8fcc4be1007ccf4412ae5e90303e335fdb412"]
    commit2cve["4b99edb0ea26e99ef65c5fe68670e6b1f9382d44"] = ["CVE-2021-39522"]
    commit2cve["dac8fcc4be1007ccf4412ae5e90303e335fdb412"] = ["CVE-2021-39530"]

    # Check if it is as expected
    if not check_commits_of_cves(cve2commit, commit2cve):
        raise RuntimeError("Dataset do not meet the requirements")


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


def select_scCVEs(dataset_fpath: str, output_root: str) -> None:
    """
    Select CVEs containing single commit to build new dataset.

    Args:
        dataset_fpath (str): 'TreeVul-valid.json'
        output_root (str): Path to overall output root directory.
    """
    log_banner("Selecting CVEs Containing Single Commit")
    log_and_print(f"Dataset path: {dataset_fpath}")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)
    log_and_print("Initial:")
    log_and_print(f"- commits number: {len(dataset)}")

    # Check CVE-ID with commit_id
    cve2commit, commit2cve = _get_cve2commit_and_commit2cve(dataset)

    # Reassign `cve2commit` and `commit2cve`
    _reassign_cve2commit_and_commit2cve_with_special_cases(cve2commit, commit2cve)

    log_and_print("After reassignment:")
    log_and_print(f"- CVEs number: {len(cve2commit)}")
    log_and_print(f"- Commits number: {len(commit2cve)}")

    # Separate CVEs with one commit and CVEs with multiple commits
    cve_s_commit_dict: Dict[str, str] = {}
    cve_m_commit_dict: Dict[str, List[str]] = {}
    for cve, commits in cve2commit.items():
        if len(commits) == 1:
            assert cve not in cve_s_commit_dict
            cve_s_commit_dict[cve] = commits[0]
        else:
            assert cve not in cve_m_commit_dict
            cve_m_commit_dict[cve] = commits

    log_and_print(f"Number of CVEs with single commit: {len(cve_s_commit_dict)}")
    log_and_print(f"Number of CVEs with multiple commits: {len(cve_m_commit_dict)}")

    # Select qualified dataset items
    cve_s_commit_dataset: Dict[str, List[Dict]] = {}

    for cve_id, commit_id in cve_s_commit_dict.items():
        # Special case 1: assign new CVE-ID (CVE-2016-10062) to commit 8ed56f49
        if cve_id == "CVE-2016-10062" and commit_id == "8ed56f49e4eb858c26420324d74882a22089fe3d":
            items = dataset[commit_id]
            for item in items:
                item["cve_list"] = [cve_id]
            cve_s_commit_dataset[commit_id] = items
            continue

        # Special case 2: assign new commit 32ab266 (not in original dataset) to CVE-2020-10672
        if cve_id == "CVE-2020-10672" and commit_id == "32ab266118407e763d7875a555551780540b5ef5":
            new_item = {
                "cve_list": [cve_id],
                "cwe_list": "CWE-502",
                "path_list": ["CWE-664", "CWE-913", "CWE-502"],
                "repo": "FasterXML/jackson-databind",
                "commit_id": commit_id,
                "file_name": "src/mapper/java/org/codehaus/jackson/map/jsontype/impl/SubTypeValidator.java"
            }
            cve_s_commit_dataset[commit_id] = [new_item]
            continue

        # Special case 3: retain the composite CVE-ID (CVE-2020-24265,CVE-2020-24266) as the new ID for this commit
        if cve_id == "CVE-2020-24265+CVE-2020-24266" and commit_id == "d3110859064b15408dbca1294dc7e31c2208504d":
            items = dataset[commit_id]
            for item in items:
                item["cve_list"] = [cve_id]
            cve_s_commit_dataset[commit_id] = items
            continue

        # Normal cases
        same_commit_cve_ids = []
        if commit_id in cve_s_commit_dataset:
            same_commit_cve_ids = cve_s_commit_dataset[commit_id][0]["cve_list"]

        items = dataset[commit_id]
        same_commit_cve_ids.append(cve_id)
        for item in items:
            item["cve_list"] = same_commit_cve_ids

        cve_s_commit_dataset[commit_id] = items

    cves_with_same_single_commits: List[List[str]] = []
    for commit_id, items in cve_s_commit_dataset.items():
        cve_list = None
        for item in items:
            if cve_list is not None:
                assert item["cve_list"] == cve_list
            else:
                cve_list = item["cve_list"]
        if len(cve_list) > 1:
            cves_with_same_single_commits.append(cve_list)

    log_and_print("-" * 40 + " CVEs with Single Commit Count " + "-" * 40)
    log_and_print(f"Different commit number: {len(cve_s_commit_dataset)}")
    log_and_print(f"Number of CVEs with different "
                  f"single commit: {len(cve_s_commit_dataset) - len(cves_with_same_single_commits)}")
    log_and_print(f"Number of CVEs with same single commit: {sum([len(g) for g in cves_with_same_single_commits])}")
    logger.info(f"Detailed CVEs with same single commit:\n{json.dumps(cves_with_same_single_commits, indent=4)}")

    # Save
    save_dpath = make_hie_dirs(output_root, "TreeVul")
    cve_s_commit_dataset_jpath = os.path.join(save_dpath, "TreeVul_valid_scCVE.json")
    log_and_print(f"Dataset for saving CVEs with single valid commit (scCVE): {cve_s_commit_dataset_jpath}")
    with open(cve_s_commit_dataset_jpath, 'w') as f:
        json.dump(cve_s_commit_dataset, f, indent=4)


# log_file = "./logs/build_TreeVul_valid_scCVE.log"
# default_add_logger(log_file)
# treevul_valid = "/root/projects/VDTest/output/TreeVul/TreeVul_valid.json"
# output_dir = "/root/projects/VDTest/output"
# select_scCVEs(treevul_valid, output_dir)


"""Select CVEs with Single Commit Single File (scsfCVE)"""


def select_scsfCVEs(dataset_fpath: str, output_root: str) -> None:
    """
    After selecting CVEs containing single valid commit,
    this method select CVEs containing single valid commit which changes single file and build new dataset.

    Args:
        dataset_fpath (str): 'TreeVul_valid_scCVE.json'
        output_root (str): Path to overall output root directory.
    """
    log_banner("Selecting CVEs Containing Single Valid Commit which Changes Single File")
    log_and_print(f"Dataset for saving CVEs with single valid commit (scCVE): {dataset_fpath}")

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    # Select
    new_dataset: Dict[str, Dict] = {}
    for commit_id, items in dataset.items():
        if len(items) == 1:
            new_dataset[commit_id] = items

    log_and_print(f"Number of CVEs containing single valid commit which changes single file: {len(new_dataset)}")

    # Save
    save_dpath = make_hie_dirs(output_root, "TreeVul")
    new_dataset_fpath = os.path.join(save_dpath, "TreeVul_valid_scsfCVE.json")
    with open(new_dataset_fpath, 'w') as f:
        json.dump(new_dataset, f, indent=4)

    log_and_print(f"Dataset for saving CVEs containing single valid commit "
                  f"which changes single file (scsfCVE): {new_dataset_fpath}")


# log_file = "./logs/build_TreeVul_valid_scsfCVE.log"
# default_add_logger(log_file)
# output_dir = "/root/projects/VDTest/output"
# treevul_valid_scCVE = "/root/projects/VDTest/output/TreeVul/TreeVul_valid_scCVE.json"
# select_scsfCVEs(treevul_valid_scCVE, output_dir)

"""Dataset Count Language"""


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
    log_banner("Dataset File Language Count")
    log_and_print(f"Dataset: {dataset_fpath}")

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

    log_and_print(f"File Language Count:\n{json.dumps(language_count, indent=4)}")


# log_file = "./logs/TreeVul_scsfCVE_lang_count.log"
# default_add_logger(log_file)
# treevul_valid_scsfCVE = "/root/projects/VDTest/output/TreeVul/TreeVul_valid_scsfCVE.json"
# count_dataset_file_language(treevul_valid_scsfCVE)
