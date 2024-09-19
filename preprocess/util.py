import os
import re
import json
import shutil
import time
import subprocess
import requests

from typing import *
from datetime import datetime, timedelta
from loguru import logger

from utils import run_command
from preprocess.log import cprint

from typing import *


def clone_repo(auth_repo: str, repo_dpath: str, timeout: int = 30, token: str = '') -> bool | None:
    """Clone a GitHub repository to local.

    Args:
        auth_repo (str): Form like 'auther_name/repo_name'.
        repo_dpath (str): Path to the local dir for saving this repo.
        timeout (int): Timeout in seconds.
        token (str): GitHub OAuth token.
    Returns:
        bool | None:
            True: Successfully Clone.
            False: Unsuccessfully Clone.
            None: Repo not found.
    """
    cprint(f"Clone Repo - Repo: {auth_repo}", style='bold')

    repo_url = f"https://{token}@github.com/{auth_repo}.git"
    clone_command = ["git", "clone", repo_url, repo_dpath]
    _, error_msg = run_command(clone_command, timeout=timeout)

    if error_msg:
        not_found_flag = False
        if "repository not found" in error_msg.lower():
            # Special case to record
            error_msg = "Repository not found"
            not_found_flag = True
        elif "time out" in error_msg.lower():
            error_msg = "Timed out"
        else:
            error_msg = "Other error"
        cprint(f"Failed! Reason: {error_msg}.", style='red')

        # Delete local dir for saving this repo
        try:
            shutil.rmtree(repo_dpath)
            cprint("Deleting dir successful.", style='yellow')
        except Exception as e:
            cprint("Deleting dir failed.", style='red')

        if not not_found_flag:
            return False
        else:
            return None
    else:
        cprint("Done!", style='green')
        return True


def checkout_commit(repo_dpath: str, commit_hash: str, revert: bool = True) -> bool:
    """
    Args:
        repo_dpath (str): Path to the local dir for saving this repo.
        commit_hash (str): Commit id/hash.
        revert (bool): Whether to revert the state after checkout.

    Returns:
        bool: True if the commit exists, False otherwise.
    """
    # Checkout to the specified commit
    checkout_command = ['git', 'checkout', commit_hash]
    _, error_msg = run_command(checkout_command, cwd=repo_dpath)

    if error_msg:
        return False

    # Revert to the previous state if necessary
    if revert:
        revert_command = ['git', 'checkout', '-']
        stdout, stderr = run_command(revert_command, cwd=repo_dpath)
        if stderr:
            cprint(f'Failed to revert the repo state! ({repo_dpath})', style='red')
    return True


"""GITHUB API CONNECT"""


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


"""COMMIT VALIDITY CHECKING"""


def is_commit_exist(auth_repo: str, commit_hash: str, token: str = '') -> Tuple[bool | None, Dict | None]:
    """Determine if a commit exists by fetching it from GitHub."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    commit_url = f'https://api.github.com/repos/{auth_repo}/commits/{commit_hash}'
    try:
        commit_response = requests.get(commit_url, headers=headers, timeout=10)

        if commit_response.status_code == 200:
            # Commit exists
            return True, commit_response.json()
        elif commit_response.status_code == 404:
            # Commit does not exist
            return False, None
        elif commit_response.status_code == 422 and "No commit found for SHA" in commit_response.json()["message"]:
            return False, None
        elif commit_response.status_code in {500, 502, 503, 504}:
            # Temporary server issues, need to retry
            return None, None
        else:
            # Unexpected status code, need to retry
            return None, None
    except requests.exceptions.RequestException as e:
        # Checked failed, need to retry
        return None, None


def calculate_date_range(commit_date: str, second_sep: int = 60) -> Tuple[str, str]:
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    commit_datetime = datetime.strptime(commit_date, date_format)

    start_date = commit_datetime - timedelta(seconds=second_sep)
    end_date = commit_datetime + timedelta(seconds=second_sep)

    start_date_str = datetime.strftime(start_date, date_format)
    end_date_str = datetime.strftime(end_date, date_format)

    return start_date_str, end_date_str


def is_commit_reproducible(auth_repo: str, commit_hash: str, start_date: str, end_date: str, token: str = '') -> bool | None:
    url = f"https://api.github.com/repos/{auth_repo}/commits"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {'since': start_date, 'until': end_date, 'per_page': 100}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            return None

        commits = response.json()
    except requests.exceptions.RequestException as e:
        return None

    for commit in commits:
        if commit['sha'] == commit_hash:
            return True
    return False


def is_commit_exist_in_repo(repo_dpath: str, commit_hash: str) -> bool:
    try:
        result = subprocess.run(
            ['git', '-C', repo_dpath, 'cat-file', '-t', commit_hash],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip() == 'commit'
    except subprocess.CalledProcessError:
        return False


"""PULL RELATED COMMIT"""


def extract_pull_info_from_url(pull_url: str) -> Tuple[str, int] | None:
    pattern = r'^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$'
    match = re.match(pattern, pull_url)

    if not match:
        return None

    auth_repo = match.group(1)
    pull_number = int(match.group(2))

    return auth_repo, pull_number


def is_pull_exist(auth_repo: str, pull_number: int, token: str = "") -> bool | None:
    api_url = f"https://api.github.com/repos/{auth_repo}/pull/{pull_number}"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            return None
    except requests.exceptions.RequestException as e:
        return None


def get_commits_from_pull_request(auth_repo: str, pull_number: int, token: str = '') -> List[str] | None:
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    commits_url = f"https://api.github.com/repos/{auth_repo}/pulls/{pull_number}/commits"

    try:
        response = requests.get(commits_url, headers=headers, timeout=10)

        if response.status_code == 200:
            commits_data = response.json()
            commits = [commit['sha'] for commit in commits_data]
            return commits
        else:
            return None

    except requests.exceptions.RequestException as e:
        return None


"""ISSUE RELATED COMMIT"""


def extract_issue_info_from_url(issue_url: str) -> Tuple[str, int] | None:
    pattern = r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$"
    match = re.match(pattern, issue_url)

    if not match:
        return None

    auth_repo = match.group(1)
    issue_number = int(match.group(2))

    return auth_repo, issue_number


def is_issue_exist(auth_repo: str, issue_number: int, token: str = "") -> bool | None:
    api_url = f"https://api.github.com/repos/{auth_repo}/issues/{issue_number}"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            return None
    except requests.exceptions.RequestException as e:
        return None


def get_related_commits_from_issue_events(auth_repo: str, issue_number: int, token: str = '') -> List[str] | None:
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    events_url = f"https://api.github.com/repos/{auth_repo}/issues/{issue_number}/events"

    try:
        response = requests.get(events_url, headers=headers, timeout=10)

        if response.status_code == 200:
            events = response.json()
            commits = []
            for event in events:
                if event['event'] == 'referenced' and 'commit_id' in event:
                    commits.append(event['commit_id'])
            return commits
        else:
            return None

    except requests.RequestException as e:
        return None


"""COMMIT"""


def extract_commit_info_from_url(commit_url: str) -> Tuple[str, str] | None:
    pattern = r"^https://github\.com/([\w-]+/[\w-]+)/commit/([a-fA-F0-9]+)$"
    match = re.match(pattern, commit_url)

    if not match:
        return None

    auth_repo = match.group(1)
    commit_hash = match.group(2)

    return auth_repo, commit_hash


"""COMMIT LANGUAGE"""


def get_file_lang(file_name: str) -> List[str]:
    if file_name.endswith(".py"):
        return ["Python"]
    elif file_name.endswith(".c") or file_name.endswith(".h"):
        return ["C"]
    elif file_name.endswith(".cpp") or file_name.endswith(".cc"):
        return ["C++"]
    elif file_name.endswith(".java"):
        return ["Java"]
    elif file_name.endswith(".php") or file_name.endswith(".phpt"):
        return ["PHP"]
    elif file_name.endswith(".js") or file_name.endswith(".jsx"):
        return ["JavaScript"]
    elif file_name.endswith(".cs"):
        return ["C#"]
    elif file_name.endswith(".ts"):
        return ["TypeScript"]
    elif file_name.endswith(".rb"):
        return ["Ruby"]
    elif file_name.endswith(".go"):
        return ["Go"]
    elif file_name.endswith(".html"):
        return ["HTML"]
    elif file_name.endswith(".pm") or file_name.endswith(".t"):
        return ["Perl"]
    elif file_name.endswith(".rs"):
        return ["Rust"]
    elif file_name.endswith(".cshtml"):
        return ["C#", "HTML"]
    elif file_name.endswith(".vue"):
        return ["JavaScript", "HTML"]
    else:
        return []


def get_commit_lang(auth_repo: str, commit_hash: str, token: str = "") -> List[str] | None:
    res = is_commit_exist(auth_repo, commit_hash, token)
    if not res:
        return None

    _, commit_json = res

    pl_list: List[str] = []
    for file in commit_json["files"]:
        file_name = file["filename"]
        langs = get_file_lang(file_name)
        pl_list.extend(langs)

    pl_list = list(set(pl_list))
    return pl_list


"""CWE"""


def get_cwe_depth(
        cwe_id: str,
        cwe_tree_fpath: str = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
) -> int | None:
    """NOTE: For now, only VIEW-1000 is required"""
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    if cwe_id not in cwe_tree:
        return None

    min_path = min(cwe_tree[cwe_id]["cwe_paths"], key=len)
    return len(min_path)
