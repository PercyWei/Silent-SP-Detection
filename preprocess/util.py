import os
import re
import shutil
import subprocess
from typing import *

from utils import run_command
from preprocess.log import cprint

from typing import *


def make_hie_dirs(root: str, *dirs: str) -> str:
    """Make hierarchical directories recursively."""
    new_dpath = os.path.join(root, *dirs)
    if not os.path.exists(new_dpath):
        os.makedirs(new_dpath, exist_ok=True)

    return new_dpath


def clone_repo(auth_repo: str, repo_dpath: str, timeout: int = 30, token: str = '') -> Optional[bool]:
    """
    Clone a GitHub repository to local.

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


def checkout_commit(repo_dpath: str, commit_id: str, revert: bool = True) -> bool:
    """
    Args:
        repo_dpath (str): Path to the local dir for saving this repo.
        commit_id (str): Commit id/hash.
        revert (bool): Whether to revert the state after checkout.

    Returns:
        bool:
            True: commit checkout succeed.
            False: commit checkout failed.
    """
    cprint(f"Checkout Commit - Repo: {repo_dpath.split('/')[-1]}, commit id: {commit_id}")

    # Checkout to the specified commit
    checkout_command = ['git', 'checkout', commit_id]
    _, error_msg = run_command(checkout_command, cwd=repo_dpath)

    if error_msg:
        cprint("Checkout Result: False", style='red')
        return False

    cprint("Checkout Result: True", style='green')
    # Revert to the previous state if necessary
    if revert:
        cprint('Revert state ...')
        revert_command = ['git', 'checkout', '-']
        stdout, stderr = run_command(revert_command, cwd=repo_dpath)

        if stderr:
            cprint('Failed!', style='red')
        cprint('Done!', style='green')

    return True

