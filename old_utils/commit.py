import os
import re
import shutil
import subprocess
from typing import *

from old_utils.utils import execute_command


def clone_repo(logger, auth_repo: str, repo_dpath: str, timeout: int = 30, token: str = '') -> Optional[bool]:
    """
        Clone GitHub repository to local.

        Args:
        logger:
        auth:
        repo:
        repo_dpath: local repo path

        Returns:
            True: Clone successful.
            False: Clone failed.
            None: Repo not found.
    """
    logger.info(">>> Start cloning ...")
    logger.info(f">>> Repo name: {auth_repo}.")

    not_found_flag = False

    repo_url = f"https://{token}@github.com/{auth_repo}.git"
    clone_command = ["git", "clone", repo_url, repo_dpath]
    stdout, stderr = execute_command(clone_command, timeout=timeout)

    if stderr:
        if "repository not found" in stderr.lower():
            error_msg = "Repository not found."
            not_found_flag = True
        elif "time out" in stderr.lower():
            error_msg = "Timed out."
        else:
            error_msg = "Other error."
        logger.error(f"Clone failed! Reason: {error_msg}.")

        try:
            logger.info("Deleting cloned repo dir ...")
            shutil.rmtree(repo_dpath)
        except Exception as e:
            logger.warning("Deleting dir failed!")

        if not not_found_flag:
            return False
        else:
            return None
    else:
        logger.info("Clone successful.")
        return True


def checkout_commit(logger, repo_dpath: str, commit_id: str, revert: bool = True) -> bool:
    """
        Args:
        logger:
        repo_dpath:
        commit_id:
        revert: whether to revert the state after checkout.

        Returns:
             True: commit checkout succeed.
             False: commit checkout failed.
    """
    logger.info(">>> Checkout Commit ...")
    logger.info(f">>> Repo dpath: {repo_dpath}, commit id: {commit_id}.")

    # Checkout to the specified commit
    checkout_command = ['git', 'checkout', commit_id]
    stdout, stderr = execute_command(checkout_command, cwd=repo_dpath)

    if stderr:
        return False

    # Revert to the previous state if necessary
    if revert:
        logger.info('Revert state ...')
        revert_command = ['git', 'checkout', '-']
        stdout, stderr = execute_command(revert_command, cwd=repo_dpath)

        if stderr:
            logger.warning(f'Revert state failed!')

    return True
