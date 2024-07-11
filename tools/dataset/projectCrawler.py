import json
import os
import subprocess
from typing import *

from old_utils.logging import start_with_logger


def crawl_cve_project_with_commit(auth_repo: str, cve_id: str, commit_id: str, repo_save_dpath: str, logger):
    cve_save_dpath = os.path.join(repo_save_dpath, cve_id)
    if os.path.exists(cve_save_dpath):
        logger.info(f"{cve_id} already exists.")
        return
    else:
        os.makedirs(cve_save_dpath, exist_ok=True)

    repo_git = "https://github.com/" + auth_repo + ".git"
    command = ["git", "clone", repo_git]

    result = subprocess.run(command, cwd=cve_save_dpath, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)




def crawl_TreeVul_projects():
    logger = start_with_logger(__name__, log_fname="crawl_TreeVul_Projects")

