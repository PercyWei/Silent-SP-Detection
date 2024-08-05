# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/task.py

from abc import ABC, abstractmethod
from dataclasses import dataclass

from agent_app.util import cd, repo_reset_and_clean_checkout, repo_checkout


@dataclass(kw_only=True)
class Task:
    """
    Tasks that only contain a codebase and a commit content.
    """
    repo_name: str
    commit_hash: str
    head_commit_hash: str
    local_repo_dpath: str
    commit_content: str
    cwe_id: str

    @property
    def project_path(self) -> str:
        return self.local_repo_dpath

    def setup_project(self) -> None:
        with cd(self.project_path):
            repo_checkout(self.commit_hash)

    def reset_project(self) -> None:
        with cd(self.project_path):
            repo_checkout(self.head_commit_hash)
