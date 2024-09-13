# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/task.py

from dataclasses import dataclass

from agent_app.util import cd, repo_checkout


@dataclass(kw_only=True)
class Task:
    """
    Tasks that only contain a codebase and a commit content.
    """
    # Base info
    repo_name: str
    commit_hash: str
    commit_content: str
    commit_type: int
    cwe_id: str
    # Setup info
    local_repo_dpath: str
    head_commit_hash: str

    @property
    def project_path(self) -> str:
        return self.local_repo_dpath

    def setup_project(self) -> None:
        with cd(self.project_path):
            repo_checkout(self.commit_hash)

    def reset_project(self) -> None:
        with cd(self.project_path):
            repo_checkout(self.head_commit_hash)
