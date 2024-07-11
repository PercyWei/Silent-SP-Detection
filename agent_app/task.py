# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/task.py

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from agent_app.util import cd, repo_reset_and_clean_checkout


class Task(ABC):
    @property
    @abstractmethod
    def project_path(self) -> str:
        raise NotImplementedError("abstract method")

    @property
    @abstractmethod
    def commit_id(self) -> str:
        raise NotImplementedError("abstract method")

    @abstractmethod
    def get_commit_content(self) -> str:
        raise NotImplementedError("abstract method")

    @abstractmethod
    def setup_project(self) -> None:
        """Set up the project before starting to resolve the task."""
        raise NotImplementedError("abstract method")

    @abstractmethod
    def reset_project(self) -> None:
        """Reset project to initial state."""
        raise NotImplementedError("abstract method")


@dataclass(kw_only=True)
class PlainTask(Task):
    """
    Tasks that only contain a codebase and a commit content.
    """
    repo_name: str
    commit_hash: str
    local_repo_dpath: str
    commit_content: str

    @property
    def project_path(self) -> str:
        return self.local_repo_dpath

    @property
    def commit_id(self) -> str:
        return self.commit_hash

    def get_commit_content(self) -> str:
        return self.commit_content

    def setup_project(self) -> None:
        with cd(self.project_path):
            repo_reset_and_clean_checkout(self.commit_hash)

    def reset_project(self) -> None:
        with cd(self.project_path):
            repo_reset_and_clean_checkout(self.commit_hash)
