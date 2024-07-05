# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: app/raw_tasks.py

import os
import json
from abc import ABC, abstractmethod

from app.task import Task, PlainTask
from app.utils import cd, get_commit_content


class RawTask(ABC):
    @property
    @abstractmethod
    def task_id(self) -> str:
        raise NotImplementedError("abstract base class")

    @abstractmethod
    def to_task(self) -> Task:
        raise NotImplementedError("abstract base class")

    @abstractmethod
    def dump_meta_data(self, output_dir: str) -> None:
        raise NotImplementedError("abstract base class")


class RawLocalTask(RawTask):
    """
    Encapsulate everything required to run ACR on a local repo cloned from GitHub.
    """

    def __init__(self, task_id: str, repo_name: str, local_repo_dpath: str, commit_hash: str):
        self._task_id = task_id
        self.repo_name = repo_name
        self.local_repo_dpath = local_repo_dpath
        self.commit_hash = commit_hash
        self.commit_content = self.read_commit_content_from_git_log()

    @property
    def task_id(self) -> str:
        return self._task_id

    def read_commit_content_from_git_log(self) -> str:
        with cd(self.local_repo_dpath):
            commit_content = get_commit_content(self.commit_hash)
        return commit_content

    def dump_meta_data(self, output_dpath: str):
        meta = {
            "task_info": {
                "base_commit": self.commit_hash,
                "commit_content": self.commit_content,
                "instance_id": self.task_id,
            },
            "setup_info": {"repo_path": self.local_repo_dpath},
        }

        meta_file = os.path.join(output_dpath, "meta.json")

        with open(meta_file, "w") as f:
            json.dump(meta, f, indent=4)

    def to_task(self) -> PlainTask:
        return PlainTask(
            repo_name=self.repo_name,
            commit_hash=self.commit_hash,
            local_repo_dpath=self.local_repo_dpath,
            commit_content=self.commit_content,
        )


