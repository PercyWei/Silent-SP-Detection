# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/raw_tasks.py

from __future__ import annotations

import os
import json
from abc import ABC, abstractmethod

from typing import *

from agent_app.task import Task
from agent_app.util import cd, get_head_commit_hash, get_commit_content, clone_repo


class RawTask(ABC):
    @property
    @abstractmethod
    def task_id(self) -> str:
        raise NotImplementedError("abstract base class")

    @abstractmethod
    def to_task(self) -> Task:
        raise NotImplementedError("abstract base class")

    @abstractmethod
    def dump_meta_data(self, output_dir: str, other_info) -> None:
        raise NotImplementedError("abstract base class")


class RawLocalTask(RawTask):
    """
    Encapsulate everything required to run ACR on a local repo cloned from GitHub.
    """
    def __init__(
            self,
            task_id: str,
            commit_type: int,
            cwe_list: List[str],
            repo_name: str,
            commit_hash: str,
            local_repo_dpath: str
    ):
        self.valid = True

        self._task_id = task_id
        # target
        self.commit_type = commit_type
        self.cwe_list = cwe_list
        # source
        self.repo_name = repo_name
        self.commit_hash = commit_hash
        self.local_repo_dpath = local_repo_dpath

        # I. Prepare local repo
        res = self.prepare_local_repo()
        if not res:
            self.valid = False
            return

        # II. Get HEAD commit hash for repo reset
        self.head_commit_hash = get_head_commit_hash(local_repo_dpath)
        if self.head_commit_hash is None:
            self.valid = False
            return

        # III. Extract raw commit content
        self.commit_content = self.read_raw_commit_content_from_git_log()
        if self.commit_content is None:
            self.valid = False
            return

    @property
    def task_id(self) -> str:
        return self._task_id

    def prepare_local_repo(self) -> bool:
        if not os.path.exists(self.local_repo_dpath):
            res = clone_repo(self.repo_name, self.local_repo_dpath)
            return res
        return True

    def read_raw_commit_content_from_git_log(self) -> str:
        commit_content = get_commit_content(self.commit_hash, self.local_repo_dpath)
        return commit_content

    def dump_meta_data(self, output_dpath: str, other_info: Dict) -> None:
        meta = {
            "task_info": {
                "commit_type": self.commit_type,
                "cwe_list": self.cwe_list,
                "instance_id": self.task_id,
                "repo": self.repo_name,
                "commit_hash": self.commit_hash,
                "commit_content": self.commit_content
            },
            "setup_info": {
                "repo_path": self.local_repo_dpath,
                "head_commit_hash": self.head_commit_hash
            }
        }
        meta.update(other_info)

        meta_file = os.path.join(output_dpath, "meta.json")
        with open(meta_file, "w") as f:
            json.dump(meta, f, indent=4)

    def to_task(self) -> Task:
        return Task(
            repo_name=self.repo_name,
            commit_hash=self.commit_hash,
            commit_content=self.commit_content,
            commit_type=self.commit_type,
            cwe_list=self.cwe_list,
            local_repo_dpath=self.local_repo_dpath,
            head_commit_hash=self.head_commit_hash
        )
