import os
import json

from typing import *

from agent_app.commit.commit_util import (
    CombineInfo,
    parse_commit_content, get_code_before_commit,
    init_comb_info_for_del_file, init_comb_info_for_add_file,
    analyse_modified_file
)


class CommitInitError(Exception):
    pass


class CommitManager:
    def __init__(self, local_repo_dpath: str, commit_hash: str, raw_commit_content: str):
        ####################### Basic information #######################
        self.local_repo_dpath = local_repo_dpath
        self.commit_hash = commit_hash
        self.raw_commit_content = raw_commit_content

        ####################### Information for all files involved #######################
        # (1) Record commit file number
        self.valid_file_num: int = 0

        # (2) Record commit file paths
        self.del_files: List[str] = []
        self.add_files: List[str] = []
        self.mod_files: List[str] = []

        # (3) Record commit file content info
        self.file_comb_info: Dict[str, CombineInfo] = {}

        ####################### Information only for modified files #######################
        # file_path -> diff context (includes imports, class signatures and function signatures)
        self.file_diff_context: Dict[str, str] = {}

        ####################### Update #######################
        try:
            self._update()
        except Exception as e:
            raise e


    """ UPDATE """


    def _update(self) -> None:
        commit_info = parse_commit_content(self.raw_commit_content)

        if len(commit_info) == 0:
            raise CommitInitError()

        for diff_file_info in commit_info:
            file_type = diff_file_info["file_type"]

            if file_type == "added":
                self._update_with_added_file(diff_file_info)
            elif file_type == "removed":
                self._update_with_deleted_file(diff_file_info)
            else:
                self._update_with_modified_file(diff_file_info)


    def _update_with_modified_file(self, diff_file_info: Dict) -> None:
        parent_commit = diff_file_info["parent_commit"]
        old_fpath = diff_file_info["old_fpath"]
        new_fpath = diff_file_info["new_fpath"]

        # TODO: For now, we do not consider commits that contain files with both: 1) changed path 2) changed content.
        if old_fpath != new_fpath:
            with open("/root/projects/VDTest/output/agent/rename_file.txt", "a") as f:
                repo = self.local_repo_dpath.split("/")[-1].replace("_", "/")
                f.write(f"url: https://github.com/{repo}/commit/{self.commit_hash}\n"
                        f"old_fpath: {old_fpath}, new_fpath: {new_fpath}\n\n")
            raise CommitInitError("The file path has changed")
        fpath = old_fpath

        old_ori_code = get_code_before_commit(self.local_repo_dpath, self.commit_hash, old_fpath, parent_commit)
        abs_new_fpath = os.path.join(self.local_repo_dpath, new_fpath)
        with open(abs_new_fpath, "r") as f:
            new_ori_code = f.read()

        res = analyse_modified_file(old_ori_code, new_ori_code, diff_file_info)

        if res is not None:
            self.valid_file_num += 1

            comb_info, diff_context = res

            ## (1) File path
            assert fpath is not None
            self.mod_files.append(fpath)

            ## (2) File content
            self.file_comb_info[fpath] = comb_info

            ## (5) Diff context (used to prepare init commit prompt)
            self.file_diff_context[fpath] = diff_context


    def _update_with_added_file(self, diff_file_info: Dict) -> None:
        new_fpath = diff_file_info["new_fpath"]

        self.valid_file_num += 1

        ## (1) File path
        assert new_fpath is not None
        self.add_files.append(new_fpath)

        ## (2) File content (original, combined)
        abs_new_fpath = os.path.join(self.local_repo_dpath, new_fpath)
        with open(abs_new_fpath, "r") as f:
            ori_code = f.read()
        comb_code_lines = diff_file_info["code_diff"][0]["diff_code_snippet"]
        assert len(ori_code.splitlines()) == len(comb_code_lines)

        comb_info = init_comb_info_for_add_file(ori_code, '\n'.join(comb_code_lines))

        self.file_comb_info[new_fpath] = comb_info


    def _update_with_deleted_file(self, diff_file_info: Dict) -> None:
        parent_commit = diff_file_info["parent_commit"]
        old_fpath = diff_file_info["old_fpath"]

        self.valid_file_num += 1

        ## (1) File path
        assert old_fpath is not None
        self.del_files.append(old_fpath)

        ## (2) File content (original, combined)
        ori_code = get_code_before_commit(self.local_repo_dpath, self.commit_hash, old_fpath, parent_commit)
        comb_code_lines = diff_file_info["code_diff"][0]["diff_code_snippet"]
        assert len(ori_code.splitlines()) == len(comb_code_lines)

        comb_info = init_comb_info_for_del_file(ori_code, '\n'.join(comb_code_lines))

        self.file_comb_info[old_fpath] = comb_info


    """ Convert files information to seq """


    def describe_commit_files(self) -> str:
        add_file_descs: Dict[str, str] = {}
        for fname in self.add_files:
            add_file_descs[fname] = self._add_file_info_desc(fname)

        del_file_descs: Dict[str, str] = {}
        for fname in self.del_files:
            del_file_descs[fname] = self._del_file_info_desc(fname)

        mod_file_descs: Dict[str, str] = {}
        for fname in self.mod_files:
            mod_file_descs[fname] = self._mod_file_info_desc(fname)

        file_num = 0
        commit_desc = ""
        if len(add_file_descs) > 0:
            commit_desc += "## ADD files:"
            for fname, file_desc in add_file_descs.items():
                file_num += 1
                commit_desc += (f"\n\n# File {file_num}: {fname}"
                                f"\n{file_desc}")

            commit_desc += "\n\n"

        if len(del_file_descs) > 0:
            commit_desc += "## DELETE files:"
            for fname, file_desc in del_file_descs.items():
                file_num += 1
                commit_desc += (f"\n\n# File {file_num}: {fname}"
                                f"\n{file_desc}")

            commit_desc += "\n\n"

        if len(mod_file_descs) > 0:
            commit_desc += "## MODIFY files:"
            for fname, file_desc in mod_file_descs.items():
                file_num += 1
                commit_desc += (f"\n\n# File {file_num}: {fname}"
                                f"\n{file_desc}")

        commit_desc = commit_desc.strip()
        commit_desc = f"<commit>\n{commit_desc}\n</commit>"

        return commit_desc


    def _mod_file_info_desc(self, fpath: str) -> str | None:
        if fpath not in self.mod_files:
            return None

        diff_context = self.file_diff_context[fpath]
        file_desc = f"<code>\n{diff_context}\n</code>"

        return file_desc


    def _add_file_info_desc(self, fpath: str) -> str | None:
        if fpath not in self.add_files:
            return None

        # TODO: For files added in the commit, we just show its original file content
        code = self.file_comb_info[fpath].new_code
        assert code is not None

        file_desc = f"<code>\n{code}\n</code>"

        return file_desc


    def _del_file_info_desc(self, fpath: str) -> str | None:
        if fpath not in self.del_files:
            return None

        # TODO: For files deleted in the commit, we just show its original file content
        code = self.file_comb_info[fpath].old_code
        assert code is not None

        file_desc = f"<code>\n{code}\n</code>"

        return file_desc


    """ Find related code """


    def find_related_code(self, locations: Dict):
        # FIXME
        pass


    def _find_diff_line(self, fpath: str, line: str, source: str | None = None):
        # FIXME
        pass

