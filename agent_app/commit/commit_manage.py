import os

from typing import *

from agent_app.commit.commit_util import (
    SourceFileType,
    CombineInfo, DiffCodeSnippet,
    extract_commit_content_info, get_code_before_commit,
    build_struct_indexes_from_common_code, analyse_modified_file
)
from utils import LineRange


class CommitInitError(Exception):
    pass


class CommitManager:
    def __init__(self, local_repo_dpath: str, commit_hash: str, raw_commit_content: str):
        ####################### Basic information #######################
        self.local_repo_dpath = local_repo_dpath
        self.commit_hash = commit_hash
        self.raw_commit_content = raw_commit_content

        ####################### Information for all files involved #######################
        ######## (1) Record commit file number ########
        self.valid_files_num: int = 0

        ######## (2) Record commit file paths ########
        self.del_files: List[str] = []
        self.add_files: List[str] = []
        self.mod_files: List[str] = []

        ######## (3) Record commit file content ########
        # NOTE: We remain the same, and do not add '-'
        self.code_before: Dict[str, str] = {}  # file_path (before commit) -> file_code
        # NOTE: We remain the same, and do not add '+'
        self.code_after: Dict[str, str] = {}   # file_path (after commit) -> file_code
        # NOTE: We filter out blank lines and comment lines
        self.code_comb: Dict[str, str] = {}    # file_path (before / after commit) -> file_code

        ######## (4) Record line id lookup dict ########
        self.line_id_before2comb: Dict[str, Dict[int, int]] = {}  # code_before -> code_comb
        self.line_id_after2comb: Dict[str, Dict[int, int]] = {}   # code_after  -> code_comb

        ######## (5) Record structs in combined code ########
        # file_path -> [(func_name, func_range)]
        self.file_func_index: Dict[str, List[Tuple[str, LineRange]]] = {}
        # file_path -> [(class_name, class_range)]
        self.file_class_index: Dict[str, List[Tuple[str, LineRange]]] = {}
        # file_path -> [(class_name -> [(classFunc_name, classFunc_range)])]
        self.file_classFunc_index: Dict[str, List[Tuple[str, List[Tuple[str, LineRange]]]]] = {}

        ####################### Information only for modified files #######################
        # file_path -> [diff code snippet]
        self.files_diff_code_snips: Dict[str, List[DiffCodeSnippet]] = {}

        ####################### Update #######################
        try:
            self._update()
        except Exception as e:
            raise e

    """ UPDATE """

    def _update(self) -> None:
        commit_info = extract_commit_content_info(self.raw_commit_content)

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
        old_fpath = diff_file_info["old_fpath"]
        new_fpath = diff_file_info["new_fpath"]

        if old_fpath != new_fpath:
            with open("/root/projects/VDTest/output/agent/rename_file.txt", "a") as f:
                repo = self.local_repo_dpath.split("/")[-1].replace("_", "/")
                f.write(f"url: https://github.com/{repo}/commit/{self.commit_hash}\n"
                        f"old_fpath: {old_fpath}, new_fpath: {new_fpath}\n\n")
            raise CommitInitError("The file path has changed")

        fpath = old_fpath

        old_ori_content = get_code_before_commit(self.local_repo_dpath, self.commit_hash, old_fpath)
        abs_new_fpath = os.path.join(self.local_repo_dpath, new_fpath)
        with open(abs_new_fpath, "r") as f:
            new_ori_content = f.read()

        comb_info, diff_code_snips, comb_funcs, comb_classes, comb_classesFuncs = \
            analyse_modified_file(fpath, old_ori_content, new_ori_content, diff_file_info)

        if len(diff_code_snips) != 0:
            self.valid_files_num += 1

            ## (1) File path
            assert fpath is not None
            # NOTE: For modified file, key is the name of file after, value is the name of file before, same below
            self.mod_files.append(fpath)

            ## (2) File content (original, combined)
            self.code_before[fpath] = comb_info.code_before
            self.code_after[fpath] = comb_info.code_after
            self.code_comb[fpath] = comb_info.code_comb

            ## (3) All structs in combined code (used for searching)
            self.file_func_index[fpath] = comb_funcs
            self.file_class_index[fpath] = comb_classes
            self.file_classFunc_index[fpath] = comb_classesFuncs

            ## (4) Line id lookup (used for searching)
            self.line_id_before2comb[fpath] = comb_info.li_lookup_before2comb
            self.line_id_after2comb[fpath] = comb_info.li_lookup_after2comb

            ## (5) Diff lines (used to prepare init commit prompt)
            self.files_diff_code_snips[fpath] = diff_code_snips

        else:
            # TODO: For test, delete later.
            with open("/root/projects/VDTest/output/agent/log.json", "a") as f:
                repo = self.local_repo_dpath.split("/")[-1].replace("_", "/")
                f.write(f"url: https://github.com/{repo}/commit/{self.commit_hash}\n"
                        f"Empty file: {fpath}\n\n")

    def _update_with_added_file(self, diff_file_info: Dict) -> None:
        new_fpath = diff_file_info["new_fpath"]

        self.valid_files_num += 1

        ## (1) File path
        assert new_fpath is not None
        self.add_files.append(new_fpath)

        ## (2) File content (original, combined)
        abs_new_fpath = os.path.join(self.local_repo_dpath, new_fpath)
        with open(abs_new_fpath, "r") as f:
            new_ori_content = f.read()
        assert len(new_ori_content) == len(diff_file_info["code_diff"]["diff_code_snippet"])

        self.code_after[new_fpath] = new_ori_content
        self.code_comb[new_fpath] = diff_file_info["code_diff"]["diff_code_snippet"]

        ## (3) All structs in combined code (used to search in)
        funcs, classes, classes_funcs = build_struct_indexes_from_common_code(new_ori_content)
        self.file_func_index[new_fpath] = funcs
        self.file_class_index[new_fpath] = classes
        self.file_classFunc_index[new_fpath] = classes_funcs

        ## (4) Line id lookup (used for searching)
        self.line_id_after2comb[new_fpath] = {i + 1: i + 1 for i in range(len(new_ori_content))}

    def _update_with_deleted_file(self, diff_file_info: Dict) -> None:
        old_fpath = diff_file_info["old_fpath"]

        self.valid_files_num += 1

        ## (1) File path
        assert old_fpath is not None
        self.del_files.append(old_fpath)

        ## (2) File content (original, combined)
        old_ori_content = get_code_before_commit(self.local_repo_dpath, self.commit_hash, old_fpath)
        assert len(old_ori_content) == len(diff_file_info["code_diff"]["diff_code_snippet"])

        self.code_before[old_fpath] = old_ori_content
        self.code_comb[old_fpath] = diff_file_info["code_diff"]["diff_code_snippet"]

        ## (3) All structs in combined code (used to search in)
        funcs, classes, classes_funcs = build_struct_indexes_from_common_code(old_ori_content)
        self.file_func_index[old_fpath] = funcs
        self.file_class_index[old_fpath] = classes
        self.file_classFunc_index[old_fpath] = classes_funcs

        ## (4) Line id lookup (used for searching)
        self.line_id_before2comb[old_fpath] = {i + 1: i + 1 for i in range(len(old_ori_content))}

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
            commit_desc += "## ADD files:\n"
            for fname, file_desc in add_file_descs.items():
                file_num += 1
                commit_desc += f"# File {file_num}: {fname}\n"
                commit_desc += file_desc + "\n"

        if len(del_file_descs) > 0:
            commit_desc += "## DELETE files:\n"
            for fname, file_desc in del_file_descs.items():
                file_num += 1
                commit_desc += f"# File {file_num}: {fname}\n"
                commit_desc += file_desc + "\n"

        if len(mod_file_descs) > 0:
            commit_desc += "## MODIFY files:\n"
            for fname, file_desc in mod_file_descs.items():
                file_num += 1
                commit_desc += f"# File {file_num}: {fname}\n"
                commit_desc += file_desc + "\n"

        commit_desc = f"<commit>\n{commit_desc}</commit>"

        return commit_desc

    def _mod_file_info_desc(self, fpath: str) -> str | None:
        """
        For a modified file involved in the commit, return the sorted modified content.

        Args:
            fpath: File path after commit.
        Returns:
            str:
        """
        if fpath not in self.mod_files:
            return None

        file_diff_desc = ""
        for diff_code_snip in self.files_diff_code_snips[fpath]:
            diff_code_str = diff_code_snip.get_only_diff_code()

            prefix = ""
            if diff_code_snip.class_name is not None:
                prefix += "<class>" + diff_code_snip.class_name + "</class> "
            if diff_code_snip.func_name is not None:
                prefix += "<func>" + diff_code_snip.func_name + "</func>"

            file_diff_desc += f"{prefix}\n<code>\n{diff_code_str}\n</code>\n\n"

        return file_diff_desc

    def _add_file_info_desc(self, fpath: str) -> str | None:
        if fpath not in self.add_files:
            return None

        # TODO: For files added in the commit, we just show its original file content
        file_seq = self.code_after[fpath]
        if file_seq.splitlines()[-1].strip() != "":
            file_seq += "\n"

        file_seq += (f"\n<code>"
                     f"\n{file_seq}"
                     f"\n</code>")

        return file_seq

    def _del_file_info_desc(self, fpath: str) -> str | None:
        if fpath not in self.del_files:
            return None

        # TODO: For files deleted in the commit, we just show its original file content
        file_seq = self.code_before[fpath]
        if file_seq.splitlines()[-1].strip() != "":
            file_seq += "\n"

        file_seq += (f"\n<code>"
                     f"\n{file_seq}"
                     f"\n</code>")

        return file_seq

    """ Find related code """

    def find_related_code(self, locations: Dict):
        """

        Args:
            locations (Dict): Generated by Proxy Agent
        """
        for loc in locations:
            fpath = loc["file"]
            code_snippet = loc["code"]
            class_name = loc["class"] if "class" in loc else None
            func_name = loc["func"] if "func" in loc else None

            if fpath in self.del_files:
                # FIXME
                pass

            if fpath in self.add_files:
                # FIXME
                pass

            if fpath in self.mod_files or fpath in list(self.mod_files.values()):
                full_code_snippet = []

                lines = code_snippet.split("\n")
                for line in lines:
                    if line.startswith("-"):
                        source = SourceFileType.OLD
                    elif line.startswith("+"):
                        source = SourceFileType.NEW
                    else:
                        source = None

    def _find_diff_line(self, fpath: str, line: str, source: str | None = None):
        # FIXME
        pass

