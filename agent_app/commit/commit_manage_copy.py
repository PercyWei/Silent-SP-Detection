import os

from typing import *
from collections import namedtuple

from agent_app.commit.commit_util import (
    extract_commit_content_info,
    get_code_before_commit,
    filter_blank_and_comment_in_code, filter_blank_lines_in_commit,
    SourceFileType,
    ContIndStructType, ContIndClassType, ContIndType,
    DiffStructType, DiffClassType, DiffType,
    analyse_diff_within_file
)
from agent_app.static_analysis.parse import LocationType, Location

# - id: int
# - source: FileType
# - code: str
DiffLine = namedtuple("DiffLine", ["id", "source", "code"])

################### For grouping continous lines in the same struct into the same group ###################
## For struct Global, Function, ClassGlobal and ClassFunction
# - struct_type: LocationType
# - struct_name: str
# - all_lines: List[List[DiffLine]]
ContLineStructType = namedtuple("ContLineStructType", ["struct_type", "struct_name", "all_lines"])
## For struct Class
# - struct_type: LocationType
# - struct_name: str
# - children: List[ContLineStructType]
ContLineClassType = namedtuple("ContLineClassType", ["struct_type", "struct_name", "children"])
## For top level items of root (Global, Function, Class)
ContLineType = ContLineStructType | ContLineClassType


class CommitInitError(Exception):
    pass


class CommitManager:
    def __init__(self, local_repo_dpath: str, commit_hash: str, raw_commit_content: str):
        ####################### Basic information #######################
        self.local_repo_dpath = local_repo_dpath
        self.commit_hash = commit_hash
        self.raw_commit_content = raw_commit_content

        ####################### Information for all files involved #######################
        self.valid_files_num: int = 0

        self.del_files: List[str] = []
        self.add_files: List[str] = []
        # file after -> file before
        self.mod_files: Dict[str, str] = {}

        ## NOTE: We filter blank lines in these files
        # file_name (name of file before commit) -> file_code
        self.code_before: Dict[str, str] = {}
        # file_name (name of file after commit) -> file_code
        self.code_after: Dict[str, str] = {}

        ####################### Information only for modified files #######################
        # Full code in the diff struct (Global / Class / Function)
        #   key: file_name (new) -> value: different diff structs (List)
        #                        -> element: a diff struct with full code
        self.code_diff: Dict[str, List[DiffType]] = {}
        # Continuous code lines in the same struct (Global / Class / Function)
        #   key: file_name (new) -> value: different diff structs (List)
        #                        -> element: a struct group with continuous lines
        self.cont_diff_lines: Dict[str, List[ContLineType]] = {}

        ####################### Update #######################
        try:
            self._update()
        except Exception as e:
            raise e

    """ Update """

    def _update(self) -> None:
        commit_info = extract_commit_content_info(self.raw_commit_content)

        if len(commit_info) == 0:
            raise CommitInitError

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

        ## (1)
        assert old_fpath is not None and new_fpath is not None and new_fpath not in self.mod_files
        # NOTE: For modified file, key is the name of file after, value is the name of file before
        self.mod_files[new_fpath] = old_fpath

        ## (2)
        old_file_content = get_code_before_commit(self.local_repo_dpath, self.commit_hash, old_fpath)
        nb_old_file_content, old_line_id_lookup = filter_blank_and_comment_in_code(old_file_content)
        self.code_before[old_fpath] = nb_old_file_content

        abs_new_fpath = os.path.join(self.local_repo_dpath, new_fpath)
        with open(abs_new_fpath, "r") as f:
            new_file_content = f.read()
        nb_new_file_content, new_line_id_lookup = filter_blank_and_comment_in_code(new_file_content)
        self.code_after[new_fpath] = nb_new_file_content

        ## (3) and (4)
        del_line_index2id, add_line_index2id, nb_diff_code_snippet = \
            filter_blank_lines_in_commit(diff_file_info, old_line_id_lookup, new_line_id_lookup)


        # file_before = f"/root/projects/VDTest/output/dataset/{old_fpath.replace('/', '_')}_before.json"
        # with open(file_before, "w") as f:
        #     f.write(old_file_content)
        #
        # file_before = f"/root/projects/VDTest/output/dataset/{old_fpath.replace('/', '_')}_nb_before.json"
        # with open(file_before, "w") as f:
        #     f.write(nb_old_file_content)
        #
        # file_after = f"/root/projects/VDTest/output/dataset/{new_fpath.replace('/', '_')}_after.json"
        # with open(file_after, "w") as f:
        #     f.write(new_file_content)
        #
        # file_after = f"/root/projects/VDTest/output/dataset/{new_fpath.replace('/', '_')}_nb_after.json"
        # with open(file_after, "w") as f:
        #     f.write(nb_new_file_content)


        cont_ind_items, diff_structs = analyse_diff_within_file(
            old_file_content=nb_old_file_content,
            new_file_content=nb_new_file_content,
            del_line_index2id=del_line_index2id,
            add_line_index2id=add_line_index2id,
            diff_code_snippet=nb_diff_code_snippet
        )

        ################################### Inner Function ###################################

        def _process_cont_ind_struct(_cont_ind_struct: ContIndStructType) -> ContLineStructType:
            _struct_type: LocationType = _cont_ind_struct.struct_type
            _struct_name: str = _cont_ind_struct.struct_name
            _all_cont_indexes: List[List[int]] = _cont_ind_struct.all_indexes

            _struct_cont_diff_lines: List[List[DiffLine]] = []
            for _cont_indexes in _all_cont_indexes:
                _cont_diff_lines: List[DiffLine] = []

                for _ind in _cont_indexes:
                    _diff_line: DiffLine | None = None

                    if _ind in del_line_index2id:
                        _diff_line = DiffLine(
                            id=del_line_index2id[_ind],
                            source=SourceFileType.OLD,
                            code=nb_diff_code_snippet[_ind]
                        )
                    elif _ind in add_line_index2id:
                        _diff_line = DiffLine(
                            id=add_line_index2id[_ind],
                            source=SourceFileType.NEW,
                            code=nb_diff_code_snippet[_ind]
                        )

                    assert _diff_line is not None
                    _cont_diff_lines.append(_diff_line)

                _struct_cont_diff_lines.append(_cont_diff_lines)

            _cont_line_struct = ContLineStructType(
                struct_type=_struct_type,
                struct_name=_struct_name,
                all_lines=_struct_cont_diff_lines
            )

            return _cont_line_struct

        def _process_cont_ind_class(_cont_ind_class: ContIndClassType) -> ContLineClassType:
            _class_type: LocationType = _cont_ind_class.struct_type
            _class_name: str = _cont_ind_class.struct_name
            _cont_ind_children: List[ContIndStructType] = _cont_ind_class.children

            _cont_line_children: List[ContLineStructType] = []
            for _cont_ind_child in _cont_ind_children:
                _cont_line_child = _process_cont_ind_struct(_cont_ind_child)
                _cont_line_children.append(_cont_line_child)

            _cont_line_class = ContLineClassType(
                struct_type=_class_type,
                struct_name=_class_name,
                children=_cont_line_children
            )

            return _cont_line_class

        ################################### Inner Function ###################################

        file_cont_line_items: List[ContLineType] = []
        for cont_ind_item in cont_ind_items:
            if isinstance(cont_ind_item, ContIndClassType):
                cont_line_class = _process_cont_ind_class(cont_ind_item)
                file_cont_line_items.append(cont_line_class)
            else:
                assert isinstance(cont_ind_item, ContIndStructType)
                cont_line_struct = _process_cont_ind_struct(cont_ind_item)
                file_cont_line_items.append(cont_line_struct)

        if len(file_cont_line_items) != 0 and len(diff_structs) != 0:
            self.valid_files_num += 1
            # NOTE: For modified file, key is the name of file after
            self.cont_diff_lines[new_fpath] = file_cont_line_items
            # NOTE: For modified file, key is the name of file after
            self.code_diff[new_fpath] = diff_structs
        else:
            # FIXME: test, delete later
            with open("/root/projects/VDTest/output/agent/log.json", "a") as f:
                f.write(f"Commit: {self.commit_hash}\nFile {new_fpath}\n")

    def _update_with_added_file(self, diff_file_info: Dict) -> None:
        new_fpath = diff_file_info["new_fpath"]

        self.valid_files_num += 1

        # (1)
        assert new_fpath is not None
        self.add_files.append(new_fpath)

        # (2)
        abs_new_fpath = os.path.join(self.local_repo_dpath, new_fpath)
        with open(abs_new_fpath, "r") as f:
            new_file_content = f.read()
        nb_new_file_content, new_line_id_lookup = filter_blank_and_comment_in_code(new_file_content)
        self.code_after[new_fpath] = nb_new_file_content

    def _update_with_deleted_file(self, diff_file_info: Dict) -> None:
        old_fpath = diff_file_info["old_fpath"]

        self.valid_files_num += 1

        # (1)
        assert old_fpath is not None
        self.del_files.append(old_fpath)

        # (2)
        old_file_content = get_code_before_commit(self.local_repo_dpath, self.commit_hash, old_fpath)
        nb_old_file_content, old_line_id_lookup = filter_blank_and_comment_in_code(old_file_content)
        self.code_before[old_fpath] = nb_old_file_content

    """ Convert files information to seq """

    def commit_files_info_seq(self) -> str:
        add_file_seqs: List[str] = []
        for fname in self.add_files:
            add_file_seqs.append(self._add_file_info_seq(fname))

        del_file_seqs: List[str] = []
        for fname in self.del_files:
            del_file_seqs.append(self._del_file_info_seq(fname))

        mod_file_seqs: List[str] = []
        for fname_after in self.mod_files:
            mod_file_seqs.append(self._mod_file_info_seq(fname_after))

        file_num = 0
        commit_seq = ""
        if len(add_file_seqs) > 0:
            commit_seq += "## ADD files:\n"
            for file_seq in add_file_seqs:
                file_num += 1
                commit_seq += f"# File {file_num}\n"
                commit_seq += file_seq + "\n"

        if len(del_file_seqs) > 0:
            commit_seq += "## DELETE files:\n"
            for file_seq in del_file_seqs:
                file_num += 1
                commit_seq += f"# File {file_num}\n"
                commit_seq += file_seq + "\n"

        if len(mod_file_seqs) > 0:
            commit_seq += "## MODIFY files:\n"
            for file_seq in mod_file_seqs:
                file_num += 1
                commit_seq += f"# File {file_num}\n"
                commit_seq += file_seq + "\n"

        commit_seq = f"<commit>\n{commit_seq}</commit>\n"

        return commit_seq

    def _cont_line_struct_to_seq(self, cont_line_struct: ContLineStructType, class_prefix: str = "") -> str:
        """
        For struct Global, Function, ClassGlobal or ClassFunction.
        """
        struct_type: LocationType = cont_line_struct.struct_type
        struct_name: str = cont_line_struct.struct_name
        all_cont_lines: List[List[DiffLine]] = cont_line_struct.all_lines

        global_types = (LocationType.UNIT, LocationType.CLASS_UNIT)
        func_types = (LocationType.FUNCTION, LocationType.CLASS_FUNCTION)
        support_types = global_types + func_types

        ## (1) Necessary checks
        assert struct_type in support_types
        if struct_type in global_types:
            assert len(all_cont_lines) == 1

        ## (2) Read all diff lines in this struct, and separate not continous lines with "..."
        code_part = ""
        for i, cont_lines in enumerate(all_cont_lines):
            for li in cont_lines:
                code_part += li.code + "\n"

            if i < len(all_cont_lines) - 1:
                code_part += "...\n"

        ## (3) Add prefix to indicate the struct type is "Global" or "Function"
        if struct_type in global_types:
            struct_prefix = f"<global></global>"
        else:
            struct_prefix = f"<func>{struct_name}</func>"

        struct_seq = f"{class_prefix}{struct_prefix}\n<code>\n{code_part}</code>\n"

        return struct_seq

    def _cont_line_class_to_seq(self, cont_line_class: ContLineClassType) -> str:
        class_type: LocationType = cont_line_class.struct_type
        class_name: str = cont_line_class.struct_name
        children: List[ContLineStructType] = cont_line_class.children

        ## (1) Necessary checks
        assert class_type == LocationType.CLASS

        ## (2) Read all children struct (ClassGlobal, ClassFunction) in this Class
        class_seq = ""
        for child in children:
            child_seq = self._cont_line_struct_to_seq(child, f"<class>{class_name}</class> ")
            class_seq += child_seq + "\n"

        return class_seq

    def _mod_file_info_seq(self, fpath: str) -> str | None:
        """
        For a modified file involved in the commit, return the sorted modified content.

        Args:
            fpath: Path of file after commit.
        Returns:
            str:
        """
        if fpath not in self.mod_files:
            return None

        file_cont_diff_lines = self.cont_diff_lines[fpath]

        items_seq = ""
        for cont_diff_line_item in file_cont_diff_lines:
            if isinstance(cont_diff_line_item, ContLineStructType):
                items_seq += self._cont_line_struct_to_seq(cont_diff_line_item) + "\n"
            elif isinstance(cont_diff_line_item, ContLineClassType):
                items_seq += self._cont_line_class_to_seq(cont_diff_line_item) + "\n"
            else:
                raise RuntimeError

        fpath_before = self.mod_files[fpath]
        if fpath_before != fpath:
            file_seq = (f"<old_file>{fpath_before}</old_file>\n"
                        f"<new_file>{fpath}</new_file>\n\n"
                        f"{items_seq}")
        else:
            file_seq = (f"<file>{fpath}</file>\n\n"
                        f"{items_seq}")

        return file_seq

    def _add_file_info_seq(self, fpath: str) -> str | None:
        if fpath not in self.add_files:
            return None

        # TODO: For files added in the commit, we just show its original file content
        file_seq = self.code_after[fpath]
        if file_seq.splitlines()[-1].strip() != "":
            file_seq += "\n"

        file_seq += (f"<file>{fpath}</file>\n"
                     f"<code>\n"
                     f"{file_seq}"
                     f"</code>\n")

        return file_seq

    def _del_file_info_seq(self, fpath: str) -> str | None:
        if fpath not in self.del_files:
            return None

        # TODO: For files deleted in the commit, we just show its original file content
        file_seq = self.code_before[fpath]
        if file_seq.splitlines()[-1].strip() != "":
            file_seq += "\n"

        file_seq += (f"<file>{fpath}</file>\n"
                     f"<code>\n"
                     f"{file_seq}"
                     f"</code>\n")

        return file_seq

    """ Find related code """

    def find_mod_file_after_commit(self, fname: str) -> str | None:
        """file before -> file after"""
        for file_after, file_before in self.mod_files.items():
            if file_before == fname:
                return file_after
        return None

    def find_mod_file_before_commit(self, fname: str) -> str | None:
        """file after -> file before"""
        if fname in self.mod_files:
            return self.mod_files[fname]
        return None

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

