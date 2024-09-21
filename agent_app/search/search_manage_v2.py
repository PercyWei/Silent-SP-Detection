# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_manage.py
import os
import re
import pathlib
import chardet

from typing import *
from collections import defaultdict
from collections.abc import MutableMapping

from agent_app.search import search_util_v2
from agent_app.search.search_util_v2 import SearchResult
from agent_app.data_structures import (
    LineRange, CodeRange, CombineInfo,
    SearchStatus
)


FuncIndexType = MutableMapping[str, List[CodeRange]]
ClassIndexType = MutableMapping[str, List[CodeRange]]
ClassFuncIndexType = MutableMapping[str, MutableMapping[str, List[CodeRange]]]

FileImportLibType = MutableMapping[str, List[Tuple[str, str, str]]]


RESULT_SHOW_LIMIT = 3


class SearchManager:
    def __init__(self, local_repo_dpath: str, commit_files: Dict, file_comb_info: Dict[str, CombineInfo]):
        ## NOTE: All paths that appear below are RELATIVE paths (relative to repo root)

        # -------------------------------- Basic Info -------------------------------- #
        self.local_repo_dpath = local_repo_dpath
        self.parsed_files: List[str] = []
        self.parsed_failed_files: List[str] = []

        # -------------------------------- Commit Files Info -------------------------------- #
        ## (1) File paths
        self.diff_files: List[str] = []
        self.del_files: List[str] = []
        self.add_files: List[str] = []
        self.mod_files: List[str] = []

        ## (2) File contents
        self.old_code: Dict[str, str] = {}   # file path -> file content before
        self.new_code: Dict[str, str] = {}   # file path -> file content after
        self.comb_code: Dict[str, str] = {}  # file path -> file content comb

        ## (3) Line id lookup
        self.line_id_old2new: Dict[str, Dict[int, int]] = {}   # file path -> {line id old -> line id new}
        self.line_id_old2comb: Dict[str, Dict[int, int]] = {}  # file path -> {line id old -> line id comb}
        self.line_id_new2comb: Dict[str, Dict[int, int]] = {}  # file path -> {line id new -> line id comb}

        ## (4) Struct indexes
        ## Record func / class / class func in old file
        # func name  -> [(file path, line range)]
        self.old_func_index: FuncIndexType = defaultdict(list)
        # class name -> [(file path, line range)]
        self.old_class_index: ClassIndexType = defaultdict(list)
        # class name -> {func name -> [(file path, line range)]}
        self.old_classFunc_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))

        ## Record func / class / class func in new file
        # func name  -> [(file path, line range)]
        self.new_func_index: FuncIndexType = defaultdict(list)
        # class name -> [(file path, line range)]
        self.new_class_index: ClassIndexType = defaultdict(list)
        # class name -> {func name -> [(file path, line range)]}
        self.new_classFunc_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))

        ## (5) Imported libraries
        # file path -> [(package path, attr name, alias name)]
        self.diff_file_import_libs: FileImportLibType = {}

        # -------------------------------- Unchanged Files Info -------------------------------- #
        ## (1) File paths
        self.nodiff_files: List[str] = []

        ## (2) Struct indexes
        # func_name -> [(file_name, line range)]
        self.nodiff_func_index: FuncIndexType = defaultdict(list)
        # class name -> [(file path, line range)]
        self.nodiff_class_index: ClassIndexType = defaultdict(list)
        # class name -> {func name -> [(file path, line range)]}
        self.nodiff_classFunc_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))

        ## (3) Imported libraries
        # file path -> [(package path, attr name, alias name)]
        self.nodiff_file_import_libs: FileImportLibType = {}

        # -------------------------------- Update -------------------------------- #
        self._update(commit_files, file_comb_info)


    """UPDATE"""


    def _update(self, commit_files: Dict, file_comb_info: Dict[str, CombineInfo]) -> None:
        # Step I: Update commit files info
        self._update_commit_file_info(commit_files, file_comb_info)

        # Step II: Update unchanged files info
        self._update_nodiff_file_info()

        # Step III: Summarize
        self.diff_files = self.del_files + self.add_files + self.mod_files
        self.parsed_files: List[str] = self.diff_files + self.nodiff_files


    def _update_commit_file_info(self, commit_files: Dict, file_comb_info: Dict[str, CombineInfo]) -> None:
        """For recording information of files involved in the commit.
        NOTE: Some information has been processed in the commit_manager.
        """
        ## (1) File paths
        self.del_files = commit_files['del_files']
        self.add_files = commit_files['add_files']
        self.mod_files = commit_files['mod_files']

        for fpath, comb_info in file_comb_info.items():
            ## (2) File contents
            if comb_info.old_code is not None:
                self.old_code[fpath] = comb_info.old_code
            if comb_info.new_code is not None:
                self.new_code[fpath] = comb_info.new_code
            self.comb_code[fpath] = comb_info.comb_code

            ## (3) Line id lookup
            # NOTE: Deleted and added files have no line id lookup
            if fpath in self.mod_files:
                self.line_id_old2new[fpath] = comb_info.line_id_old2new
                self.line_id_old2comb[fpath] = comb_info.line_id_old2comb
                self.line_id_new2comb[fpath] = comb_info.line_id_new2comb

            ## (4) Struct indexes
            # 4.1 Functions / Classes / Class functions in old file
            for func_name, func_range in comb_info.old_func_index:
                self.old_func_index[func_name].append(CodeRange(fpath, func_range))
            for class_name, class_range in comb_info.old_class_index:
                self.old_class_index[class_name].append(CodeRange(fpath, class_range))
            for class_name, classFuncs in comb_info.old_classFunc_index:
                for classFunc_name, classFunc_range in classFuncs:
                    self.old_classFunc_index[class_name][classFunc_name].append(CodeRange(fpath, classFunc_range))

            # 4.2 Functions / Classes / Class functions in new file
            for func_name, func_range in comb_info.new_func_index:
                self.new_func_index[func_name].append(CodeRange(fpath, func_range))
            for class_name, class_range in comb_info.new_class_index:
                self.new_class_index[class_name].append(CodeRange(fpath, class_range))
            for class_name, classFuncs in comb_info.new_classFunc_index:
                for classFunc_name, classFunc_range in classFuncs:
                    self.new_classFunc_index[class_name][classFunc_name].append(CodeRange(fpath, classFunc_range))

            ## (5) Imported libraries
            # 5.1 Imported libraries in old file
            if comb_info.old_code is not None:
                old_libs, *_ = search_util_v2.parse_python_code(comb_info.old_code)
            else:
                old_libs = []
            # 5.2 Imported libraries in new file
            if comb_info.new_code is not None:
                new_libs, *_ = search_util_v2.parse_python_code(comb_info.new_code)
            else:
                new_libs = []

            self.diff_file_import_libs[fpath] = list(set(old_libs + new_libs))


    def _update_nodiff_file_info(self) -> None:
        """For recording information of files unchanged in the commit."""
        abs_py_fpaths = search_util_v2.find_python_files(self.local_repo_dpath)

        for abs_py_fpath in abs_py_fpaths:
            rel_py_fpath = os.path.relpath(abs_py_fpath, self.local_repo_dpath)

            ## Step 1: Filter out diff files (in commit)
            if rel_py_fpath in self.del_files + self.add_files + self.mod_files:
                continue

            ## Step 2: Parse the code
            try:
                file_content = pathlib.Path(abs_py_fpath).read_text()
            except UnicodeDecodeError:
                try:
                    with open(abs_py_fpath, 'rb') as f:
                        result = chardet.detect(f.read())
                    encoding = result['encoding']
                    file_content = pathlib.Path(abs_py_fpath).read_text(encoding=encoding)
                except (UnicodeDecodeError, TypeError):
                    self.parsed_failed_files.append(rel_py_fpath)
                    continue

            struct_info = search_util_v2.parse_python_code(file_content)

            if struct_info is None:
                self.parsed_failed_files.append(rel_py_fpath)
                continue

            self.nodiff_files.append(rel_py_fpath)

            ## Step 3: Build search indexes
            libs, funcs, classes, class_to_funcs = struct_info

            # (1) Collect imported libs
            self.nodiff_file_import_libs[rel_py_fpath] = libs

            # (2) Build (top-level) function index and file function index
            for f, start, end in funcs:
                self.nodiff_func_index[f].append(CodeRange(rel_py_fpath, LineRange(start, end)))

            # (3) Build class index and file class index
            for c, start, end in classes:
                self.nodiff_class_index[c].append(CodeRange(rel_py_fpath, LineRange(start, end)))

            # (4) Build classFunction index and file classFunction index
            for c, class_funcs in class_to_funcs.items():
                for f, start, end in class_funcs:
                    self.nodiff_classFunc_index[c][f].append(CodeRange(rel_py_fpath, LineRange(start, end)))


    """GET CODE SNIPPET FUNCTIONS"""


    def _get_full_call(self, ori_call: str, fpath: str) -> str:
        """
        Prevent the following case:
            In code, a func is called like "... module.func(arg) ...", but the Agent only extract "func" for searching.
            So we need to complete the call like "module.func" to search.
        """
        if fpath in self.nodiff_files:
            abs_fpath = os.path.join(self.local_repo_dpath, fpath)
            with open(abs_fpath, 'r') as f:
                file_content = f.read()
        else:
            file_content = self.comb_code[fpath]


        complete_call = None

        # Find continuous characters containing original call (ex: a.b.call(x,y))
        call_pattern = rf'(?<=\s|^)([^\s]*{ori_call}[^\s]*)'
        for call_match in re.findall(call_pattern, file_content):
            # Extract prefix before the call (ex: a.b.)
            prefix_pattern = rf'^(.*?){ori_call}.*$'
            prefix_match = re.match(prefix_pattern, call_match)
            if prefix_match:
                prefix = prefix_match.group(1)

                # Valid pattern: xx.xx.xx.
                valid_pattern = r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*\.$'
                if re.match(valid_pattern, prefix):
                    call = prefix + ori_call
                    if complete_call is None:
                        complete_call = call
                    elif complete_call != call:
                        # Consider only the safest case
                        return ori_call

        return complete_call if complete_call else ori_call


    def _get_class_signature_in_nodiff_file(self, class_name: str, fpath: str, class_range: LineRange) -> str:
        """Get class signature from the specified nodiff file."""
        assert fpath in self.nodiff_files
        abs_fpath = os.path.join(self.local_repo_dpath, fpath)
        class_sig = search_util_v2.get_class_signature_in_nodiff_file(abs_fpath, class_name, class_range)
        return class_sig


    def _get_class_signature_in_diff_file(
            self, class_name: str, fpath: str, old_class_range: LineRange | None, new_class_range: LineRange | None
    ) -> str:
        """Get class signature from the specified diff file."""
        assert fpath in self.del_files + self.add_files + self.mod_files
        comb_code = self.comb_code[fpath]
        old_code = self.old_code[fpath] if fpath in self.old_code else None
        new_code = self.new_code[fpath] if fpath in self.new_code else None

        line_id_old2comb = self.line_id_old2comb[fpath] if fpath in self.line_id_old2comb else None
        line_id_new_comb = self.line_id_new2comb[fpath] if fpath in self.line_id_new2comb else None

        class_sig = search_util_v2.get_class_signature_in_diff_file(
            comb_code, class_name,
            old_code, old_class_range, line_id_old2comb,
            new_code, new_class_range, line_id_new_comb
        )

        return class_sig


    def _get_code_snippet_in_nodiff_file(self, fpath: str, line_range: LineRange) -> str:
        """Get code snippet from the specified nodiff file."""
        assert fpath in self.nodiff_files
        abs_fpath = os.path.join(self.local_repo_dpath, fpath)
        code = search_util_v2.get_code_snippets_in_nodiff_file(abs_fpath, line_range.start, line_range.end)
        return code


    def _get_code_snippet_in_diff_file(
            self, fpath: str, old_line_range: LineRange | None, new_line_range: LineRange | None
    ) -> str:
        """Get code snippet from the specified diff file."""
        assert fpath in self.diff_files
        comb_code = self.comb_code[fpath]
        snippet = search_util_v2.get_code_snippet_in_diff_file(
            comb_code, old_line_range, self.line_id_old2comb[fpath], new_line_range, self.line_id_new2comb[fpath]
        )

        return snippet


    """UTILS"""


    def process_old_and_new_code_ranges(
            self, old_code_ranges: List[CodeRange], new_code_ranges: List[CodeRange]
    ) -> Dict[str, List[Tuple[LineRange | None, LineRange | None]]]:
        """Process 'old_code_ranges' and 'new_code_ranges' according to certain rules.

        Target 1: Items in 'old_code_ranges' and 'new_code_ranges' that in the same file
                are grouped into the same group.
        Target 2: Items in 'old_code_ranges' and 'new_code_ranges' that overlap in the same file
                are grouped into the same pair.
        """
        # (1) Group line ranges by file path
        file_line_range_groups: Dict[str, Tuple[List[LineRange], List[LineRange]]] = defaultdict(lambda: ([], []))
        for code_range in old_code_ranges:
            file_line_range_groups[code_range.file_path][0].append(code_range.range)

        for code_range in new_code_ranges:
            file_line_range_groups[code_range.file_path][1].append(code_range.range)

        # (2) Match old and new line ranges
        file_line_range_pairs: Dict[str, List[Tuple[LineRange | None, LineRange | None]]] = {}
        for fpath, (old_line_ranges, new_line_ranges) in file_line_range_groups.items():
            line_range_pairs = search_util_v2.match_overlap_structs(
                old_line_ranges, self.line_id_old2comb[fpath], new_line_ranges, self.line_id_new2comb[fpath]
            )
            file_line_range_pairs[fpath] = line_range_pairs

        return file_line_range_pairs


    """SEARCH FUNCTIONS"""


    def _search_class_or_func_in_file_imports(self, call_name: str, file_path: str) -> Tuple[str, SearchResult] | None:
        """Search for the class / function among the imported statements in the specified file.

        NOTE: We have confirmed that this file exists.
        Args:
            call_name (str): Function or class name.
            file_path (str): RELATIVE file path.
        Returns:
            Tuple[str, SearchResult] | None:
                - str： A description of how this class / func was imported.
                - SearchResult: Corresponding search result.
        """
        if file_path in self.nodiff_files:
            file_import_libs = self.nodiff_file_import_libs[file_path]
        else:
            file_import_libs = self.diff_file_import_libs[file_path]

        call_source = call_name.split(".")[0]

        for import_lib in file_import_libs:
            pkg_path, attr_name, alias_name = import_lib
            abs_cur_fpath = os.path.join(self.local_repo_dpath, file_path)

            if alias_name == call_source or attr_name == call_source or pkg_path.endswith(call_source):
                lib_source, attr = search_util_v2.judge_lib_source(import_lib, abs_cur_fpath, self.local_repo_dpath)

                # FIXME: Instead of looking for the import statement in the original code, we reconstruct
                #       an individual import statement based on the current import. Are any improvements needed?
                import_seq = search_util_v2.lib_info_to_seq(pkg_path, attr_name, alias_name)

                desc = f"It is imported through '{import_seq}'. The library is a {lib_source}, and "
                if lib_source == "custom library":
                    desc += f"the import path is '{attr}'."
                else:
                    desc += f"the library name is '{attr}'."

                res = SearchResult(file_path, None, None, import_seq)
                return desc, res

        return None


    def _search_func_in_class(self, func_name: str, class_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this function among the specified class in the repo / specified file."""
        result: List[SearchResult] = []

        ############## (1) For class functions in nodiff file ##############
        if class_name in self.nodiff_classFunc_index and func_name in self.nodiff_classFunc_index[class_name]:
            for classFunc_code_range in self.nodiff_classFunc_index[class_name][func_name]:
                if file_path is None or classFunc_code_range.file_path == file_path:
                    func_code = self._get_code_snippet_in_nodiff_file(
                        classFunc_code_range.file_path, classFunc_code_range.range
                    )

                    res = SearchResult(classFunc_code_range.file_path, class_name, func_name, func_code)
                    result.append(res)

        ############## (2) For class functions in diff file ##############
        old_cand_classFuncs: List[CodeRange] = self.old_classFunc_index[class_name][func_name] \
            if class_name in self.old_classFunc_index and func_name in self.old_classFunc_index[class_name] else []
        new_cand_classFuncs: List[CodeRange] = self.new_classFunc_index[class_name][func_name] \
            if class_name in self.new_classFunc_index and func_name in self.new_classFunc_index[class_name] else []

        # 1. Filter out class functions in the specified file
        if file_path is not None:
            old_cand_classFuncs = [classFunc_code_range for classFunc_code_range in old_cand_classFuncs
                                   if classFunc_code_range.file_path == file_path]
            new_cand_classFuncs = [classFunc_code_range for classFunc_code_range in new_cand_classFuncs
                                   if classFunc_code_range.file_path == file_path]

        # 2. Process old and new candidate class functions
        file_classFunc_range_pairs = self.process_old_and_new_code_ranges(old_cand_classFuncs, new_cand_classFuncs)

        # 3. Get the code snippet of each modified class functions
        for fpath, classFunc_range_pairs in file_classFunc_range_pairs.items():
            for old_classFunc_range, new_classFunc_range in classFunc_range_pairs:
                classFunc_code = self._get_code_snippet_in_diff_file(fpath, old_classFunc_range, new_classFunc_range)

                res = SearchResult(fpath, class_name, func_name, classFunc_code)
                result.append(res)

        return result


    def _search_func_in_classes(self, func_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this function among all classes in the repo / specified file."""
        result: List[SearchResult] = []

        checked_class_names = []
        # (1) For class functions in nodiff file
        for class_name in self.nodiff_class_index:
            if class_name not in checked_class_names:
                checked_class_names.append(class_name)
                res = self._search_func_in_class(func_name, class_name, file_path)
                result.extend(res)

        # (2) For class functions in diff file
        for class_name in self.old_class_index:
            if class_name not in checked_class_names:
                checked_class_names.append(class_name)
                res = self._search_func_in_class(func_name, class_name, file_path)
                result.extend(res)

        for class_name in self.new_class_index:
            if class_name not in checked_class_names:
                checked_class_names.append(class_name)
                res = self._search_func_in_class(func_name, class_name, file_path)
                result.extend(res)

        return result


    def _search_top_level_func(self, func_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this function among all top level functions in the repo / specified file."""
        result: List[SearchResult] = []

        ############## (1) For functions in nodiff file ##############
        if func_name in self.nodiff_func_index:
            for func_code_range in self.nodiff_func_index[func_name]:
                if file_path is None or func_code_range.file_path == file_path:
                    func_code = self._get_code_snippet_in_nodiff_file(func_code_range.file_path, func_code_range.range)

                    res = SearchResult(func_code_range.file_path, None, func_name, func_code)
                    result.append(res)

        ############## (2) For functions in diff file ##############
        old_cand_funcs: List[CodeRange] = self.old_func_index[func_name] if func_name in self.old_func_index else []
        new_cand_funcs: List[CodeRange] = self.new_func_index[func_name] if func_name in self.new_func_index else []

        # 1. Filter out functions in the specified file
        if file_path is not None:
            old_cand_funcs = [func_code_range for func_code_range in old_cand_funcs
                              if func_code_range.file_path == file_path]
            new_cand_funcs = [func_code_range for func_code_range in new_cand_funcs
                              if func_code_range.file_path == file_path]

        # 2. Process old and new candidate functions
        file_func_range_pairs = self.process_old_and_new_code_ranges(old_cand_funcs, new_cand_funcs)

        # 3. Get the code snippet of each modified functions
        for fpath, func_range_pairs in file_func_range_pairs.items():
            for old_func_range, new_func_range in func_range_pairs:
                func_code = self._get_code_snippet_in_diff_file(fpath, old_func_range, new_func_range)

                res = SearchResult(fpath, None, func_name, func_code)
                result.append(res)

        return result


    def _search_func(self, func_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this function in the repo / specified file, including top-level functions and class functions."""
        result: List[SearchResult] = []

        # (1) Search among all top level functions
        top_level_res = self._search_top_level_func(func_name, file_path)
        result.extend(top_level_res)

        # (2) Search among all class functions
        class_res = self._search_func_in_classes(func_name, file_path)
        result.extend(class_res)

        return result


    def _search_nodiff_class(self, class_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this class among all nodiff classes in the repo / specified file."""

        result: List[SearchResult] = []
        for class_code_range in self.nodiff_class_index[class_name]:
            if file_path is None or class_code_range.file_path == file_path:
                class_code = self._get_class_signature_in_nodiff_file(
                    class_name, class_code_range.file_path, class_code_range.range
                )

                res = SearchResult(class_code_range.file_path, class_name, None, class_code)
                result.append(res)

        return result


    def _search_diff_class(self, class_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this class among all diff classes in the repo / specified file."""

        cand_old_classes: List[CodeRange] = self.old_class_index[class_name] \
                                            if class_name in self.old_class_index else []
        cand_new_classes: List[CodeRange] = self.new_class_index[class_name] \
                                            if class_name in self.new_class_index else []

        # 1. Filter out classes in the specified file
        if file_path is not None:
            cand_old_classes = [class_code_range for class_code_range in cand_old_classes
                                if class_code_range.file_path == file_path]
            cand_new_classes = [class_code_range for class_code_range in cand_new_classes
                                if class_code_range.file_path == file_path]

        # 2. Process old and new candidate classes
        file_class_range_pairs = self.process_old_and_new_code_ranges(cand_old_classes, cand_new_classes)

        # 3. Get the signature of each modified class
        result: List[SearchResult] = []
        for fpath, class_range_pairs in file_class_range_pairs.items():
            for old_class_range, new_class_range in class_range_pairs:
                class_code = self._get_class_signature_in_diff_file(class_name, fpath, old_class_range, new_class_range)

                res = SearchResult(fpath, class_name, None, class_code)
                result.append(res)

        return result


    def _search_class(self, class_name: str, file_path: str | None = None) -> List[SearchResult]:
        """Search for this class in the repo / specified file.
        NOTE：Normally, there will not be classes with the same name in a file, but just in case.
        """
        result: List[SearchResult] = []

        if file_path is None or file_path in self.nodiff_files:
            res = self._search_nodiff_class(class_name, file_path)
            result.extend(res)

        if file_path is None or file_path in self.diff_files:
            res = self._search_diff_class(class_name, file_path)
            result.extend(res)

        return result


    """PRE-CHECK"""


    def _search_arg_pre_check(self, **kwargs) -> Tuple[bool, str]:
        empty_args = [arg_name for arg_name, value in kwargs.items() if isinstance(value, str) and value == ""]

        if empty_args:
            if len(empty_args) == 1:
                tool_output = f"All parameters must be specified, however, {empty_args[0]} is an empty string."
            else:
                args = ", ".join(empty_args)
                tool_output = f"All parameters must be specified, however, {args} are empty strings."
            return False, tool_output

        return True, ""


    def _search_file_pre_check(self, file_name: str) -> Tuple[bool, str, str | None]:
        """Determine if the given file name is detailed enough to specify a unique file.

        This function should be called before calling a search Interface which requires a file name.
        Args:
            file_name (str): File name.
        Returns:
            bool: Whether the file name is detailed enough.
            str: Tool output.
            str | None: Unique file path (RELATIVE).
        """
        candidate_py_rel_paths = [f for f in self.parsed_files if f.endswith(file_name)]

        if len(candidate_py_rel_paths) == 0:
            return True, "", None

        elif len(candidate_py_rel_paths) == 1:
            return True, "", candidate_py_rel_paths[0]

        else:
            tool_output = f"Found {len(candidate_py_rel_paths)} files with name '{file_name}':\n\n"
            for idx, fpath in enumerate(candidate_py_rel_paths):
                tool_output += f"- file {idx + 1}: {fpath}\n"

            return False, tool_output, None


    """INTERFACES"""


    def search_code_in_file(self, code_str: str, file_path: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        pass


    def search_class(self, class_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class in the entire repo.

        Args:
            class_name (str): Class name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = self._search_arg_pre_check(class_name=class_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Search the class in the repo ----------------- #
        if class_name not in self.old_class_index and class_name not in self.new_class_index \
                and class_name not in self.nodiff_class_index:
            tool_output = f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Get the signature of the class ----------------- #
        all_search_res = self._search_class(class_name)

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} classes with name '{class_name}' in the repo:\n"
        if len(all_search_res) > RESULT_SHOW_LIMIT:
            # Too much classes, simplified representation
            tool_output += "\nThey appeared in the following files:\n"
            tool_output += SearchResult.collapse_to_file_level(all_search_res)
        else:
            # Several classes, verbose representation
            for idx, res in enumerate(all_search_res):
                res_str = res.to_tagged_str()
                tool_output += f"\n- Search result {idx + 1}:\n```\n{res_str}\n```"
        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_class_in_file(self, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class in the specified file.

        Args:
            class_name (str): Class name.
            file_name (str): File name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = self._search_arg_pre_check(class_name=class_name, file_name=file_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the file is valid and unique ----------------- #
        cont_search, tool_output, file_path = self._search_file_pre_check(file_name)

        if not cont_search:
            return tool_output, SearchStatus.NON_UNIQUE_FILE, []

        if file_path is None:
            tool_output = f"Could not find file '{file_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the class in the specified file  ----------------- #
        ## 3.1 Search among the class definitions in the specified file
        if file_path in self.nodiff_files:
            all_search_res = self._search_nodiff_class(class_name, file_path)
        else:
            all_search_res = self._search_diff_class(class_name, file_path)

        if not all_search_res:
            ## 3.2 Search among the imports of the specified file
            res = self._search_class_or_func_in_file_imports(class_name, file_path)

            if res:
                import_desc, search_res = res

                tool_output = (f"Found class '{class_name}' is imported in file '{file_path}'."
                               f"\n{import_desc}")

                return tool_output, SearchStatus.FIND_IMPORT, [search_res]
            else:
                tool_output = f"Could not find class '{class_name}' in file '{file_path}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} classes with name '{class_name}' in file '{file_path}':\n"
        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += f"\n- Search result {idx + 1}:\n```\n{res_str}\n```"
        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_method_in_file(self, method_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search function in the specified file.

        NOTE: Including top level functions and class functions
        Args:
            method_name (str): Function name.
            file_name (str): File name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = self._search_arg_pre_check(method_name=method_name, file_name=file_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the file is valid and unique ----------------- #
        cont_search, tool_output, file_path = self._search_file_pre_check(file_name)

        if not cont_search:
            return tool_output, SearchStatus.NON_UNIQUE_FILE, []

        if file_path is None:
            tool_output = f"Could not find file '{file_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the function in the specified file ----------------- #
        # 3.1 Search among the function definitions in the specified file
        all_search_res: List[SearchResult] = self._search_func(method_name, file_path)

        if not all_search_res:
            ## 3.2 Search among the imports in the specified file
            res = self._search_class_or_func_in_file_imports(method_name, file_path)

            if res:
                import_desc, search_res = res

                tool_output = (f"Found method '{method_name}' is imported in file '{file_path}'."
                               f"\n{import_desc}")

                return tool_output, SearchStatus.FIND_IMPORT, [search_res]
            else:
                tool_output = f"Could not find method '{method_name}' in file '{file_path}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in file '{file_path}':\n"

        # NOTE: When searching for a method in one file, it's rare that there are many candidates,
        #       so we do not trim the result
        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += f"\n- Search result {idx + 1}:\n```\n{res_str}\n```"
        return tool_output, SearchStatus.FIND_CODE, all_search_res


    # TODO: Considering the accuracy of the search, should we keep the search API calls that
    #        do not contain file path and the related index?
    def search_method_in_class(self, method_name: str, class_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class function in the specified class.

        Args:
            method_name (str): Function name.
            class_name (str): Class name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = self._search_arg_pre_check(method_name=method_name, class_name=class_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the class exists ----------------- #
        if class_name not in self.old_class_index and class_name not in self.new_class_index \
                and class_name not in self.nodiff_class_index:
            tool_output = f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the function in the specified classes ----------------- #
        all_search_res: List[SearchResult] = self._search_func_in_class(method_name, class_name)

        if not all_search_res:
            # TODO: Consider whether to search among imports when no function definition is found.
            tool_output = f"Could not find method '{method_name}' in class '{class_name}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in class '{class_name}':\n"

        # NOTE: There can be multiple classes defined in multiple files, which contain the same method,
        #       so we still trim the result, just in case
        if len(all_search_res) > RESULT_SHOW_LIMIT:
            tool_output += f"\nToo many results, showing full code for {RESULT_SHOW_LIMIT} of them, and the rest just file names:"

        # (1) For the top-k, show detailed info
        top_k_res = all_search_res[:RESULT_SHOW_LIMIT]
        for idx, res in enumerate(top_k_res):
            res_str = res.to_tagged_str()
            tool_output += f"\n- Search result {idx + 1}:\n```\n{res_str}\n```"
        # (2) For the rest, collect the file names into a set
        if rest := all_search_res[RESULT_SHOW_LIMIT:]:
            tool_output += "\nOther results are in these files:\n"
            tool_output += SearchResult.collapse_to_file_level(rest)

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_method_in_class_in_file(
            self, method_name: str, class_name: str, file_name: str
    ) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class function in the specified class and file.

        Args:
            method_name (str): Function name.
            class_name (str): Class name.
            file_name (str): File name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = \
            self._search_arg_pre_check(method_name=method_name, class_name=class_name, file_name=file_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the file is valid and unique ----------------- #
        cont_search, tool_output, file_path = self._search_file_pre_check(file_name)

        if not cont_search:
            return tool_output, SearchStatus.NON_UNIQUE_FILE, []

        if file_path is None:
            tool_output = f"Could not find file '{file_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # TODO: Consider whether to search class first.
        # ----------------- (3) Search the class in the specified file ----------------- #
        # if not class_exist:
        #     ## 3.2 Search class among the imports of the specified file
        #     res = self._search_class_or_func_in_file_import_libs(class_name, file_path)
        #
        #     if res:
        #         import_desc, search_res = res
        #
        #         tool_output = f"Found class '{class_name}' is imported in file '{file_path}'.\n\n"
        #         tool_output = tool_output + import_desc
        #
        #         return tool_output, SearchStatus.FIND_IMPORT, []
        #     else:
        #         tool_output = f"Could not find class '{class_name}' in file '{file_path}'."
        #         return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the function in the specified class and file ----------------- #
        all_search_res: List[SearchResult] = self._search_func_in_class(method_name, class_name, file_path)

        if not all_search_res:
            tool_output = f"Could not find method '{method_name}' in class '{class_name}' in file '{file_path}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in class '{class_name}' in file '{file_path}':\n"
        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += f"\n- Search result {idx + 1}:\n```\n{res_str}\n```"
        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def get_classes_and_methods_in_file(self, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        pass

