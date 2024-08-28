# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_manage.py
import os
import re
import pathlib

from typing import *
from collections import defaultdict, namedtuple
from collections.abc import MutableMapping
from enum import Enum

from agent_app.search import search_util
from agent_app.search.search_util import SearchResult
from agent_app.data_structures import SearchStatus
from utils import LineRange


FuncIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]
ClassIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]
ClassFuncIndexType = MutableMapping[str, MutableMapping[str, List[Tuple[str, LineRange]]]]

FileImportLibType = MutableMapping[str, List[Tuple[str, str, str]]]


RESULT_SHOW_LIMIT = 3


class SearchFileType(str, Enum):
    NO_DIFF = "nodiff"
    DIFF = "diff"


class SearchManager:
    def __init__(self, local_repo_dpath: str, commit_files_info: Dict):
        ## NOTE: All paths that appear below are RELATIVE paths (relative to repo root)

        # -------------------------------- Basic Info -------------------------------- #
        self.local_repo_dpath = local_repo_dpath
        self.parsed_files: List[str] = []
        self.parsed_failed_files: List[str] = []

        # -------------------------------- Commit Files Info -------------------------------- #
        ## (1) File paths
        self.del_files: List[str] = []
        self.add_files: List[str] = []
        self.mod_files: List[str] = []

        ## (2) File contents
        self.code_before: Dict[str, str] = {}  # file path -> file content before
        self.code_after: Dict[str, str] = {}   # file path -> file content after
        self.code_comb: Dict[str, str] = {}    # file path -> file content comb

        ## (3) Line id lookup
        self.line_id_before2comb: Dict[str, Dict[int, int]] = {}  # file path -> {line id after  -> line id comb}
        self.line_id_after2comb: Dict[str, Dict[int, int]] = {}   # file path -> {line id before -> line id comb}

        ## (4) Struct indexes
        self.diff_func_index: FuncIndexType = {}            # func name  -> [(file path, line_range)]
        self.diff_class_index: ClassIndexType = {}          # class name -> [(file path, line range)]
        self.diff_classFunc_index: ClassFuncIndexType = {}  # class name -> {func name -> [(file path, line range)]}

        ## (5) Imported libraries
        self.diff_file_import_libs: FileImportLibType = {}  # file path -> [(package path, attr name, alias name)]

        # -------------------------------- Unchanged Files Info -------------------------------- #
        ## (1) File paths
        self.unchanged_files: List[str] = []

        ## (2) Struct indexes
        self.nodiff_func_index: FuncIndexType = {}            # func_name  -> [(file_name, line_range)]
        self.nodiff_class_index: ClassIndexType = {}          # class name -> [(file path, line range)]
        self.nodiff_classFunc_index: ClassFuncIndexType = {}  # class name -> {func name -> [(file path, line range)]}

        ## (3) Imported libraries
        self.nodiff_file_import_libs: FileImportLibType = {}  # file path -> [(package path, attr name, alias name)]

        # -------------------------------- Update -------------------------------- #
        self._update(commit_files_info)


    """Update attributes"""

    def _update(self, commit_files_info: Dict) -> None:
        # Step I: Update commit files info
        self._update_commit_file_info(commit_files_info)

        # Step II: Update unchanged files info
        self._update_nodiff_file_info()

        # Step III: Summarize
        self.parsed_files: List[str] = self.del_files + self.add_files + self.mod_files + self.unchanged_files

    def _update_commit_file_info(self, commit_files_info: Dict) -> None:

        """For recording information of files involved in the commit.

        NOTE: The following information has been processed in the commit_manager.
        """
        # (1) File paths
        self.del_files = commit_files_info['del_files']
        self.add_files = commit_files_info['add_files']
        self.mod_files = commit_files_info['mod_files']

        # (2) File contents
        self.code_before = commit_files_info['code_before']
        self.code_after = commit_files_info['code_after']
        self.code_comb = commit_files_info['code_comb']

        # (3) Line id lookup
        self.line_id_before2comb = commit_files_info['before2comb_line_id_lookup']
        self.line_id_after2comb = commit_files_info['after2comb_line_id_lookup']

        # (4) Struct indexes
        self.diff_func_index: FuncIndexType = defaultdict(list)
        self.diff_class_index: ClassIndexType = defaultdict(list)
        self.diff_classFunc_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))

        for fpath, file_funcs in commit_files_info['file_func_index'].items():
            for func_name, func_range in file_funcs:
                self.diff_func_index[func_name].append((fpath, func_range))

        for fpath, file_classes in commit_files_info['file_class_index'].items():
            for class_name, class_range in file_classes:
                self.diff_class_index[class_name].append((fpath, class_range))

        for fpath, class_to_funcs in commit_files_info['file_classFunc_index'].items():
            for class_name, classFuncs in class_to_funcs:
                for classFunc_name, classFunc_range in classFuncs:
                    self.diff_classFunc_index[class_name][classFunc_name].append((fpath, classFunc_range))

        # (5) Imported libraries
        self.diff_file_import_libs: FileImportLibType = defaultdict(list)

        for fpath in self.del_files + self.add_files + self.mod_files:
            old_libs, *_ = search_util.parse_python_code(self.code_before[fpath]) if fpath in self.code_before else []
            new_libs, *_ = search_util.parse_python_code(self.code_after[fpath]) if fpath in self.code_after else []

            self.diff_file_import_libs[fpath] = list(set(old_libs + new_libs))


    def _update_nodiff_file_info(self) -> None:
        """For recording information of files unchanged in the commit.

        Process: Traverse the python files in the local repo and analyze them individually.
        """
        self.nodiff_file_import_libs: FileImportLibType = defaultdict(list)

        self.nodiff_func_index: FuncIndexType = defaultdict(list)
        self.nodiff_class_index: ClassIndexType = defaultdict(list)
        self.nodiff_classFunc_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))

        abs_py_fpaths = search_util.find_python_files(self.local_repo_dpath)

        for abs_py_fpath in abs_py_fpaths:
            rel_py_fpath = os.path.relpath(abs_py_fpath, self.local_repo_dpath)

            ## Step 1: Filter out diff files (in commit)
            if rel_py_fpath in self.del_files + self.add_files + self.mod_files:
                continue

            ## Step 2: Parse the code
            file_content = pathlib.Path(abs_py_fpath).read_text()
            struct_info = search_util.parse_python_code(file_content)

            if struct_info is None:
                self.parsed_failed_files.append(rel_py_fpath)
                continue

            self.unchanged_files.append(rel_py_fpath)

            ## Step 3: Build search indexes
            libs, funcs, classes, class_to_funcs = struct_info

            # (1) Collect imported libs
            self.nodiff_file_import_libs[rel_py_fpath] = libs

            # (2) Build (top-level) function index and file function index
            for f, start, end in funcs:
                self.nodiff_func_index[f].append((rel_py_fpath, LineRange(start, end)))

            # (3) Build class index and file class index
            for c, start, end in classes:
                self.nodiff_class_index[c].append((rel_py_fpath, LineRange(start, end)))

            # (4) Build classFunction index and file classFunction index
            for c, class_funcs in class_to_funcs.items():
                for f, start, end in class_funcs:
                    self.nodiff_classFunc_index[c][f].append((rel_py_fpath, LineRange(start, end)))


    """Get Code Snippet Functions"""

    def _get_full_call(self, ori_call: str, fpath: str) -> str:
        """
        Prevent the following case:
            In code, a func is called like "... module.func(arg) ...", but the Agent only extract "func" for searching.
            So we need to complete the call like "module.func" to search.
        """
        if fpath in self.unchanged_files:
            abs_fpath = os.path.join(self.local_repo_dpath, fpath)
            with open(abs_fpath, 'r') as f:
                file_content = f.read()
        else:
            file_content = self.code_comb[fpath]


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


    def _get_class_signature_in_file(self, class_name: str, fpath: str) -> str:
        """Get class signature from specific file.

        By default, We assume that no class with the same name can appear in a single file.
        """
        if fpath in self.unchanged_files:
            abs_fpath = os.path.join(self.local_repo_dpath, fpath)
            class_sig = search_util.get_class_signature_in_repo(abs_fpath, class_name)
        else:
            file_comb = self.code_comb[fpath]
            file_before = self.code_before[fpath] if fpath in self.code_before else None
            file_after = self.code_after[fpath] if fpath in self.code_after else None

            before2comb_line_id_lookup = self.line_id_before2comb[fpath] \
                if fpath in self.line_id_before2comb else None
            after2comb_line_id_lookup = self.line_id_after2comb[fpath] \
                if fpath in self.line_id_after2comb else None

            class_sig = search_util.get_class_signature_in_file(
                file_comb, class_name,
                file_before, before2comb_line_id_lookup,
                file_after, after2comb_line_id_lookup
            )

        return class_sig


    def _get_code_snippet_in_file(self, fpath: str, start: int, end: int) -> str:
        """Get code snippet from specific file according to line ids."""
        if fpath in self.unchanged_files:
            # For unchanged file, get code snippet from repo
            abs_fpath = os.path.join(self.local_repo_dpath, fpath)
            code = search_util.get_code_snippets_in_repo(abs_fpath, start, end)
        else:
            # For modified file, get code snippet directly from the saved combined file
            file = self.code_comb[fpath]
            code = search_util.get_code_snippet_in_file(file, start, end)

        return code


    """Search Functions"""


    def _search_class_or_func_in_file_import_libs(self, call_name: str, fpath: str) -> Tuple[str, SearchResult] | None:
        """
        Search for the class / function in the imported statements of the specific file.

        NOTE: We have confirmed that this file exists.
        Args:
            call_name (str): Function or class name.
            fpath (str): RELATIVE file path.
        Returns:
            Tuple[str, SearchResult] | None:
                - str： A description of how this class / func was imported.
                - SearchResult: Corresponding search result.
        """
        if fpath in self.unchanged_files:
            file_import_libs = self.nodiff_file_import_libs[fpath]
        else:
            file_import_libs = self.diff_file_import_libs[fpath]

        call_source = call_name.split(".")[0]

        for import_lib in file_import_libs:
            pkg_path, attr_name, alias_name = import_lib
            abs_cur_fpath = os.path.join(self.local_repo_dpath, fpath)

            if alias_name == call_source or attr_name == call_source or pkg_path.endswith(call_source):
                lib_source, attr = search_util.judge_lib_source(import_lib, abs_cur_fpath, self.local_repo_dpath)

                # FIXME: Instead of looking for the import statement in the original code, we reconstruct
                #       an individual import statement based on the current import. Are any improvements needed?
                import_seq = search_util.lib_info_to_seq(pkg_path, attr_name, alias_name)

                desc = f"It is imported through '{import_seq}'. The library is {lib_source}, and "
                if lib_source == "custom library":
                    desc += f"the import path is '{attr}'.\n"
                else:
                    desc += f"the library name is '{attr}'.\n"

                res = SearchResult(fpath, None, None, import_seq)

                return desc, res

        return None


    # def _search_func_in_class_in_file(self, func_name: str, class_name: str, fpath: str) -> List[SearchResult]:
    #     """Search for the function name in the specific class of specific file.
    #
    #     NOTE: We have confirmed that this class exists in this file.
    #     Args:
    #         func_name (str): Function name.
    #         class_name (str): Class name.
    #         fpath (str): Relative file path.
    #     Returns:
    #         The list of code snippets searched.
    #     """
    #     result: List[SearchResult] = []
    #
    #     if fpath in self.unchanged_files:
    #         file_classFunc_index = self.nodiff_classFunc_index[fpath]
    #     else:
    #         file_classFunc_index = self.diff_classFunc_index[fpath]
    #
    #     class_to_funcs: List[Tuple[str, List[Tuple[str, LineRange]]]] = []
    #     for c, classFuncs in file_classFunc_index:
    #         if c == class_name:
    #             class_to_funcs.append((c, classFuncs))
    #
    #     assert class_to_funcs
    #
    #     for _, classFuncs in class_to_funcs:
    #         for classFunc, (start, end) in classFuncs:
    #             if classFunc == func_name:
    #                 classFunc_code = self._get_code_snippet_in_file(fpath, start, end)
    #
    #                 res = SearchResult(fpath, class_name, func_name, classFunc_code)
    #                 result.append(res)
    #
    #     return result
    #
    #
    # def _search_func_in_classes_in_file(self, func_name: str, fpath: str) -> List[SearchResult]:
    #     """Search for the function name in all classes of the specific file.
    #
    #     NOTE: We have confirmed that this file exists.
    #     Args:
    #         func_name (str): Function name.
    #         fpath (str): Relative file path.
    #     Returns:
    #         The list of code snippets searched.
    #     """
    #     result: List[SearchResult] = []
    #
    #     if fpath in self.unchanged_files:
    #         class_index = self.nodiff_class_index
    #     else:
    #         class_index = self.diff_class_index
    #
    #     for class_name, locs in class_index.items():
    #         for file, _ in locs:
    #             if file == fpath:
    #                 res = self._search_func_in_class_in_file(func_name, class_name, fpath)
    #                 result.extend(res)
    #                 break
    #     return result
    #
    #
    # def _search_top_level_func_in_file(self, func_name: str, fpath: str) -> List[SearchResult]:
    #     """Search for the function name in all top level functions of the specific file.
    #
    #     NOTE: We have confirmed that this file exists.
    #     Args:
    #         func_name (str): Function name.
    #         fpath (str): Relative file path.
    #     Returns:
    #         List: The list of code snippets searched.
    #     """
    #     result: list[SearchResult] = []
    #
    #     if fpath in self.unchanged_files:
    #         func_index = self.nodiff_func_index
    #     else:
    #         func_index = self.diff_func_index
    #
    #     if func_name not in func_index:
    #         return result
    #
    #     for fpath, (start, end) in func_index[func_name]:
    #         func_code = self._get_code_snippet_in_file(fpath, start, end)
    #         res = SearchResult(fpath, None, func_name, func_code)
    #         result.append(res)
    #
    #     return result
    #
    #
    # def _search_func_in_file(self, func_name: str, fpath: str) -> List[SearchResult]:
    #     """Search for this function in specific file, including top-level functions and class functions.
    #
    #     NOTE: We have confirmed that this file exists.
    #     """
    #     result: List[SearchResult] = []
    #
    #     # (1) Search in top level functions
    #     top_level_res = self._search_top_level_func_in_file(func_name, fpath)
    #     result.extend(top_level_res)
    #
    #     # (2) Search in class functions
    #     class_res = self._search_func_in_classes_in_file(func_name, fpath)
    #     result.extend(class_res)
    #
    #     return result


    def _search_func_in_class(self, func_name: str, class_name: str) -> List[SearchResult]:
        """Search for the function name in the specific class.
        Args:
            func_name (str): Function name.
            class_name (str): Class name.
        Returns:
            The list of code snippets searched.
        """
        result: List[SearchResult] = []

        if class_name in self.nodiff_classFunc_index and func_name in self.nodiff_classFunc_index[class_name]:
            for fpath, (start, end) in self.nodiff_classFunc_index[class_name][func_name]:
                func_code = self._get_code_snippet_in_file(fpath, start, end)
                res = SearchResult(fpath, class_name, func_name, func_code)
                result.append(res)

        if class_name in self.diff_classFunc_index and func_name in self.diff_classFunc_index[class_name]:
            for fpath, (start, end) in self.diff_classFunc_index[class_name][func_name]:
                func_code = self._get_code_snippet_in_file(fpath, start, end)
                res = SearchResult(fpath, class_name, func_name, func_code)
                result.append(res)

        return result


    def _search_func_in_classes(self, func_name: str) -> List[SearchResult]:
        """Search for the function name in all classes.
        Args:
            func_name (str): Function name.
        Returns:
            The list of code snippets searched.
        """
        result: List[SearchResult] = []

        for class_name in self.nodiff_class_index:
            ress = self._search_func_in_class(func_name, class_name)
            result.extend(ress)

        for class_name in self.diff_class_index:
            ress = self._search_func_in_class(func_name, class_name)
            result.extend(ress)

        return result


    def _search_top_level_func(self, func_name: str) -> List[SearchResult]:
        """Search for the function name in all top level functions.
        Args:
            func_name (str): Function name.
        Returns:
            List: The list of code snippets searched.
        """
        result: List[SearchResult] = []

        if func_name in self.nodiff_func_index:
            for fpath, (start, end) in self.nodiff_func_index[func_name]:
                func_code = self._get_code_snippet_in_file(fpath, start, end)
                res = SearchResult(fpath, None, func_name, func_code)
                result.append(res)

        if func_name in self.diff_func_index:
            for fpath, (start, end) in self.diff_func_index[func_name]:
                func_code = self._get_code_snippet_in_file(fpath, start, end)
                res = SearchResult(fpath, None, func_name, func_code)
                result.append(res)

        return result


    def _search_func_in_repo(self, func_name: str) -> List[SearchResult]:
        """Search for this function in the repo, including top-level functions and class functions.
        Args:
            func_name (str): Function name.
        Returns:
            List: The list of code snippets searched.
        """
        result: List[SearchResult] = []

        # (1) Search in top level functions
        top_level_res = self._search_top_level_func(func_name)
        result.extend(top_level_res)

        # (2) Search in class functions
        class_res = self._search_func_in_classes(func_name)
        result.extend(class_res)

        return result


    def _search_pre_check(self, **kwargs) -> Tuple[bool, str]:
        empty_args = [arg_name for arg_name, value in kwargs.items() if isinstance(value, str) and value == ""]

        if empty_args:
            if len(empty_args) == 1:
                tool_output = f"All parameters must be specified, however, {empty_args[0]} is an empty string."
            else:
                args = ", ".join(empty_args)
                tool_output = f"All parameters must be specified, however, {args} are empty strings."
            return False, tool_output

        return True, ""


    def _search_with_file_before(self, file_name: str) -> Tuple[bool, str, str | None]:
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


    """Interfaces"""

    # FIXME: Not complete

    def search_code_in_file(self, code_str: str, fpath: str) -> Tuple[str, str, bool]:
        """
        Search for this code string in specific file.
        """
        all_search_results: List[SearchResult] = []
        for file_path in self.parsed_files:
            searched_line_and_code: list[tuple[int, str]] = (
                search_util.get_code_region_containing_code(file_path, code_str)
            )
            if not searched_line_and_code:
                continue
            for searched in searched_line_and_code:
                line_no, code_region = searched
                class_name, func_name = self.file_line_to_class_and_func(file_path, line_no)

                res = SearchResult(file_path, class_name, func_name, code_region)
                all_search_results.append(res)

        if not all_search_results:
            tool_output = f"Could not find code {code_str} in the codebase."
            summary = tool_output
            return tool_output, summary, False

        # good path
        tool_output = f"Found {len(all_search_results)} snippets containing `{code_str}` in the codebase:\n\n"
        summary = tool_output

        if len(all_search_results) > RESULT_SHOW_LIMIT:
            tool_output += "They appeared in the following files:\n"
            tool_output += SearchResult.collapse_to_file_level(all_search_results)
        else:
            for idx, res in enumerate(all_search_results):
                res_str = res.to_tagged_str()
                tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, summary, True


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
        cont_search, tool_output = self._search_pre_check(class_name=class_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Search the class in the repo ----------------- #
        if class_name not in self.diff_class_index and class_name not in self.nodiff_class_index:
            tool_output = f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Get the signature of the class ----------------- #
        all_search_res: List[SearchResult] = []

        if class_name in self.diff_class_index:
            for fpath, _ in self.diff_class_index[class_name]:
                class_code = self._get_class_signature_in_file(class_name, fpath)

                res = SearchResult(fpath, class_name, None, class_code)
                all_search_res.append(res)

        if class_name in self.nodiff_class_index:
            for fpath, _ in self.nodiff_class_index[class_name]:
                class_code = self._get_class_signature_in_file(class_name, fpath)

                res = SearchResult(fpath, class_name, None, class_code)
                all_search_res.append(res)

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} classes with name '{class_name}' in the repo:\n\n"
        if len(all_search_res) > RESULT_SHOW_LIMIT:
            # Too much classes, simplified representation
            tool_output += "They appeared in the following files:\n"
            tool_output += SearchResult.collapse_to_file_level(all_search_res)
        else:
            # Several classes, verbose representation
            for idx, res in enumerate(all_search_res):
                res_str = res.to_tagged_str()
                tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, SearchStatus.FIND_ANY, all_search_res


    def search_class_in_file(self, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class in the specific file.

        Args:
            class_name (str): Class name.
            file_name (str): File name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = self._search_pre_check(class_name=class_name, file_name=file_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the file is valid and unique ----------------- #
        cont_search, tool_output, fpath = self._search_with_file_before(file_name)

        if not cont_search:
            return tool_output, SearchStatus.NON_UNIQUE_FILE, []

        if fpath is None:
            tool_output = f"Could not find file '{file_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the class in the specific file  ----------------- #
        if fpath in self.unchanged_files:
            class_index = self.nodiff_class_index
        else:
            class_index = self.diff_class_index

        ## 3.1 Search in the class definitions of the specific file
        class_exist = False
        if class_name in class_index:
            for file, _ in class_index[class_name]:
                if file == file_name:
                    class_exist = True
                    break

        if not class_exist:
            ## 3.2 Search in the imports of the specific file
            res = self._search_class_or_func_in_file_import_libs(class_name, fpath)

            if res:
                import_desc, search_res = res

                tool_output = f"Found class '{class_name}' is imported in file '{fpath}'.\n\n"
                tool_output = tool_output + import_desc

                return tool_output, SearchStatus.FIND_ANY, [search_res]
            else:
                tool_output = f"Could not find class '{class_name}' in file '{fpath}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Get the signature of the class ----------------- #
        class_sig = self._get_class_signature_in_file(class_name, fpath)
        search_res = SearchResult(fpath, class_name, None, class_sig)

        # ----------------- (5) Prepare the response ----------------- #
        tool_output = f"Found 1 class with name '{class_name}' in file '{fpath}':\n\n"
        res_str = search_res.to_tagged_str()
        tool_output += f"- Search result:\n```\n{res_str}\n```\n"
        return tool_output, SearchStatus.FIND_ANY, [search_res]


    def search_method_in_file(self, method_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search function in the specific file.

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
        cont_search, tool_output = self._search_pre_check(method_name=method_name, file_name=file_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the file is valid and unique ----------------- #
        cont_search, tool_output, fpath = self._search_with_file_before(file_name)

        if not cont_search:
            return tool_output, SearchStatus.NON_UNIQUE_FILE, []

        if fpath is None:
            tool_output = f"Could not find file '{file_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the function in the repo (filter later) ----------------- #
        all_search_res: List[SearchResult] = self._search_func_in_repo(method_name)

        # ----------------- (4) Search the function in the specific file ----------------- #
        ## 4,1 Filter
        all_search_res = [res for res in all_search_res if res.file_path == file_name]

        if not all_search_res:
            ## 4.2 Search in the imports of the specific file
            res = self._search_class_or_func_in_file_import_libs(method_name, fpath)

            if res:
                import_desc, search_res = res

                tool_output = f"Found method '{method_name}' is imported in file '{fpath}'.\n\n"
                tool_output = tool_output + import_desc

                return tool_output, SearchStatus.FIND_ANY, [search_res]
            else:
                tool_output = f"Could not find method '{method_name}' in file '{fpath}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (5) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in file '{fpath}':\n\n"

        # NOTE: When searching for a method in one file, it's rare that there are many candidates,
        #       so we do not trim the result
        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, SearchStatus.FIND_ANY, all_search_res

    # TODO: Considering the accuracy of the search, should we keep the search API calls that
    #        do not contain file path and the related index?
    def search_method_in_class(self, method_name: str, class_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class function in the specific class.

        Args:
            method_name (str): Function name.
            class_name (str): Class name.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        # ----------------- (1) Check if the arg is an empty str ----------------- #
        cont_search, tool_output = self._search_pre_check(method_name=method_name, class_name=class_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the class exists ----------------- #
        if class_name not in self.diff_class_index and class_name not in self.nodiff_class_index:
            tool_output = f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the function in the specific classes ----------------- #
        all_search_res: List[SearchResult] = self._search_func_in_class(method_name, class_name)

        if not all_search_res:
            tool_output = f"Could not find method '{method_name}' in class '{class_name}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in class '{class_name}':\n\n"

        # NOTE: There can be multiple classes defined in multiple files, which contain the same method,
        #       so we still trim the result, just in case
        if len(all_search_res) > RESULT_SHOW_LIMIT:
            tool_output += f"Too many results, showing full code for {RESULT_SHOW_LIMIT} of them, and the rest just file names:\n"
        first_five = all_search_res[:RESULT_SHOW_LIMIT]
        for idx, res in enumerate(first_five):
            res_str = res.to_tagged_str()
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        # For the rest, collect the file names into a set
        if rest := all_search_res[RESULT_SHOW_LIMIT:]:
            tool_output += "Other results are in these files:\n"
            tool_output += SearchResult.collapse_to_file_level(rest)
        return tool_output, SearchStatus.FIND_ANY, all_search_res


    def search_method_in_class_in_file(self, method_name: str, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search class function in the specific class and file.

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
            self._search_pre_check(method_name=method_name, class_name=class_name, file_name=file_name)

        if not cont_search:
            return tool_output, SearchStatus.INVALID_ARGUMENT, []

        # ----------------- (2) Check whether the file is valid and unique ----------------- #
        cont_search, tool_output, fpath = self._search_with_file_before(file_name)

        if not cont_search:
            return tool_output, SearchStatus.NON_UNIQUE_FILE, []

        if fpath is None:
            tool_output = f"Could not find file '{file_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Search the class in the specific file ----------------- #
        if fpath in self.unchanged_files:
            class_index = self.nodiff_class_index
        else:
            class_index = self.diff_class_index

        ## 3.1 Search in the class definitions of the specific file
        class_exist = False
        if class_name in class_index:
            for file, _ in class_index[class_name]:
                if file == file_name:
                    class_exist = True
                    break

        if not class_exist:
            ## 3.2 Search in the imports of the specific file
            res = self._search_class_or_func_in_file_import_libs(class_name, fpath)

            if res:
                import_desc, search_res = res

                tool_output = f"Found class '{class_name}' is imported in file '{fpath}'.\n\n"
                tool_output = tool_output + import_desc

                return tool_output, SearchStatus.FIND_NONE, []
            else:
                tool_output = f"Could not find class '{class_name}' in file '{fpath}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Search the function in the specific class and file ----------------- #
        all_search_res: List[SearchResult] = self._search_func_in_class(method_name, class_name)

        all_search_res = [res for res in all_search_res if res.file_path == file_name]

        if not all_search_res:
            tool_output = f"Could not find method '{method_name}' in class '{class_name}' in file '{fpath}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (5) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in class '{class_name}' in file '{fpath}':\n\n"
        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, SearchStatus.FIND_ANY, all_search_res


    def get_classes_and_methods_in_file(self, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        pass

