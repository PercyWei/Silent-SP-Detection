# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_manage.py
import json
import os
import re
import sys
import glob

from typing import *
from collections import defaultdict
from collections.abc import MutableMapping
from abc import abstractmethod

from agent_app import globals, globals_opt
from agent_app.search import search_util
from agent_app.search.search_util import PySearchResult, JavaSearchResult
from agent_app.static_analysis.py_ast_parse import ASTParser as PyASTParser
from agent_app.static_analysis.java_ast_parse import ASTParser as JavaASTParser
from agent_app.data_structures import (
    LineRange, CodeRange,
    PyDiffFileInfo, JavaDiffFileInfo,
    SearchStatus
)


# For Python & Java
ClassIndexType = MutableMapping[str, List[CodeRange]]
MethodInClassIndexType = MutableMapping[str, MutableMapping[str, List[CodeRange]]]

# Only for Python
FuncIndexType = MutableMapping[str, List[CodeRange]]
PyFileImportType = MutableMapping[str, List[Tuple[str, str, str]]]

# Only for Java
IfaceIndexType = MutableMapping[str, List[CodeRange]]
IfaceInClassIndexType = MutableMapping[str, MutableMapping[str, List[CodeRange]]]
ClassInClassIndexType = MutableMapping[str, MutableMapping[str, List[CodeRange]]]
JavaFileImportType = MutableMapping[str, List[str]]


RESULT_SHOW_LIMIT = 3


"""BASE SEARCH MANAGER"""


class BaseSearchManager:

    def __init__(self, local_repo_dpath: str, **kwargs):
        # Basic Info
        self.local_repo_dpath = local_repo_dpath
        self.parsed_files: List[str] = []
        self.parsed_failed_files: List[str] = []


    """UPDATE"""


    @abstractmethod
    def _update_parsed_files(self):
        pass


    """UTILS"""


    @staticmethod
    def find_overlap_line_ranges_from_code_ranges(
            old_code_ranges: List[CodeRange],
            new_code_ranges: List[CodeRange],
            file_line_id_old2merge: Dict[str, Dict[int, int]],
            file_line_id_new2merge: Dict[str, Dict[int, int]]
    ) -> Dict[str, List[Tuple[List[LineRange], List[LineRange]]]]:
        """
        Find line ranges in 'old_code_ranges' and 'new_code_ranges' that belongs to the same structure
        before and after the modification.
        """
        # (1) Group line ranges by file path
        file_lranges: Dict[str, Tuple[List[LineRange], List[LineRange]]] = defaultdict(lambda: ([], []))
        for code_range in old_code_ranges:
            file_lranges[code_range.file_path][0].append(code_range.range)
        for code_range in new_code_ranges:
            file_lranges[code_range.file_path][1].append(code_range.range)

        # (2) Match old and new line ranges
        file_lrange_groups: Dict[str, List[Tuple[List[LineRange], List[LineRange]]]] = {}
        for fpath, (old_lranges, new_lranges) in file_lranges.items():
            lrange_group = search_util.group_overlap_struct_line_range(
                old_lranges, new_lranges, file_line_id_old2merge[fpath], file_line_id_new2merge[fpath]
            )
            file_lrange_groups[fpath] = lrange_group

        return file_lrange_groups


    """PRE-CHECK"""


    def file_name_pre_check(self, tool_name: str, file_name: str) -> Tuple[str, SearchStatus | None, str | None]:
        """Determine if the given file name is detailed enough to specify a unique file.

        This function should be called before calling a tool which requires a file name.
        Args:
            tool_name (str): Name of the tool to check.
            file_name (str): File name.
        Returns:
            str: Tool output.
            SearchStatus | None: Search status.
            str | None: Unique file path (RELATIVE).
        """
        cand_fpaths = [f for f in self.parsed_files if f.endswith(file_name)]

        if len(cand_fpaths) == 0:
            return f"Could not find file '{file_name}' in the repo.", SearchStatus.FIND_NONE, None

        elif len(cand_fpaths) == 1:
            return "", None, cand_fpaths[0]

        else:
            tool_output = f"Found {len(cand_fpaths)} files with name '{file_name}':\n"
            for idx, fpath in enumerate(cand_fpaths):
                tool_output += f"\n- file {idx + 1}: {fpath}"
            tool_output += f"\nPlease specify a detailed file name and call the search API '{tool_name}' again."

            return tool_output, SearchStatus.WIDE_SEARCH_RANGE, None


"""PYTHON SEARCH MANAGER"""


class PySearchManager(BaseSearchManager):

    def __init__(
            self,
            local_repo_dpath: str,
            del_files: List[str],
            add_files: List[str],
            mod_files: List[str],
            file_diff_info: Dict[str, PyDiffFileInfo]
    ):
        ## NOTE: All paths that appear below are RELATIVE paths (relative to repo root)

        # -------------------------------- I. Basic Info -------------------------------- #
        super().__init__(local_repo_dpath)

        # -------------------------------- II. Commit / Changed Files Info -------------------------------- #
        self.diff_files: List[str] = []
        self.del_files: List[str] = []
        self.add_files: List[str] = []
        self.mod_files: List[str] = []

        # file path -> file content
        self.old_code: Dict[str, str] = {}
        self.new_code: Dict[str, str] = {}
        self.merge_code: Dict[str, str] = {}

        self.line_id_old2new: Dict[str, Dict[int, int]] = {}    # file path -> {line id old -> line id new}
        self.line_id_old2merge: Dict[str, Dict[int, int]] = {}  # file path -> {line id old -> line id merged}
        self.line_id_new2merge: Dict[str, Dict[int, int]] = {}  # file path -> {line id new -> line id merged}

        self.old_func_index: FuncIndexType = defaultdict(list)    # name  -> [(file path, line range)]
        self.old_class_index: ClassIndexType = defaultdict(list)  # name  -> [(file path, line range)]
        self.old_inclass_method_index: MethodInClassIndexType = defaultdict(lambda: defaultdict(list))  # class name -> {name -> [(file path, line range)]}

        self.new_func_index: FuncIndexType = defaultdict(list)    # name  -> [(file path, line range)]
        self.new_class_index: ClassIndexType = defaultdict(list)  # name  -> [(file path, line range)]
        self.new_inclass_method_index: MethodInClassIndexType = defaultdict(lambda: defaultdict(list))  # class name -> {name -> [(file path, line range)]}

        self.diff_file_imports: PyFileImportType = {}  # file path -> [(package path, attr name, alias name)]

        # -------------------------------- III. Unchanged Files Info -------------------------------- #
        self.nodiff_files: List[str] = []

        self.nodiff_func_index: FuncIndexType = defaultdict(list)    # name  -> [(file path, line range)]
        self.nodiff_class_index: ClassIndexType = defaultdict(list)  # name  -> [(file path, line range)]
        self.nodiff_inclass_method_index: MethodInClassIndexType = defaultdict(lambda: defaultdict(list))  # class name -> {name -> [(file path, line range)]}

        self.nodiff_file_imports: PyFileImportType = {}  # file path -> [(package path, attr name, alias name)]

        # -------------------------------- IV. AST Parser -------------------------------- #
        self.ast_parser = PyASTParser()

        # -------------------------------- Update -------------------------------- #
        self.update(del_files, add_files, mod_files, file_diff_info)


    """UPDATE"""


    def update(
            self,
            del_files: List[str],
            add_files: List[str],
            mod_files: List[str],
            file_diff_info: Dict[str, PyDiffFileInfo]
    ) -> None:
        # Step 1: Update commit files info
        self._update_commit_file_info(del_files, add_files, mod_files, file_diff_info)

        # Step 2: Update unchanged files info
        self._update_nodiff_file_info()

        # Step 3: Collect all parsed files
        self._update_parsed_files()


    def _update_commit_file_info(
            self,
            del_files: List[str],
            add_files: List[str],
            mod_files: List[str],
            file_diff_info: Dict[str, PyDiffFileInfo]
    ) -> None:
        """For recording information of files involved in the commit.
        NOTE: All information has been processed in the commit_manager.
        """
        ## File paths
        self.del_files = del_files
        self.add_files = add_files
        self.mod_files = mod_files
        self.diff_files = self.del_files + self.add_files + self.mod_files

        for file_path, diff_info in file_diff_info.items():
            ## File contents
            if diff_info.old_code is not None:
                self.old_code[file_path] = diff_info.old_code
            if diff_info.new_code is not None:
                self.new_code[file_path] = diff_info.new_code
            self.merge_code[file_path] = diff_info.merge_code

            ## Line id mapping
            # NOTE: Deleted and added files have no line id mapping
            if file_path in self.mod_files:
                self.line_id_old2new[file_path] = diff_info.line_id_old2new
                self.line_id_old2merge[file_path] = diff_info.line_id_old2merge
                self.line_id_new2merge[file_path] = diff_info.line_id_new2merge

            ## Struct indexes
            for name, lrange in diff_info.old_func_index:
                self.old_func_index[name].append(CodeRange(file_path, lrange))
            for name, lrange in diff_info.old_class_index:
                self.old_class_index[name].append(CodeRange(file_path, lrange))
            for class_name, inclass_methods in diff_info.old_inclass_method_index.items():
                for name, lrange in inclass_methods:
                    self.old_inclass_method_index[class_name][name].append(CodeRange(file_path, lrange))

            for name, lrange in diff_info.new_func_index:
                self.new_func_index[name].append(CodeRange(file_path, lrange))
            for name, lrange in diff_info.new_class_index:
                self.new_class_index[name].append(CodeRange(file_path, lrange))
            for class_name, inclass_methods in diff_info.new_inclass_method_index.items():
                for name, lrange in inclass_methods:
                    self.new_inclass_method_index[class_name][name].append(CodeRange(file_path, lrange))

            ## Imports
            self.diff_file_imports[file_path] = list(set(diff_info.old_imports + diff_info.new_imports))


    def _update_nodiff_file_info(self) -> None:
        """For recording information of files unchanged in the commit."""
        abs_file_paths = search_util.find_python_files(self.local_repo_dpath)

        for abs_file_path in abs_file_paths:
            rel_file_path = os.path.relpath(abs_file_path, self.local_repo_dpath)

            ## Step 1: Filter out diff files (in commit)
            if rel_file_path in self.diff_files:
                continue

            ## Step 2: Parse the code
            self.ast_parser.reset()
            set_flag = self.ast_parser.set(code=None, code_fpath=abs_file_path)
            assert set_flag

            parse_flag = self.ast_parser.parse_python_code()
            if not parse_flag:
                self.parsed_failed_files.append(rel_file_path)
                continue

            ## Step 3: Update info of nodiff file
            # Imports
            self.nodiff_file_imports[rel_file_path] = self.ast_parser.all_imports

            # Search indexes
            for name, lrange in self.ast_parser.all_funcs:
                self.nodiff_func_index[name].append(CodeRange(rel_file_path, lrange))
            for name, lrange in self.ast_parser.all_classes:
                self.nodiff_class_index[name].append(CodeRange(rel_file_path, lrange))
            for class_name, inclass_methods in self.ast_parser.all_inclass_methods.items():
                for name, lrange in inclass_methods:
                    self.nodiff_inclass_method_index[class_name][name].append(CodeRange(rel_file_path, lrange))


    def _update_parsed_files(self) -> None:
        self.parsed_files: List[str] = self.diff_files + self.nodiff_files


    """LIBRARY"""


    def is_path_in_repo(self, abs_pkg_path: str, attr_name: str) -> Tuple[str, str] | None:
        """Determine whether a path points to a package or module in the repo, and get its relative path to repo root.

        NOTE 1: `abs_pkg_path` could be path to package / module.
        NOTE 2: `attr_name` could be the name of package / module / class / function ....
        Args:
            abs_pkg_path (str): ABSOLUTE path to PACKAGE or MODULE.
            attr_name (str): Name of the package / module / class / function ....
        Returns:
            Tuple[str, str] | None:
                - str: RELATIVE path to PACKAGE or MODULE, i.e. DIR path or FILE path.
                - str: Name of imported code element (class / func / ...), '' if no code element is imported.
        """
        if not abs_pkg_path.startswith(self.local_repo_dpath):
            return None

        ## Case 1: abs_pkg_path` is a MODULE, `attr_name` is a code element (class / function ...)
        elif os.path.isfile(abs_pkg_path + ".py"):
            abs_pkg_path = abs_pkg_path + ".py"
            attr_name = attr_name

        ## Case 2: `abs_pkg_path` is a PACKAGE, `attr_name` is a PACKAGE
        elif os.path.isdir(os.path.join(abs_pkg_path, attr_name)):
            abs_pkg_path = os.path.join(abs_pkg_path, attr_name)
            attr_name = ''

        ## Case 3: `abs_pkg_path` is a PACKAGE, `attr_name` is a MODULE
        elif os.path.isfile(os.path.join(abs_pkg_path, attr_name + ".py")):
            abs_pkg_path = os.path.join(abs_pkg_path, attr_name + ".py")
            attr_name = ''

        ## Case 4: `abs_pkg_path` is a PACKAGE, `attr_name` is a code element (class / function ...)
        # NOTE: In this case, these imported code elements are usually written in __init__.py
        elif os.path.isdir(abs_pkg_path):
            abs_pkg_path = abs_pkg_path
            attr_name = attr_name

        ## Case 5: Other special cases, for example, dynamic import
        # ex: /urllib3_urllib3/src/urllib3/request.py
        else:
            rel_pkg_path = os.path.relpath(abs_pkg_path, self.local_repo_dpath)
            path_parts = rel_pkg_path.split("/")
            pkg_path = os.path.join(self.local_repo_dpath, path_parts[0])

            if not os.path.isdir(pkg_path):
                return None

            abs_pkg_path = abs_pkg_path
            attr_name = attr_name

        rel_pkg_path = os.path.relpath(abs_pkg_path, self.local_repo_dpath)

        return rel_pkg_path, attr_name


    def is_custom_lib(
            self,
            import_stmt_info: Tuple[str, str, str],
            abs_cur_fpath: str
    ) -> Tuple[bool, Tuple[str, str] | None]:
        """Determine whether an import is a custom library.

        NOTE 1: `local_cur_py_file` is ABSOLUTE path.
        NOTE 2: File paths in `repo_py_files` are all ABSOLUTE paths, i.e. root/projects/....
        Args:
            import_stmt_info (Tuple[str, str, str]):
                - str: pkg path (I. 'xx' in 'import xx'; II. 'xx.xx' in 'from xx.xx import xxx')
                - str: attr name (pkg / module / class / function ...)
                - str: alias name
            abs_cur_fpath (str): Current Python file path.
        Returns:
            bool: True if the import is a custom library, False otherwise.
            Tuple[str, str, str] | None:
                - str: Repo pacakge / module RELATIVE path, i.e. DIR path or FILE path.
                - str: Name of imported code element (class / function ...), '' if no code element is imported.
        """
        assert abs_cur_fpath.startswith(self.local_repo_dpath)

        pkg_path, attr_name, _ = import_stmt_info

        ###########################################################
        ########### Case 1: Form "from ..xx import xxx" ###########
        ###########################################################

        def _count_path_levels(path: str) -> int:
            l = 0
            for char in path:
                if char == '.':
                    l += 1
                else:
                    break
            return l

        if pkg_path.startswith("."):
            # cur_fpath: /root/...project/.../A/B/x.py
            # target (pkg_path): ..C.D -> levels: 2
            levels = _count_path_levels(pkg_path)

            # prefix -> /root/...project/.../A
            prefix = "/".join(abs_cur_fpath.split("/")[:-levels])
            # rest -> C/D
            rest = pkg_path[levels:].replace(".", "/")
            # abs_pkg_path: /root/...project/.../A/C/D <- /root/...project/.../A + C/D
            abs_pkg_path = os.path.join(prefix, rest)

            rel_pkg_path, attr_name = self.is_path_in_repo(abs_pkg_path, attr_name)

            return True, (rel_pkg_path, attr_name)

        ############################################################
        ########### Case 2: Form "from xx.xx import xxx" ###########
        ############################################################

        ## Option 1: Since the code may dynamically change the paths where Python looks for modules and packages,
        #       while importing custom packages or modules in the project, the search paths may be more than:
        #       1) the project root dir, and 2) the current dir, so here we search for all the possible paths for a match.
        # Adv: Comprehensive consideration
        # Dis: 1) Time consuming; 2) Possible false-classification

        pkg_path_regex = re.compile(re.escape(pkg_path.replace(".", "/")))
        abs_repo_fpaths = glob.glob(os.path.join(self.local_repo_dpath, "**/*.py"), recursive=True)

        for abs_py_fpath in abs_repo_fpaths:
            rel_py_path = os.path.relpath(abs_py_fpath, self.local_repo_dpath)

            match = pkg_path_regex.search(rel_py_path)

            if match:
                # repo_dpath: /root/.../project
                # abs_fpath:  /root/.../project/A/B/C/D/.../x.py
                # rel_fpath:  A/B/C/D/.../x.py
                # target (pkg_path): C.D <-> C/D

                # prefix -> A/B
                prefix = rel_py_path[:match.start()]
                # abs_pkg_path: /root/.../project/A/B/C/D <- /root/.../project + A/B + C/D
                abs_pkg_path = os.path.join(self.local_repo_dpath, prefix, pkg_path.replace(".", "/"))

                res = self.is_path_in_repo(abs_pkg_path, attr_name)
                if not res:
                    continue

                rel_pkg_path, attr_name = res

                return True, (rel_pkg_path, attr_name)

        ## Option 2: While importing custom packages or modules in the project, we only consider two paths for
        #       Python to find modules and packages: 1) the repo root dir, and 2) the current dir.
        # Adv: Simple logic and fast speed
        # Dis: Possible mis-classification

        # 1) Relative to REPO ROOT to import
        # abs_pkg_path = os.path.join(local_repo_dpath, pkg_path.replace(".", "/"))
        # res = _path_in_repo(abs_pkg_path, attr_name, local_repo_dpath)
        # if res:
        #     rel_pkg_path, attr_name = res
        #     return True, (rel_pkg_path, attr_name)
        #
        # # 2) Relative to CURRENT DIR
        # prefix = "/" + "/".join(abs_cur_fpath.split("/")[:-1])
        # abs_pkg_path = os.path.join(prefix, pkg_path.replace(".", "/"))
        # res = _path_in_repo(abs_pkg_path, attr_name, local_repo_dpath)
        # if res:
        #     rel_pkg_path, attr_name = res
        #     return True, (rel_pkg_path, attr_name)

        return False, None


    def is_standard_lib(self, import_stmt_info: Tuple[str, str, str]) -> Tuple[bool, Tuple[str, str] | None]:
        """Determine whether an import is a standard library.

        Args:
            import_stmt_info (Tuple[str, str, str]):
                - str: pkg path (I. 'xx' in 'import xx'; II. 'xx.xx' in 'from xx.xx import xxx').
                - str: attr name (pkg / module / class / function ...).
                - str: alias name.
        Returns:
            bool: True if the import is a standard library, False otherwise.
            Tuple[str, str, str] | None:
                - str: Lib name, like 'os', 'sys'.
                - str: Complete import path of package / module / ... , like 'os.path', 'os.path.join'.
        """
        pkg_path, attr_name, alias_name = import_stmt_info

        if pkg_path.startswith("."):
            return False, None

        try:
            local_pkg = __import__(pkg_path)
            local_pkg_path = getattr(local_pkg, '__file__', None)
            res = local_pkg_path is None or any(
                local_pkg_path.startswith(p) for p in sys.path if 'site-packages' not in p)
        except ModuleNotFoundError:
            return False, None
        except Exception:
            raise RuntimeError(f"Unsupported import path: {pkg_path}, {attr_name}, {alias_name}")

        if not res:
            return False, None

        lib_name = pkg_path.split(".")[0]
        if attr_name == "":
            # Import form is "import xxx" or "import xx.xxx"
            comp_import_path = pkg_path
        else:
            # Import form is "from xx.xx import xxx"
            comp_import_path = pkg_path + "." + attr_name

        return True, (lib_name, comp_import_path)


    def judge_lib_source(
            self,
            import_stmt_info: Tuple[str, str, str],
            abs_cur_fpath: str,
    ) -> Tuple[str, str]:
        """Judge the source of the library imported.

        Three types of sources: standard, third-party, custom
        Args:
            import_stmt_info (Tuple[str, str, str]):
                - str: pkg path (I. 'xx' in 'import xx'; II. 'xx.xx' in 'from xx.xx import xxx')
                - str: attr name (pkg / module / class / function ...)
                - str: alias name
            abs_cur_fpath (str): Current Python file path.
        Returns:
            str: Source of lib imported.
            str:
                - For standard lib or third-party lib: lib name.
                - For custom lib: package / module RELATIVE path.
        """
        ######## (1) Standard library ########
        res, stand_lib = self.is_standard_lib(import_stmt_info)
        if res:
            lib_name, _ = stand_lib
            return "standard library", lib_name

        ######## (2) Custom library ########
        res, custom_lib = self.is_custom_lib(import_stmt_info, abs_cur_fpath)
        if res:
            rel_pkg_path, attr_name = custom_lib
            return "custom library", rel_pkg_path

        ######## (3) Third-party library ########
        pkg_path, *_ = import_stmt_info
        lib_name = pkg_path.split(".")[0]

        return "third-party library", lib_name


    """EXTRACT CODE SNIPPET"""


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
            file_content = self.merge_code[fpath]


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
        class_sig = search_util.get_class_signature_from_nodiff_file(
            abs_fpath=abs_fpath,
            class_name=class_name,
            class_range=class_range,
            lang='Python'
        )
        return class_sig


    def _get_class_signature_in_diff_file(
            self, class_name: str, fpath: str, old_class_ranges: List[LineRange], new_class_ranges: List[LineRange]
    ) -> str:
        """Get class signature from the specified diff file."""
        assert fpath in self.diff_files
        # NOTE: Classes with the same name in a file are generally not allowed in Python (the former will be overwritten by the latter).
        assert 1 <= len(old_class_ranges) + len(new_class_ranges) <= 2

        old_class_range = old_class_ranges[0] if old_class_ranges else None
        new_class_range = new_class_ranges[0] if new_class_ranges else None

        merge_code = self.merge_code[fpath]
        old_code = self.old_code[fpath] if fpath in self.old_code else None
        new_code = self.new_code[fpath] if fpath in self.new_code else None

        line_id_old2merge = self.line_id_old2merge[fpath] if fpath in self.line_id_old2merge else None
        line_id_new2merge = self.line_id_new2merge[fpath] if fpath in self.line_id_new2merge else None

        class_sig_code = search_util.get_class_signature_from_diff_file(
            merge_file_content=merge_code,
            old_file_content=old_code,
            new_file_content=new_code,
            line_id_old2merge=line_id_old2merge,
            line_id_new2merge=line_id_new2merge,
            class_name=class_name,
            old_class_range=old_class_range,
            new_class_range=new_class_range,
            lang='Python'
        )

        return class_sig_code


    def _get_code_snippet_in_nodiff_file(self, fpath: str, line_range: LineRange) -> str:
        """Get code snippet from the specified nodiff file."""
        assert fpath in self.nodiff_files
        abs_fpath = os.path.join(self.local_repo_dpath, fpath)
        code = search_util.get_code_snippet_from_nodiff_file(abs_fpath, line_range.start, line_range.end)
        return code


    def _get_code_snippet_in_diff_file(
            self, fpath: str, old_line_ranges: List[LineRange], new_line_ranges: List[LineRange]
    ) -> str:
        """Get code snippet from the specified diff file."""
        assert fpath in self.diff_files
        merge_code = self.merge_code[fpath]
        snippet = search_util.get_code_snippet_from_diff_file(
            merge_code, old_line_ranges, new_line_ranges, self.line_id_old2merge[fpath], self.line_id_new2merge[fpath]
        )

        return snippet


    """SEARCH FUNCTIONS"""


    @staticmethod
    def lib_info_to_seq(pkg_path: str, attr_name: str, alias_name: str) -> str:
        if attr_name == "":
            import_seq = f"import {pkg_path}"
        else:
            import_seq = f"from {pkg_path} import {attr_name}"

        import_seq = import_seq + f" as {alias_name}" if alias_name != "" else import_seq

        return import_seq


    def _search_class_or_func_in_file_imports(self, call_name: str, file_path: str) -> Tuple[str, PySearchResult] | None:
        """Search for the class / function among the imported statements in the specified file.

        NOTE: We have confirmed that this file exists.
        Args:
            call_name (str): Function or class name.
            file_path (str): RELATIVE file path.
        Returns:
            Tuple[str, PySearchResult] | None:
                - str： A description of how this class / func was imported.
                - SearchResult: Corresponding search result.
        """
        if file_path in self.nodiff_files:
            file_import_libs = self.nodiff_file_imports[file_path]
        else:
            file_import_libs = self.diff_file_imports[file_path]

        call_source = call_name.split(".")[0]

        for import_lib in file_import_libs:
            pkg_path, attr_name, alias_name = import_lib
            abs_cur_fpath = os.path.join(self.local_repo_dpath, file_path)

            if alias_name == call_source or attr_name == call_source or pkg_path.endswith(call_source):
                lib_source, attr = self.judge_lib_source(import_lib, abs_cur_fpath)

                # FIXME: Instead of looking for the import statement in the original code, we reconstruct
                #       an individual import statement based on the current import. Are any improvements needed?
                import_seq = self.lib_info_to_seq(pkg_path, attr_name, alias_name)

                desc = f"It is imported through '{import_seq}'. The library is a {lib_source}, and "
                if lib_source == "custom library":
                    desc += f"the import path is '{attr}'."
                else:
                    desc += f"the library name is '{attr}'."

                res = PySearchResult(
                    file_path=file_path,
                    code=import_seq,
                    func_name=None,
                    class_name=None,
                    inclass_method_name=None
                )
                return desc, res

        return None


    def _search_method_in_class(self, func_name: str, class_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this method among the specified class in the repo / specified file."""
        result: List[PySearchResult] = []

        ############## (1) For inclass methods in nodiff file ##############
        nodiff_cand_inclass_methods: List[CodeRange] = self.nodiff_inclass_method_index.get(class_name, {}).get(func_name, [])
        for inclass_method_crange in nodiff_cand_inclass_methods:
            if file_path is None or inclass_method_crange.file_path == file_path:
                method_code = self._get_code_snippet_in_nodiff_file(
                    inclass_method_crange.file_path, inclass_method_crange.range
                )

                res = PySearchResult(
                    file_path=inclass_method_crange.file_path,
                    code=method_code,
                    func_name=None,
                    class_name=class_name,
                    inclass_method_name=func_name
                )
                result.append(res)

        ############## (2) For inclass methods in diff file ##############
        # 1. Get candidate inclass methods in the repo or specified file
        old_cand_inclass_methods: List[CodeRange] = self.old_inclass_method_index.get(class_name, {}).get(func_name, [])
        new_cand_inclass_methods: List[CodeRange] = self.new_inclass_method_index.get(class_name, {}).get(func_name, [])

        if file_path is not None:
            old_cand_inclass_methods = [crange for crange in old_cand_inclass_methods if crange.file_path == file_path]
            new_cand_inclass_methods = [crange for crange in new_cand_inclass_methods if crange.file_path == file_path]

        # 2. Process old and new candidate inclass methods
        file_inclass_method_lrange_groups = self.find_overlap_line_ranges_from_code_ranges(
            old_code_ranges=old_cand_inclass_methods,
            new_code_ranges=new_cand_inclass_methods,
            file_line_id_old2merge=self.line_id_old2merge,
            file_line_id_new2merge=self.line_id_new2merge
        )

        # 3. Get the code snippet of each modified inclass method
        for fpath, lrange_groups in file_inclass_method_lrange_groups.items():
            for old_lranges, new_lranges in lrange_groups:
                inclass_method_code = self._get_code_snippet_in_diff_file(fpath, old_lranges, new_lranges)

                res = PySearchResult(
                    file_path=fpath,
                    code=inclass_method_code,
                    func_name=None,
                    class_name=class_name,
                    inclass_method_name=func_name
                )
                result.append(res)

        return result


    def _search_func_in_classes(self, func_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this function among all classes in the repo / specified file."""
        result: List[PySearchResult] = []

        checked_class_names = []
        # (1) For class functions in nodiff file
        for class_name in self.nodiff_class_index:
            if class_name not in checked_class_names:
                checked_class_names.append(class_name)
                res = self._search_method_in_class(func_name, class_name, file_path)
                result.extend(res)

        # (2) For class functions in diff file
        for class_name in self.old_class_index:
            if class_name not in checked_class_names:
                checked_class_names.append(class_name)
                res = self._search_method_in_class(func_name, class_name, file_path)
                result.extend(res)

        for class_name in self.new_class_index:
            if class_name not in checked_class_names:
                checked_class_names.append(class_name)
                res = self._search_method_in_class(func_name, class_name, file_path)
                result.extend(res)

        return result


    def _search_top_level_func(self, func_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this function among all top level functions in the repo / specified file."""
        result: List[PySearchResult] = []

        ############## (1) For functions in nodiff file ##############
        if func_name in self.nodiff_func_index:
            for func_crange in self.nodiff_func_index[func_name]:
                if file_path is None or func_crange.file_path == file_path:
                    code = self._get_code_snippet_in_nodiff_file(func_crange.file_path, func_crange.range)

                    res = PySearchResult(
                        file_path=func_crange.file_path,
                        code=code,
                        func_name=func_name,
                        class_name=None,
                        inclass_method_name=None
                    )
                    result.append(res)

        ############## (2) For functions in diff file ##############
        # 1. Filter out candidate functions
        old_cand_funcs: List[CodeRange] = self.old_func_index[func_name] if func_name in self.old_func_index else []
        new_cand_funcs: List[CodeRange] = self.new_func_index[func_name] if func_name in self.new_func_index else []

        if file_path is not None:
            old_cand_funcs = [crange for crange in old_cand_funcs if crange.file_path == file_path]
            new_cand_funcs = [crange for crange in new_cand_funcs if crange.file_path == file_path]

        # 2. Process old and new candidate functions
        file_func_lrange_groups = self.find_overlap_line_ranges_from_code_ranges(
            old_cand_funcs, new_cand_funcs, self.line_id_old2merge, self.line_id_new2merge
        )

        # 3. Get the code snippet of each modified functions
        for fpath, func_lrange_groups in file_func_lrange_groups.items():
            for old_lranges, new_lranges in func_lrange_groups:
                code = self._get_code_snippet_in_diff_file(fpath, old_lranges, new_lranges)

                res = PySearchResult(
                    file_path=fpath,
                    code=code,
                    func_name=func_name,
                    class_name=None,
                    inclass_method_name=None
                )
                result.append(res)

        return result


    def _search_func(self, func_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this function in the repo / specified file, including top-level functions and class functions."""
        result: List[PySearchResult] = []

        # (1) Search among all top level functions
        top_level_res = self._search_top_level_func(func_name, file_path)
        result.extend(top_level_res)

        # (2) Search among all class methods
        class_res = self._search_func_in_classes(func_name, file_path)
        result.extend(class_res)

        return result


    def _search_nodiff_class(self, class_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this class among all nodiff classes in the repo / specified file."""

        result: List[PySearchResult] = []
        for class_crange in self.nodiff_class_index[class_name]:
            if file_path is None or class_crange.file_path == file_path:
                sig_code = self._get_class_signature_in_nodiff_file(
                    class_name, class_crange.file_path, class_crange.range
                )

                res = PySearchResult(
                    file_path=class_crange.file_path,
                    code=sig_code,
                    func_name=None,
                    class_name=class_name,
                    inclass_method_name=None
                )
                result.append(res)

        return result


    def _search_diff_class(self, class_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this class among all diff classes in the repo / specified file."""
        result: List[PySearchResult] = []

        # 1. Filter out candidate classes
        cand_old_classes: List[CodeRange] = self.old_class_index[class_name] if class_name in self.old_class_index else []
        cand_new_classes: List[CodeRange] = self.new_class_index[class_name] if class_name in self.new_class_index else []

        if file_path is not None:
            cand_old_classes = [crange for crange in cand_old_classes if crange.file_path == file_path]
            cand_new_classes = [crange for crange in cand_new_classes if crange.file_path == file_path]

        # 2. Process old and new candidate classes
        file_class_lrange_groups = self.find_overlap_line_ranges_from_code_ranges(
            cand_old_classes, cand_new_classes, self.line_id_old2merge, self.line_id_new2merge
        )

        # 3. Get the signature of each modified class
        for fpath, class_lrange_groups in file_class_lrange_groups.items():
            for old_lranges, new_lranges in class_lrange_groups:
                sig_code = self._get_class_signature_in_diff_file(class_name, fpath, old_lranges, new_lranges)

                res = PySearchResult(
                    file_path=fpath,
                    code=sig_code,
                    func_name=None,
                    class_name=class_name,
                    inclass_method_name=None
                )
                result.append(res)

        return result


    def _search_class(self, class_name: str, file_path: str | None = None) -> List[PySearchResult]:
        """Search for this class in the repo / specified file.
        NOTE：Normally, there will not be classes with the same name in a file, but just in case.
        """
        result: List[PySearchResult] = []

        if file_path is None or file_path in self.nodiff_files:
            res = self._search_nodiff_class(class_name, file_path)
            result.extend(res)

        if file_path is None or file_path in self.diff_files:
            res = self._search_diff_class(class_name, file_path)
            result.extend(res)

        return result


    """INTERFACES"""


    def search_code_in_file(self, code_str: str, file_path: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        # FIXME: Not complete!
        pass


    def search_top_level_function(self, func_name: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a top-level function in the codebase."""
        # ----------------- (1) Search the function in the repo ----------------- #
        if func_name not in self.old_func_index and func_name not in self.new_func_index \
                and func_name not in self.nodiff_func_index:
            tool_output = f"Could not find top-level function '{func_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (2) Get the entire snippet of the function ----------------- #
        all_search_res = self._search_top_level_func(func_name)

        # ----------------- (3) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} top-level functions with name '{func_name}' in the repo:\n"

        if globals_opt.opt_to_ctx_retrieval_detailed_search_struct_tool:
            if len(all_search_res) > RESULT_SHOW_LIMIT:
                # Too much functions, simplified representation
                tool_output += "\nThey appeared in the following files:\n"
                tool_output += PySearchResult.collapse_to_file_level(all_search_res)
            else:
                # Several functions, verbose representation
                for idx, res in enumerate(all_search_res):
                    res_str = res.to_tagged_str()
                    tool_output += (f"\n- Search result {idx + 1}:"
                                    f"\n```"
                                    f"\n{res_str}"
                                    f"\n```")
        else:
            tool_output += "\nThey appeared in the following files:\n"
            tool_output += JavaSearchResult.collapse_to_file_level(all_search_res)
            tool_output += "\nIf you want to get the detailed content of a function, please use the search API 'search_method_in_file(method_name, file_name)'"

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_class(self, class_name: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a class in the codebase."""
        # ----------------- (1) Search the class in the repo ----------------- #
        if class_name not in self.old_class_index and class_name not in self.new_class_index \
                and class_name not in self.nodiff_class_index:
            tool_output = f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (2) Get the signature of the class ----------------- #
        all_search_res = self._search_class(class_name)

        # ----------------- (3) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} classes with name '{class_name}' in the repo:\n"

        if globals_opt.opt_to_ctx_retrieval_detailed_search_struct_tool:
            if len(all_search_res) > RESULT_SHOW_LIMIT:
                # Too much classes, simplified representation
                tool_output += "\nThey appeared in the following files:\n"
                tool_output += PySearchResult.collapse_to_file_level(all_search_res)
            else:
                # Several classes, verbose representation
                for idx, res in enumerate(all_search_res):
                    res_str = res.to_tagged_str()
                    tool_output += (f"\n- Search result {idx + 1}:"
                                    f"\n```"
                                    f"\n{res_str}"
                                    f"\n```")
        else:
            tool_output += "\nThey appeared in the following files:\n"
            tool_output += JavaSearchResult.collapse_to_file_level(all_search_res)
            tool_output += "\nIf you want to get the detailed content of a class, please use the search API 'search_class_in_file(class_name, file_name)'"

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_method_in_file(self, method_name: str, file_name: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a method in a given file, including top-level function and inclass method."""
        # ----------------- (1) Check whether the file is valid and unique ----------------- #
        tool_output, search_status, file_path = self.file_name_pre_check(
            tool_name="search_method_in_file",
            file_name=file_name
        )
        if file_path is None:
            assert tool_output and search_status
            return tool_output, search_status, []

        # ----------------- (2) Search the function in the specified file ----------------- #
        ## 1. Search among the definitions in the specified file
        all_search_res: List[PySearchResult] = self._search_func(method_name, file_path)

        ## 2. Search among the imports in the specified file
        if not all_search_res:
            res = self._search_class_or_func_in_file_imports(method_name, file_path)

            if res:
                import_desc, search_res = res

                tool_output = (f"Found method '{method_name}' is imported in file '{file_path}'."
                               f"\n{import_desc}")

                return tool_output, SearchStatus.FIND_IMPORT, [search_res]
            else:
                tool_output = f"Could not find method '{method_name}' in file '{file_path}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in file '{file_path}':\n"

        # NOTE: When searching for a method in one file, it's rare that there are many candidates,
        #       so we do not trim the result
        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_class_in_file(self, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a class in a given file."""
        # ----------------- (1) Check whether the file is valid and unique ----------------- #
        tool_output, search_status, file_path = self.file_name_pre_check(
            tool_name="search_class_in_file",
            file_name=file_name
        )
        if file_path is None:
            assert tool_output and search_status
            return tool_output, search_status, []

        # ----------------- (2) Search the class in the specified file  ----------------- #
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

        # ----------------- (3) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} classes with name '{class_name}' in file '{file_path}':\n"

        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_method_in_class(self, method_name: str, class_name: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a method in a given class."""
        # ----------------- (1) Check whether the class exists ----------------- #
        if class_name not in self.old_class_index and class_name not in self.new_class_index \
                and class_name not in self.nodiff_class_index:
            tool_output = f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (2) Search the function in the specified classes ----------------- #
        all_search_res: List[PySearchResult] = self._search_method_in_class(method_name, class_name)

        if not all_search_res:
            # TODO: Consider whether to search among imports when no function definition is found.
            tool_output = f"Could not find method '{method_name}' in class '{class_name}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Prepare the response ----------------- #
        tool_output = f"Found {len(all_search_res)} methods with name '{method_name}' in class '{class_name}':\n"

        # NOTE: There can be multiple classes defined in multiple files, which contain the same method,
        #       so we still trim the result, just in case
        if len(all_search_res) > RESULT_SHOW_LIMIT:
            tool_output += f"\nToo many results, showing full code for {RESULT_SHOW_LIMIT} of them, and the rest just file names:"

        # (1) For the top-k, show detailed info
        top_k_res = all_search_res[:RESULT_SHOW_LIMIT]
        for idx, res in enumerate(top_k_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        # (2) For the rest, collect the file names into a set
        if rest := all_search_res[RESULT_SHOW_LIMIT:]:
            tool_output += "\nOther results are in these files:\n"
            tool_output += PySearchResult.collapse_to_file_level(rest)

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_method_in_class_in_file(self, method_name: str, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a method in a given class which is in a given file."""
        # ----------------- (1) Check whether the file is valid and unique ----------------- #
        tool_output, search_status, file_path = self.file_name_pre_check(
            tool_name="search_method_in_class_in_file",
            file_name=file_name
        )
        if file_path is None:
            assert tool_output and search_status
            return tool_output, SearchStatus.WIDE_SEARCH_RANGE, []

        # TODO: Consider whether to search class first.
        # ----------------- (2) Search the class in the specified file ----------------- #
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
        all_search_res: List[PySearchResult] = self._search_method_in_class(method_name, class_name, file_path)

        if not all_search_res:
            tool_output = f"Could not find method '{method_name}' in class '{class_name}' in file '{file_path}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (4) Prepare the response ----------------- #
        tool_output = f"In class '{class_name}' of file '{file_path}', found {len(all_search_res)} methods named '{method_name}':\n"

        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        return tool_output, SearchStatus.FIND_CODE, all_search_res


"""JAVA SEARCH MANAGER"""


class JavaSearchManager(BaseSearchManager):

    def __init__(
            self,
            local_repo_dpath: str,
            del_files: Dict[str, str | None],
            add_files: Dict[str, str | None],
            mod_files: Dict[str, str | None],
            file_diff_info: Dict[str, JavaDiffFileInfo]
    ):
        ## NOTE: All (file / dir) paths that appear below are RELATIVE paths (relative to repo root).

        # -------------------------------- I. Basic Info -------------------------------- #
        super().__init__(local_repo_dpath)

        self.standard_packages: List[str] = []
        # full package name -> dir path
        self.custom_packages: Dict[str, str | None] = {}
        # NOTE: Only for custom packages
        # full package name -> [type name] (type: class, interface, enum, record, annotation)
        self.package_space: Dict[str, List[str]] = {}

        # -------------------------------- II. Commit / Changed Files Info -------------------------------- #
        # file path -> full package name
        self.del_files: List[str] = []
        self.add_files: List[str] = []
        self.mod_files: List[str] = []
        self.diff_files: Dict[str, str | None] = {}

        # file path -> file content
        self.old_code: Dict[str, str] = {}
        self.new_code: Dict[str, str] = {}
        self.merge_code: Dict[str, str] = {}

        self.line_id_old2new: Dict[str, Dict[int, int]] = {}    # file path -> {line id old -> line id new}
        self.line_id_old2merge: Dict[str, Dict[int, int]] = {}  # file path -> {line id old -> line id merged}
        self.line_id_new2merge: Dict[str, Dict[int, int]] = {}  # file path -> {line id new -> line id merged}

        self.old_iface_index: IfaceIndexType = defaultdict(list)  # name -> [(file path, line range)]
        self.old_class_index: ClassIndexType = defaultdict(list)  # name -> [(file path, line range)]
        self.old_inclass_method_index: MethodInClassIndexType = defaultdict(lambda: defaultdict(list))  # class name -> {name -> [(file path, line range)]}
        self.old_inclass_iface_index: IfaceInClassIndexType = defaultdict(lambda: defaultdict(list))    # class name -> {name -> [(file path, line range)]}
        self.old_inclass_class_index: ClassInClassIndexType = defaultdict(lambda: defaultdict(list))    # class name -> {name -> [(file path, line range)]}

        self.new_iface_index: IfaceIndexType = defaultdict(list)  # name -> [(file path, line range)]
        self.new_class_index: ClassIndexType = defaultdict(list)  # name -> [(file path, line range)]
        self.new_inclass_method_index: MethodInClassIndexType = defaultdict(lambda: defaultdict(list))  # class name -> {name -> [(file path, line range)]}
        self.new_inclass_iface_index: IfaceInClassIndexType = defaultdict(lambda: defaultdict(list))    # class name -> {name -> [(file path, line range)]}
        self.new_inclass_class_index: ClassInClassIndexType = defaultdict(lambda: defaultdict(list))    # class name -> {name -> [(file path, line range)]}

        self.diff_file_imports: JavaFileImportType = {}  # file path -> [full import stmt]

        # -------------------------------- III. Unchanged Files Info -------------------------------- #
        # file path -> full package name
        self.nodiff_files: Dict[str, str | None] = {}

        self.nodiff_iface_index: IfaceIndexType = defaultdict(list)  # name -> [(file path, line range)]
        self.nodiff_class_index: ClassIndexType = defaultdict(list)  # name -> [(file path, line range)]
        self.nodiff_inclass_method_index: MethodInClassIndexType = defaultdict(lambda: defaultdict(list))  # class name -> {name -> [(file path, line range)]}
        self.nodiff_inclass_iface_index: IfaceInClassIndexType = defaultdict(lambda: defaultdict(list))    # class name -> {name -> [(file path, line range)]}
        self.nodiff_inclass_class_index: ClassInClassIndexType = defaultdict(lambda: defaultdict(list))    # class name -> {name -> [(file path, line range)]}

        self.nodiff_file_imports: JavaFileImportType = {}  # file path -> [full import stmt]

        # -------------------------------- IV. AST Parser -------------------------------- #
        self.ast_parser = JavaASTParser()

        # -------------------------------- Update -------------------------------- #
        self.update(del_files, add_files, mod_files, file_diff_info)


    """UPDATE"""


    @staticmethod
    def get_package_dir_path(full_package_name: str, file_path: str) -> str | None:
        full_package_name = full_package_name.replace('.', '/')

        dir_path = None
        if full_package_name in file_path:
            # Check
            file_dir = "/".join(file_path.split("/")[:-1])
            assert file_dir.endswith(full_package_name)

            last_sos = file_path.rfind(full_package_name)
            last_eos = last_sos + len(full_package_name)
            dir_path = file_path[:last_eos]

        return dir_path


    def update(
            self,
            del_files: Dict[str, str | None],
            add_files: Dict[str, str | None],
            mod_files: Dict[str, str | None],
            file_diff_info: Dict[str, JavaDiffFileInfo]
    ) -> None:
        # (1) Update commit files info
        self._update_commit_file_info(del_files, add_files, mod_files, file_diff_info)

        # (2) Update unchanged files info
        self._update_nodiff_file_info()

        # (3) Update package info
        self._update_all_packages()

        # (4) Collect all parsed files
        self._update_parsed_files()

        # (5) Update standard packages
        self._update_standard_packages()


    def _update_commit_file_info(
            self,
            del_files: Dict[str, str | None],
            add_files: Dict[str, str | None],
            mod_files: Dict[str, str | None],
            file_diff_info: Dict[str, JavaDiffFileInfo]
    ) -> None:
        """For recording information of files involved in the commit.
        NOTE: All information has been processed in the commit_manager.
        """
        ## File paths
        self.del_files: List[str] = list(del_files.keys())
        self.add_files: List[str] = list(add_files.keys())
        self.mod_files: List[str] = list(mod_files.keys())
        self.diff_files: Dict[str, str | None] = {**del_files, **add_files, **mod_files}

        for file_path, diff_info in file_diff_info.items():
            ## File contents
            if diff_info.old_code is not None:
                self.old_code[file_path] = diff_info.old_code
            if diff_info.new_code is not None:
                self.new_code[file_path] = diff_info.new_code
            self.merge_code[file_path] = diff_info.merge_code

            ## Line id mapping
            # NOTE: Deleted and added files have no line id mapping
            if file_path in self.mod_files:
                self.line_id_old2new[file_path] = diff_info.line_id_old2new
                self.line_id_old2merge[file_path] = diff_info.line_id_old2merge
                self.line_id_new2merge[file_path] = diff_info.line_id_new2merge

            ## Search indexes
            if diff_info.old_code is not None:
                for name, lrange in diff_info.old_iface_index:
                    self.old_iface_index[name].append(CodeRange(file_path, lrange))
                for name, lrange in diff_info.old_class_index:
                    self.old_class_index[name].append(CodeRange(file_path, lrange))
                for class_name, inclass_ifaces in diff_info.old_inclass_iface_index.items():
                    for name, lrange in inclass_ifaces:
                        self.old_inclass_iface_index[class_name][name].append(CodeRange(file_path, lrange))
                for class_name, inclass_classes in diff_info.old_inclass_class_index.items():
                    for name, lrange in inclass_classes:
                        self.old_inclass_class_index[class_name][name].append(CodeRange(file_path, lrange))
                for class_name, inclass_methods in diff_info.old_inclass_method_index.items():
                    for name, lrange in inclass_methods:
                        self.old_inclass_method_index[class_name][name].append(CodeRange(file_path, lrange))

            if diff_info.new_code is not None:
                for name, lrange in diff_info.new_iface_index:
                    self.new_iface_index[name].append(CodeRange(file_path, lrange))
                for name, lrange in diff_info.new_class_index:
                    self.new_class_index[name].append(CodeRange(file_path, lrange))
                for class_name, inclass_ifaces in diff_info.new_inclass_iface_index.items():
                    for name, lrange in inclass_ifaces:
                        self.new_inclass_iface_index[class_name][name].append(CodeRange(file_path, lrange))
                for class_name, inclass_classes in diff_info.new_inclass_class_index.items():
                    for name, lrange in inclass_classes:
                        self.new_inclass_class_index[class_name][name].append(CodeRange(file_path, lrange))
                for class_name, inclass_methods in diff_info.new_inclass_method_index.items():
                    for name, lrange in inclass_methods:
                        self.new_inclass_method_index[class_name][name].append(CodeRange(file_path, lrange))

            ## Imports
            file_imports = []
            if diff_info.old_code is not None:
                file_imports = diff_info.old_imports
            if diff_info.new_code is not None:
                file_imports = list(set(file_imports + diff_info.new_imports))
            self.diff_file_imports[file_path] = file_imports


    def _update_nodiff_file_info(self) -> None:
        """For recording information of files unchanged in the commit."""
        abs_file_paths = search_util.find_java_files(self.local_repo_dpath)

        for abs_file_path in abs_file_paths:
            rel_file_path = os.path.relpath(abs_file_path, self.local_repo_dpath)

            ## Step 1: Filter out diff files (in commit)
            if rel_file_path in self.diff_files:
                continue

            ## Step 2: Parse the code
            self.ast_parser.reset()
            set_flag = self.ast_parser.set(code=None, code_fpath=abs_file_path)
            assert set_flag

            parse_flag = self.ast_parser.parse_java_code()
            if not parse_flag:
                self.parsed_failed_files.append(rel_file_path)
                continue

            ## Step 3: Update info of nodiff file
            # File package
            self.nodiff_files[rel_file_path] = self.ast_parser.package_name

            # Imports
            self.nodiff_file_imports[rel_file_path] = self.ast_parser.all_imports

            # Search indexes
            for name, lrange in self.ast_parser.all_interfaces:
                self.nodiff_iface_index[name].append(CodeRange(rel_file_path, lrange))
            for name, lrange in self.ast_parser.all_classes:
                self.nodiff_class_index[name].append(CodeRange(rel_file_path, lrange))
            for class_name, inclass_ifaces in self.ast_parser.all_inclass_interfaces.items():
                for name, lrange in inclass_ifaces:
                    self.nodiff_inclass_iface_index[class_name][name].append(CodeRange(rel_file_path, lrange))
            for class_name, inclass_classes in self.ast_parser.all_inclass_classes.items():
                for name, lrange in inclass_classes:
                    self.nodiff_inclass_class_index[class_name][name].append(CodeRange(rel_file_path, lrange))
            for class_name, inclass_methods in self.ast_parser.all_inclass_methods.items():
                for name, lrange in inclass_methods:
                    self.nodiff_inclass_method_index[class_name][name].append(CodeRange(rel_file_path, lrange))


    def _update_all_packages(self) -> None:
        all_files = {**self.diff_files, **self.nodiff_files}

        for file_path, package_name in all_files.items():
            # (1) Current file has no package declaration
            if package_name is None:
                continue

            # (2) Current package has been successfully added
            if self.custom_packages.get(package_name, None) is not None:
                continue

            # (3) Add current package
            abs_pkg_dpath = None
            pkg_dpath = self.get_package_dir_path(package_name, file_path)

            if pkg_dpath is not None:
                abs_pkg_dpath = os.path.join(self.local_repo_dpath, pkg_dpath)
                assert os.path.isdir(abs_pkg_dpath)

            # 1. Package path
            self.custom_packages[package_name] = pkg_dpath

            # 2. Package types
            package_types: List[str] = []

            if abs_pkg_dpath is not None:
                for sub in os.listdir(abs_pkg_dpath):
                    if sub.endswith(".java"):
                        package_types.append(sub[:-5])

            self.package_space[package_name] = package_types


    def _update_parsed_files(self) -> None:
        self.parsed_files: List[str] = list(self.diff_files.keys()) + list(self.nodiff_files.keys())


    def _update_standard_packages(self) -> None:
        with open(globals.java_standard_packages_file, 'r') as f:
            self.standard_packages = json.load(f)


    """EXTRACT CODE SNIPPET"""


    def _get_class_signature_in_nodiff_file(self, class_name: str, fpath: str, class_range: LineRange) -> str:
        """Get class signature from the specified nodiff file.
        Strategy:
        Reason:"""
        assert fpath in self.nodiff_files
        abs_fpath = os.path.join(self.local_repo_dpath, fpath)
        class_sig = search_util.get_class_signature_from_nodiff_file(abs_fpath, class_name, class_range, lang='Java')
        return class_sig


    def _get_class_signature_in_diff_file(
            self, class_name: str, fpath: str, old_class_lranges: List[LineRange], new_class_lranges: List[LineRange]
    ) -> str:
        """Get class signature from the specified diff file."""
        assert fpath in self.diff_files
        # NOTE: In Java, it is not allowed for a file to contain classes with the same name.
        assert 1 <= len(old_class_lranges) + len(new_class_lranges) <= 2

        merge_code = self.merge_code[fpath]
        old_code = self.old_code[fpath] if fpath in self.old_code else None
        new_code = self.new_code[fpath] if fpath in self.new_code else None

        line_id_old2merge = self.line_id_old2merge[fpath] if fpath in self.line_id_old2merge else None
        line_id_new2merge = self.line_id_new2merge[fpath] if fpath in self.line_id_new2merge else None

        old_class_lrange = old_class_lranges[0] if old_class_lranges else None
        new_class_lrange = new_class_lranges[0] if new_class_lranges else None

        class_sig = search_util.get_class_signature_from_diff_file(
            merge_file_content=merge_code,
            old_file_content=old_code,
            new_file_content=new_code,
            line_id_old2merge=line_id_old2merge,
            line_id_new2merge=line_id_new2merge,
            class_name=class_name,
            old_class_range=old_class_lrange,
            new_class_range=new_class_lrange,
            lang='Java'
        )

        return class_sig


    def _get_iface_signature_in_nodiff_file(self, iface_name: str, fpath: str, iface_range: LineRange) -> str:
        """Get interface signature from the specified nodiff file.
        Strategy: For interface, we extract its entire snippet.
        Reason: Methods in the interface are all abstract methods, which has no method body but only method signature."""
        return self._get_code_snippet_in_nodiff_file(fpath, iface_range)


    def _get_iface_signature_in_diff_file(
            self, iface_name: str, fpath: str, old_iface_lranges: List[LineRange], new_iface_lranges: List[LineRange]
    ) -> str:
        """Get interface signature from the specified diff file.
        Strategy: For interface, we extract its entire snippet.
        Reason: Methods in the interface are all abstract methods, which has no method body but only method signature.
        """
        # NOTE: In Java, it is not allowed for a file to contain interfaces with the same name.
        assert 1 <= len(old_iface_lranges) + len(new_iface_lranges) <= 2

        return self._get_code_snippet_in_diff_file(fpath, old_iface_lranges, new_iface_lranges)


    def _get_code_snippet_in_nodiff_file(self, fpath: str, line_range: LineRange) -> str:
        """Get code snippet from the specified nodiff file."""
        assert fpath in self.nodiff_files
        abs_fpath = os.path.join(self.local_repo_dpath, fpath)
        code = search_util.get_code_snippet_from_nodiff_file(abs_fpath, line_range.start, line_range.end)
        return code


    def _get_code_snippet_in_diff_file(
            self, fpath: str, old_line_ranges: List[LineRange], new_line_ranges: List[LineRange]
    ) -> str:
        """Get code snippet from the specified diff file."""
        assert fpath in self.diff_files
        merge_code = self.merge_code[fpath]
        snippet = search_util.get_code_snippet_from_diff_file(
            merged_file_content=merge_code,
            old_line_ranges=old_line_ranges,
            new_line_ranges=new_line_ranges,
            line_id_old2merge=self.line_id_old2merge[fpath],
            line_id_new2merge=self.line_id_new2merge[fpath]
        )
        return snippet


    """SEARCH FUNCTIONS"""


    @staticmethod
    def find_match_package_for_import(import_name: str, cand_packages: List[str]) -> str | None:
        """Find the package which most likely to be the source of the import statement in the candidate packages.

        RULE 1: Matching packages should appear at the beginning of the import name.
        RULE 2: The matching package with the deepest level is most likely to be the source of the import.
        RULE 3: Candidate packages may not cover the import source, so we need to check the result.
        """
        match_pkg = ""
        for pkg in cand_packages:
            if import_name.startswith(pkg) and len(pkg) > len(match_pkg):
                match_pkg = pkg
        if match_pkg:
            return match_pkg
        else:
            return None


    def _search_type_in_file_imports(self, call_name: str, file_path: str) -> Tuple[str, JavaSearchResult] | None:
        """Search for the type among the imported statements in the specified file.

        NOTE 1: We have confirmed that this file exists.
        NOTE 2: The types imported include: class / interface / enum / record / annotation / method
        Args:
            call_name (str): Type name.
            file_path (str): RELATIVE file path.
        Returns:
            Tuple[str, JavaSearchResult] | None:
                - str： A description of how this type is imported.
                - JavaSearchResult: Corresponding search result.
        """
        ## While searching like 'A.B', get 'A' to search in the imports and package types
        call_source = call_name.split('.')[0]

        if file_path in self.nodiff_files:
            cur_package_name = self.nodiff_files[file_path]
            file_imports = self.nodiff_file_imports[file_path]
        else:
            cur_package_name = self.diff_files[file_path]
            file_imports = self.diff_file_imports[file_path]

        ## (1) Search in the types included in the current package
        if cur_package_name is not None:
            if call_source in self.package_space[cur_package_name]:
                desc = f"Type '{call_source}' is in the package where file '{file_path}' is located, and the package is '{cur_package_name}'."

                code = f"Since type '{call_source}' is in the same package as the current file, there is no need to import explicitly."
                res = JavaSearchResult(file_path=file_path, package_name=cur_package_name, code=code)

                return desc, res

        ## (2) Search in the types imported from other packages
        for full_import_stmt in file_imports:
            # There are two types of the full import statement:
            # 1. import xxx.xx
            # 2. import static xxx.xx
            import_stmt_parts = re.split(r'\s+', full_import_stmt)
            assert len(import_stmt_parts) == 2 or len(import_stmt_parts) == 3

            import_name = import_stmt_parts[-1]

            import_pkg = None
            import_pkg_type = None
            if import_name.endswith(".*"):
                # TODO: For now, we can only handle such imports from custom packages.
                import_pkg = self.find_match_package_for_import(import_name, list(self.custom_packages.keys()))
                if import_pkg is not None:
                    import_pkg_type = "custom package"

                    import_left_parts = import_name.split('.')[len(import_pkg.split('.')):-1]
                    if len(import_left_parts) > 0:
                        # TODO: For now, we do not search call in the specified file considering the cost.
                        # This statement imports types in a file of this package
                        # pkg_rel_dir_path = self.custom_packages[import_pkg]
                        # pkg_abs_dir_path = os.path.join(self.local_repo_dpath, pkg_rel_dir_path)
                        # import_file_path = os.path.join(pkg_abs_dir_path, import_left_parts[0] + ".java")
                        # assert os.path.isfile(import_file_path)
                        pass
                    else:
                        # This statement imports types in this package
                        if call_source in self.package_space[import_pkg]:
                            desc = f"Type {call_source} is imported through '{full_import_stmt}', the package is '{import_pkg}' and it is a {import_pkg_type}."
                            res = JavaSearchResult(file_path=file_path, package_name=import_pkg, code=full_import_stmt)
                            return desc, res
            else:
                if import_name.split('.')[-1] == call_source:

                    def _find_import_pkg_source() -> Tuple[str | None, str | None]:
                        # 1. Standard package
                        pkg = self.find_match_package_for_import(import_name, self.standard_packages)
                        if pkg is not None:
                            return pkg, "standard package"

                        # 2. Custom package
                        pkg = self.find_match_package_for_import(import_name, list(self.custom_packages.keys()))
                        if pkg is not None:
                            return pkg, "custom package"

                        return None, None

                    import_pkg, import_pkg_type = _find_import_pkg_source()

                    desc = f"Type {call_source} is imported through '{full_import_stmt}'"
                    if import_pkg is not None and import_pkg_type is not None:
                        desc += f", while the package is {import_pkg} and it is a {import_pkg_type}."
                    else:
                        # TODO: For packages not found, we believe it might to be a third-party package.
                        desc += ", while the package might to be a third-party package."
                    res = JavaSearchResult(file_path=file_path, package_name=import_pkg, code=full_import_stmt)

                    return desc, res

        return None


    def _search_type_in_class_of_nodiff_file(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str,
            file_path: str | None = None
    ) -> List[JavaSearchResult]:
        """Search for this type among the specified class in the repo / specified file.

        NOTE 1: We only consider nodiff files.
        NOTE 2: Type here indicate interface / class / method in class.
        """
        assert ttype in ['interface', 'class', 'method']

        if ttype == 'interface':
            nodiff_inclass_type_index = self.nodiff_inclass_iface_index
        elif ttype == 'class':
            nodiff_inclass_type_index = self.nodiff_inclass_class_index
        else:
            nodiff_inclass_type_index = self.nodiff_inclass_method_index

        result: List[JavaSearchResult] = []

        cand_inclass_types: List[CodeRange] = nodiff_inclass_type_index.get(class_name, {}).get(type_name, [])
        for cand_inclass_type in cand_inclass_types:
            if file_path is None or cand_inclass_type.file_path == file_path:
                # NOTE: For interface / class / method in class, we extract its entire code snippet.
                inclass_type_code = self._get_code_snippet_in_nodiff_file(
                    cand_inclass_type.file_path, cand_inclass_type.range
                )

                if ttype == 'interface':
                    res = JavaSearchResult(
                        file_path=cand_inclass_type.file_path,
                        class_name=class_name,
                        inclass_iface_name=type_name,
                        code=inclass_type_code
                    )
                elif ttype == 'class':
                    res = JavaSearchResult(
                        file_path=cand_inclass_type.file_path,
                        class_name=class_name,
                        inclass_class_name=type_name,
                        code=inclass_type_code
                    )
                else:
                    res = JavaSearchResult(
                        file_path=cand_inclass_type.file_path,
                        class_name=class_name,
                        inclass_method_name=type_name,
                        code=inclass_type_code
                    )

                result.append(res)

        return result


    def _search_type_in_class_of_diff_file(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str,
            file_path: str | None = None
    ) -> List[JavaSearchResult]:
        """Search for this type among the specified class in the repo / specified file.

        NOTE 1: We only consider diff files.
        NOTE 2: Type here indicate interface / class / method in class.
        """
        assert ttype in ['interface', 'class', 'method']

        if ttype == 'interface':
            old_inclass_type_index = self.old_inclass_iface_index
            new_inclass_type_index = self.new_inclass_iface_index
        elif ttype == 'class':
            old_inclass_type_index = self.old_inclass_class_index
            new_inclass_type_index = self.new_inclass_class_index
        else:
            old_inclass_type_index = self.old_inclass_method_index
            new_inclass_type_index = self.new_inclass_method_index

        # 1. Get candidate inclass types in the repo or specified file
        old_cand_inclass_types: List[CodeRange] = old_inclass_type_index.get(class_name, {}).get(type_name, [])
        new_cand_inclass_types: List[CodeRange] = new_inclass_type_index.get(class_name, {}).get(type_name, [])

        if file_path is not None:
            old_cand_inclass_types = [inclass_type for inclass_type in old_cand_inclass_types
                                      if inclass_type.file_path == file_path]
            new_cand_inclass_types = [inclass_type for inclass_type in new_cand_inclass_types
                                      if inclass_type.file_path == file_path]

        # 2. Process old and new candidate inclass types
        file_inclass_type_lrange_groups = self.find_overlap_line_ranges_from_code_ranges(
            old_code_ranges=old_cand_inclass_types,
            new_code_ranges=new_cand_inclass_types,
            file_line_id_old2merge=self.line_id_old2merge,
            file_line_id_new2merge=self.line_id_new2merge
        )

        # 3. Get the code snippet of each modified inclass type
        result: List[JavaSearchResult] = []
        for fpath, lrange_groups in file_inclass_type_lrange_groups.items():
            for old_lranges, new_lranges in lrange_groups:
                # NOTE: For interface / class / method in class, we extract its entire code snippet.
                inclass_type_code = self._get_code_snippet_in_diff_file(fpath, old_lranges, new_lranges)

                if ttype == 'interface':
                    res = JavaSearchResult(
                        file_path=fpath,
                        class_name=class_name,
                        inclass_iface_name=type_name,
                        code=inclass_type_code
                    )
                elif ttype == 'class':
                    res = JavaSearchResult(
                        file_path=fpath,
                        class_name=class_name,
                        inclass_class_name=type_name,
                        code=inclass_type_code
                    )
                else:
                    res = JavaSearchResult(
                        file_path=fpath,
                        class_name=class_name,
                        inclass_method_name=type_name,
                        code=inclass_type_code
                    )

                result.append(res)

        return result


    def _search_type_in_class(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str,
            file_path: str | None = None
    ) -> List[JavaSearchResult]:
        """Search for this type among the specified class in the repo / specified file.

        NOTE: Type here indicate interface / class / method in class.
        """
        assert ttype in ['interface', 'class', 'method']

        result: List[JavaSearchResult] = []

        if file_path is None or file_path in self.nodiff_files:
            res = self._search_type_in_class_of_nodiff_file(ttype, type_name, class_name, file_path)
            result.extend(res)

        if file_path is None or file_path in self.diff_files:
            res = self._search_type_in_class_of_diff_file(ttype, type_name, class_name, file_path)
            result.extend(res)

        return result


    def _search_top_level_type_of_nodiff_file(
            self,
            ttype: Literal['interface', 'class'],
            type_name: str,
            file_path: str | None = None
    ) -> List[JavaSearchResult]:
        """Search for this top-level type in the repo / specified file.

        NOTE 1: Top-level type here indicate top-level interface / class.
        NOTE 2: We only consider nodiff files.
        """
        assert ttype in ['interface', 'class']

        if ttype == "interface":
            nodiff_type_index = self.nodiff_iface_index
        else:
            nodiff_type_index = self.nodiff_class_index

        result: List[JavaSearchResult] = []

        cand_types: List[CodeRange] = nodiff_type_index.get(type_name, [])
        for cand_type in cand_types:
            if file_path is None or cand_type.file_path == file_path:
                # For top-level interface / class, we extract its signature code snippet.
                if ttype == "interface":
                    iface_sig = self._get_iface_signature_in_nodiff_file(
                        type_name, cand_type.file_path, cand_type.range
                    )
                    res = JavaSearchResult(file_path=cand_type.file_path, iface_name=type_name, code=iface_sig)
                else:
                    class_sig = self._get_class_signature_in_nodiff_file(
                        type_name, cand_type.file_path, cand_type.range
                    )
                    res = JavaSearchResult(file_path=cand_type.file_path, class_name=type_name, code=class_sig)

                result.append(res)

        return result


    def _search_top_level_type_of_diff_file(
            self,
            ttype: Literal['interface', 'class'],
            type_name: str,
            file_path: str | None = None
    ) -> List[JavaSearchResult]:
        """Search for this top-level type in the repo / specified file.

        NOTE 1: Top-level type here indicate top-level interface / class.
        NOTE 2: We only consider diff files.
        """
        assert ttype in ['interface', 'class']

        if ttype == "interface":
            old_type_index = self.old_iface_index
            new_type_index = self.new_iface_index
        else:
            old_type_index = self.old_class_index
            new_type_index = self.new_class_index

        # 1. Get candidate top-level classes / interfaces in the repo or specified file
        cand_old_types: List[CodeRange] = old_type_index[type_name] if type_name in old_type_index else []
        cand_new_types: List[CodeRange] = new_type_index[type_name] if type_name in new_type_index else []

        if file_path is not None:
            cand_old_types = [cand_type for cand_type in cand_old_types if cand_type.file_path == file_path]
            cand_new_types = [cand_type for cand_type in cand_new_types if cand_type.file_path == file_path]

        # 2. Process old and new candidate top-level classes / interfaces
        file_type_lrange_groups = self.find_overlap_line_ranges_from_code_ranges(
            old_code_ranges=cand_old_types,
            new_code_ranges=cand_new_types,
            file_line_id_old2merge=self.line_id_old2merge,
            file_line_id_new2merge=self.line_id_new2merge
        )

        # 3. Get the signature of each modified top-level class / interface
        result: List[JavaSearchResult] = []
        for fpath, type_lrange_groups in file_type_lrange_groups.items():
            for old_lranges, new_lranges in type_lrange_groups:
                # For top-level interface / class, we extract its signature code snippet.
                if ttype == "interface":
                    iface_sig = self._get_iface_signature_in_diff_file(type_name, fpath, old_lranges, new_lranges)
                    res = JavaSearchResult(file_path=fpath, iface_name=type_name, code=iface_sig)
                else:
                    class_sig = self._get_class_signature_in_diff_file(type_name, fpath, old_lranges, new_lranges)
                    res = JavaSearchResult(file_path=fpath, class_name=type_name, code=class_sig)

                result.append(res)

        return result


    def _search_top_level_type(
            self,
            ttype: Literal['interface', 'class'],
            type_name: str,
            file_path: str | None = None
    ) -> List[JavaSearchResult]:
        """Search for this top-level type in the repo / specified file.

        NOTE: Top-level type here indicate top-level interface / class.
        """
        assert ttype in ['interface', 'class']

        result: List[JavaSearchResult] = []

        if file_path is None or file_path in self.nodiff_files:
            res = self._search_top_level_type_of_nodiff_file(ttype, type_name, file_path)
            result.extend(res)

        if file_path is None or file_path in self.diff_files:
            res = self._search_top_level_type_of_diff_file(ttype, type_name, file_path)
            result.extend(res)

        return result


    """UNIFIED IMPLEMENTATION"""


    def search_top_level_type(
            self,
            ttype: Literal['interface', 'class'],
            type_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search class or interface in the entire repo.
        NOTE: Not a search API, just a unified implementation of search APIs 'search_class' and 'search_interface'.
        """
        assert ttype in ['interface', 'class']

        # ----------------- (1) Search the class / interface in the repo ----------------- #
        if ttype == 'interface':
            old_type_index = self.old_iface_index
            new_type_index = self.new_iface_index
            nodiff_type_index = self.nodiff_iface_index
        else:
            old_type_index = self.old_class_index
            new_type_index = self.new_class_index
            nodiff_type_index = self.nodiff_class_index

        if type_name not in old_type_index and type_name not in new_type_index and type_name not in nodiff_type_index:
            tool_output = f"Could not find {ttype} '{type_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (2) Get the signature of the classes / interfaces ----------------- #
        all_search_res = self._search_top_level_type(ttype, type_name)

        # ----------------- (3) Prepare the response ----------------- #
        if ttype == 'interface':
            tool_output = f"Found {len(all_search_res)} interfaces with name '{type_name}' in the repo:\n"
        else:
            tool_output = f"Found {len(all_search_res)} classes with name '{type_name}' in the repo:\n"

        if globals_opt.opt_to_ctx_retrieval_detailed_search_struct_tool:
            if len(all_search_res) > RESULT_SHOW_LIMIT:
                # Too much classes / interfaces, simplified representation
                tool_output += "\nThey appeared in the following files:\n"
                tool_output += JavaSearchResult.collapse_to_file_level(all_search_res)
            else:
                # Several classes / interfaces, verbose representation
                for idx, res in enumerate(all_search_res):
                    res_str = res.to_tagged_str()
                    tool_output += (f"\n- Search result {idx + 1}:"
                                    f"\n```"
                                    f"\n{res_str}"
                                    f"\n```")
        else:
            # TODO: Since there may be cases where, 'search_type' and 'search_type_in_file' appear at the same time,
            #       in order to avoid presenting the same code snippet repeatedly, we set the responsibilities of
            #       these two types of search APIs as follow:
            #       1. search_type: provide the file locations of the type;
            #       2. search_type_in_file: provide more detailed code snippets of the type.
            tool_output += "\nThey appeared in the following files:\n"
            tool_output += JavaSearchResult.collapse_to_file_level(all_search_res)
            if ttype == 'interface':
                tool_output += "\nIf you want to get the detailed content of an interface, please use the search API 'search_interface_in_file(iface_name, file_name)'"
            else:
                tool_output += "\nIf you want to get the detailed content of a class, please use the search API 'search_class_in_file(class_name, file_name)'"

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_top_level_type_in_file(
            self,
            ttype: Literal['interface', 'class'],
            type_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search class or interface in the specified file.
        NOTE: Not a search API, just a unified implementation of search APIs
              'search_class_in_file' and 'search_interface_in_file'.
        """
        assert ttype in ['interface', 'class']

        # ----------------- (1) Search the class / interface in the specified file  ----------------- #
        ## 1. Search among the definitions in the specified file
        if file_name in self.nodiff_files:
            all_search_res = self._search_top_level_type_of_nodiff_file(ttype, type_name, file_name)
        else:
            all_search_res = self._search_top_level_type_of_diff_file(ttype, type_name, file_name)

        ## 2. Search among the imports of the specified file
        if not all_search_res:
            res = self._search_type_in_file_imports(type_name, file_name)

            if res:
                import_desc, search_res = res

                tool_output = (f"Found {ttype} '{type_name}' is imported in file '{file_name}'."
                               f"\n{import_desc}")

                return tool_output, SearchStatus.FIND_IMPORT, [search_res]
            else:
                tool_output = f"Could not find {ttype} '{type_name}' in file '{file_name}'."
                return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (2) Prepare the response ----------------- #
        if ttype == "interface":
            tool_output = f"Found {len(all_search_res)} interfaces with name '{type_name}' in file '{file_name}':\n"
        else:
            tool_output = f"Found {len(all_search_res)} classes with name '{type_name}' in file '{file_name}':\n"

        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_inclass_type_in_class(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search inclass type in the specified class.

        NOTE 1: Not a search API, just a unified implementation of searching inclass type in class.
        NOTE 2: Inclass type here indicate inclass interface / class / method.
        """
        tool_output = ""
        if ttype not in ['interface', 'class', 'method']:
            old_ttype = ttype
            assert old_ttype.lower() in ['annotation', 'enum', 'record']
            ttype = 'interface' if old_ttype.lower() == 'annotation' else 'class'
            tool_output = f"NOTE: You called 'search_inclass_type_in_class' with 'ttype={old_ttype}', please use '{ttype}' next time.\n"

        # ----------------- (1) Check whether the class exists ----------------- #
        if all(class_name not in c for c in [self.old_class_index, self.new_class_index, self.nodiff_class_index]):
            tool_output += f"Could not find class '{class_name}' in the repo."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (2) Search the inclass type in the specified classes ----------------- #
        all_search_res: List[JavaSearchResult] = self._search_type_in_class(ttype, type_name, class_name)

        if not all_search_res:
            # TODO: Consider whether to search among imports when no type definition is found.
            tool_output += f"Could not find {ttype} '{type_name}' in class '{class_name}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Prepare the response ----------------- #
        if ttype == 'interface':
            tool_output += f"Found {len(all_search_res)} interfaces with name '{type_name}' in class '{class_name}':\n"
        elif ttype == 'class':
            tool_output += f"Found {len(all_search_res)} classes with name '{type_name}' in class '{class_name}':\n"
        else:
            tool_output += f"Found {len(all_search_res)} methods with name '{type_name}' in class '{class_name}':\n"

        # NOTE: There can be multiple classes defined in multiple files, which contain the types with the same name,
        #       so we still trim the result, just in case
        if len(all_search_res) > RESULT_SHOW_LIMIT:
            tool_output += f"\nToo many results, showing full code for {RESULT_SHOW_LIMIT} of them, and the rest just file names:"

        # 1. For the top-k, show detailed info
        top_k_res = all_search_res[:RESULT_SHOW_LIMIT]
        for idx, res in enumerate(top_k_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        # 2. For the rest, collect the file names into a set
        if rest := all_search_res[RESULT_SHOW_LIMIT:]:
            tool_output += "\nOther results are in these files:\n"
            tool_output += PySearchResult.collapse_to_file_level(rest)

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    def search_inclass_type_in_class_in_file(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search inclass type in the specified class and file.

        NOTE 1: Not a search API, just a unified implementation of searching inclass type in class within file.
        NOTE 2: Inclass type here indicate inclass interface / class / method.
        """
        tool_output = ""
        if ttype not in ['interface', 'class', 'method']:
            old_ttype = ttype
            assert old_ttype.lower() in ['annotation', 'enum', 'record']
            ttype = 'interface' if old_ttype.lower() == 'annotation' else 'class'
            tool_output = f"NOTE: You called 'search_inclass_type_in_class_in_file' with 'ttype={old_ttype}', please use '{ttype}' next time.\n"

        # TODO: Consider whether to search class first.
        # ----------------- (1) Search the class in the specified file ----------------- #
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

        # --------- (2) Search the interface / class / method in the specified class and file --------- #
        all_search_res: List[JavaSearchResult] = self._search_type_in_class(ttype, type_name, class_name, file_name)

        if not all_search_res:
            tool_output += f"In class '{class_name}' of file '{file_name}', found no inclass {ttype} named '{type_name}'."
            return tool_output, SearchStatus.FIND_NONE, []

        # ----------------- (3) Prepare the response ----------------- #
        if ttype == 'interface':
            tool_output += f"In class '{class_name}' of file '{file_name}', found {len(all_search_res)} inclass interfaces named '{type_name}':\n"
        elif ttype == 'class':
            tool_output += f"In class '{class_name}' of file '{file_name}', found {len(all_search_res)} inclass classes named '{type_name}':\n"
        else:
            tool_output += f"In class '{class_name}' of file '{file_name}', found {len(all_search_res)} inclass methods named '{type_name}':\n"

        for idx, res in enumerate(all_search_res):
            res_str = res.to_tagged_str()
            tool_output += (f"\n- Search result {idx + 1}:"
                            f"\n```"
                            f"\n{res_str}"
                            f"\n```")

        return tool_output, SearchStatus.FIND_CODE, all_search_res


    """INTERFACES"""


    def search_code_in_file(self, code_str: str, file_path: str) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        # FIXME: Not complete!
        pass


    def search_class_or_interface(self, type_name: str) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        # FIXME: Not complete!
        pass


    def search_class_or_interface_in_file(self, type_name: str, file_name: str) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        # FIXME: Not complete!
        pass


    def search_interface(
            self,
            iface_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for an interface in the codebase."""
        return self.search_top_level_type(ttype='interface', type_name=iface_name)


    def search_class(
            self,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a class in the codebase."""
        return self.search_top_level_type(ttype='class', type_name=class_name)


    def search_interface_in_file(
            self,
            iface_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for an interface in a given file."""
        tool_output, search_status, file_path = self.file_name_pre_check(
            tool_name="search_interface_in_file",
            file_name=file_name
        )
        if file_path is None:
            assert tool_output and search_status
            return tool_output, search_status, []

        return self.search_top_level_type_in_file(ttype='interface', type_name=iface_name, file_name=file_path)


    def search_class_in_file(
            self,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a class in a given file."""
        tool_output, search_status, file_path = self.file_name_pre_check(
            tool_name="search_class_in_file",
            file_name=file_name
        )
        if file_path is None:
            assert tool_output and search_status
            return tool_output, search_status, []

        return self.search_top_level_type_in_file(ttype='class', type_name=class_name, file_name=file_path)


    def search_type_in_class(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a type in a given class. 'Type' indicates interface or class or method."""
        return self.search_inclass_type_in_class(ttype, type_name, class_name)


    def search_type_in_class_in_file(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a type in a given class which is in a given file. 'Type' indicate interface or class or method."""
        tool_output, search_status, file_path = self.file_name_pre_check(
            tool_name="search_type_in_class_in_file",
            file_name=file_name
        )
        if file_path is None:
            assert tool_output and search_status
            return tool_output, search_status, []

        return self.search_inclass_type_in_class_in_file(ttype, type_name, class_name, file_path)
