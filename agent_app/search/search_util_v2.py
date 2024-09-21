# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_utils.py

import os
import sys
import re
import ast
import glob

from typing import *
from dataclasses import dataclass

from agent_app.data_structures import LineRange, CodeSnippetLocation
from agent_app.commit.parse import cal_class_or_func_def_range


@dataclass
class SearchResult(CodeSnippetLocation):
    """Dataclass to hold the search result containing the location of code snippet."""

    @staticmethod
    def collapse_to_file_level(lst) -> str:
        """Collapse search results to file level."""
        res = dict()  # file -> count
        for r in lst:
            if r.file_path not in res:
                res[r.file_path] = 1
            else:
                res[r.file_path] += 1
        res_str = ""
        for file_path, count in res.items():
            file_part = f"<file>{file_path}</file>"
            res_str += f"- {file_part} ({count} matches)\n"
        res_str.rstrip()
        return res_str

    @staticmethod
    def collapse_to_method_level(lst) -> str:
        """Collapse search results to method level."""
        res = dict()  # file -> dict(method -> count)
        for r in lst:
            if r.file_path not in res:
                res[r.file_path] = dict()
            func_str = r.func_name if r.func_name is not None else "Not in a function"
            if func_str not in res[r.file_path]:
                res[r.file_path][func_str] = 1
            else:
                res[r.file_path][func_str] += 1
        res_str = ""
        for file_path, funcs in res.items():
            file_part = f"<file>{file_path}</file>"
            for func, count in funcs.items():
                if func == "Not in a function":
                    func_part = func
                else:
                    func_part = f" <func>{func}</func>"
                res_str += f"- {file_part}{func_part} ({count} matches)\n"
        res_str.rstrip()
        return res_str


def find_python_files(dir_path: str) -> List[str]:
    """Get all .py files recursively from a directory.

    Skips files that are obviously not from the source code, such third-party library code.

    Args:
        dir_path (str): Path to the directory.
    Returns:
        List[str]: List of .py file paths. These paths are ABSOLUTE path!
    """
    abs_py_fpaths = glob.glob(os.path.join(dir_path, "**/*.py"), recursive=True)
    res = []
    for abs_fpath in abs_py_fpaths:
        rel_path = abs_fpath[len(dir_path) + 1:]
        if rel_path.startswith("build"):
            continue
        res.append(abs_fpath)
    return res


"""BUILD STRUCT INDEX"""


def parse_python_code(file_content: str) -> Tuple[List, List, List, Dict] | None:
    """Main method to parse AST and build search index."""
    try:
        tree = ast.parse(file_content)
    except Exception:
        # Failed to read/parse one file, we should ignore it
        return None

    import_libs: List[Tuple[str, str, str]] = []                # [(pkg path, attr name, alias name)]
    ## NOTE: The following 'start' and 'end' are both 1-based.
    funcs: List[Tuple[str, int, int]] = []                      # [(func name, start, end)]
    classes: List[Tuple[str, int, int]] = []                    # [(class name, start, end)]
    class_to_funcs: Dict[str, List[Tuple[str, int, int]]] = {}  # {class name -> [(class func name, start, end)]}

    for child in ast.iter_child_nodes(tree):
        ###### (1) Import libraries ######
        if isinstance(child, ast.Import):
            for alias in child.names:
                pkg_path = alias.name if alias.name is not None else ""
                attr_name = ""
                alias_name = alias.asname if alias.asname is not None else ""
                # ori_stmt = get_code_snippet_in_file(file_content, child.lineno, child.end_lineno)

                import_libs.append((pkg_path, attr_name, alias_name))

        if isinstance(child, ast.ImportFrom):
            module_path = child.level * "." + child.module if child.module is not None else child.level * "."
            # ori_stmt = get_code_snippet_in_file(file_content, child.lineno, child.end_lineno)

            for alias in child.names:
                attr_name = alias.name if alias.name is not None else ""
                alias_name = alias.asname if alias.asname is not None else ""

                import_libs.append((module_path, attr_name, alias_name))

        ###### (2) Function ######
        if isinstance(child, ast.FunctionDef) or isinstance(child, ast.AsyncFunctionDef):
            start_lineno, end_lineno = cal_class_or_func_def_range(child)
            funcs.append((child.name, start_lineno, end_lineno))

        if isinstance(child, ast.ClassDef):
            ###### (3) Class ######
            start_lineno, end_lineno = cal_class_or_func_def_range(child)
            classes.append((child.name, start_lineno, end_lineno))

            ###### (4) Class function ######
            class_funcs = []
            for node in ast.walk(child):
                if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    start_lineno, end_lineno = cal_class_or_func_def_range(node)
                    class_funcs.append((node.name, start_lineno, end_lineno))
            class_to_funcs[child.name] = class_funcs

    return import_libs, funcs, classes, class_to_funcs


"""EXTRACT IMPORTED LIB"""


def lib_info_to_seq(pkg_path: str, attr_name: str, alias_name: str) -> str:
    if attr_name == "":
        import_seq = f"import {pkg_path}"
    else:
        import_seq = f"from {pkg_path} import {attr_name}"

    import_seq = import_seq + f" as {alias_name}" if alias_name != "" else import_seq

    return import_seq


def _path_in_repo(abs_pkg_path: str, attr_name: str, local_repo_dpath: str) -> Tuple[str, str] | None:
    """Determine whether a path points to a package or module in the repo, and get its relative path to repo root.

    NOTE 1: `abs_pkg_path` could be path to package / module.
    NOTE 2: `attr_name` could be the name of package / module / class / function ....
    Args:
        abs_pkg_path (str): ABSOLUTE path to PACKAGE or MODULE.
        attr_name (str): Name of the package / module / class / function ....
        local_repo_dpath (str): Local repo path.
    Returns:
        Tuple[str, str] | None:
            - str: RELATIVE path to PACKAGE or MODULE, i.e. DIR path or FILE path.
            - str: Name of imported code element (class / func / ...), '' if no code element is imported.
    """
    if not abs_pkg_path.startswith(local_repo_dpath):
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
        rel_pkg_path = os.path.relpath(abs_pkg_path, local_repo_dpath)
        path_parts = rel_pkg_path.split("/")
        pkg_path = os.path.join(local_repo_dpath, path_parts[0])

        if not os.path.isdir(pkg_path):
            return None

        abs_pkg_path = abs_pkg_path
        attr_name = attr_name

    rel_pkg_path = os.path.relpath(abs_pkg_path, local_repo_dpath)

    return rel_pkg_path, attr_name


def is_custom_lib(
        import_lib: Tuple[str, str, str],
        abs_cur_fpath: str,
        local_repo_dpath: str
) -> Tuple[bool, Tuple[str, str] | None]:
    """Determine whether an import is a custom library.

    NOTE 1: `local_cur_py_file` is ABSOLUTE path.
    NOTE 2: File paths in `repo_py_files` are all ABSOLUTE paths, i.e. root/projects/....
    Args:
        import_lib (Tuple[str, str, str]):
            - str: pkg path (I. 'xx' in 'import xx'; II. 'xx.xx' in 'from xx.xx import xxx')
            - str: attr name (pkg / module / class / function ...)
            - str: alias name
        abs_cur_fpath (str): Current Python file path.
        local_repo_dpath (str): Local repo root path.
    Returns:
        bool: True if the import is a custom library, False otherwise.
        Tuple[str, str, str] | None:
            - str: Repo pacakge / module RELATIVE path, i.e. DIR path or FILE path.
            - str: Name of imported code element (class / function ...), '' if no code element is imported.
    """
    assert abs_cur_fpath.startswith(local_repo_dpath)

    pkg_path, attr_name, _ = import_lib

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

        rel_pkg_path, attr_name = _path_in_repo(abs_pkg_path, attr_name, local_repo_dpath)

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
    abs_repo_fpaths = glob.glob(os.path.join(local_repo_dpath, "**/*.py"), recursive=True)

    for abs_py_fpath in abs_repo_fpaths:
        rel_py_path = os.path.relpath(abs_py_fpath, local_repo_dpath)

        match = pkg_path_regex.search(rel_py_path)

        if match:
            # repo_dpath: /root/.../project
            # abs_fpath:  /root/.../project/A/B/C/D/.../x.py
            # rel_fpath:  A/B/C/D/.../x.py
            # target (pkg_path): C.D <-> C/D

            # prefix -> A/B
            prefix = rel_py_path[:match.start()]
            # abs_pkg_path: /root/.../project/A/B/C/D <- /root/.../project + A/B + C/D
            abs_pkg_path = os.path.join(local_repo_dpath, prefix, pkg_path.replace(".", "/"))

            res = _path_in_repo(abs_pkg_path, attr_name, local_repo_dpath)
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


def is_standard_lib(import_lib: Tuple[str, str, str]) -> Tuple[bool, Tuple[str, str] | None]:
    """Determine whether an import is a standard library.

    Args:
        import_lib (Tuple[str, str, str]):
            - str: pkg path (I. 'xx' in 'import xx'; II. 'xx.xx' in 'from xx.xx import xxx').
            - str: attr name (pkg / module / class / function ...).
            - str: alias name.
    Returns:
        bool: True if the import is a standard library, False otherwise.
        Tuple[str, str, str] | None:
            - str: Lib name, like 'os', 'sys'.
            - str: Complete import path of package / module / ... , like 'os.path', 'os.path.join'.
    """
    pkg_path, attr_name, alias_name = import_lib

    if pkg_path.startswith("."):
        return False, None

    try:
        local_pkg = __import__(pkg_path)
        local_pkg_path = getattr(local_pkg, '__file__', None)
        res = local_pkg_path is None or any(local_pkg_path.startswith(p) for p in sys.path if 'site-packages' not in p)
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
        import_lib: Tuple[str, str, str],
        abs_cur_fpath: str,
        local_repo_dpath: str
) -> Tuple[str, str]:
    """Judge the source of the library imported.

    Three types of sources: standard, third-party, custom
    Args:
        import_lib (Tuple[str, str, str]):
            - str: pkg path (I. 'xx' in 'import xx'; II. 'xx.xx' in 'from xx.xx import xxx')
            - str: attr name (pkg / module / class / function ...)
            - str: alias name
        abs_cur_fpath (str): Current Python file path.
        local_repo_dpath (str): Local repo root path.
    Returns:
        str: Source of lib imported.
        str:
            - For standard lib or third-party lib: lib name.
            - For custom lib: package / module RELATIVE path.
    """
    ######## (1) Standard library ########
    res, stand_lib = is_standard_lib(import_lib)
    if res:
        lib_name, _ = stand_lib
        return "standard library", lib_name

    ######## (2) Custom library ########
    res, custom_lib = is_custom_lib(import_lib, abs_cur_fpath, local_repo_dpath)
    if res:
        rel_pkg_path, attr_name = custom_lib
        return "custom library", rel_pkg_path

    ######## (3) Third-party library ########
    pkg_path, *_ = import_lib
    lib_name = pkg_path.split(".")[0]

    return "third-party library", lib_name


"""COMBINE LINES"""


def is_overlap_in_comb_file(
        old_range: LineRange, line_id_old2comb: Dict[int, int],
        new_range: LineRange, line_id_new2comb: Dict[int, int]
) -> bool:
    old_comb_range = (line_id_old2comb[old_range.start], line_id_old2comb[old_range.end])
    new_comb_range = (line_id_new2comb[new_range.start], line_id_new2comb[new_range.end])
    return old_comb_range[0] >= new_comb_range[1] and old_comb_range[1] <= new_comb_range[0]


def match_overlap_structs(
        old_ranges: List[LineRange], line_id_old2comb: Dict[int, int],
        new_ranges: List[LineRange], line_id_new2comb: Dict[int, int]
) -> List[Tuple[LineRange | None, LineRange | None]]:
    """Find the corresponding snippets for several code snippets before and after modification.

    NOTE 1: All inputs are for the same file.
    NOTE 2: Here 'line range' is used to refer to the code snippet.
    NOTE 3: We only check whether there are unmodified lines in both code snippets, i.e. whether there is overlap.
    TODO: If a code snippet A is copied, deleted, and pasted to a new location B, although their functions are
          exactly the same, since they have no overlapping code lines in the combined code, they are considered
          as two independent code snippets, i.e. A is a deleted snippet and B is an added code snippet.
    """
    # [(old struct range, new struct range)]
    struct_pairs: List[Tuple[LineRange | None, LineRange | None]] = []

    # (1) Extract one item from 'old_ranges' at a time and search for the matching item in 'new_ranges'
    for i in range(len(old_ranges)):
        old_range = old_ranges[i]

        match_idx = None
        for j in range(len(new_ranges)):
            new_range = new_ranges[j]
            if is_overlap_in_comb_file(old_range, line_id_old2comb, new_range, line_id_new2comb):
                match_idx = j
                break

        if match_idx is not None:
            struct_pairs.append((old_range, new_ranges[match_idx]))
            new_ranges.pop(match_idx)
        else:
            struct_pairs.append((old_range, None))

    # (2) If there are any remaining items in ‘new_ranges’, it means that they are added structs
    for new_range in new_ranges:
        struct_pairs.append((None, new_range))

    return struct_pairs


"""EXTRACT CODE SNIPPET"""


def get_code_snippet_in_file(file_content: str, start: int, end: int) -> str:
    """Get the code snippet in the file according to the line ids, without line numbers.

    Args:
        file_content (str): File content.
        start (int): Start line number. (1-based)
        end (int): End line number. (1-based)
    """
    file_lines = file_content.splitlines(keepends=True)
    snippet = ""
    for i in range(start - 1, end):
        snippet += file_lines[i]
    return snippet


def get_code_snippet_in_diff_file(
        comb_file_content: str,
        old_line_range: LineRange | None, line_id_old2comb: Dict[int, int],
        new_line_range: LineRange | None, line_id_new2comb: Dict[int, int],
) -> str:
    """Get the code snippet in the range in the file, without line numbers.

    NOTE: For diff files, since we have stored them with the modifications in the search_manager,
          so we get their contents from there instead of the local repo.
    Args:
        comb_file_content (str): Content of combined file.
        old_line_range (LineRange | None): Line range in old file.
        line_id_old2comb (Dict[int, int] | None): Line id lookup dict, code before -> code comb.
        new_line_range (LineRange | None): Line range in new file.
        line_id_new2comb (Dict[int, int] | None): Line id lookup dict, code after -> code comb.
    """
    if old_line_range is None or new_line_range is None:
        # Deleted / added code snippet
        if old_line_range is not None:
            comb_start = line_id_old2comb[old_line_range.start]
            comb_end = line_id_old2comb[old_line_range.end]
        elif new_line_range is not None:
            comb_start = line_id_new2comb[new_line_range.start]
            comb_end = line_id_new2comb[new_line_range.end]
        else:
            raise RuntimeError("Input 'old_line_range' and 'new_line_range' cannot be None at the same time")

    else:
        # Modified code snippet
        assert line_id_old2comb is not None and line_id_new2comb is not None
        assert is_overlap_in_comb_file(old_line_range, line_id_old2comb, new_line_range, line_id_new2comb)

        comb_start = min(line_id_old2comb[old_line_range.start], line_id_new2comb[new_line_range.start])
        comb_end = max(line_id_old2comb[old_line_range.end], line_id_new2comb[new_line_range.end])

    comb_file_lines = comb_file_content.splitlines(keepends=True)
    snippet = ""
    for i in range(comb_start - 1, comb_end):
        snippet += comb_file_lines[i]

    return snippet


def get_code_snippets_in_nodiff_file(abs_fpath: str, start: int, end: int) -> str:
    """Get the code snippet in the range in the file, without line numbers.

    NOTE: For nodiff files, we get their contents from the local repo.
    Args:
        abs_fpath (str): Absolute path to the file.
        start (int): Start line number. (1-based)
        end (int): End line number. (1-based)
    """
    with open(abs_fpath, 'r') as f:
        file_content = f.readlines()
    snippet = ""
    for i in range(start - 1, end):
        snippet += file_content[i]
    return snippet


def extract_func_sig_lines_from_ast(func_ast: ast.FunctionDef) -> List[int]:
    """Extract the function signature from the AST node.

    Includes the decorators, method name, and parameters.
    Args:
        func_ast (ast.FunctionDef): AST of the function.
    Returns:
        List[int]: The source line numbers that contains the function signature (1-based).
    """
    func_start_line = func_ast.lineno
    if func_ast.decorator_list:
        # has decorators
        decorator_start_lines = [d.lineno for d in func_ast.decorator_list]
        decorator_first_line = min(decorator_start_lines)
        func_start_line = min(decorator_first_line, func_start_line)
    # decide end line from body
    if func_ast.body:
        # has body
        body_start_line = func_ast.body[0].lineno
        end_line = body_start_line - 1
    else:
        # no body
        end_line = func_ast.end_lineno
    assert end_line is not None
    return list(range(func_start_line, end_line + 1))


def extract_class_sig_lines_from_ast(class_ast: ast.ClassDef) -> List[int]:
    """Extract the class signature from the AST node.

    Args:
        class_ast (ast.ClassDef): AST of the class.
    Returns:
        List[int]: The source line numbers that contains the class signature (1-based).
    """
    # STEP (1): Extract the class signature
    sig_start_line = class_ast.lineno
    if class_ast.body:
        # has body
        body_start_line = class_ast.body[0].lineno
        sig_end_line = body_start_line - 1
    else:
        # no body
        sig_end_line = class_ast.end_lineno
    assert sig_end_line is not None
    sig_lines = list(range(sig_start_line, sig_end_line + 1))

    # STEP (2): Extract the function signatures and assign signatures
    for stmt in class_ast.body:
        if isinstance(stmt, ast.FunctionDef):
            sig_lines.extend(extract_func_sig_lines_from_ast(stmt))
        elif isinstance(stmt, ast.Assign):
            # for Assign, skip some useless cases where the assignment is to create docs
            stmt_str_format = ast.dump(stmt)
            if "__doc__" in stmt_str_format:
                continue
            # otherwise, Assign is easy to handle
            assert stmt.end_lineno is not None
            assign_range = list(range(stmt.lineno, stmt.end_lineno + 1))
            sig_lines.extend(assign_range)

    return sig_lines


def extract_class_sig_lines_from_file(file_content: str, class_name: str, class_range: LineRange) -> List[int]:
    tree = ast.parse(file_content)
    relevant_line_ids: List[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            ## Determine whether the node is the required class
            # 1. Check name
            if node.name != class_name:
                continue
            # 2. Check range
            start, end = cal_class_or_func_def_range(node)
            if start != class_range.start or end != class_range.end:
                continue

            ## Extract relevant lines
            relevant_line_ids = extract_class_sig_lines_from_ast(node)  # 1-based
            break

    # Normally, the class signature related lines should not be empty.
    assert relevant_line_ids

    return relevant_line_ids


def get_class_sig_lines_content(file_content: str, line_ids: List[int]) -> str:
    if not line_ids:
        return ""

    file_lines = file_content.splitlines(keepends=True)
    result = ""
    for line_id in line_ids:
        line_content: str = file_lines[line_id - 1]
        if line_content.strip().startswith("#"):
            # This kind of comment could be left until this stage.
            # Reason: # comments are not part of func body if they appear at beginning of func
            continue
        result += line_content

    return result


def get_class_signature_in_nodiff_file(abs_fpath: str, class_name: str, class_range: LineRange) -> str:
    """Get the class signature.

    NOTE: For nodiff files, we get their contents from the local repo.
    Args:
        abs_fpath (str): Absolute path to the file.
        class_name (str): Name of the class.
        class_range (LineRange): Line range of the class.
    """
    with open(abs_fpath, "r") as f:
        file_content = f.read()

    relevant_line_ids = extract_class_sig_lines_from_file(file_content, class_name, class_range)

    result = get_class_sig_lines_content(file_content, relevant_line_ids)

    return result


def get_class_signature_in_diff_file(
        comb_file_content: str, class_name: str,
        old_file_content: str | None, old_class_range: LineRange | None, line_id_old2comb: Dict[int, int] | None,
        new_file_content: str | None, new_class_range: LineRange | None, line_id_new2comb: Dict[int, int] | None
) -> str:
    """Get the class signature.

    Step 1: Find the signature lines of the specific class from the code before and after commit.
    Step 2: Query the line id lookup dict to find corresponding signature lines in combined code,
            and merge them to get the final signature lines.

    NOTE: For diff files, since we have stored them with the modifications in the search_manager,
          so we get their contents from there instead of the local repo.
    Args:
        comb_file_content (str): Content of combined file.
        class_name (str): Name of the class.
        old_file_content (str | None): Content of file before commit.
        old_class_range (LineRange | None): Line range of the class in old file.
        line_id_old2comb (Dict[int, int] | None): Line id lookup dict, code before -> code comb.
        new_file_content (str | None): Content of file after commit.
        new_class_range (LineRange | None): Line range of the class in new file.
        line_id_new2comb (Dict[int, int] | None): Line id lookup dict, code after -> code comb.
    """
    if old_file_content is None or new_file_content is None:
        # Deleted / added file
        if old_file_content is not None:
            assert line_id_old2comb is not None
            ori_content = old_file_content
            class_range = old_class_range
            line_id_ori2comb = line_id_old2comb
        else:
            assert line_id_new2comb is not None
            ori_content = new_file_content
            class_range = new_class_range
            line_id_ori2comb = line_id_new2comb

        relevant_line_ids = extract_class_sig_lines_from_file(ori_content, class_name, class_range)

        comb_relevant_line_ids = [line_id_ori2comb[li] for li in relevant_line_ids]

        result = get_class_sig_lines_content(comb_file_content, comb_relevant_line_ids)

    else:
        # Modified file
        assert line_id_old2comb is not None and line_id_new2comb is not None
        assert is_overlap_in_comb_file(old_class_range, line_id_old2comb, new_class_range, line_id_new2comb)

        old_relevant_line_ids = extract_class_sig_lines_from_file(old_file_content, class_name, old_class_range)
        new_relevant_line_ids = extract_class_sig_lines_from_file(new_file_content, class_name, new_class_range)

        comb_relevant_line_ids = []
        for old_line_id in old_relevant_line_ids:
            comb_relevant_line_ids.append(line_id_old2comb[old_line_id])

        for new_line_id in new_relevant_line_ids:
            comb_relevant_line_ids.append(line_id_new2comb[new_line_id])

        comb_relevant_line_ids = sorted(list(set(comb_relevant_line_ids)))

        result = get_class_sig_lines_content(comb_file_content, comb_relevant_line_ids)

    return result
