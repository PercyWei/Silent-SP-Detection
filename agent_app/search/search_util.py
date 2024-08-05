# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_utils.py

import os
import re
import ast
import glob
import pathlib

from typing import *
from dataclasses import dataclass

from agent_app.util import to_relative_path


@dataclass
class SearchResult:
    """Dataclass to hold search results."""

    file_path: str  # This is absolute path
    class_name: str | None
    func_name: str | None
    code: str

    def to_tagged_upto_file(self, project_root: str) -> str:
        """Convert the search result to a tagged string, upto file path."""
        rel_path = to_relative_path(self.file_path, project_root)
        file_part = f"<file>{rel_path}</file>"
        return file_part

    def to_tagged_upto_class(self, project_root: str) -> str:
        """Convert the search result to a tagged string, upto class."""
        prefix = self.to_tagged_upto_file(project_root)
        class_part = f"<class>{self.class_name}</class>" if self.class_name is not None else ""
        return f"{prefix}\n{class_part}"

    def to_tagged_upto_func(self, project_root: str) -> str:
        """Convert the search result to a tagged string, upto function."""
        prefix = self.to_tagged_upto_class(project_root)
        func_part = f" <func>{self.func_name}</func>" if self.func_name is not None else ""
        return f"{prefix}{func_part}"

    def to_tagged_str(self, project_root: str) -> str:
        """Convert the search result to a tagged string."""
        prefix = self.to_tagged_upto_func(project_root)
        code_part = f"<code>\n{self.code}\n</code>"
        return f"{prefix}\n{code_part}"

    @staticmethod
    def collapse_to_file_level(lst, project_root: str) -> str:
        """Collapse search results to file level."""
        res = dict()  # file -> count
        for r in lst:
            if r.file_path not in res:
                res[r.file_path] = 1
            else:
                res[r.file_path] += 1
        res_str = ""
        for file_path, count in res.items():
            rel_path = to_relative_path(file_path, project_root)
            file_part = f"<file>{rel_path}</file>"
            res_str += f"- {file_part} ({count} matches)\n"
        return res_str

    @staticmethod
    def collapse_to_method_level(lst, project_root: str) -> str:
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
            rel_path = to_relative_path(file_path, project_root)
            file_part = f"<file>{rel_path}</file>"
            for func, count in funcs.items():
                if func == "Not in a function":
                    func_part = func
                else:
                    func_part = f" <func>{func}</func>"
                res_str += f"- {file_part}{func_part} ({count} matches)\n"
        return res_str


def find_python_files(dir_path: str) -> list[str]:
    """Get all .py files recursively from a directory.

    Skips files that are obviously not from the source code, such third-party library code.

    Args:
        dir_path (str): Path to the directory.
    Returns:
        List[str]: List of .py file paths. These paths are ABSOLUTE path!
    """
    py_files = glob.glob(os.path.join(dir_path, "**/*.py"), recursive=True)
    res = []
    for file in py_files:
        rel_path = file[len(dir_path) + 1:]
        if rel_path.startswith("build"):
            continue
        res.append(file)
    return res


def get_top_level_funcs(node: ast.AST):
    top_level_funcs: List[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef) or isinstance(child, ast.AsyncFunctionDef):
            top_level_funcs.append(child)

    return top_level_funcs


def parse_python_file(abs_fpath: str) -> Tuple[List, Dict, List] | None:
    """
    Main method to parse AST and build search index.
    Handles complication where python ast module cannot parse a file.
    """
    try:
        file_content = pathlib.Path(abs_fpath).read_text()
        tree = ast.parse(file_content)
    except Exception:
        # Failed to read/parse one file, we should ignore it
        return None

    # (1) Get all classes defined in the file
    classes: List[Tuple[str, int, int]] = []
    # (2) For each class in the file, get all functions defined in the class.
    class_to_funcs: Dict[str, List[Tuple[str, int, int]]] = {}
    # (3) Get top-level functions in the file (exclude functions defined in classes)
    top_level_funcs: List[Tuple[str, int, int]] = []

    for child in ast.iter_child_nodes(tree):
        if isinstance(child, ast.ClassDef):
            ## Part (1): collect class info
            classes.append((child.name, child.lineno, child.end_lineno))  # 1-based

            ## Part (2): collect (top level) function info inside this class
            class_funcs = [
                (n.name, n.lineno, n.end_lineno)   # 1-based
                for n in get_top_level_funcs(child)
            ]
            class_to_funcs[child.name] = class_funcs

    ## Part (3): collect top level function info
    top_level_func_nodes = get_top_level_funcs(tree)
    for node in top_level_func_nodes:
        top_level_funcs.append((node.name, node.lineno, node.end_lineno))  # 1-based

    return classes, class_to_funcs, top_level_funcs


def get_code_snippets(abs_fpath: str, start: int, end: int) -> str:
    """Get the code snippet in the range in the file, without line numbers.

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


def extract_func_sig_from_ast(func_ast: ast.FunctionDef) -> List[int]:
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


def extract_class_sig_from_ast(class_ast: ast.ClassDef) -> List[int]:
    """Extract the class signature from the AST.

    Args:
        class_ast (ast.ClassDef): AST of the class.

    Returns:
        List[int]: The source line numbers that contains the class signature (1-based).
    """
    # STEP (1): extract the class signature
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

    # STEP (2): extract the function signatures and assign signatures
    for stmt in class_ast.body:
        if isinstance(stmt, ast.FunctionDef):
            sig_lines.extend(extract_func_sig_from_ast(stmt))
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


def get_class_signature(file_abs_path: str, class_name: str) -> str:
    """Get the class signature.

    Args:
        file_abs_path (str): Absolute path to the file.
        class_name (str): Name of the class.
    """
    with open(file_abs_path) as f:
        file_content = f.read()

    tree = ast.parse(file_content)
    relevant_line_ids = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            # We reached the target class node
            relevant_line_ids = extract_class_sig_from_ast(node)  # 1-based
            break

    if not relevant_line_ids:
        return ""
    else:
        file_content = file_content.splitlines(keepends=True)
        result = ""
        for line_id in relevant_line_ids:
            line_content: str = file_content[line_id - 1]
            if line_content.strip().startswith("#"):
                # This kind of comment could be left until this stage.
                # Reason: # comments are not part of func body if they appear at beginning of func
                continue
            result += line_content
        return result
