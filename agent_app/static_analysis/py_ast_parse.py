import os
import sys
import re
import ast
import pathlib
import chardet

from typing import *
from loguru import logger

from agent_app.data_structures import LineRange, PySimNodeType, PySimNode


def cal_class_or_func_def_range(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> Tuple[int, int]:
    """Calculate the code line ranges for definition of class or function.
    NOTE: Includes the decorators.
    """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based

    # NOTE: For ClassDef / FunctionDef node, `lineno`, `end_lineno` and `decorator_list` are treated separately.
    for decorator in node.decorator_list:
        if hasattr(decorator, 'lineno'):
            start_lineno = min(start_lineno, decorator.lineno)
        if hasattr(decorator, 'end_lineno'):
            end_lineno = max(end_lineno, decorator.end_lineno)

    return start_lineno, end_lineno


def extract_func_sig_lines_from_ast(func_ast: ast.FunctionDef | ast.AsyncFunctionDef) -> List[int]:
    """Extract the function signature from the AST node.

    Includes the decorators, method name, and parameters.
    Args:
        func_ast (ast.FunctionDef | ast.AsyncFunctionDef): AST node of the function.
    Returns:
        List[int]: The source line numbers that contains the function signature (1-based).
    """
    start_lineno, _ = cal_class_or_func_def_range(func_ast)
    sig_start_line = start_lineno

    if func_ast.body:
        body_start_line = func_ast.body[0].lineno
        sig_end_line = body_start_line - 1
    else:
        sig_end_line = func_ast.end_lineno

    return list(range(sig_start_line, sig_end_line + 1))


def extract_func_sig_lines_from_snippet(func_code: str, func_start: int = 1) -> List[int]:
    """Extract the function signature from the function code snippet."""
    tree = ast.parse(func_code)
    assert len(tree.body) == 1

    func_ast = tree.body[0]
    assert isinstance(func_ast, ast.FunctionDef) or isinstance(func_ast, ast.AsyncFunctionDef)

    # Extract
    sig_line_ids = extract_func_sig_lines_from_ast(func_ast)
    # Normalize
    sig_line_ids = [func_start + line_id - 1 for line_id in sig_line_ids]

    return sig_line_ids


def extract_class_sig_lines_from_ast(class_ast: ast.ClassDef, detailed: bool = True) -> List[int]:
    """Extract the class signature from the AST node.

    Args:
        class_ast (ast.ClassDef): AST node of the class.
        detailed (bool): Whether to get a detailed body.
    Returns:
        List[int]: The source line numbers that contains the class signature (1-based).
    """
    # (1) Extract the class base signature
    start_lineno, _ = cal_class_or_func_def_range(class_ast)
    sig_start_line = start_lineno

    if class_ast.body:
        body_start_line = class_ast.body[0].lineno
        sig_end_line = body_start_line - 1
    else:
        sig_end_line = class_ast.end_lineno

    sig_lines = list(range(sig_start_line, sig_end_line + 1))

    # (2) Extract the relevant lines in the class body
    for stmt in class_ast.body:
        # Extract the assign statement anyway
        if isinstance(stmt, ast.Assign):
            # Skip some useless cases where the assignment is to create docs
            stmt_str_format = ast.dump(stmt)
            if "__doc__" in stmt_str_format:
                continue

            assign_lines = list(range(stmt.lineno, stmt.end_lineno + 1))
            sig_lines.extend(assign_lines)

        # Extract the method signature only if detailed=True
        elif detailed and (isinstance(stmt, ast.FunctionDef) or isinstance(stmt, ast.AsyncFunctionDef)):
            func_sig_lines = extract_func_sig_lines_from_ast(stmt)
            sig_lines.extend(func_sig_lines)

    sig_lines = list(sorted(set(sig_lines)))

    return sig_lines


def extract_class_sig_lines_from_snippet(class_code: str, class_start: int = 1, detailed: bool = True) -> List[int]:
    """Extract the class signature from the class code snippet."""
    tree = ast.parse(class_code)
    assert len(tree.body) == 1

    class_ast = tree.body[0]
    assert isinstance(class_ast, ast.ClassDef)

    # Extract
    sig_line_ids = extract_class_sig_lines_from_ast(class_ast, detailed)
    # Normalize
    sig_line_ids = [class_start + line_id - 1 for line_id in sig_line_ids]

    return sig_line_ids


def extract_class_sig_lines_from_file(file_content: str, class_name: str, class_range: LineRange) -> List[int]:
    """Extract the class signature from the entire code file."""
    tree = ast.parse(file_content)
    sig_line_ids: List[int] = []
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

            ## Extract signature lines
            sig_line_ids = extract_class_sig_lines_from_ast(node)  # 1-based
            break

    return sig_line_ids


"""MAIN ENTRY"""


class ASTParser:
    def __init__(self):
        # Parse the code entered or read from a file
        self.code: str | None = None
        self.code_fpath: str | None = None
        self.code_len: int = 0

        self.cur_node_id: int | None = None
        # (1) Simple Node data
        self.all_nodes: Dict[int, PySimNode] = {}  # {Simple Node id -> Simple Node}
        self.li2node_map: Dict[int, int] = {}      # {line id        -> Simple Node id}
        # (2) Struct indexes (class, function, inclass method)
        self.all_funcs: List[Tuple[str, LineRange]] = []                       # [(function name, line range)]
        self.all_classes: List[Tuple[str, LineRange]] = []                     # [(class name, line range)]
        self.all_inclass_methods: Dict[str, List[Tuple[str, LineRange]]] = {}  # {class name -> [(inclass method name, line range)]}
        # (3) Imports
        self.all_imports: List[Tuple[str, str, str]] = []  # [(pkg path, attr name, alias name)]


    def reset(self):
        self.code = None
        self.code_fpath = None
        self.code_len = 0

        self.cur_node_id = None
        self.all_nodes = {}
        self.li2node_map = {}
        self.all_funcs = []
        self.all_classes = []
        self.all_inclass_methods = {}
        self.all_imports = []


    def set(self, code: str | None, code_fpath: str | None) -> bool:
        # Reset before setting
        self.reset()

        # Check arguments
        if not ((code is None) ^ (code_fpath is None)):
            raise RuntimeError("One and only one of 'code' and 'code_fpath' must be None.")

        # Main
        if code is not None:
            self.code = code
        else:
            assert code_fpath is not None
            code_fpath = os.path.abspath(code_fpath)

            if not os.path.exists(code_fpath) or not code_fpath.endswith(".py"):
                logger.info(f"Input 'code_fpath' {code_fpath} is invalid.")
                return False

            try:
                with open(code_fpath, 'rb') as f:
                    result = chardet.detect(f.read())
                encoding = result['encoding']
                code = pathlib.Path(code_fpath).read_text(encoding=encoding)
            except (UnicodeDecodeError, TypeError) as e:
                logger.debug(f"Failed to read {code_fpath} for ast parsing due to {str(e)}.")
                return False

            self.code = code
            self.code_fpath = code_fpath

        return True


    def _update_all_nodes(
            self,
            father_node_id: int | None,
            node_type: PySimNodeType,
            ast_type: str,
            node_name: str,
            node_range: LineRange
    ) -> PySimNode:
        assert isinstance(self.cur_node_id, int)

        cur_node = PySimNode(
            id=self.cur_node_id,
            father=father_node_id,
            type=node_type,
            ast=ast_type,
            name=node_name,
            range=node_range
        )
        self.all_nodes[self.cur_node_id] = cur_node
        self.cur_node_id += 1

        return cur_node


    def _update_line_to_node_map(self, line_node: PySimNode) -> None:
        for line_id in line_node.get_full_range():
            assert line_id not in self.li2node_map
            self.li2node_map[line_id] = line_node.id


    @staticmethod
    def is_main_line(line: str) -> bool:
        pattern = r'^\s*if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:'
        match = re.search(pattern, line, re.MULTILINE)
        return bool(match)


    def _update_with_root(self, tree: ast.Module) -> PySimNode:
        self.cur_node_id = 0

        root_ast_type = type(tree).__name__
        root_name = ""
        root_range = LineRange(start=1, end=self.code_len)

        root_node = self._update_all_nodes(None, PySimNodeType.ROOT, root_ast_type, root_name, root_range)

        return root_node


    def _update_with_import(self, ast_node: ast.Import | ast.ImportFrom, father_node_id: int) -> None:
        assert isinstance(ast_node, ast.Import) or isinstance(ast_node, ast.ImportFrom)

        unit_ast_type = type(ast_node).__name__
        unit_name = ""
        unit_range = LineRange(start=ast_node.lineno, end=ast_node.end_lineno)

        unit_node = self._update_all_nodes(father_node_id, PySimNodeType.UNIT, unit_ast_type, unit_name, unit_range)
        self._update_line_to_node_map(unit_node)

        if isinstance(ast_node, ast.Import):
            for alias in ast_node.names:
                pkg_path = alias.name if alias.name is not None else ""
                attr_name = ""
                alias_name = alias.asname if alias.asname is not None else ""

                self.all_imports.append((pkg_path, attr_name, alias_name))
        else:
            module_path = ast_node.level * '.' + ast_node.module if ast_node.module is not None else ast_node.level * '.'
            for alias in ast_node.names:
                attr_name = alias.name if alias.name is not None else ""
                alias_name = alias.asname if alias.asname is not None else ""

                self.all_imports.append((module_path, attr_name, alias_name))


    def _update_with_funcdef(self, ast_node: ast.FunctionDef | ast.AsyncFunctionDef, father_node_id: int) -> None:
        assert isinstance(ast_node, ast.FunctionDef) or isinstance(ast_node, ast.AsyncFunctionDef)

        func_ast_type = type(ast_node).__name__
        func_name = ast_node.name
        func_start, func_end = cal_class_or_func_def_range(ast_node)
        func_range = LineRange(start=func_start, end=func_end)

        func_node = self._update_all_nodes(father_node_id, PySimNodeType.FUNCTION, func_ast_type, func_name, func_range)
        self._update_line_to_node_map(func_node)

        self.all_funcs.append((func_name, func_range))


    def _update_with_class_body(self, ast_node: ast.ClassDef, class_node: PySimNode) -> None:
        assert isinstance(ast_node, ast.ClassDef) and class_node.type == PySimNodeType.CLASS

        # (1) Add class outer
        if len(ast_node.body) > 0:
            first_child = ast_node.body[0]
            if isinstance(first_child, ast.FunctionDef) or isinstance(first_child, ast.AsyncFunctionDef):
                first_child_start, _ = cal_class_or_func_def_range(first_child)
            else:
                first_child_start = first_child.lineno

            if class_node.range.start < first_child_start:
                child_ast_type = "CLASS_OUTER"
                child_name = ""
                child_range = LineRange(start=class_node.range.start, end=first_child_start - 1)

                child_node = self._update_all_nodes(
                    class_node.id, PySimNodeType.CLASS_UNIT, child_ast_type, child_name, child_range
                )
                self._update_line_to_node_map(child_node)
        else:
            child_ast_type = "CLASS_OUTER"
            child_name = ""
            child_range = class_node.range
            child_node = self._update_all_nodes(
                class_node.id, PySimNodeType.CLASS_UNIT, child_ast_type, child_name, child_range
            )
            self._update_line_to_node_map(child_node)

        # (2) Add top-level children of class body
        inclass_methods: List[Tuple[str, LineRange]] = []

        for class_child in ast_node.body:
            child_ast_type = type(class_child).__name__
            child_name = class_child.name if hasattr(class_child, 'name') else ""

            if isinstance(class_child, ast.FunctionDef) or isinstance(class_child, ast.AsyncFunctionDef):
                child_type = PySimNodeType.CLASS_METHOD
                child_start, child_end = cal_class_or_func_def_range(class_child)
                child_range = LineRange(start=child_start, end=child_end)

                inclass_methods.append((child_name, child_range))
            else:
                child_type = PySimNodeType.CLASS_UNIT
                child_range = LineRange(start=class_child.lineno, end=class_child.end_lineno)

            child_node = self._update_all_nodes(class_node.id, child_type, child_ast_type, child_name, child_range)
            self._update_line_to_node_map(child_node)

        self.all_inclass_methods[class_node.name] = inclass_methods


    def _update_with_classdef(self, ast_node: ast.ClassDef, father_node_id: int) -> None:
        assert isinstance(ast_node, ast.ClassDef)

        class_ast_type = type(ast_node).__name__
        class_name = ast_node.name
        class_start, class_end = cal_class_or_func_def_range(ast_node)
        class_range = LineRange(start=class_start, end=class_end)

        class_node = self._update_all_nodes(father_node_id, PySimNodeType.CLASS, class_ast_type, class_name, class_range)
        self._update_with_class_body(ast_node, class_node)

        self.all_classes.append((class_name, class_range))


    def _update_with_main_body(self, ast_node: ast.If, main_node: PySimNode) -> None:
        assert isinstance(ast_node, ast.If) and main_node.type == PySimNodeType.MAIN

        main_children = [ast_node.test] + ast_node.body + ast_node.orelse

        for main_child in main_children:
            child_ast_type = type(ast_node).__name__
            child_name = main_child.name if hasattr(main_child, 'name') else ''

            if isinstance(main_child, ast.FunctionDef) or isinstance(main_child, ast.AsyncFunctionDef):
                child_start, child_end = cal_class_or_func_def_range(main_child)
            else:
                child_start = main_child.lineno
                child_end = main_child.end_lineno
            child_range = LineRange(start=child_start, end=child_end)

            child_node = self._update_all_nodes(
                main_node.id, PySimNodeType.MAIN_UNIT, child_ast_type, child_name, child_range
            )
            self._update_line_to_node_map(child_node)


    def _update_with_main(self, ast_node: ast.If, father_node_id: int) -> None:
        assert isinstance(ast_node, ast.If)

        main_ast_type = type(ast_node).__name__
        main_name = ""
        main_range = LineRange(start=ast_node.lineno, end=ast_node.end_lineno)

        main_node = self._update_all_nodes(father_node_id, PySimNodeType.MAIN, main_ast_type, main_name, main_range)

        self._update_with_main_body(ast_node, main_node)


    def _update_with_other(self, ast_node: ast.AST, father_node_id: int) -> None:
        unit_ast_type = type(ast_node).__name__
        unit_name = ast_node.name if hasattr(ast_node, 'name') else ""
        unit_range = LineRange(start=ast_node.lineno, end=ast_node.end_lineno)

        unit_node = self._update_all_nodes(father_node_id, PySimNodeType.UNIT, unit_ast_type, unit_name, unit_range)
        self._update_line_to_node_map(unit_node)


    def parse_python_code(self) -> bool:
        """Parse the Python code.
        (1) Extract the following Simple Nodes:
        - Top level structs:
            - Unit
            - Function
            - Class
            - Main
        - Class child structs
            - Class Unit
            - Class Method
        - Main child structs
            - Main Unit
        (2) Build important struct indexes
        - Function
        - Class
        - Inclass method
        """
        # NOTE: Need a valid 'code' for AST parsing.
        if self.code is not None:
            code_lines = self.code.splitlines(keepends=False)
            self.code_len = len(code_lines)

            # ---------------------- Step 1: AST parse ---------------------- #
            try:
                tree = ast.parse(self.code)
            except Exception as e:
                logger.debug("AST parsing file failed!")
                return False

            # ---------------------- Step 2: Add root node ---------------------- #
            root_node = self._update_with_root(tree)

            # ---------------------- Step 3: Iterate over the top-level elements of the code ---------------------- #
            tree_children = list(ast.iter_child_nodes(tree))

            for i, child in enumerate(tree_children):
                ## (1) Imports
                if isinstance(child, ast.Import) or isinstance(child, ast.ImportFrom):
                    self._update_with_import(child, root_node.id)

                ## (2) Functions
                elif isinstance(child, ast.FunctionDef) or isinstance(child, ast.AsyncFunctionDef):
                    self._update_with_funcdef(child, root_node.id)

                ## (3) Classes and class methods
                elif isinstance(child, ast.ClassDef):
                    self._update_with_classdef(child, root_node.id)

                ## (4) Main blocks
                elif isinstance(child, ast.If) and self.is_main_line(code_lines[child.lineno - 1]):
                    self._update_with_main(child, root_node.id)

                else:
                    self._update_with_other(child, root_node.id)

            return True
        else:
            return False
