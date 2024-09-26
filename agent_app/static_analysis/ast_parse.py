import os
import sys
import ast

from typing import *


def are_overlap_lines(line_ids_1: List[int], line_ids_2: List[int]) -> bool:
    overlap = list(set(line_ids_1) & set(line_ids_2))
    return len(overlap) > 0


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
        func_ast (ast.FunctionDef | ast.AsyncFunctionDef): AST of the function.
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


def extract_func_sig_lines_from_code(func_code: str) -> List[int]:
    """Extract the function signature from the code snippet."""
    tree = ast.parse(func_code)
    assert len(tree.body) == 1

    func_ast = tree.body[0]
    assert isinstance(func_ast, ast.FunctionDef) or isinstance(func_ast, ast.AsyncFunctionDef)

    return extract_func_sig_lines_from_ast(func_ast)


def extract_class_sig_lines_from_ast(class_ast: ast.ClassDef, include_func_sig: bool = True) -> List[int]:
    """Extract the class signature from the AST node.

    Args:
        class_ast (ast.ClassDef): AST of the class.
        include_func_sig (bool): Whether to include the function signatures.
    Returns:
        List[int]: The source line numbers that contains the class signature (1-based).
    """
    # (1) Extract the class signature
    start_lineno, _ = cal_class_or_func_def_range(class_ast)
    sig_start_line = start_lineno

    if class_ast.body:
        body_start_line = class_ast.body[0].lineno
        sig_end_line = body_start_line - 1
    else:
        sig_end_line = class_ast.end_lineno

    sig_lines = list(range(sig_start_line, sig_end_line + 1))

    # (2) Extract the function signatures and assign signatures
    for stmt in class_ast.body:
        if include_func_sig and (isinstance(stmt, ast.FunctionDef) or isinstance(stmt, ast.AsyncFunctionDef)):
            func_sig_lines = extract_func_sig_lines_from_ast(stmt)
            assert not are_overlap_lines(sig_lines, func_sig_lines)
            sig_lines.extend(func_sig_lines)
        elif isinstance(stmt, ast.Assign):
            # Skip some useless cases where the assignment is to create docs
            stmt_str_format = ast.dump(stmt)
            if "__doc__" in stmt_str_format:
                continue

            assign_lines = list(range(stmt.lineno, stmt.end_lineno + 1))
            assert not are_overlap_lines(sig_lines, assign_lines)
            sig_lines.extend(assign_lines)

    return sig_lines


def extract_class_sig_lines_from_code(class_code: str, include_func_sig: bool = True) -> List[int]:
    """Extract the class signature from the code snippet."""
    tree = ast.parse(class_code)
    assert len(tree.body) == 1

    class_ast = tree.body[0]
    assert isinstance(class_ast, ast.ClassDef)

    return extract_class_sig_lines_from_ast(class_ast, include_func_sig)


if __name__ == "__main__":
   pass