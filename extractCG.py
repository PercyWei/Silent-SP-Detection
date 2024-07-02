import os
import sys
import argparse
from typing import *
from collections import deque
from pycparser import c_parser, c_ast, parse_file

import clang.cindex

from clang.cindex import Cursor
from clang.cindex import CursorKind


class FuncCallVisitor(c_ast.NodeVisitor):
    def visit_FuncCall(self, node):
        print(f"Function call: {node.name.name}")
        self.generic_visit(node)

def get_function_calls(input_rpath: str, output_rpath: str):

    c_files = os.listdir(input_rpath)

    for c_file in c_files:
        if c_file.endswith(".c"):
            c_filepath = os.path.join(input_rpath, c_file)

            # Parse C file
            parser = c_parser.CParser()
            ast = parse_file(c_filepath, use_cpp=True)

            # Traverse AST to get all function calls
            print("=" * 20 + c_file + "=" * 20)
            visitor = FuncCallVisitor()
            visitor.visit(ast)

def extract_func_calls_of_target_func(root_node, current_file, target_function=None, call_list=None):
    search_nodes = deque([root_node])
    if call_list is None:
        call_list = {
            'local_calls': [],
            'external_calls': [],
            'unknown_calls': []
        }
    find_function = None

    while search_nodes:
        node = search_nodes.popleft()

        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            if node.spelling == target_function:
                find_function = node
                break

        for child in node.get_node_ast_children():
            search_nodes.append(child)

    if find_function:
        search_calls = deque([find_function])

        while search_calls:
            node = search_calls.popleft()

            if node.kind == clang.cindex.CursorKind.CALL_EXPR:
                if node.location.file:
                    if node.location.file.name == current_file:
                        call_list['local_calls'].append((node.spelling, node.location.file.name))
                    else:
                        call_list['external_calls'].append((node.spelling, node.location.file.name))
                else:
                    call_list['unknown_calls'].append((node.spelling, 'unknown location'))

            for child in node.get_children():
                search_nodes.append(child)

    return call_list


if __name__ == '__main__':
    # python extractCG.py -i ../C_files -o ../C_files/CGs
    # parser = argparse.ArgumentParser(description="Extract CG from C file.")
    # parser.add_argument('-i', '--input_rpath', type=str, help='Path of dir containing C files', required=True)
    # parser.add_argument('-o', '--output_rpath', type=str, help='Path of dir containing output', required=True)

    # args = parser.parse_args()

    clang.cindex.Config.set_library_file("/usr/local/lib/libclang.so")

    current_file = 'data/CrossFileVul_test/freetype2/CVE-2014-9659/cf2intrp.c'
    target_function = 'cf2_interpT2CharString'

    index = clang.cindex.Index.create()
    tu = index.parse(current_file)

    function_calls = extract_func_calls_of_target_func(tu.cursor, current_file, target_function)
    print(function_calls)
    # get_function_calls(args.input_rpath, args.output_rpath)
