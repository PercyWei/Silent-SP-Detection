import os
import abc
import json
import networkx as nx

from typing import *

from tree_sitter import Language, Parser, Node as tsNode


def build_library(tree_sitter_root_dpath: str):
    # Output .so file
    build_dpath = os.path.join(tree_sitter_root_dpath, "build")
    if not os.path.exists(build_dpath):
        os.makedirs(build_dpath, exist_ok=True)

    so_fpath = os.path.join(build_dpath, "my-languages.so")

    # Tree-sitter parser repos
    repo_dpath = os.path.join(tree_sitter_root_dpath, "parsers")
    assert os.path.exists(repo_dpath)

    repo_paths = []
    repos = os.listdir(repo_dpath)
    for repo in repos:
        repo_fpath = os.path.join(repo_dpath, repo)
        repo_paths.append(repo_fpath)

    print(f"Output .so file: {so_fpath}.")
    print(f"Parser repos:")
    print(json.dumps(repo_paths, indent=4))

    Language.build_library(so_fpath, repo_paths)


def prepare_specified_lang_parser(lang: str, so_fpath: str) -> Parser:
    assert lang in ["c", "cpp", "python", "java"]
    parser = Parser()
    Specific_LANGUAGE = Language(so_fpath, lang)
    parser.set_language(Specific_LANGUAGE)

    return parser


def extract_subgraph(G, edge_type):
    """Extract an edge subgraph with a given type."""
    return nx.edge_subgraph(
        G,
        [
            (u, v, k)
            for u, v, k, attr in G.edges(data=True, keys=True)
            if attr["graph_type"] == edge_type
        ],
    )


def find_error_nodes(root_node: tsNode) -> List[tsNode]:
    error_nodes = []

    for child in root_node.children:
        if child.type == 'ERROR':
            error_nodes.append(child)

    return error_nodes


class Counter:
    """Utility class to keep track of an incrementable counter."""
    def __init__(self):
        self._id = 0

    def get(self) -> int:
        return self._id

    def get_and_increment(self) -> int:
        _id = self.get()
        self._id += 1
        return _id


class BaseNodeParser(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def parse(node: tsNode):
        pass


class BaseNodeVisitor(abc.ABC):
    def __init__(self):
        pass

    @abc.abstractmethod
    def visit(self, node: tsNode):
        pass

    @abc.abstractmethod
    def visit_default(self, node: tsNode):
        pass


class TraversalFindFaultLines(BaseNodeVisitor, BaseNodeParser):
    def __init__(self):
        super().__init__()
        self._has_error_lines = []
        self._is_missing_lines = []

    @staticmethod
    def parse(node: tsNode):
        traversal = TraversalFindFaultLines()
        traversal.visit(node)
        has_error_lines, is_missing_lines = traversal.get_fault_lines()

        return has_error_lines, is_missing_lines

    @staticmethod
    def get_type(node: tsNode) -> str:
        return node.type

    def visit(self, node: tsNode):
        getattr(self, f"visit_{self.get_type(node)}", self.visit_default)(node=node)

    def visit_children(self, node: tsNode):
        for child in node.children:
            self.visit(child)

    def visit_default(self, node: tsNode):
        if node.has_error or node.is_missing:
            if node.start_point[0] == node.end_point[0]:
                if node.has_error:
                    self._has_error_lines.append(node.start_point[0])
                if node.is_missing:
                    self._is_missing_lines.append(node.start_point[0])
            else:
                self.visit_children(node)

    def get_fault_lines(self) -> Tuple[List, List]:
        return self._has_error_lines, self._is_missing_lines
