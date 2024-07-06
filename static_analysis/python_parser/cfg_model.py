# This code is modified from https://github.com/coetaur0/staticfg/
# Original file: staticfg/model.py

"""
Control flow graph for Python programs.
"""
# Aurelien Coet, 2018.

from __future__ import annotations

import ast
import astor
import graphviz as gv

from typing import *


class Block(object):
    """
    Basic block in CFG.

    Contains a list of statements executed in a program without any control
    jumps. A block of statements is exited through one of its exits. Exits are
    a list of Links that represent control flow jumps.
    """
    __slots__ = ["id", "statements", "func_calls", "predecessors", "exits"]

    def __init__(self, id: int):
        # Id of the block.
        self.id: int = id
        # Statements in the block.
        self.statements: List[ast.stmt] = []
        # Calls to functions inside the block (represents context switches to some functions' CFGs).
        self.func_calls: List[str] = []
        # Links to predecessors in a control flow graph.
        self.predecessors: List[Link] = []
        # Links to the next blocks in a control flow graph.
        self.exits: List[Link] = []

    def __str__(self):
        if self.statements:
            return "block:{}@{}".format(self.id, self.at())
        return "empty block:{}".format(self.id)

    def __repr__(self):
        txt = "{} with {} exits".format(str(self), len(self.exits))
        if self.statements:
            txt += ", body=["
            txt += ", ".join([ast.dump(node) for node in self.statements])
            txt += "]"
        return txt

    def at(self) -> Optional[int]:
        """
        Get the line number of the first statement of the block in the program.
        """
        if self.statements and self.statements[0].lineno >= 0:
            return self.statements[0].lineno
        return None

    def is_empty(self) -> bool:
        """
        Check if the block is empty.

        Returns:
            A boolean indicating if the block is empty (True) or not (False).
        """
        return len(self.statements) == 0

    def get_line_range(self) -> Tuple[int, int]:
        start_stmt = self.statements[0]
        end_stmt = self.statements[-1]

        start_line_id = start_stmt.lineno

        if isinstance(end_stmt, ast.If):
            end_line_id = end_stmt.test.end_lineno
        elif isinstance(end_stmt, ast.For):
            end_line_id = end_stmt.iter.end_lineno
        elif isinstance(end_stmt, ast.While):
            end_line_id = end_stmt.test.end_lineno
        else:
            # TODO: Consider whether there are other special circumstances
            end_line_id = end_stmt.end_lineno

        return start_line_id, end_line_id

    def get_source(self) -> str:
        """
        Get a string containing the Python source code corresponding to the statements in the block.

        Returns:
            A string containing the source code of the statements.
        """
        src = ""
        for statement in self.statements:
            # TODO: Consider other more precise representations
            if type(statement) in [ast.If, ast.For, ast.While]:
                src += (astor.to_source(statement)).split('\n')[0] + "\n"
            elif type(statement) in [ast.FunctionDef, ast.AsyncFunctionDef]:
                src += (astor.to_source(statement)).split('\n')[0] + "...\n"
            elif isinstance(statement, ast.With):
                src += 'with ' + ', '.join([astor.to_source(wi) for wi in statement.items]).rstrip() + ":\n"
            else:
                src += astor.to_source(statement)
        return src

    def get_calls(self) -> str:
        """
        Get a string containing the calls to other functions inside the block.

        Returns:
            A string containing the names of the functions called inside the block.
        """
        txt = ""
        for func_name in self.func_calls:
            txt += func_name + '\n'
        return txt


class Link(object):
    """
    Link between blocks in a control flow graph.

    Represents a control flow jump between two blocks. Contains an exit case in
    the form of an expression, representing the case in which the associated
    control jump is made.
    """

    __slots__ = ["source", "target", "exit_case"]

    def __init__(self, source: Block, target: Block, exit_case: Optional[ast.expr] = None):
        # Block from which the control flow jump was made.
        self.source: Block = source
        # Target block of the control flow jump.
        self.target: Block = target
        # 'Case' leading to a control flow jump through this link.
        self.exit_case: Optional[ast.expr] = exit_case

    def __str__(self):
        return "link from {} to {}".format(str(self.source), str(self.target))

    def __repr__(self):
        if self.exit_case is not None:
            return "{}, with exit case {}".format(str(self),
                                                  ast.dump(self.exit_case))
        return str(self)

    def get_exit_case(self) -> str:
        """
        Get a string containing the Python source code corresponding to the exit_case of the Link.

        Returns:
            A string containing the source code.
        """
        if self.exit_case:
            return astor.to_source(self.exit_case)
        return ""


class CFG(object):
    """
    Control flow graph (CFG).

    A control flow graph is composed of basic blocks and links between them
    representing control flow jumps. It has a unique entry block and several
    possible 'final' blocks (blocks with no exits representing the end of the
    CFG).
    """

    def __init__(self, name: str, asynch: bool = False):
        # Name of the function or module being represented.
        self.name = name
        # Type of function represented by the CFG (sync or async).
        # A Python program is considered as a synchronous function (main).
        self.asynch = asynch
        # Entry block of the CFG.
        self.entry_block: Optional[Block] = None
        # Final blocks of the CFG.
        self.final_blocks: List[Block] = []
        # Sub-CFGs for functions defined inside the current CFG.
        self.function_cfgs: Dict[str, CFG] = {}
        # Sub-CFGs for classes defined inside the current CFG.
        self.class_cfgs: Dict[str,  CFG] = {}
        self.class_def_cfgs: Dict[str, Dict[str, CFG]] = {}

    def __str__(self):
        return "CFG for {}".format(self.name)

    def _visit_blocks(self, graph: gv.Digraph, block: Block, visited: List, calls: bool = True):
        # Don't visit blocks twice.
        if block.id in visited:
            return

        node_label = block.get_source()
        line_range = block.get_line_range()

        graph.node(str(block.id), label=f"range: {line_range[0]}~{line_range[1]}\n\n" + node_label)
        visited.append(block.id)

        # Show the block's function calls in a node.
        if calls and block.func_calls:
            calls_node = str(block.id) + "_calls"
            calls_label = block.get_calls().strip()
            graph.node(calls_node, label=calls_label, _attributes={'shape': 'box'})
            graph.edge(str(block.id), calls_node, label="calls", _attributes={'style': 'dashed'})

        # Recursively visit all the blocks of the CFG.
        for exit_link in block.exits:
            self._visit_blocks(graph=graph,
                               block=exit_link.target,
                               visited=visited,
                               calls=calls)
            edge_label = exit_link.get_exit_case().strip()
            graph.edge(str(block.id), str(exit_link.target.id), label=edge_label)

    def _build_visual(self, save_format: str = 'pdf', calls: bool = True) -> gv.Digraph:
        graph = gv.Digraph(name='cluster' + self.name,
                           format=save_format,
                           graph_attr={'label': self.name})
        self._visit_blocks(graph=graph,
                           block=self.entry_block,
                           visited=[],
                           calls=calls)

        # Build the sub-graphs for the function definitions in the CFG and add them to the graph.
        for sub_cfg in self.function_cfgs:
            subgraph = self.function_cfgs[sub_cfg]._build_visual(save_format=save_format,
                                                                 calls=calls)
            graph.subgraph(subgraph)

        for _, def_cfgs in self.class_def_cfgs.items():
            for _, def_cfg in def_cfgs.items():
                subgraph = def_cfg._build_visual(save_format=save_format,
                                                 calls=calls)
                graph.subgraph(subgraph)

        return graph

    def build_visual(self, save_fname: str, save_dpath: str, save_format: str, calls: bool = True, show: bool = False):
        """
        Build a visualisation of the CFG with graphviz and output it in a DOT file.

        Args:
            save_fname: Name of the output visualisation file.
            save_dpath: Path to the dir saving the output visualisation file.
            save_format: The format used for the output visualisation file (PDF, ...).
            calls: If true, show functions called in the block, otherwise not.
            show: If true, open the output file after building the visualisation, otherwise not.
        """
        graph = self._build_visual(save_format, calls)
        graph.render(filename=save_fname, directory=save_dpath, view=show)

    def __iter__(self):
        """
        Generator that yields all the blocks in the current graph, then recursively yields from any sub graphs
        """
        visited = set()
        to_visit = [self.entry_block]

        while to_visit:
            block = to_visit.pop(0)
            visited.add(block)
            for exit_ in block.exits:
                if exit_.target in visited or exit_.target in to_visit:
                    continue
                to_visit.append(exit_.target)
            yield block

        for subcfg in self.function_cfgs.values():
            yield from subcfg
