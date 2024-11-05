import json
import warnings
import networkx as nx

from typing import *
from collections import defaultdict
from matplotlib import pyplot as plt
from tree_sitter import Node as tsNode

from .ast_parser import ASTParser
# from ..util import Counter
from tools.dependency.util import Counter
from old_utils.logging import logger


class CFGVisitor:
    """
        Visitor which creates CFGs for each function and the whole file.
    """
    def __init__(self, ast: nx.DiGraph):
        self.ast = ast
        self.cfg = nx.DiGraph()
        self.counter = Counter()

        self.current_cfgs = nx.DiGraph()
        self.cfgs = {}
        self.funcs = []

        self.fringes = []
        self.break_fringes = []
        self.continue_fringes = []
        self.gotos = {}
        self.labels = {}

    def get_node_ast_children(self, ast_node_id: int) -> List[int]:
        """
        Get AST children of a node.

        Args:
            ast_node_id: The AST node id
        Returns:
            List[int]: List of id of the AST child of the node
        """
        return list(self.ast.successors(ast_node_id))

    def preprocess(self, init_ast_node_id: int):
        """
            1. Find all function_definition
            2.

        Args:
            init_ast_node_id:
        Returns:
        """
        if self.ast.all_nodes[init_ast_node_id]['type'] == "translation_unit":
            pass

        elif self.ast.all_nodes[init_ast_node_id]['type'] == "function_definition":
           pass
        else:
            logger.error()

    def postprocess(self):
        """
        Perform final postprocessing steps on a CFG.
        """
        # pass through dummy nodes
        nodes_to_remove = []
        for n, attr in self.cfg.all_nodes(data=True):
            if attr.get("dummy", False):
                preds = list(self.cfg.predecessors(n))
                succs = list(self.cfg.successors(n))
                # Forward label from edges incoming to dummy.
                for pred in preds:
                    new_edge_label = list(self.cfg.adj[pred][n].values())[0].get(
                        "label", None
                    )
                    for succ in succs:
                        self.cfg.add_edge(pred, succ, label=new_edge_label)
                nodes_to_remove.append(n)
        self.cfg.remove_nodes_from(nodes_to_remove)



    """VISIT"""

    def visit(self, ast_node_id: int, **kwargs) -> bool:
        ast_node: Dict = self.ast.all_nodes[ast_node_id]
        visit_result = getattr(
            self, "visit_" + ast_node["node_type"], self.visit_default
        )(ast_node_id=ast_node_id, **kwargs)

        visit_children = visit_result.pop('visit_children')
        continue_visit = visit_result.pop('continue_visit')
        if visit_children:
            self.visit_children(ast_node_id, **visit_result)

        return continue_visit

    def visit_children(self, ast_node_id: int, **kwargs):
        """
        Visit child tree-sitter nodes.

        Args:
            ast_node_id: Parent AST node id
            **kwargs: Attributes passed to child node
        """
        ast_children_ids = self.get_node_ast_children(ast_node_id)
        for ast_child_id in ast_children_ids:
            continue_visit = self.visit(ast_child_id, **kwargs)
            if not continue_visit:
                break

    @staticmethod
    def construct_visit_result(visit_children: bool = True, continue_visit: bool = True, **kwargs) -> Dict:
        """
        Constructs visit result after visiting tree-sitter node.
        Args:
            visit_children: If to continue visiting child nodes
            continue_visit: If to continue visiting next node of the same level
            **kwargs: Other attributes to pass to child nodes
        Returns:
        """
        return {
            "visit_children": visit_children,
            "continue_visit": continue_visit,
            **kwargs
        }

    """ADD NODE"""

    def add_dummy_node(self) -> int:
        """
        Add a dummy node to the CFG.
        Dummy nodes are nodes whose connections should be forwarded in a post-processing step.

        Returns:
            int: Current dummy CFG node id
        """
        cfg_node_id = self.counter.get_and_increment()
        self.cfg.add_node(cfg_node_id, dummy=True, label="DUMMY")

        return cfg_node_id

    def add_cfg_node(self, ast_node_id: Optional[int], label=None, **kwargs) -> int:
        """
        Add CFG node to the graph, inheriting properties from the progenitor AST node if any.

        Args:
            ast_node_id: The corresponding AST node id
            label: CFG node label
        Returns:
            int: Current CFG node id
        """

        def check_key_conflict(ori_dict: Dict, updt_dict: Dict) -> List:
            _conflict_keys = []
            for updt_key in updt_dict.keys():
                if updt_key in ori_dict:
                    conflict_keys.append(updt_key)
            return _conflict_keys

        updt_cfg_node_attr = {**kwargs}
        if label is not None:
            updt_cfg_node_attr["label"] = label
        # Add AST attributes
        cfg_node_attr = {}
        if ast_node_id is not None:
            ast_node: Dict = self.ast.all_nodes[ast_node_id]

            conflict_keys = check_key_conflict(ast_node, updt_cfg_node_attr)
            if len(conflict_keys) != 0:
                logger.warning('Key conflict was found between its original AST attributes and new CFG attributes '
                               'while creating a new CFG node.\n'
                               f'AST attributes:\n{json.dumps({k: ast_node[k] for k in conflict_keys}, indent=4)}\n'
                               f'CFG attributes:\n{json.dumps({k: updt_cfg_node_attr[k] for k in conflict_keys}, indent=4)}')

            cfg_node_attr.update(ast_node)
        # Add CFG attributes
        cfg_node_attr.update(updt_cfg_node_attr)
        cfg_node_id = self.counter.get_and_increment()
        # Add node in CFG graph
        self.cfg.add_node(cfg_node_id, **cfg_node_attr)

        return cfg_node_id

    """ADD EDGE"""

    def add_edge_from_fringe_to(self, dst_cfg_node_id: int):
        """
        Attach the current fringe to a node, transferring edge types if any are assigned.
        """
        fringe_by_type = defaultdict(list)
        for src_node_id in self.fringes:
            if isinstance(src_node_id, tuple):
                fringe_by_type[src_node_id[1]].append(src_node_id[0])
            else:
                fringe_by_type[None].append(src_node_id)
        for edge_type, fringe in fringe_by_type.items():
            edge_attrs = {}
            if edge_type is not None:
                edge_attrs["label"] = str(edge_type)
            self.cfg.add_edges_from(zip(fringe, [dst_cfg_node_id] * len(self.fringes)), **edge_attrs)
        self.fringes = []

    """VISITOR RULES"""

    def visit_default(self, ast_node_id: int, **kwargs) -> Dict:
        return self.construct_visit_result(visit_children=True, **kwargs)

    def visit_function_definition(self, ast_node_id: int, **kwargs):
        entry_cfg_node_id = self.add_cfg_node(ast_node_id=None, label="FUNC_ENTRY")
        self.cfg.graph["entry"] = entry_cfg_node_id
        self.add_edge_from_fringe_to(entry_cfg_node_id)
        self.fringes.append(entry_cfg_node_id)

        self.visit_children(n, **kwargs)

        exit_id = self.add_cfg_node(None, "FUNC_EXIT")
        self.add_edge_from_fringe_to(exit_id)
        # paste goto edges
        for label in self.gotos:
            try:
                self.cfg.add_edge(self.gotos[label], self.labels[label], label="goto")
            except KeyError:
                warnings.warn("missing goto target. Skipping.", f"label={label}", f"gotos={self.gotos}")
        for n in nx.descendants(self.cfg, entry_cfg_node_id):
            attr = self.cfg.all_nodes[n]
            if attr.get("n", None) is not None and attr["n"].type == "return_statement":
                self.cfg.add_edge(n, exit_id, label="return")
        self.fringes.append(exit_id)

    """STRAIGHT LINE STATEMENTS"""

    def enter_statement(self, ast_node_id: int):
        cfg_node_id = self.add_cfg_node(ast_node_id)
        self.add_edge_from_fringe_to(cfg_node_id)
        self.fringes.append(cfg_node_id)

    def visit_expression_statement(self, ast_node_id: int, **kwargs) -> Dict:
        self.enter_statement(ast_node_id)
        return self.construct_visit_result(visit_children=True, **kwargs)

    def visit_declaration(self, ast_node_id: int, **kwargs) -> Dict:
        self.enter_statement(ast_node_id)
        return self.construct_visit_result(visit_children=True, **kwargs)

    """STRUCTURED CONTROL FLOW"""

    def visit_if_statement(self, ast_node_id: int, **kwargs) -> Dict:
        cond_ast_node_id = None
        cons_ast_node_id = None
        alt_ast_node_id = None

        for child_ast_node_id in self.get_node_ast_children(ast_node_id):
            child_ast_node = self.ast.all_nodes[child_ast_node_id]
            if 'field' in child_ast_node and child_ast_node['field'] == 'condition':
                cond_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'consequence':
                cons_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'alternative':
                alt_ast_node_id = child_ast_node['ast_node_id']

        assert cond_ast_node_id is not None and cons_ast_node_id is not None

        cond_cfg_node_id = self.add_cfg_node(cond_ast_node_id)
        self.add_edge_from_fringe_to(cond_cfg_node_id)

        self.fringes.append((cond_cfg_node_id, True))
        self.visit(cons_ast_node_id)
        # NOTE: this assert doesn't work in the case of an if with an empty else
        # assert len(self.fringe) == 1, "fringe should now have last statement of compound_statement"

        if alt_ast_node_id is not None:
            old_fringe = self.fringes
            self.fringes = [(cond_cfg_node_id, False)]
            self.visit(alt_ast_node_id)
            self.fringes = old_fringe + self.fringes
        else:
            self.fringes.append((cond_cfg_node_id, False))

        return self.construct_visit_result(visit_children=False)

    def visit_for_statement(self, ast_node_id: int, **kwargs) -> Dict:
        for_ast_node_id = None
        init_ast_node_id = None
        cond_ast_node_id = None
        updt_ast_node_id = None
        body_ast_node_id = None

        for child_ast_node_id in self.get_node_ast_children(ast_node_id):
            child_ast_node = self.ast.all_nodes[child_ast_node_id]
            if child_ast_node['node_type'] == 'for':
                for_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'initializer':
                init_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'condition':
                cond_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'update':
                updt_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'body':
                body_ast_node_id = child_ast_node['ast_node_id']

        assert for_ast_node_id is not None and body_ast_node_id is not None

        if cond_ast_node_id is not None:
            cond_cfg_node_id = self.add_cfg_node(cond_ast_node_id)
        else:
            for_ast_node = self.ast.all_nodes[for_ast_node_id]
            cond_cfg_node_id = self.add_cfg_node(ast_node_id=None, label="<TRUE>",
                                                 start=for_ast_node['start'], end=for_ast_node['end'])

        if init_ast_node_id is not None:
            init_cfg_node_id = self.add_cfg_node(init_ast_node_id)
            self.add_edge_from_fringe_to(init_cfg_node_id)
            self.cfg.add_edge(init_cfg_node_id, cond_cfg_node_id)
        else:
            self.add_edge_from_fringe_to(cond_cfg_node_id)
        self.fringes.append((cond_cfg_node_id, True))

        # Visit body
        self.visit(body_ast_node_id)
        # NOTE: this assert doesn't work in the case of an if with an empty else
        # assert len(self.fringe) == 1, "fringe should now have last statement of compound_statement"
        if updt_ast_node_id is not None:
            updt_cfg_node_id = self.add_cfg_node(updt_ast_node_id)
            self.add_edge_from_fringe_to(updt_cfg_node_id)
            self.cfg.add_edge(updt_cfg_node_id, cond_cfg_node_id)
            self.cfg.add_edges_from(
                zip(self.continue_fringes, [updt_cfg_node_id] * len(self.continue_fringes)),
                label="continue",
            )
            self.continue_fringes = []
        else:
            self.add_edge_from_fringe_to(cond_cfg_node_id)
            self.cfg.add_edges_from(
                zip(self.continue_fringes, [cond_cfg_node_id] * len(self.continue_fringes)),
                label="continue",
            )
            self.continue_fringes = []
        self.fringes.append((cond_cfg_node_id, False))

        self.fringes += [(break_fringe, "break") for break_fringe in self.break_fringes]
        self.break_fringes = []

        return self.construct_visit_result(visit_children=False)

    def visit_while_statement(self, ast_node_id: int, **kwargs) -> Dict:
        cond_ast_node_id = None
        body_ast_node_id = None

        for child_ast_node_id in self.get_node_ast_children(ast_node_id):
            child_ast_node = self.ast.all_nodes[child_ast_node_id]
            if 'field' in child_ast_node and child_ast_node['field'] == 'condition':
                cond_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'body':
                body_ast_node_id = child_ast_node['ast_node_id']

        assert cond_ast_node_id is not None and body_ast_node_id is not None

        cond_cfg_node_id = self.add_cfg_node(cond_ast_node_id)

        self.add_edge_from_fringe_to(cond_cfg_node_id)
        self.fringes.append((cond_cfg_node_id, True))

        # Visit body
        self.visit(body_ast_node_id)
        self.add_edge_from_fringe_to(cond_cfg_node_id)
        self.fringes.append((cond_cfg_node_id, False))

        self.cfg.add_edges_from(
            zip(self.continue_fringes, [cond_cfg_node_id] * len(self.continue_fringes)),
            label="continue",
        )
        self.continue_fringes = []
        self.fringes += [(break_fringe, "break") for break_fringe in self.break_fringes]
        self.break_fringes = []

    def visit_do_statement(self, ast_node_id: int, **kwargs) -> Dict:
        cond_ast_node_id = None
        body_ast_node_id = None

        for child_ast_node_id in self.get_node_ast_children(ast_node_id):
            child_ast_node = self.ast.all_nodes[child_ast_node_id]
            if 'field' in child_ast_node and child_ast_node['field'] == 'condition':
                cond_ast_node_id = child_ast_node['ast_node_id']
            elif 'field' in child_ast_node and child_ast_node['field'] == 'body':
                body_ast_node_id = child_ast_node['ast_node_id']

        assert cond_ast_node_id is not None and body_ast_node_id is not None

        cfg_dummy_node_id = self.add_dummy_node()
        self.add_edge_from_fringe_to(cfg_dummy_node_id)
        self.fringes.append(cfg_dummy_node_id)

        # Visit body
        self.visit(body_ast_node_id)

        cond_cfg_node_id = self.add_cfg_node(cond_ast_node_id)
        self.add_edge_from_fringe_to(cond_cfg_node_id)
        self.cfg.add_edge(cond_cfg_node_id, cfg_dummy_node_id, label=str(True))
        self.fringes.append((cond_cfg_node_id, False))

        self.cfg.add_edges_from(
            zip(self.continue_fringes, [cond_cfg_node_id] * len(self.continue_fringes)),
            label="continue",
        )
        self.continue_fringes = []
        self.fringes += [(n, "break") for n in self.break_fringes]
        self.break_fringes = []

        return self.construct_visit_result(visit_children=False)

    def visit_switch_statement(self, n, **kwargs):
        cond = self.get_node_ast_children(self.get_node_ast_children(n)[0])[0]
        cond_id = self.add_cfg_node(cond)
        self.add_edge_from_fringe_to(cond_id)
        cases = self.get_node_ast_children(self.get_node_ast_children(n)[1])
        default_was_hit = False
        for case in cases:
            while self.ast.all_nodes[case]["node_type"] != "case_statement":
                if self.ast.all_nodes[case]["node_type"] == "labeled_statement":
                    self.add_label_node(case)
                    case = self.get_node_ast_children(case)[1]
                else:
                    raise NotImplementedError(self.ast.all_nodes[case]["node_type"])
            case_children = self.get_node_ast_children(case)
            case_attr = self.ast.all_nodes[case]
            if len(self.get_node_ast_children(case)) == 0:
                continue
            body_nodes = [
                c
                for c in case_children
                if case_attr["body_begin"] <= self.ast.all_nodes[c]["child_idx"]
            ]
            if case_attr["is_default"]:
                default_was_hit = True
            case_text = self.ast.all_nodes[case]["code"]
            case_text = case_text[: case_text.find(":") + 1]
            # TODO: append previous cases with no body
            self.fringes.append((cond_id, case_text))
            for body_node in body_nodes:
                should_continue = self.visit(body_node)
                if should_continue == False:
                    break
        if not default_was_hit:
            self.fringes.append((cond_id, "default:"))
        self.fringes += [(n, "break") for n in self.break_fringes]
        self.break_fringes = []

    def visit_return_statement(self, ast_node_id: int, **kwargs):
        cfg_node_id = self.add_cfg_node(ast_node_id)
        self.add_edge_from_fringe_to(cfg_node_id)

        # TODO: Consider the case that labeled_statement exists in the subsequent statements
        return self.construct_visit_result(continue_visit=False)

    def visit_break_statement(self, ast_node_id: int, **kwargs):
        cfg_node_id = self.add_cfg_node(ast_node_id)
        self.add_edge_from_fringe_to(cfg_node_id)
        self.break_fringes.append(cfg_node_id)

        # TODO: Consider the case that labeled_statement exists in the subsequent statements
        return self.construct_visit_result(continue_visit=False)

    def visit_continue_statement(self, ast_node_id: int, **kwargs):
        cfg_node_id = self.add_cfg_node(ast_node_id)
        self.add_edge_from_fringe_to(cfg_node_id)
        self.continue_fringes.append(cfg_node_id)

        # TODO: Consider the case that labeled_statement exists in the subsequent statements
        return self.construct_visit_result(continue_visit=False)

    def visit_goto_statement(self, ast_node_id: int, **kwargs):
        label_ast_node_id = None

        for child_ast_node_id in self.get_node_ast_children(ast_node_id):
            child_ast_node = self.ast.all_nodes[child_ast_node_id]
            if 'field' in child_ast_node and child_ast_node['field'] == 'label':
                label_ast_node_id = child_ast_node['ast_node_id']
                break

        assert label_ast_node_id is not None

        cfg_node_id = self.add_cfg_node(ast_node_id)
        self.add_edge_from_fringe_to(cfg_node_id)

        goto_label_node = self.ast.all_nodes[label_ast_node_id]
        assert goto_label_node["node_type"] == "statement_identifier"
        self.gotos[goto_label_node["code"]] = cfg_node_id

        # TODO: Consider the case that labeled_statement exists in the subsequent statements
        return self.construct_visit_result(continue_visit=False)

    def add_label_node(self, ast_node_id: int):
        label_ast_node_id = None

        for child_ast_node_id in self.get_node_ast_children(ast_node_id):
            child_ast_node = self.ast.all_nodes[child_ast_node_id]
            if 'field' in child_ast_node and child_ast_node['field'] == 'label':
                label_ast_node_id = child_ast_node['ast_node_id']
                break

        assert label_ast_node_id is not None

        # code = self.ast.nodes[ast_node_id]["code"]
        # code = code[:code.find(":") + 1]
        # cfg_node_id = self.add_cfg_node(ast_node_id, code=code)
        cfg_node_id = self.add_cfg_node(ast_node_id)
        self.add_edge_from_fringe_to(cfg_node_id)

        label_child = self.ast.all_nodes[label_ast_node_id]
        assert label_child["node_type"] == "statement_identifier"
        self.labels[label_child["code"]] = cfg_node_id
        self.fringes.append(cfg_node_id)

    def visit_labeled_statement(self, ast_node_id: int, **kwargs) -> Dict:
        self.add_label_node(ast_node_id)
        return self.construct_visit_result()


class CFGParser:
    @staticmethod
    def parse(data: Union[nx.DiGraph, str]) -> Optional[nx.DiGraph]:
        """
            Parse data into a CFG.
            Data can be a AST graph (nx.Graph) or source code file path (str).
        """
        if isinstance(data, nx.Graph):
            assert data.graph["graph_type"] == "AST"
            ast = data
        else:
            ast = ASTParser.parse(data)

        if ast is None:
            logger.error('AST is None, cannot construct CFG.')
            return None
        visitor = CFGVisitor(ast)
        visitor.preprocess()
        visitor.visit(ast.graph["root_node"])
        visitor.postprocess()
        visitor.cfg.graph["graph_type"] = "CFG"
        visitor.cfg.graph["parents"] = {"AST": ast}

        return visitor.cfg
