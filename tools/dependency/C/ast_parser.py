import networkx as nx

from typing import *
from tree_sitter import Node as tsNode

# from ..util import Counter, prepare_specified_lang_parser, TraversalFindFaultLines
from tools.dependency.util import Counter, prepare_specified_lang_parser, TraversalFindFaultLines
from old_utils.logging import logger


def assert_boolean_expression(n):
    assert (
        n.type.endswith("_statement")
        or n.type.endswith("_expression")
        or n.type in ("true", "false", "identifier", "number_literal")  # TODO: handle ERROR (most often shows up as comma_expression in for loop conditional)
    ), (n, n.type, n.text.decode())


class AstErrorException(Exception):
    pass


class ASTVisitor:
    """
        AST visitor which creates an AST tree.
    """
    def __init__(self, strict: bool):
        self.ast = nx.DiGraph()
        self.counter = Counter()
        self.strict = strict

    @staticmethod
    def get_type(node: tsNode) -> str:
        return node.type

    @staticmethod
    def check_ast_error_in_children(node: tsNode):
        if any(child.type == "ERROR" for child in node.children):
            raise AstErrorException(node.text.decode())

    """VISIT"""

    def visit(self, node: tsNode, parent_id: Optional[int], **kwargs):
        """
        Visit a tree-sitter node.

        Args:
            node: The tree-sitter node to visit
            parent_id: The id of parent of current tree-sitter node
            **kwargs: Attributes passed from parent tree-sitter node
        """
        if self.strict:
            if node.has_error or node.is_missing:
                has_error_lines, is_missing_lines = TraversalFindFaultLines.parse(node)
                logger.error(f"Tree-sitter parsing find error\n"
                             f"\t\thas_error lines: {has_error_lines}, is_missing lines: {is_missing_lines}.")
                raise AstErrorException()
        else:
            # TODO: How to deal with node with error or missing?
            pass

        # Visit current node
        visit_result = getattr(
            self, f"visit_{self.get_type(node)}", self.visit_default
        )(node=node, parent_id=parent_id, **kwargs)

        # Visit children of current node
        visit_children = visit_result.pop('visit_children')
        current_id = visit_result.pop('current_id')
        if visit_children:
            self.visit_children(node=node, parent_id=current_id, **visit_result)

    def visit_children(self, node: tsNode, parent_id: Optional[int], **kwargs):
        """
        Visit child tree-sitter nodes.

        Args:
            node: Parent tree-sitter node
            parent_id: Parent tree-sitter node id
            **kwargs: Attributes passed to child node
        """
        for i, child in enumerate(node.children):
            self.visit(child, parent_id, **kwargs)

    @staticmethod
    def construct_visit_result(visit_children: bool, current_id: Optional[int], **kwargs) -> Dict:
        """
        Constructs visit result after visiting tree-sitter node.
        Args:
            visit_children: If to continue visiting child nodes
            current_id: Current node id
            **kwargs: Other attributes to pass to child nodes
        Returns:
        """
        return {
            "visit_children": visit_children,
            "current_id": current_id,
            **kwargs
        }

    """ADD NODE AND EDGE"""

    def add_node_and_edge(self, node: tsNode, parent_id: Optional[int], **kwargs) -> int:
        code = node.text.decode()
        current_id = self.counter.get_and_increment()
        if parent_id is None:
            self.ast.graph["root_node"] = current_id

        def attr_to_label(node_type: str, node_code: str) -> str:
            lines = node_code.splitlines()
            if len(lines) > 0:
                node_code = lines[0]
                max_len = 27
                trimmed_code = node_code[:max_len]
                if len(lines) > 1 or len(node_code) > max_len:
                    trimmed_code += "..."
            else:
                trimmed_code = node_code
            return node_type + "\n" + trimmed_code

        # TODO: Whether to consider unnamed nodes?
        # if node.is_named and node.type != "comment":
        if node.type != "comment":
            # Add node
            self.ast.add_node(
                current_id,
                n=node,
                label=attr_to_label(node.type, code),
                code=code,
                node_type=node.type,
                start=node.start_point,
                end=node.end_point,
                ast_node_id=current_id,
                parent_id=parent_id,
                **kwargs
            )
            # Add edge
            if parent_id is not None:
                self.ast.add_edge(parent_id, current_id)

        return current_id

    """VISIT RULES"""
    def visit_default(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        current_id = self.add_node_and_edge(node, parent_id=parent_id, **kwargs)
        return self.construct_visit_result(visit_children=True, current_id=current_id)

    def visit_case_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)

        colon_idx = 0
        while node.children[colon_idx].type != ":":
            colon_idx += 1
        body_begin = colon_idx + 1
        is_default = any(child for child in node.children if child.text.decode() == "default")

        current_id = self.add_node_and_edge(node, parent_id=parent_id,
                                            body_begin=body_begin, is_default=is_default,
                                            **kwargs)

        return self.construct_visit_result(visit_children=True, current_id=current_id)


    def visit_if_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)
        assert len(node.children) == 3 or len(node.children) == 4

        cond_child = node.child_by_field_name('condition')
        cons_child = node.child_by_field_name('consequence')
        alt_child = node.child_by_field_name('alternative')

        assert cond_child is not None and cons_child is not None
        has_alt = alt_child is not None

        current_id = self.add_node_and_edge(node, parent_id=parent_id,
                                            has_alt=has_alt,
                                            **kwargs)

        # Visit children
        for child in node.children:
            if child == cond_child:
                self.visit(child, parent_id=current_id, field='condition')
            elif child == cons_child:
                self.visit(child, parent_id=current_id, field='consequence')
            elif has_alt and child == alt_child:
                self.visit(child, parent_id=current_id, field='alternative')
            else:
                self.visit(child, parent_id=current_id)

        return self.construct_visit_result(visit_children=False, current_id=current_id)

    def visit_for_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)

        init_child = node.child_by_field_name('initializer')
        cond_child = node.child_by_field_name('condition')
        updt_child = node.child_by_field_name('update')
        body_child = node.child_by_field_name('body')

        has_init = init_child is not None
        has_cond = cond_child is not None
        has_updt = updt_child is not None
        assert body_child is not None

        current_id = self.add_node_and_edge(node, parent_id=parent_id,
                                            has_init=has_init, has_cond=has_cond, has_updt=has_updt,
                                            **kwargs)

        # Visit children
        for child in node.children:
            if has_init and child == init_child:
                self.visit(child, parent_id=current_id, field='initializer')
            elif has_cond and child == cond_child:
                self.visit(child, parent_id=current_id, field='condition')
            elif has_updt and child == updt_child:
                self.visit(child, parent_id=current_id, field='update')
            elif child == body_child:
                self.visit(child, parent_id=current_id, field='body')
            else:
                self.visit(child, parent_id=current_id)

        return self.construct_visit_result(visit_children=False, current_id=current_id)

    def visit_while_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)

        cond_child = node.child_by_field_name('condition')
        body_child = node.child_by_field_name('body')

        assert cond_child is not None and body_child is not None

        current_id = self.add_node_and_edge(node, parent_id=parent_id, **kwargs)

        # Visit children
        for child in node.children:
            if child == cond_child:
                self.visit(child, parent_id=current_id, field='condition')
            elif child == body_child:
                self.visit(child, parent_id=current_id, field='body')
            else:
                self.visit(child, parent_id=current_id)

        return self.construct_visit_result(visit_children=False, current_id=current_id)

    def visit_do_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)

        cond_child = node.child_by_field_name('condition')
        body_child = node.child_by_field_name('body')

        assert cond_child is not None and body_child is not None

        current_id = self.add_node_and_edge(node, parent_id=parent_id, **kwargs)

        # Visit children
        for child in node.children:
            if child == cond_child:
                self.visit(child, parent_id=current_id, field='condition')
            elif child == body_child:
                self.visit(child, parent_id=current_id, field='body')
            else:
                self.visit(child, parent_id=current_id)

        return self.construct_visit_result(visit_children=False, current_id=current_id)

    def visit_goto_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)

        label_child = node.child_by_field_name('label')

        assert label_child is not None

        current_id = self.add_node_and_edge(node, parent_id=parent_id, **kwargs)

        # Visit children
        for child in node.children:
            if child == label_child:
                self.visit(child, parent_id=current_id, field='label')
            else:
                self.visit(child, parent_id=current_id)

        return self.construct_visit_result(visit_children=False, current_id=current_id)

    def visit_labeled_statement(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
        self.check_ast_error_in_children(node)

        label_child = node.children[0]
        assert node.field_name_for_child(0) == "label"

        current_id = self.add_node_and_edge(node, parent_id=parent_id, **kwargs)

        # Visit children
        for child in node.children:
            if child == label_child:
                self.visit(child, parent_id=current_id, field='label')
            else:
                self.visit(child, parent_id=current_id)

        return self.construct_visit_result(visit_children=False, current_id=current_id)

    # def visit_function_definition(self, node: tsNode, parent_id: Optional[int], **kwargs) -> Dict:
    #     pass

    # def visit_ERROR(self):



class ASTParser:
    @staticmethod
    def parse(fpath: str, strict: bool = True,
              so_fpath: str = "/root/projects/tree-sitter-projects/build/my-languages.so") -> Optional[nx.DiGraph]:
        try:
            with open(fpath, "r", encoding='utf-8') as f:
                source_code = f.read()

            parser = prepare_specified_lang_parser("c", so_fpath)
            source_code_byte = bytes(source_code, "utf-8")
            tree = parser.parse(source_code_byte)
            root_node = tree.root_node

            visitor = ASTVisitor(strict=strict)
            visitor.visit(root_node, parent_id=None)
            visitor.ast.graph["graph_type"] = "AST"
            return visitor.ast

        except UnicodeDecodeError:
            logger.error('Failed to construct AST while opening source code file: UnicodeDecodeError')
        except AstErrorException:
            logger.error('Failed to construct AST while parsing source code file: AstErrorException')

        return None
