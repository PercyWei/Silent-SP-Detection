from typing import *

from tree_sitter import Node as tsNode


def _find_import_path_in_dotted_name_node(dotted_name_node: tsNode) -> List[str]:
    """
        'dotted_name' statement is formatted as 'p1.p2'.

        Args:
            dotted_name_node:
        Returns:
            List[str]: Import path like [p1, p2]
    """
    assert dotted_name_node.grammar_name == 'dotted_name'
    dotted_name = dotted_name_node.text.decode('utf-8')
    import_path = dotted_name.split('.')

    return import_path


def _find_import_path_in_aliased_import_node(aliased_import_node: tsNode) -> List[str]:
    """
        'aliased_import' statement is formatted as 'p1.p2 as p'.

        Args:
            aliased_import_node:
        Returns:
            List[str]: Import path like [p1, p2]
    """
    assert aliased_import_node.grammar_name == 'aliased_import'
    for child in aliased_import_node.children:
        assert child.grammar_name in ['dotted_name', 'as', 'identifier', 'line_continuation']

    import_path = _find_import_path_in_dotted_name_node(aliased_import_node.children[0])

    return import_path


def _find_import_path_in_relative_import_node(relative_import_node: tsNode) -> List[str]:
    """
        'relative_import' statement is formatted as:
            .
            ..
            .p1.p2
            ..p1.p2

        Args:
            relative_import_node:
        Returns:
            List[str]: Import path like ['.', p1, p2] or ['..', p1, p2]
    """
    assert len(relative_import_node.children) == 1 or len(relative_import_node.children) == 2
    import_prefix_node = relative_import_node.children[0]
    dotted_name_node = relative_import_node.children[1] if len(relative_import_node.children) > 1 else None

    import_path = []
    # 'import_prefix' means ‘.’/‘..' in '.p1.p2'/'..p1.p2'
    # Get '.'/'..' first
    import_path.append(import_prefix_node.text.decode('utf-8'))

    # 'dotted_name' means 'p1.p2' in '.p1.p2'/'..p1.p2'
    # Get ['p1', 'p2'] then
    if dotted_name_node is not None:
        suffix_import_path = _find_import_path_in_dotted_name_node(dotted_name_node)
        import_path.extend(suffix_import_path)

    return import_path


def _find_import_path_in_import_stat_node(import_statement_node: tsNode) -> List[List[str]]:
    """
        'import_statement' statement is formatted as:
            import p1.p2, ...
            import p1.p2 as p, ...

        Args:
            import_statement_node:
        Returns:
            List[List[str]]: A List containing import path like [p1, p2]
    """
    assert len(import_statement_node.children) >= 2
    assert import_statement_node.children[0].grammar_name == 'import'

    # Find import path in each 'dotted_name' node or 'aliased_import' node
    import_paths = []
    for child in import_statement_node.children[1:]:
        if child.grammar_name == 'dotted_name':
            current_import_path = _find_import_path_in_dotted_name_node(child)
            import_paths.append(current_import_path)
        elif child.grammar_name == 'aliased_import':
            current_import_path = _find_import_path_in_aliased_import_node(child)
            import_paths.append(current_import_path)
        elif child.grammar_name == ',':
            continue
        else:
            raise RuntimeError(
                f"Child of 'import_statement' node has an unexpected grammar_name: {child.grammar_name}!")

    return import_paths


def _find_import_path_in_import_from_stat_node(import_from_statement_node: tsNode) -> Tuple[List[str], List[str]]:
    """
        'import_from_statement' statement is formatted as:
            1. After 'from'
                from p1.p2 import ...
                from .p1.p2 import ...
                from ..p1.p2 import ...
            2. After 'import'
                from ... import *
                from ... import m1, ...
                from ... import m1 as m, ...
                from ... import (m1, m2 as m, ...)

        Args:
            import_from_statement_node
        Returns:
            List[str]: 'prefix_import_path', import path between 'from' and 'import' in 'from xx import ...'
            List[List[str]]: 'suffix_import_paths', a List containing import path like after 'import' in 'from ... import xx, xx'
    """
    assert len(import_from_statement_node.children) >= 4
    assert import_from_statement_node.children[0].grammar_name == 'from'
    assert import_from_statement_node.children[2].grammar_name == 'import'

    # For 'prefix_import_path' after 'from' in 'from xx import ...'
    if import_from_statement_node.children[1].grammar_name == 'relative_import':
        prefix_import_path = _find_import_path_in_relative_import_node(import_from_statement_node.children[1])
    elif import_from_statement_node.children[1].grammar_name == 'dotted_name':
        prefix_import_path = _find_import_path_in_dotted_name_node(import_from_statement_node.children[1])
    else:
        raise RuntimeError(f"The second child of 'import_from_statement' node has an unexpected grammar_name: "
                           f"{import_from_statement_node.children[1].grammar_name}!")

    # For 'suffix_import_path' after 'import' in 'from ... import xx'
    suffix_import_paths = []
    for node in import_from_statement_node.children[3:]:
        if node.grammar_name == 'wildcard_import':
            assert len(import_from_statement_node.children) == 4
        elif node.grammar_name == 'dotted_name':
            current_suffix_import_path = _find_import_path_in_dotted_name_node(node)
            assert len(current_suffix_import_path) == 1

            suffix_import_paths.append(current_suffix_import_path[0])
        elif node.grammar_name == 'aliased_import':
            current_suffix_import_path = _find_import_path_in_aliased_import_node(node)
            assert len(current_suffix_import_path) == 1

            suffix_import_paths.append(current_suffix_import_path[0])
        elif node.grammar_name == ',' or node.grammar_name == '(' or node.grammar_name == ')' \
                or node.grammar_name == 'line_continuation':
            continue
        else:
            raise RuntimeError(f"Child of 'import_from_statement' node has an unexpected grammar_name: "
                               f"{node.grammar_name}!")

    return prefix_import_path, suffix_import_paths


def _find_import_path_in_future_import_stat_node(future_import_statement_node: tsNode) -> List[str]:
    """
        'future_import_statement' statement is formatted as
            from __future__ import m1, ...
            from __future__ import m1 as m, ...
            from __future__ import (m1, m2 as m, ...)

        Args:
            future_import_statement_node:
        Returns:
            List[str]: elements after 'import' in 'from __future__ import ...'
    """
    assert len(future_import_statement_node.children) >= 4
    assert future_import_statement_node.children[0].grammar_name == 'from'
    assert future_import_statement_node.children[1].grammar_name == '__future__'
    assert future_import_statement_node.children[2].grammar_name == 'import'

    import_paths = []
    for child in future_import_statement_node.children[3:]:
        if child.grammar_name == 'dotted_name':
            current_import_path = _find_import_path_in_dotted_name_node(child)
            assert len(current_import_path) == 1

            import_paths.append(current_import_path[0])
        elif child.grammar_name == 'aliased_import':
            current_import_path = _find_import_path_in_aliased_import_node(child)
            assert len(current_import_path) == 1

            import_paths.append(current_import_path[0])
        elif child.grammar_name == ',' or child.grammar_name == '(' or child.grammar_name == ')' \
                or child.grammar_name == 'line_continuation':
            continue
        else:
            raise RuntimeError(
                f"Child of 'future_import_statement' node has an unexpected grammar_name: {child.grammar_name}!")

    return import_paths


def _find_func_or_class_def_node_in_decorated_def_node(decorated_definition_node: tsNode) -> tsNode:
    assert decorated_definition_node.type == 'decorated_definition'
    for child in decorated_definition_node.children[:-1]:
        assert child.type == 'decorator'

    assert decorated_definition_node.children[-1].type == 'class_definition' or \
           decorated_definition_node.children[-1].type == 'function_definition'

    return decorated_definition_node.children[-1]


def find_top_level_elements_in_py(root_node: tsNode) -> Tuple[List, List, List, List, List]:
    """
    There are 5 types of top-level elements in Python source code.
    import_statement:
    global_statement:
    func_def:
    class_def:
    if_main_block:

    Args:
        root_node:
    """
    import_statements = []
    global_statements = []
    func_defs = []
    class_defs = []
    if_main_block = []

    for child in root_node.children:
        if child.type == 'future_import_statement' or \
                child.type == 'import_statement' or \
                child.type == 'import_from_statement':
            import_statements.append(child)

        elif child.type == 'decorated_definition':
            definition = child.child_by_field_name('definition')
            if definition.type == 'class_definition':
                class_defs.append(child)
            elif definition.type == 'function_definition':
                func_defs.append(child)
            else:
                raise RuntimeError(f"Unexpected type {child.type} in 'definition' field of 'decorated_definition'.")

        elif child.type == 'function_definition':
            func_defs.append(child)

        elif child.type == 'class_definition':
            class_defs.append(child)

        elif child.type == 'if_statement' and \
                (child.text.decode('utf-8').startswith("if __name__ == '__main__':") or
                 child.text.decode('utf-8').startswith('if __name__ == "__main__":')):
            if_main_block.append(child)

        else:
            global_statements.append(child)

    assert len(if_main_block) == 1 or len(if_main_block) == 0

    return import_statements, global_statements, func_defs, class_defs, if_main_block









