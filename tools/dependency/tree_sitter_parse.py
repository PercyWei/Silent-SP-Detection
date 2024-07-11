import os
import json
import re
import queue
from typing import *

import tree_sitter
from tree_sitter import Parser, Language, Node as tsNode

from old_utils.logging import logger
from old_utils.dependency import build_project_structure, traversal_proj_struct_find_spec_file_extension_files
from old_utils.utils import set_value_in_dict
from tree_sitter_parse_py import (_find_import_path_in_import_stat_node,
                                  _find_import_path_in_import_from_stat_node,
                                  _find_import_path_in_future_import_stat_node,
                                  _find_func_or_class_def_node_in_decorated_def_node,
                                  find_top_level_elements_in_py)


def remove_continuous_blank_lines(source_code: str) -> str:
    cleaned_code = re.sub(r'(\n\s*\n)+', '\n\n', source_code)
    return cleaned_code


def remove_comments(root_node: tsNode, source_code_bytes: bytearray) -> bytearray:
    """
    Remove comments from source code under tree-sitter

    Args:
        root_node: Root node of source code generated by tree-sitter
        source_code_bytes: Binary representation of the source code
    Returns:
        Binary representation of the source code without comments
    """
    comment_nodes = []

    tasks = queue.SimpleQueue()
    tasks.put(root_node)
    while not tasks.empty():
        node = tasks.get()
        if node.type == 'comment':
            comment_nodes.append(node)
        else:
            for child in node.children:
                tasks.put(child)

    new_code = bytearray()
    start_byte = 0
    for node in sorted(comment_nodes, key=lambda n: n.start_byte):
        new_code.extend(source_code_bytes[start_byte:node.start_byte])
        start_byte = node.end_byte
    new_code.extend(source_code_bytes[start_byte:])
    return new_code


def is_path_in_project(path: List[str], prefix_path: List[str], project_structure: Dict) -> bool:
    """
        Judge if the 'new_path' is a path to project package or module.

        Args:
            path:
            prefix_path: Where to start searching (root / current module dir)
            project_structure:
        Returns:
            bool: True if the given path is in project_structure, else False
    """
    complete_path = prefix_path + path

    # For path [p1, p2, ..., pn]
    # p1, p2, ..., pn-1 must be packages
    current_level = project_structure
    for path_part in complete_path[:-1]:
        if path_part in current_level:
            current_level = current_level[path_part]
            if current_level is None:
                logger.warning(f"Module not at the end: {complete_path}")
                return False
        else:
            return False

    # pn could be a package or module
    assert current_level is not None
    if complete_path[-1] in current_level:
        if current_level[complete_path[-1]] is None:
            logger.warning(f"Module not end with '.py': {complete_path}")
            return False
        else:
            # Path is package
            pass
    elif complete_path[-1] + '.py' in current_level:
        # Path is module
        pass
    else:
        return False

    # Check for package compliance
    invalid_flag = False
    current_level = project_structure
    for path_part in complete_path[:-1]:
        current_level = current_level[path_part]
        if '__init__.py' not in current_level:
            invalid_flag = True

    if complete_path[-1] in current_level:
        current_level = current_level[complete_path[-1]]
        if '__init__.py' not in current_level:
            invalid_flag = True

    if invalid_flag:
        logger.warning(f"Invalid import path! Package with no '__init.py__': {complete_path}")

    return True


def is_import_path_rel_or_abs_in_project(import_path: List[str],
                                         current_module_path: List[str],
                                         project_structure: Dict) -> Tuple[List, bool]:
    """

        Args:
            import_path:
            current_module_path: Path to current .py module, like ['p1', 'p2', 'm1'], while '/p1/p2/m3.py' is the path
            project_structure:
        Returns:
            Import path (List): Relative to project root if judgement result is True
            Judgement result (bool):
    """
    # Relative import (search from the current module dir)
    assert current_module_path[-1].endswith('.py')
    rel_result = is_path_in_project(import_path, current_module_path[:-1], project_structure)
    if not rel_result:
        # Absolute import (search from project root)
        abs_result = is_path_in_project(import_path, [], project_structure)
        if not abs_result:
            return import_path, False
        else:
            return import_path, True
    else:
        return current_module_path[:-1] + import_path, True


def add_import_module_suffix(module_name: str) -> List[str]:
    """
        Get the full names of commonly python import modules.
    """
    py_module = module_name + '.py'
    pyi_module = module_name + '.pyi'
    pyc_module = module_name + '.pyc'
    pyo_module = module_name + '.pyo'

    return [py_module, pyi_module, pyc_module, pyo_module]


def is_module_in_current_level(element_name: str, current_level: Dict) -> bool:
    """
        Judge if the given element is a module in current level.
    """
    full_module_names = add_import_module_suffix(element_name)

    module_exist_flag = False
    for full_module_name in full_module_names:
        if full_module_name in current_level:
            module_exist_flag = True
            break

    return module_exist_flag


def is_package_in_current_level(element_name: str, current_level: Dict) -> bool:
    """
        Judge if the given element is a package in current level.
    """
    return element_name in current_level


def judge_project_import_of_py_file(import_stmt_node: tsNode,
                                    project_structure: Dict,
                                    current_module_path: List[str]) -> List[Tuple[List, bool, Optional[str], List[str]]]:
    """
        Judge if the import statement imports a package or module for the project.

        Args:
            import_stmt_node:
            project_structure:
            current_module_path: Path to current .py module, like ['p1', 'p2', 'm1'], while '/p1/p2/m3.py' is the path
        Returns:
            List: import path
            bool: if the path to project module or package
            Optional[str]: error msg, None if no error
            List[str]: import items, only valid for 'import_from_statement' and 'future_import_statement'
    """
    import_path_result_list = []

    if import_stmt_node.grammar_name == 'import_statement':
        import_paths = _find_import_path_in_import_stat_node(import_stmt_node)

        # For the import of form 'import p1.p2.m, ...':
        # 1. p1, p2 can only be packages
        # 2. m can be package or module
        # 3. p1, p2, m can not be class or func in module
        for import_path in import_paths:
            import_path_from_root, result = is_import_path_rel_or_abs_in_project(import_path,
                                                                                 current_module_path,
                                                                                 project_structure)
            current_import_path_result = (import_path_from_root, result, None, [])
            import_path_result_list.append(current_import_path_result)

    elif import_stmt_node.grammar_name == 'import_from_statement':
        prefix_import_path, suffix_import_paths = _find_import_path_in_import_from_stat_node(import_stmt_node)

        # For the import of form 'from p1.p2.p3 import m, ...':
        # 1. p1, p2 can only be packages
        # 2. p3 can be package or module
        # 3. p1, p2, p3 can not be class or func in module
        # Note: The above is the same as 'import_statement'

        # 4. Nesting is not supported after 'import', therefore it can only be 'm' but not 'p4.m'
        # 5. m can be package / module / class or func in module

        error_flag = False
        import_path_result = ()
        # Judge 'prefix_import_path' first
        if set(prefix_import_path[0]) == {'.'}:
            # Relative import: 'from ..p1.p2.p3 import ...'
            up_levels = len(prefix_import_path[0])
            assert up_levels <= len(current_module_path)

            abs_prefix_import_path = current_module_path[:-up_levels] + prefix_import_path[1:]
            prefix_import_path_result = True

            # Check if the path exists: ..p1.p2.p3
            # Check [..., p1, p2] first
            error_msg = f"The original import path is like '..p1.p2.p3' while it not exist: {abs_prefix_import_path}"

            current_level = project_structure
            try:
                for path_level in abs_prefix_import_path[:-1]:
                    current_level = current_level[path_level]
            except KeyError:
                error_flag = True
                import_path_result = (abs_prefix_import_path, False, error_msg)

            # Check p3 then
            last_path_part = abs_prefix_import_path[-1]
            if not error_flag:
                if not (is_package_in_current_level(last_path_part, current_level) or
                        is_module_in_current_level(last_path_part, current_level)):
                    error_flag = True
                    import_path_result = (abs_prefix_import_path, False, error_msg)

        else:
            # Absolute import: 'from p1.p2.p3 import ...'
            abs_prefix_import_path, prefix_import_path_result = is_import_path_rel_or_abs_in_project(prefix_import_path,
                                                                                                     current_module_path,
                                                                                                     project_structure)

        if not error_flag:
            import_path_result = (abs_prefix_import_path, True, None)

        import_path_result = (*import_path_result, suffix_import_paths)
        import_path_result_list.append(import_path_result)

        # TODO: The following approach may be too granular and ill-considered
        # # Judge 'suffix_import_paths' then
        # if prefix_import_path_result:
        #     # p1, p2 are packages, p3 is package or module
        #     if len(suffix_import_paths) == 0:
        #         # Format is 'from p1.p2.p3 import *'
        #         import_path_with_result_list.append((abs_prefix_import_path, True, None))
        #     else:
        #         # Format is 'from p1.p2.p3 import ...'
        #         current_level = project_structure
        #         try:
        #             for path_level in abs_prefix_import_path[:-1]:
        #                 current_level = current_level[path_level]
        #         except KeyError:
        #             # Error: path not exist, may only occur when using relative import (i.e. '.p1.p2.p3')
        #             error_msg = f"The original import is like '..p1.p2' and path not exist: {abs_prefix_import_path}"
        #             import_path_with_result_list.append((abs_prefix_import_path, False, error_msg))
        #             return import_path_with_result_list
        #
        #         # p3 is 'abs_prefix_import_path[-1]'
        #         if abs_prefix_import_path[-1] not in current_level:
        #             # p3 is module, m can only be class or func in module
        #             if not is_module_in_current_level(abs_prefix_import_path[-1], current_level):
        #                 # Error: p3 (module) not exist
        #                 error_mag = f"Path is to module while it not exist: {abs_prefix_import_path}"
        #                 import_path_with_result_list.append((abs_prefix_import_path, False, error_mag))
        #             else:
        #                 # p3 (module) exists
        #                 import_path_with_result_list.append((abs_prefix_import_path, True, None))
        #         else:
        #             # p3 is package, m can be package / module / class or func in module
        #             current_level = current_level[abs_prefix_import_path[-1]]
        #
        #             for suffix_import_path in suffix_import_paths:
        #                 if suffix_import_path in current_level or is_module_in_current_level(suffix_import_path, current_level):
        #                     # m is package or module
        #                     import_path_with_result_list.append((abs_prefix_import_path + [suffix_import_path], True, None))
        #                 else:
        #                     # m is class or func in module
        #                     # TODO: some incorrect import may happen here
        #                     if (abs_prefix_import_path, True, None) not in import_path_with_result_list:
        #                         import_path_with_result_list.append((abs_prefix_import_path, True, None))
        #
        # else:
        #     if len(suffix_import_paths) == 0:
        #         # Format is 'from ... import *'
        #         import_path_with_result_list.append((abs_prefix_import_path, False))
        #     else:
        #         # Format is 'from ... import ...'
        #         for suffix_import_path in suffix_import_paths:
        #             import_path_with_result_list.append((abs_prefix_import_path + [suffix_import_path], False))

    elif import_stmt_node.grammar_name == 'future_import_statement':
        import_paths = _find_import_path_in_future_import_stat_node(import_stmt_node)

        # TODO: Features imported from __future__ are limited in doc
        import_path_result = (['__future__'], False, None, import_paths)
        import_path_result_list.append(import_path_result)

    else:
        raise RuntimeError(f"import_stmt_node has an unexpected grammar_name: {import_stmt_node.grammar_name}!")

    return import_path_result_list


def parse_and_get_root_node(lang: str, so_fpath: str, source_fpath: str):
    """
        Parse the source code and return the root node of its parse tree.

        Args:
            lang: Programming language
            so_fpath:
            source_fpath: Path to source code file
        Returns:
             root_node: Root node of the parsed tree
    """
    assert lang in ["c", "cpp", "python", "java"]
    parser = prepare_specified_lang_parser(lang, so_fpath)

    try:
        with open(source_fpath, "r", encoding='utf-8') as f:
            source_code = f.read()

        source_code_byte = bytes(source_code, "utf-8")
        old_tree = parser.parse(source_code_byte)

        # Remove comments and extra blank lines
        old_root_node = old_tree.root_node
        no_comments_code_byte = remove_comments(old_root_node, source_code_byte)
        no_comments_code = no_comments_code_byte.decode("utf-8")
        clean_code = remove_continuous_blank_lines(no_comments_code)

        # Find top nodes of the cleaned source code
        new_tree = parser.parse(bytes(clean_code, "utf-8"))
        new_root_node = new_tree.root_node

        return new_root_node
    except UnicodeDecodeError:
        logger.error("UnicodeDecodeError while reading source code file!")
        return None


def parse(lang: str, so_fpath: str, source_fpath: str, project_structure: Dict, current_module_path: List[str]):

    if lang == 'python':
        logger.info(f"Tree-sitter parse >>> source code: {'/'.join(current_module_path)}.")

        root_node = parse_and_get_root_node(lang, so_fpath, source_fpath)

        if root_node is not None:
            import_statements, global_statements, func_defs, class_defs, if_main_block = \
                find_top_level_elements_in_py(root_node)

            # Test function: judge_project_import
            # for i, import_statement_node in enumerate(import_statements):
            #     import_path_with_result_list = judge_project_import(import_statement_node,
            #                                                         project_structure, current_module_path)
            #     logger.info('=' * 50 + f"{i + 1}" + '=' * 50)
            #     logger.info(f"Import statement: {import_statement_node.text.decode('utf-8')}")
            #     for import_path, result, error_msg, import_items in import_path_with_result_list:
            #         logger.info(f"--  import path: {'.'.join(import_path)}")
            #         logger.info(f"--       result: {result}")
            #         logger.info(f"-- import items: {import_items}")
            #         if error_msg is not None:
            #             logger.info(f"--    error msg: {error_msg}")

    elif lang == 'java':
        # TODO
        pass
    elif lang == 'c':
        # TODO
        pass
    elif lang == 'cpp':
        # TODO
        pass
    else:
        raise RuntimeError(f"Unsupported language: {lang}!")


def get_project_py_files_info(so_fpath: str, project_root_dpath: str, project_structure: Dict) -> Dict:
    """
        Get information of all files with specified programming language in the given project.

        Args:
            so_fpath:
            project_root_dpath:
            project_structure
        Returns:
            A Dict:
                key: File path (absolute to project root)
                value: File information (Dict):
                    'file_path' (List): The key path in the 'project_structure' dict
                    'class_defs' (List): Class names
                    'function_defs' (List): Function names
                    'global_stmts' (List): Global statements
    """
    # Find all files with specified programming language in the given project
    py_file_paths = traversal_proj_struct_find_spec_file_extension_files(project_structure, [], '.py')

    all_py_file_info = {}
    for py_file_path in py_file_paths:
        py_fpath = os.path.join(project_root_dpath, '/'.join(py_file_path))
        assert os.path.exists(py_fpath)

        current_file_info = {'file_path': py_file_path}

        root_node = parse_and_get_root_node('python', so_fpath, py_fpath)
        if root_node is not None:
            import_statements, global_statements, func_defs, class_defs, if_main_block = \
                find_top_level_elements_in_py(root_node)

            class_items = []
            func_items = []
            global_items = []

            # Get all class names
            for class_def_node in class_defs:
                if class_def_node.type == 'decorated_definition':
                    class_def_node = _find_func_or_class_def_node_in_decorated_def_node(class_def_node)

                if class_def_node.children[1].type == 'identifier':
                    current_class_name = class_def_node.children[1].text.decode('utf-8')
                else:
                    for child in class_def_node.children:
                        print(child.type, end=' ')
                    raise RuntimeError("The second child of 'class_definition' node is not a node of type 'identifier' "
                                       "denoting class name.")
                class_items.append(current_class_name)

            # Get all function names
            for func_def_node in func_defs:
                if func_def_node.type == 'decorated_definition':
                    func_def_node = _find_func_or_class_def_node_in_decorated_def_node(func_def_node)

                if func_def_node.children[1].type == 'identifier':
                    current_func_name = func_def_node.children[1].text.decode('utf-8')
                elif func_def_node.children[2].type == 'identifier':
                    current_func_name = func_def_node.children[2].text.decode('utf-8')
                else:
                    for child in func_def_node.children:
                        print(child.type, end=' ')
                    raise RuntimeError("The second or third child of 'function_definition' node is not a node of "
                                       "type 'identifier' denoting function name.")
                func_items.append(current_func_name)

            # Get all global statements
            for global_stmt_node in global_statements:
                global_items.append(global_stmt_node.text.decode('utf-8'))
            for if_main_block_node in if_main_block:
                global_items.append(if_main_block_node.text.decode('utf-8'))

            # Complete information
            current_file_info.update({
                'class_defs': class_items,
                'func_defs': func_items,
                'global_stmts': global_items,
            })

        all_py_file_info[py_fpath] = current_file_info

    return all_py_file_info


def get_project_java_files_info(so_fpath: str, project_root_dpath: str, project_structure: Dict) -> Dict:
    # TODO
    pass


def get_project_c_files_info(so_fpath: str, project_root_dpath: str, project_structure: Dict) -> Dict:
    # TODO
    pass


def get_project_cpp_files_info(so_fpath: str, project_root_dpath: str, project_structure: Dict) -> Dict:
    # TODO
    pass


def get_project_all_lang_files_info(so_fpath: str, project_root_dpath: str, project_structure: Dict) -> Dict:
    all_lang = ['python', 'java', 'c', 'cpp']

    all_lang_file_info = {}
    for lang in all_lang:
        if lang == 'python':
            current_lang_files_info = get_project_py_files_info(so_fpath, project_root_dpath, project_structure)
        elif lang == 'java':
            current_lang_files_info = get_project_java_files_info(so_fpath, project_root_dpath, project_structure)
        elif lang == 'c':
            current_lang_files_info = get_project_c_files_info(so_fpath, project_root_dpath, project_structure)
        elif lang == 'cpp':
            current_lang_files_info = get_project_cpp_files_info(so_fpath, project_root_dpath, project_structure)
        else:
            raise RuntimeError(f"Unsupported language: {lang}!")

        all_lang_file_info[lang] = current_lang_files_info

    return all_lang_file_info



