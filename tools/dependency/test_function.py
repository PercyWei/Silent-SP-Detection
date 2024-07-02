import json
import os
from typing import *
from tree_sitter import Node as tsNode

from joern_parse import (joern_parse_source_code, readFullCPG, readDot, readCPGDot,
                         select_node_useful_info)
from tree_sitter_parse import parse, get_project_all_lang_files_info, remove_comments

from util import prepare_specified_lang_parser
from C.ast_parser import ASTParser
from C.cfg_parser import CFGParser
from C.preprocess import PreProcessError, preprocess, preprocess_error


from utils.dependency import build_project_structure
from utils.utils import execute_command
from utils.logging import logger


class ASTNode:
    def __init__(self, node_id: str, node_info):
        self.id = node_id
        self.father = None
        self.children = []
        self.info = node_info

    def set_father(self, father: str):
        assert self.father is None
        self.father = father

    def add_child(self, child: str):
        self.children.append(child)


def test_joern_parse_source_code(source_fpath: str, out_dpath: str):
    result = joern_parse_source_code(source_fpath, out_dpath)
    print(result)


def test_readFullCPG(p_name: str, f_name: str, joern_out_dpath: str, out_dpath: str):
    result = readFullCPG(p_name, f_name, joern_out_dpath, out_dpath)
    print(result)


def test_readDot(dot_dpath: str) -> Tuple[List[str], List[Tuple[str, str]]]:
    files = os.listdir(dot_dpath)

    all_vertices = []
    all_edges = []

    for file in files:
        file_path = os.path.join(dot_dpath, file)
        if file.endswith('.dot'):
            file_vertices, file_edges = readDot(file_path)

            all_vertices += file_vertices
            all_edges += file_edges

            all_vertices = list(set(all_vertices))
            all_edges = list(set(all_edges))

    return all_vertices, all_edges


def test_readCPGDot(source_fpath: str, root_out_dpath: str):
    """
    Check if the vertices and edges read from the corresponding json and dot files are the same.

    Args:
        source_fpath: Path to the source code file
        root_out_dpath: Path to the root dir of output files
    """
    p_name = source_fpath.split('/')[4]
    f_name = '.'.join(source_fpath.split('/')[5:])
    joern_out_dpath = os.path.join(root_out_dpath, 'Joern_output', p_name, f_name)

    all_cpg_dot_vertices = []
    all_cpg_dot_edges = []
    all_cpg_json_vertices = []
    all_cpg_json_edges = []

    cpg_dot_dpath = os.path.join(joern_out_dpath, 'cpg_dot')
    cpg_json_dpath = os.path.join(joern_out_dpath, 'cpg')

    sub_cpg_dot_dirs = os.listdir(cpg_dot_dpath)
    sub_cpg_json_dirs = os.listdir(cpg_json_dpath)

    assert set(sub_cpg_dot_dirs) == set(sub_cpg_json_dirs)

    for sub_cpg_dir in sub_cpg_dot_dirs:
        sub_cpg_dot_dpath = os.path.join(cpg_dot_dpath, sub_cpg_dir)
        sub_cpg_json_dpath = os.path.join(cpg_json_dpath, sub_cpg_dir)

        cpg_dot_files = os.listdir(sub_cpg_dot_dpath)
        cpg_json_files = os.listdir(sub_cpg_json_dpath)

        assert len(cpg_dot_files) == len(cpg_json_files)

        for cpg_dot_file in cpg_dot_files:
            cpg_dot_fpath = os.path.join(sub_cpg_dot_dpath, cpg_dot_file)
            cpg_json_fpath = os.path.join(sub_cpg_json_dpath, cpg_dot_file.replace('.dot', '.json'))

            print(f"CPG dot file: {cpg_dot_fpath}.")
            print(f"CPG json file: {cpg_json_fpath}.")

            # Extract vertices and edges from CPG dot file
            cpg_dot_vertices, cpg_dot_edges = readCPGDot(cpg_dot_fpath)
            # Extract vertices and edges from CPG json file
            cpg_json_vertices, cpg_json_edges = [], []

            with open(cpg_json_fpath, 'r') as cf:
                cpg_json = json.load(cf)

            for edge_info in cpg_json["@value"]["edges"]:
                current_edge = (str(edge_info["outV"]["@value"]), str(edge_info["inV"]["@value"]))
                if current_edge not in cpg_json_edges:
                    cpg_json_edges.append(current_edge)

            for vertex_info in cpg_json["@value"]["vertices"]:
                current_vertex = str(vertex_info["id"]["@value"])
                if current_vertex not in cpg_json_vertices:
                    cpg_json_vertices.append(current_vertex)

            all_cpg_dot_vertices += cpg_dot_vertices
            all_cpg_dot_edges += cpg_dot_edges
            all_cpg_json_vertices += cpg_json_vertices
            all_cpg_json_edges += cpg_json_edges

            all_cpg_dot_vertices = list(set(all_cpg_dot_vertices))
            all_cpg_dot_edges = list(set(all_cpg_dot_edges))
            all_cpg_json_vertices = list(set(all_cpg_json_vertices))
            all_cpg_json_edges = list(set(all_cpg_json_edges))

            # Compare
            if set(cpg_dot_edges) != set(cpg_json_edges) or set(cpg_dot_vertices) != set(cpg_json_vertices):
                print(f"CPG dot edge number: {len(cpg_dot_edges)}.")
                print(f"CPG json edge number: {len(cpg_json_edges)}.")
                print(f"CPG dot vertex number: {len(cpg_dot_vertices)}.")
                print(f"CPG json vertex number: {len(cpg_json_vertices)}.")
                print('=' * 100)
                print(f"CPG dot edges:")
                print(json.dumps(cpg_dot_edges, indent=4))
                print('-' * 100)
                print(f"CPG json edges:")
                print(json.dumps(cpg_json_edges, indent=4))
                print('=' * 100)
                print(f"CPG dot vertices:")
                print(json.dumps(cpg_dot_vertices, indent=4))
                print('-' * 100)
                print(f"CPG json vertices:")
                print(json.dumps(cpg_json_vertices, indent=4))

                raise RuntimeError
            else:
                print("Done!")

    print(f"All CPG dot vertex number: {len(all_cpg_dot_vertices)}")
    print(f"All CPG dot edge number: {len(all_cpg_dot_edges)}")
    print(f"All CPG json vertex number: {len(all_cpg_json_vertices)}")
    print(f"All CPG json edge number: {len(all_cpg_json_edges)}")


def check_ast_cfg_if_in_cpg(graph_type: str, source_fpath: str, root_out_dpath: str):
    assert graph_type in ['ast', 'cfg']

    print('#' * 100)
    print(f"Source file: {source_fpath}.")
    print(f"Graph type: {graph_type.upper()}.")

    p_name = source_fpath.split('/')[4]
    f_name = '.'.join(source_fpath.split('/')[5:])
    joern_out_dpath = os.path.join(root_out_dpath, 'Joern_output', p_name, f_name)
    rcpg_dpath = os.path.join(root_out_dpath, 'reconstruct_output', p_name, f_name)

    graph_dot_dpath = os.path.join(joern_out_dpath, f'{graph_type}')

    # Extract all AST / CFG vertices and edges
    graph_vertices, graph_edges = test_readDot(graph_dot_dpath)
    print(f"{graph_type.upper()} vertex number: {len(graph_vertices)}.")
    print(f"{graph_type.upper()} edge number: {len(graph_edges)}.")

    # Extract all vertices and edges
    all_jpath = os.path.join(joern_out_dpath, 'all', 'export.json')
    with open(all_jpath, 'r') as af:
        all_content = json.load(af)

    all_vertex_info: List = all_content['@value']['vertices']
    all_edge_info: List = all_content['@value']['edges']

    all_vertices: List = [str(vertex_info["id"]["@value"]) for vertex_info in all_vertex_info]
    all_edges: Dict = {}
    for edge_info in all_edge_info:
        if edge_info["id"]["@value"] not in all_edges:
            all_edges[edge_info["id"]["@value"]] = {
                "edge": (str(edge_info["outV"]["@value"]), str(edge_info["inV"]["@value"])),
                "type": edge_info["label"]
            }

    print(f"ALL vertex number: {len(all_vertices)}.")
    print(f"ALL edge number: {len(all_edges)}.")

    # Extract all CPG vertices and edges
    # rcpg_fpath = os.path.join(rcpg_dpath, f'rcpg.json')
    # with open(rcpg_fpath, 'r') as cf:
    #     rcpg = json.load(cf)
    #
    # cpg_vertices: Dict = rcpg['vertices']
    # cpg_edges: Dict = rcpg['edges']
    #
    # print(f"CPG vertex number: {len(cpg_vertices)}.")
    # print(f"CPG edge number: {len(cpg_edges)}.")

    # not_in_cpg_vertices = []
    # not_in_cpg_edges = []

    not_in_graph_vertices = []
    not_in_graph_edges = []

    not_in_all_vertices = []
    not_in_all_edges = []

    # Check vertices
    # for vertex in graph_vertices:
    #     if str(vertex) not in cpg_vertices:
    #         not_in_cpg_vertices.append(str(vertex))
    #     else:
    #         del cpg_vertices[str(vertex)]
    # not_in_graph_vertices = [vertex_id for vertex_id, _ in cpg_vertices.items()]

    for vertex in graph_vertices:
        if str(vertex) not in all_vertices:
            not_in_all_vertices.append(str(vertex))
        else:
            all_vertices.remove(str(vertex))
    not_in_graph_vertices = all_vertices

    # Check edges
    # for _, edge_info in cpg_edges.items():
    #     if edge_info['type'] == graph_type.upper():
    #         start_vertex_id = edge_info['outV']
    #         end_vertex_id = edge_info['inV']
    #         edge = (str(start_vertex_id), str(end_vertex_id))
    #         if edge in graph_edges:
    #             graph_edges.remove(edge)
    #         else:
    #             not_in_graph_edges.append(edge)
    # not_in_cpg_edges = graph_edges

    for _, edge_info in all_edges.items():
        if edge_info["type"] == graph_type.upper():
            if edge_info["edge"] in graph_edges:
                graph_edges.remove(edge_info["edge"])
            else:
                not_in_graph_edges.append(edge_info["edge"])
    not_in_all_edges = graph_edges

    # Summarize
    print(f"Not in {graph_type.upper()} vertex number: {len(not_in_graph_vertices)}.")
    print(f"Not in {graph_type.upper()} edge number: {len(not_in_graph_edges)}.")
    # print(f"Not in CPG vertex number: {len(not_in_cpg_vertices)}.")
    # print(f"Not in CPG edge number: {len(not_in_cpg_edges)}.")
    print(f"Not in ALL vertex number: {len(not_in_all_vertices)}.")
    print(f"Not in ALL edge number: {len(not_in_all_edges)}.")
    print('=' * 100)
    print(f"Not in {graph_type.upper()} vertices:")
    print(json.dumps(not_in_graph_vertices))
    print('-' * 100)
    print(f"Not in {graph_type.upper()} edges:")
    print(json.dumps(not_in_graph_edges))
    # print('=' * 100)
    # print(f"Not in CPG vertices:")
    # print(json.dumps(not_in_cpg_vertices))
    # print('-' * 100)
    # print(f"Not in CPG edges:")
    # print(json.dumps(not_in_cpg_edges))
    print('=' * 100)
    print(f"Not in ALL vertices:")
    print(json.dumps(not_in_all_vertices))
    print('-' * 100)
    print(f"Not in ALL edges:")
    print(json.dumps(not_in_all_edges))


def build_visual_ast(source_fpath: str, root_out_dpath: str):
    print('#' * 100)
    print(f"Source file: {source_fpath}.")

    p_name = source_fpath.split('/')[4]
    f_name = '.'.join(source_fpath.split('/')[5:])
    joern_out_dpath = os.path.join(root_out_dpath, 'Joern_output', p_name, f_name)

    ast_dot_dpath = os.path.join(joern_out_dpath, 'ast')
    all_json_dpath = os.path.join(joern_out_dpath, 'all')

    ast_vertices, ast_edges = test_readDot(ast_dot_dpath)
    print(f"AST vertex number: {len(ast_vertices)}.")
    print(f"AST edge number: {len(ast_edges)}.")

    # Detailed node info
    all_jpath = os.path.join(joern_out_dpath, 'all', 'export.json')
    with open(all_jpath, 'r') as af:
        all_content = json.load(af)

    all_vertex_info: List = all_content['@value']['vertices']
    all_edge_info: List = all_content['@value']['edges']

    def search_detailed_info_with_id(_vertex_id: str) -> Optional[Dict]:
        for _vertex_info in all_vertex_info:
            if _vertex_info["id"]["@value"] == int(_vertex_id):
                _useful_vertex_info = select_node_useful_info(_vertex_info)
                return _useful_vertex_info
        return None

    # Use only vertices and edges from AST dot files
    # Create AST nodes
    ast_nodes: Dict[str, ASTNode] = {}
    for vertex_id in ast_vertices:
        vertex_info = search_detailed_info_with_id(vertex_id)
        if not vertex_info:
            print(f"Vertex {vertex_id} not found!")
        ast_node = ASTNode(vertex_id, vertex_info)
        ast_nodes[vertex_id] = ast_node

    # Add relations between nodes
    for edge in ast_edges:
        father_id, child_id = edge
        father_node = ast_nodes[father_id]
        child_node = ast_nodes[child_id]

        father_node.add_child(child_id)
        child_node.set_father(father_id)

    # Create AST
    roots: List[ASTNode] = []
    for _, ast_node in ast_nodes.items():
        if ast_node.father is None:
            roots.append(ast_node)

    if len(roots) != 1:
        print('=' * 100)
        print(f"Root number: {len(roots)}!")
        for root in roots:
            print('-' * 100)
            print(json.dumps(root.info))

    def traversal(current_node_id: str) -> Dict:
        current_ast_node = ast_nodes[current_node_id]
        sub_tree = current_ast_node.info
        sub_tree_children = []
        for child_node_id in current_ast_node.children:
            sub_tree_children.append(traversal(child_node_id))

        sub_tree['children'] = sub_tree_children
        return sub_tree

    ast_tree = {}
    for i, root in enumerate(roots):
        ast_tree[f'root_{i}'] = traversal(root.id)

    # Rearrange ast
    def rearrange_ast_tree(current_tree: Dict):
        if len(current_tree["children"]) == 0:
            return

        current_tree["children"].sort(key=lambda x: (x["order"], x["id"]))

        for child in current_tree["children"]:
            rearrange_ast_tree(child)

    for root_id, root in ast_tree.items():
        rearrange_ast_tree(root)
    with open(os.path.join(joern_out_dpath, 'ast_dot_tree.json'), 'w') as f:
        json.dump(ast_tree, f, indent=4)


def picture_all_dot(dot_dpath):
    dot_file = os.listdir(dot_dpath)
    for dot_file in dot_file:
        if dot_file.endswith('.dot'):
            command = ["dot", "-Tpng", "-o", dot_file.replace('.dot', '.png'), dot_file]
            _, stderr = execute_command(command, cwd=dot_dpath)
            if stderr:
                print(stderr)
                raise RuntimeError


def find_specified_files(project_dpath: str, file_extension: str = '.py'):
    py_files = []
    for root, _, files in os.walk(project_dpath):
        for file in files:
            if file.endswith(file_extension):
                rel_py_path = os.path.relpath(os.path.join(root, file), project_dpath)
                py_files.append(rel_py_path)

    return py_files


def test_build_project_structure(projects_dpath):
    def judge_entry_exist(current_level_path: str, current_levels: Dict):
        for entry, children in current_levels.items():
            entry_path = os.path.join(current_level_path, entry)

            if not os.path.exists(entry_path):
                error_paths.append(entry_path)

            if children is not None:
                judge_entry_exist(entry_path, current_levels[entry])

    projects = os.listdir(projects_dpath)
    for project in projects:
        project_dpath = os.path.join(projects_dpath, project)
        project_structure = build_project_structure(project_dpath)

        error_paths = []
        judge_entry_exist(project_dpath, project_structure)

        if len(error_paths) != 0:
            print('#' * 150)
            print(f"Project: {project_dpath}")
            print("Error path:")
            for error_path in error_paths:
                print(' ' * 4 + error_path)


def test_parse_judge_project_import_of_py(projects_dpath, so_fpath):
    projects = os.listdir(projects_dpath)
    for project in projects:
        project_dpath = os.path.join(projects_dpath, project)

        py_files = find_specified_files(project_dpath)
        if len(py_files) > 0:
            project_structure = build_project_structure(project_dpath)
            logger.info("#" * 100)
            logger.info("#" * 100)
            logger.info(f"Project: {project}\n" + json.dumps(project_structure, indent=4))
            for py_file in py_files:
                logger.info("#" * 100)
                abs_py_fpath = os.path.join(project_dpath, py_file)

                rel_py_fpath_list = py_file.split('/')
                if rel_py_fpath_list[0] == '':
                    rel_py_fpath_list = rel_py_fpath_list[1:]
                parse('python', so_fpath, abs_py_fpath, project_structure, rel_py_fpath_list)


def test_get_project_all_lang_files_info(projects_dpath, so_fpath):
    projects = os.listdir(projects_dpath)
    for project in projects:
        project_dpath = os.path.join(projects_dpath, project)

        py_files = find_specified_files(project_dpath)
        if len(py_files) > 0:
            project_structure = build_project_structure(project_dpath)

            logger.info("#" * 100)
            logger.info("#" * 100)
            logger.info(f"Project: {project}\n" + json.dumps(project_structure, indent=4))

            all_lang_files_info = get_project_all_lang_files_info(so_fpath, project_dpath, project_structure)
            logger.info("=" * 100 + json.dumps(all_lang_files_info, indent=4))


def test_all_c_files(projects_dpath, so_fpath):
    projects = os.listdir(projects_dpath)
    parser = prepare_specified_lang_parser('c', so_fpath)

    for project in projects:
        project_dpath = os.path.join(projects_dpath, project)

        c_files = find_specified_files(project_dpath, '.c')
        success = 0
        if len(c_files) > 0:
            for c_file in c_files:
                abs_c_fpath = os.path.join(project_dpath,c_file)

                # try:
                #     with open(abs_c_fpath, 'r', encoding="utf-8") as f:
                #         source_code = f.read()
                #
                #     root_node = parser.parse(bytes(source_code, "utf-8")).root_node
                #
                #     # Check function_definition
                #     all_function_definition = []
                #     all_not_top_function_definition = []
                #
                #     def find_all_function_definition(node: tsNode, root):
                #         for child in node.children:
                #             if child.type == 'function_definition':
                #                 if not root:
                #                     all_not_top_function_definition.append(child)
                #             find_all_function_definition(child, False)
                #
                #     find_all_function_definition(root_node, True)
                #     if len(all_not_top_function_definition) != 0:
                #         if abs_c_fpath != "/root/projects/clone_projects/it-novum_openITCOCKPIT/app/Plugin/CakePdf/Vendor/dompdf/lib/ttf2ufm/ttf2ufm-src/t1asm.c":
                #             print(abs_c_fpath)
                #             for func_def in all_not_top_function_definition:
                #                 print(func_def.start_point)
                #             raise RuntimeError
                #     else:
                #         success += 1
                #         print(f'{success}: {abs_c_fpath}')
                #
                #     prefix: preproc_if, preproc_ifdef, preproc_else, preproc_elif, preproc_elifdef
                #     suffix: <empty>, _in_field_declaration_list, _in_enumerator_list, _in_enumerator_list_no_comma
                #
                #     # Check preproc
                #     all_preproc = []
                #
                #     def find_all_preproc(node: tsNode):
                #         for child in node.children:
                #             if child.type.startswith('preproc'):
                #                 all_preproc.append(child)
                #             find_all_preproc(child)
                #
                #     find_all_preproc(root_node)
                #
                #     if len(all_preproc) != 0:
                #         print(abs_c_fpath)
                #         print('-' * 100)
                #
                #     Check ERROR
                #     all_error = []
                #
                #     def find_all_preproc(node: tsNode):
                #         for child in node.children:
                #             if child.type == 'ERROR':
                #                 all_error.append(child)
                #                 continue
                #             find_all_preproc(child)
                #
                #     find_all_preproc(root_node)
                #
                #     if len(all_error) != 0:
                #         print(abs_c_fpath)
                #         print('-' * 100)
                #
                #     Check preprocess

                try:
                    with open(abs_c_fpath, 'r', encoding="utf-8") as f:
                        c = f.read()
                    print(abs_c_fpath)
                    logger.info('=' * 100)
                    logger.info(abs_c_fpath)

                    root_node = parser.parse(bytes(c, "utf-8")).root_node
                    b_updt_c = remove_comments(root_node, bytes(c, "utf-8"))

                    root_node = parser.parse(b_updt_c).root_node
                    updt_c = b_updt_c.decode()

                    preprocess_error(root_node, updt_c.splitlines(False))
                    # preprocess(updt_c.splitlines(False))
                except UnicodeDecodeError:
                    continue
                except PreProcessError:
                    continue


def tree_sitter_nodes_demo(lang: str, so_fpath: str, demo_fpath: str):
    with open(demo_fpath, 'r', encoding='utf-8') as f:
        source_code = f.read()

    parser = prepare_specified_lang_parser(lang, so_fpath)
    tree = parser.parse(bytes(source_code, "utf-8"))
    root_node = tree.root_node
    print(type(root_node))
    print(root_node)


def test_narrow_repo_functions(py_fpath, so_fpath):
    with open(py_fpath, 'r', encoding='utf-8') as f:
        source_code = f.read()

    parser = prepare_specified_lang_parser('python', so_fpath)
    tree = parser.parse(bytes(source_code, "utf-8"))
    root_node = tree.root_node

    # TEST import
    # all_imports = []
    # for child in root_node.children:
    #     if child.type == 'import_from_statement' or child.type == 'import_statement':
    #         import_visitor = TreeSitterImportVisitor()
    #         import_visitor.visit(child)
    #
    #         current_imports = import_visitor.get_imports()
    #         all_imports.append(current_imports)
    #
    # print(json.dumps(all_imports, indent=4))

    # TEST if_statement
    # all_if_stmt_node = []
    #
    # def find_if_stmt_node(node):
    #     for child in node.children:
    #         if child.type == 'if_statement':
    #             all_if_stmt_node.append(child)
    #
    #         find_if_stmt_node(child)
    #
    # find_if_stmt_node(root_node)
    # for node in all_if_stmt_node:
    #     condition = node.child_by_field_name('condition')
    #     consequence = node.child_by_field_name('consequence')
    #     alternative = node.child_by_field_name('alternative')
    #     alternatives = []
    #     for i, child in enumerate(node.children):
    #         field_name = node.field_name_for_child(i)
    #         if field_name == 'alternative':
    #             alternatives.append(child)

    call_nodes = []

    def find_call_node(node):
        for child in node.children:
            if child.type == 'call':
                call_nodes.append(child)

            find_call_node(child)

    find_call_node(root_node)

    for node in call_nodes:
        if node.child_by_field_name('arguments').type == 'generator_expression':
            current_node = node
            print('ok')
    print('ok')


if __name__ == '__main__':
    root_out_dirpath = "./tools/dependency/test_output"
    if not os.path.exists(root_out_dirpath):
        os.makedirs(root_out_dirpath, exist_ok=True)

    source_filepaths = [
        "/root/projects/VDTest/tools/dependency/test_data/source_code_data/ansible_ansible/hacking.azp.get_recent_coverage_runs.py/get_recent_coverage_runs.py",
        "/root/projects/clone_projects/krb5_krb5/src/appl/gss-sample/gss-client.c",
        "/root/projects/clone_projects/Ardour_ardour/gtk2_ardour/add_route_dialog.cc",
        "/root/projects/clone_projects/dotCMS_core/dotCMS/src/main/java/com/dotcms/api/system/event/SystemEvent.java"
    ]

    # [TEST 1] tools/dependency/joern_parse/joern_parse_source_code function test
    # for source_filepath in source_filepaths:
    #     project_name = source_filepath.split('/')[4]
    #     file_name = '.'.join(source_filepath.split('/')[5:])
    #     joern_out_dirpath = os.path.join(root_out_dirpath, 'Joern_output', project_name, file_name)
    #     test_joern_parse_source_code(source_filepath, joern_out_dirpath)

    # [TEST 2] tools/dependency/joern_parse/readFullCPG function test
    # for source_filepath in source_filepaths:
    #     project_name = source_filepath.split('/')[4]
    #     file_name = '.'.join(source_filepath.split('/')[5:])
    #     joern_out_dirpath = os.path.join(root_out_dirpath, 'Joern_output', project_name, file_name)
    #     out_dirpath = os.path.join(root_out_dirpath, 'reconstruct_output')
    #     test_readFullCPG(project_name, file_name, joern_out_dirpath, out_dirpath)

    # [TEST 3] tools/dependency/joern_parse/readDot function test
    # for source_filepath in source_filepaths:
    #     project_name = source_filepath.split('/')[4]
    #     file_name = '.'.join(source_filepath.split('/')[5:])
    #     joern_out_dirpath = os.path.join(root_out_dirpath, 'Joern_output', project_name, file_name)
    #
    #     print('=' * 200)
    #     print(f"Project: {project_name}, file: {file_name}.")
    #     print(f"AST count:")
    #     ast_dot_dpath = os.path.join(joern_out_dirpath, "ast")
    #     ast_vertices, ast_edges = test_readDot(ast_dot_dpath)
    #     print(f"Vertex number: {len(ast_vertices)}.")
    #     print(f"Edge number: {len(ast_edges)}.")
    #
    #
    #     print(f"CFG count:")
    #     cfg_dot_dpath = os.path.join(joern_out_dirpath, "cfg")
    #     cfg_vertices, cfg_edges = test_readDot(cfg_dot_dpath)
    #     print(f"Vertex number: {len(cfg_vertices)}.")
    #     print(f"Edge number: {len(cfg_edges)}.")

    # [TEST 4] tools/dependency/joern_parse/readCPGDot function test
    # source_filepath = "/root/projects/clone_projects/Ardour_ardour/gtk2_ardour/add_route_dialog.cc"
    # test_readCPGDot(source_filepath)

    # [TEST 5]
    # for source_filepath in source_filepaths:
    #     check_ast_cfg_if_in_cpg('ast', source_filepath, root_out_dirpath)
    #     check_ast_cfg_if_in_cpg('cfg', source_filepath, root_out_dirpath)
    #     break

    # for source_filepath in source_filepaths:
    #     build_visual_ast(source_filepath, root_out_dirpath)
    #     break

    # ast_dot_dpath = "/root/projects/VDTest/tools/dependency/test_output/Joern_output/ansible_ansible/hacking.azp.get_recent_coverage_runs.py/ast"
    # picture_all_dot(ast_dot_dpath)

    # [TEST 6] tools/dependency/tree_sitter_parse/build_library function test
    tree_sitter_root_dpath = "/root/projects/tree-sitter-projects"
    # build_library(tree_sitter_root_dpath)

    # [TEST 7] tools/dependency/tree_sitter_parse/parse function test
    tree_sitter_so_fpath = os.path.join(tree_sitter_root_dpath, "build", "my-languages.so")
    # for source_filepath in source_filepaths:
    #     if source_filepath.endswith('.java'):
    #         lang = 'java'
    #     elif source_filepath.endswith('.cc'):
    #         lang = 'cpp'
    #     elif source_filepath.endswith('.c'):
    #         lang = 'c'
    #     elif source_filepath.endswith('.py'):
    #         lang = 'python'
    #     else:
    #         raise RuntimeError
    #     parse(lang, so_fpath, source_filepath)
    #
    #     break

    # [TEST 8] utils/dependency/build_project_structure function test
    clone_projects = "/root/projects/clone_projects"
    # test_build_project_structure(clone_projects)

    # [TEST 9]
    # test_parse_judge_project_import_of_py(clone_projects, so_fpath)

    # [TEST 10]
    # demo_lang = 'python'
    # demo_file_path = '/root/projects/VDTest/tools/dependency/test_data/tree_sitter_node_demo_example.py'
    # tree_sitter_nodes_demo(demo_lang, so_fpath, demo_file_path)

    # [TEST 10] utils/dependency/get_project_all_lang_files_info function test
    # test_get_project_all_lang_files_info(clone_projects, so_fpath)

    # [TEST 11] narrow repo functions test
    # py_file_path = "/root/projects/VDTest/tools/dependency/test_data/source_code_data/ansible_ansible/hacking.azp.get_recent_coverage_runs.py/get_recent_coverage_runs.py"
    # test_narrow_repo_functions(py_file_path, tree_sitter_so_fpath)

    # [TEST 12] CFG/C functions test
    # c_fpath = "/root/projects/VDTest/tools/dependency/test_data/source_code_data/krb5_krb5/src.appl.gss-sample.gss-client.c/gss-client.c"
    # ast = ASTParser.parse(c_fpath, strict=False)
    # print(list(ast.successors(0)))

    # [TEST 13]
    test_all_c_files(clone_projects, tree_sitter_so_fpath)
