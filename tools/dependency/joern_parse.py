import os
import shutil
import json
import re
from typing import *

from old_utils.utils import execute_command
from old_utils.logging import logger


withName = ['METHOD', 'NAMESPACE', 'NAMESPACE_BLOCK', 'METHOD_PARAMETER_IN', 'METHOD_PARAMETER_OUT',
            'MEMBER', 'TYPE', 'TYPE_DECL', 'TYPE_PARAMETER', 'CALL', 'CALL_REPR',
            'IDENTIFIER', 'JUMP_LABEL', 'JUMP_TARGET', 'LOCAL']
withTypeFullName = ['METHOD_PARAMETER_IN', 'METHOD_PARAMETER_OUT', 'METHOD_RETURN', 'BLOCK',
                    'LITERAL', 'METHOD_REF', 'TYPE_REF', 'UNKNOWN']
withModifierType = ['MODIFIER']
withCanonicalNAME = ['FIELD_IDENTIFIER']
withControlStructureType = ['CONTROL_STRUCTURE']
withNoType = ['RETURN']


def joern_parse_source_code(source_filepath, out_dirpath) -> bool:
    """
        Use joern to parse the source code file, and export the CPG json and AST dot.

        Args:
        source_filepath: Path of the source code file
        out_dirpath: Path of dir containing Joern output of the source code
    """
    logger.info(f'Joern parse >>> file: {source_filepath}, out_dirpath: {out_dirpath}.')

    if not os.path.exists(out_dirpath):
        os.makedirs(out_dirpath, exist_ok=True)

    # Joern parse
    env = os.environ.copy()
    env['JAVA_HOME'] = '/usr/local/jdk19'
    env['PATH'] = env['JAVA_HOME'] + "/bin:" + env['PATH']

    joern_parse_command = ["joern-parse", source_filepath]
    _, stderr = execute_command(joern_parse_command, cwd=out_dirpath, env=env)
    if stderr:
        logger.warning("Joern parse failed!")
        return False

    # Export CPG json
    cpg_out_dirpath = os.path.join(out_dirpath, "cpg")
    if os.path.exists(cpg_out_dirpath):
        if len(os.listdir(cpg_out_dirpath)) == 0:
            shutil.rmtree(cpg_out_dirpath)

    if not os.path.exists(cpg_out_dirpath):
        export_cpg_command = ["joern-export", "--format=graphson", "--repr=cpg", f"--out=./cpg"]
        _, stderr = execute_command(export_cpg_command, cwd=out_dirpath, env=env)
        if stderr:
            logger.warning("Export CPG json failed!")
            return False


    # Export AST dot
    ast_out_dirpath = os.path.join(out_dirpath, f"ast")
    if os.path.exists(ast_out_dirpath):
        if len(os.listdir(ast_out_dirpath)) == 0:
            shutil.rmtree(ast_out_dirpath)

    if not os.path.exists(ast_out_dirpath):
        export_ast_command = ["joern-export", "--format=dot", "--repr=ast", "--out=./ast"]
        _, stderr = execute_command(export_ast_command, cwd=out_dirpath, env=env)
        if stderr:
            logger.warning(f"Export AST dot failed!")
            return False

    # Export CFG dot
    cfg_out_dirpath = os.path.join(out_dirpath, f"cfg")
    if os.path.exists(cfg_out_dirpath):
        if len(os.listdir(cfg_out_dirpath)) == 0:
            shutil.rmtree(cfg_out_dirpath)

    if not os.path.exists(cfg_out_dirpath):
        export_cfg_command = ["joern-export", "--format=dot", "--repr=cfg", "--out=./cfg"]
        _, stderr = execute_command(export_cfg_command, cwd=out_dirpath, env=env)
        if stderr:
            logger.warning(f"Export CFG dot failed!")
            return False

    logger.info("Done!")
    return True


def select_node_useful_info(node_info: Dict) -> Dict:
    try:
        useful_info = {
            "id": node_info["id"]["@value"],
            "type": node_info["label"],
            "code": node_info["properties"]["CODE"]["@value"],
            "order": node_info["properties"]["ORDER"]["@value"]["@value"]
        }
    except KeyError as e:
        print(e)
        print(json.dumps(node_info, indent=4))
        raise RuntimeError

    try:
        if useful_info['type'] in withName:
            useful_info['value'] = node_info['properties']['NAME']["@value"]
        elif useful_info['type'] in withTypeFullName:
            useful_info['value'] = node_info['properties']['TYPE_FULL_NAME']["@value"]
        elif useful_info['type'] in withModifierType:
            useful_info['value'] = node_info['properties']['MODIFIER_TYPE']["@value"]
        elif useful_info['type'] in withCanonicalNAME:
            useful_info['value'] = node_info['properties']['CANONICAL_NAME']["@value"]
        elif useful_info['type'] in withControlStructureType:
            useful_info['value'] = node_info['properties']['CONTROL_STRUCTURE_TYPE']["@value"]
        elif useful_info['type'] in withNoType:
            useful_info['value'] = None
        else:
            print('-' * 100)
            print('Error vertex:')
            print(json.dumps(node_info, indent=4))
            raise RuntimeError
    except KeyError as e:
        print('-' * 100)
        print(f"Error msg: {e}.")
        print('Error vertex:')
        print(json.dumps(node_info, indent=4))
        raise RuntimeError

    if "LINE_NUMBER" in node_info["properties"]:
        useful_info["line_number"] = node_info["properties"]["LINE_NUMBER"]["@value"]["@value"]
    else:
        useful_info['line_number'] = None

    return useful_info


def readCPGJson(cpg_jpath) -> Tuple[Dict, Dict]:
    """
        Read CPG json file and extract all nodes and edges from it.

        Args:
            cpg_jpath: Path of the json file containing CPG information
        Return:
            all_vertices (Dict)
            all_edges (Dict)
    """
    with open(cpg_jpath, 'r') as f:
        data = json.load(f)

    all_vertices = {}
    all_edges = {}

    for vertex in data["@value"]["vertices"]:
        vertex_id = vertex["id"]["@value"]
        if vertex_id in all_vertices:
            continue

        node_info = select_node_useful_info(vertex)
        all_vertices[vertex_id] = node_info

    for edge in data["@value"]["edges"]:
        edge_id = edge["id"]["@value"]
        if edge_id in all_edges:
            continue

        rel = {
            "type": edge["label"],
            "inV": edge["inV"]["@value"],
            "outV": edge["outV"]["@value"]
        }

        all_edges[edge_id] = rel

    return all_vertices, all_edges


def readFullCPG(project_name, file_name, joern_out_dpath, out_dpath) -> bool:
    """
        Extract all nodes and edges from Joern cpg output.

        Args:
            project_name: Project of the source code
            file_name: Source code file name, i.e. relative path replacing '/' with '.'
            joern_out_dpath: Path to dir containing Joern output
            out_dpath: Path to dir containing output files (rcpg.json)
        """
    logger.info(f"Read CPG json >>> Project: {project_name}, file: {file_name}.")

    if not os.path.exists(out_dpath):
        os.makedirs(out_dpath, exist_ok=True)

    cpg_out_dpath = os.path.join(joern_out_dpath, 'cpg')
    if not os.path.exists(cpg_out_dpath):
        logger.warning(f"No dir named cpg in joern output dir!")
        return False

    all_vertices = {}
    all_edges = {}

    def extract_nodes_and_edges(father_dpath):
        entries = os.listdir(father_dpath)
        for entry in entries:
            entry_path = os.path.join(father_dpath, entry)

            if os.path.isdir(entry_path):
                extract_nodes_and_edges(entry_path)
            elif os.path.isfile(entry_path):
                if entry_path.endswith('.json'):
                    entry_vertices, entry_edges = readCPGJson(entry_path)

                    for vertex_id, vertex_info in entry_vertices.items():
                        if vertex_id not in all_vertices:
                            all_vertices[vertex_id] = vertex_info

                    for edge_id, edge_info in entry_edges.items():
                        if edge_id not in all_edges:
                            all_edges[edge_id] = edge_info
                else:
                    logger.warning(f"{entry_path} not end with .json!")

    cpg_item_dirs = os.listdir(cpg_out_dpath)
    for cpg_item_dir in cpg_item_dirs:
        current_cpg_item_dpath = os.path.join(cpg_out_dpath, cpg_item_dir)
        extract_nodes_and_edges(current_cpg_item_dpath)

    rcpg_content = {
        "vertices": all_vertices,
        "edges": all_edges
    }

    file_out_dpath = os.path.join(out_dpath, project_name, file_name)
    if not os.path.exists(file_out_dpath):
        os.makedirs(file_out_dpath, exist_ok=True)

    rcpg_json_fpath = os.path.join(file_out_dpath, "rcpg.json")
    with open(rcpg_json_fpath, 'w', encoding='utf-8') as f:
        json.dump(rcpg_content, f, indent=4)

    logger.info(f"Done! Vertex number: {len(all_vertices)}, Edge number: {len(all_edges)}.")
    return True


def readDot(dot_path) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Extract all vertices and edges from AST / CFG dot file.

    Args:
        dot_path: Path to the AST / CFG dot file
    Return:
        all_vertices: All vertices id
        all_edges: All edges, in form (str, str)
    """
    with open(dot_path, 'r') as f:
        content = f.readlines()

    edge_pattern = re.compile(r'^\s*"(\d+)"\s+->\s+"(\d+)"\s*$')

    all_vertices = []
    all_edges = []

    for i, line in enumerate(content):
        edge_match = edge_pattern.match(line)

        if edge_match:
            start_vertex_id, end_vertex_id = edge_match.groups()

            if start_vertex_id not in all_vertices:
                all_vertices.append(start_vertex_id)

            if end_vertex_id not in all_vertices:
                all_vertices.append(end_vertex_id)

            edge = (start_vertex_id, end_vertex_id)
            if edge not in all_edges:
                all_edges.append(edge)

    return all_vertices, all_edges


def readCPGDot(dot_path) -> Tuple[List, List]:
    with open(dot_path, 'r') as f:
        content = f.readlines()

    vertex_start_pattern = re.compile(r'^\s*(\d+)\s+\[label=.*$')
    edge_pattern = re.compile(r'^\s*(\d+)\s+->\s+(\d+)\s+\[label=.*$')

    all_vertices = []
    all_edge_vertices = []
    all_edges = []

    for i, line in enumerate(content):
        if i == 0:
            assert line.startswith('digraph')
            continue

        vertex_match = vertex_start_pattern.match(line)
        if vertex_match:
            vertex_id = vertex_match.group(1)
            if vertex_id not in all_vertices:
                all_vertices.append(vertex_id)
        else:
            edge_match = edge_pattern.match(line)
            if edge_match:
                start_vertex_id, end_vertex_id = edge_match.groups()

                if start_vertex_id not in all_edge_vertices:
                    all_edge_vertices.append(start_vertex_id)
                if end_vertex_id not in all_edge_vertices:
                    all_edge_vertices.append(end_vertex_id)

                edge = (start_vertex_id, end_vertex_id)
                if edge not in all_edges:
                    all_edges.append(edge)
            else:
                continue

    all_vertices.sort()
    all_edge_vertices.sort()
    assert all_vertices == all_edge_vertices

    # if all_vertices != all_edge_vertices:
    #     print(dot_path)
    #     print(all_vertices)
    #     print(all_edge_vertices)
    #
    #     raise RuntimeError

    return all_vertices, all_edges
