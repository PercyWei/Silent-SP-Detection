import getopt
import json
import os
from typing import *


def travelAST(node, node_list, edge_list):
    ast_node = {"id": node["id"], "type": node["type"], "value": None}

    if "value" in node.keys():
        # TODO: use 'value' or 'code'
        ast_node["value"] = node["value"]

    node_list.append(ast_node)

    if len(node["children"]) != 0:
        node_list.append(ast_node)
        for child in node["children"]:
            edge_list.append((node["id"], child["id"]))
            travelAST(child, node_list, edge_list)

    return


def constructGraph2Code(graph: Dict):

    prefix = "AST {\n"
    suffix = "}\n"

    node_list = []
    edge_list = []

    travelAST(graph["ast"], node_list, edge_list)

    node_list_str = f"node_list = {node_list}"

    edge_list_str = 'edge_list = ['
    for edge in edge_list:
        edge_list_str += f"({edge[0]} -> {edge[1]}), "
    edge_list_str = edge_list_str[:-2]
    edge_list_str += ']'

    graph_code = prefix + "\t" + node_list_str + "\n\t" + edge_list_str + "\n" + suffix

    return graph_code


def constructPrompt(code, graph: Dict):

    prefix_str = ("Give you a code along with a pseudo-code that describes the AST of the given code.\n"
                  "Note:\n"
                  "(1) AST node in node_list has three attributes: 'id', 'type' and 'value'\n"
                  "(2) AST edge in edge_list  (i -> j) means that the AST node with attribute id=i is the parent of the AST node with attribute id=j\n")
    code = "1.Code: \n```\n" + code + "\n```\n"

    pseudo_code = constructGraph2Code(graph)

    ast_code = "2.Pseudo-code of AS\n```\n" + pseudo_code + "```\n"
    suffix_str = "Q:Whether the given code is vulnerable or not. Give me answer 'YES' or 'NO'."

    return prefix_str + code + ast_code + suffix_str


if __name__ == '__main__':
    # example = {"task_name": "graph-language-modeling-graph-question-answering-webquestions", "idx": 753, "instruction": "You are a good graph reasoner. Give you a graph language that describes a graph structure and node information. You need to understand the graph and the task definition, and answer the question.\nNote: (i <-> j) means that node i and node j are connected with an undirected edge. (i -> j) means that node i and node j are connected with a directed edge. \n```\nGraph[name=\"freebase-knowledge-base\"] {\n    entity_list = ['Pacuare River', 'Gerardo Ure\u00f1a', 'Franklin Corella Vargas', 'Edgar Mar\u00edn', 'Costa Rica', 'Mata Redonda Wildlife Refuge', 'Los Chiles', 'Abangares', 'Tamarindo Wildlife Refuge', 'Sarch\u00ed', 'Carara National Park', 'Corcovado National Park', 'Union for Change Party', 'Francisco Hern\u00e1ndez', 'Earth', 'Confederaci\u00f3n de Trabajadores de Costa Rica', 'Jac\u00f3', 'Paul Raines', 'Laurel Airport', 'Death of Rigoberto Alpizar', 'Barva Volcano', 'Erick Corrales', 'La Selva Biological Station', 'Constitutional republic', 'Barra del Colorado Airport', 'Estadio Municipal  Otto Ure\u00f1a', 'Denis Pinto'];\n    triple_list = [(\"Costa Rica\" -> \"Death of Rigoberto Alpizar\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Franklin Corella Vargas\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Barva Volcano\")[relation=\"contains\"], (\"Costa Rica\" -> \"Pacuare River\")[relation=\"contains\"], (\"Costa Rica\" -> \"Denis Pinto\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Francisco Hern\u00e1ndez\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Union for Change Party\")[relation=\"organizations with this scope\"], (\"Costa Rica\" -> \"Earth\")[relation=\"administrative parent\"], (\"Costa Rica\" -> \"Erick Corrales\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Corcovado National Park\")[relation=\"contains\"], (\"Costa Rica\" -> \"Los Chiles\")[relation=\"contains\"], (\"Costa Rica\" -> \"Laurel Airport\")[relation=\"contains\"], (\"Costa Rica\" -> \"Gerardo Ure\u00f1a\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Estadio Municipal  Otto Ure\u00f1a\")[relation=\"contains\"], (\"Costa Rica\" -> \"Carara National Park\")[relation=\"contains\"], (\"Costa Rica\" -> \"Sarch\u00ed\")[relation=\"contains\"], (\"Costa Rica\" -> \"Tamarindo Wildlife Refuge\")[relation=\"contains\"], (\"Costa Rica\" -> \"Abangares\")[relation=\"second level divisions\"], (\"Costa Rica\" -> \"Paul Raines\")[relation=\"people born here\"], (\"Costa Rica\" -> \"La Selva Biological Station\")[relation=\"contains\"], (\"Costa Rica\" -> \"Jac\u00f3\")[relation=\"contains\"], (\"Costa Rica\" -> \"Confederaci\u00f3n de Trabajadores de Costa Rica\")[relation=\"organizations with this scope\"], (\"Costa Rica\" -> \"Edgar Mar\u00edn\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Mata Redonda Wildlife Refuge\")[relation=\"contains\"], (\"Costa Rica\" -> \"Barra del Colorado Airport\")[relation=\"contains\"], (\"Costa Rica\" -> \"Constitutional republic\")[relation=\"form of government\"]];\n}\n```\nTask definition: given a question and a corresponding knowledge graph, and find an entity in the graph and answer the question.\nQ: what currency is used in the location that contains the second level division la union ?\nA:", "graph_language": "```\nGraph[name=\"freebase-knowledge-base\"] {\n    entity_list = ['Pacuare River', 'Gerardo Ure\u00f1a', 'Franklin Corella Vargas', 'Edgar Mar\u00edn', 'Costa Rica', 'Mata Redonda Wildlife Refuge', 'Los Chiles', 'Abangares', 'Tamarindo Wildlife Refuge', 'Sarch\u00ed', 'Carara National Park', 'Corcovado National Park', 'Union for Change Party', 'Francisco Hern\u00e1ndez', 'Earth', 'Confederaci\u00f3n de Trabajadores de Costa Rica', 'Jac\u00f3', 'Paul Raines', 'Laurel Airport', 'Death of Rigoberto Alpizar', 'Barva Volcano', 'Erick Corrales', 'La Selva Biological Station', 'Constitutional republic', 'Barra del Colorado Airport', 'Estadio Municipal  Otto Ure\u00f1a', 'Denis Pinto'];\n    triple_list = [(\"Costa Rica\" -> \"Death of Rigoberto Alpizar\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Franklin Corella Vargas\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Barva Volcano\")[relation=\"contains\"], (\"Costa Rica\" -> \"Pacuare River\")[relation=\"contains\"], (\"Costa Rica\" -> \"Denis Pinto\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Francisco Hern\u00e1ndez\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Union for Change Party\")[relation=\"organizations with this scope\"], (\"Costa Rica\" -> \"Earth\")[relation=\"administrative parent\"], (\"Costa Rica\" -> \"Erick Corrales\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Corcovado National Park\")[relation=\"contains\"], (\"Costa Rica\" -> \"Los Chiles\")[relation=\"contains\"], (\"Costa Rica\" -> \"Laurel Airport\")[relation=\"contains\"], (\"Costa Rica\" -> \"Gerardo Ure\u00f1a\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Estadio Municipal  Otto Ure\u00f1a\")[relation=\"contains\"], (\"Costa Rica\" -> \"Carara National Park\")[relation=\"contains\"], (\"Costa Rica\" -> \"Sarch\u00ed\")[relation=\"contains\"], (\"Costa Rica\" -> \"Tamarindo Wildlife Refuge\")[relation=\"contains\"], (\"Costa Rica\" -> \"Abangares\")[relation=\"second level divisions\"], (\"Costa Rica\" -> \"Paul Raines\")[relation=\"people born here\"], (\"Costa Rica\" -> \"La Selva Biological Station\")[relation=\"contains\"], (\"Costa Rica\" -> \"Jac\u00f3\")[relation=\"contains\"], (\"Costa Rica\" -> \"Confederaci\u00f3n de Trabajadores de Costa Rica\")[relation=\"organizations with this scope\"], (\"Costa Rica\" -> \"Edgar Mar\u00edn\")[relation=\"people born here\"], (\"Costa Rica\" -> \"Mata Redonda Wildlife Refuge\")[relation=\"contains\"], (\"Costa Rica\" -> \"Barra del Colorado Airport\")[relation=\"contains\"], (\"Costa Rica\" -> \"Constitutional republic\")[relation=\"form of government\"]];\n}\n```", "graph": {"node_list": ["Pacuare River", "Gerardo Ure\u00f1a", "Franklin Corella Vargas", "Edgar Mar\u00edn", "Costa Rica", "Mata Redonda Wildlife Refuge", "Los Chiles", "Abangares", "Tamarindo Wildlife Refuge", "Sarch\u00ed", "Carara National Park", "Corcovado National Park", "Union for Change Party", "Francisco Hern\u00e1ndez", "Earth", "Confederaci\u00f3n de Trabajadores de Costa Rica", "Jac\u00f3", "Paul Raines", "Laurel Airport", "Death of Rigoberto Alpizar", "Barva Volcano", "Erick Corrales", "La Selva Biological Station", "Constitutional republic", "Barra del Colorado Airport", "Estadio Municipal  Otto Ure\u00f1a", "Denis Pinto"], "edge_list": [["Costa Rica", "people born here", "Death of Rigoberto Alpizar"], ["Costa Rica", "people born here", "Franklin Corella Vargas"], ["Costa Rica", "contains", "Barva Volcano"], ["Costa Rica", "contains", "Pacuare River"], ["Costa Rica", "people born here", "Denis Pinto"], ["Costa Rica", "people born here", "Francisco Hern\u00e1ndez"], ["Costa Rica", "organizations with this scope", "Union for Change Party"], ["Costa Rica", "administrative parent", "Earth"], ["Costa Rica", "people born here", "Erick Corrales"], ["Costa Rica", "contains", "Corcovado National Park"], ["Costa Rica", "contains", "Los Chiles"], ["Costa Rica", "contains", "Laurel Airport"], ["Costa Rica", "people born here", "Gerardo Ure\u00f1a"], ["Costa Rica", "contains", "Estadio Municipal  Otto Ure\u00f1a"], ["Costa Rica", "contains", "Carara National Park"], ["Costa Rica", "contains", "Sarch\u00ed"], ["Costa Rica", "contains", "Tamarindo Wildlife Refuge"], ["Costa Rica", "second level divisions", "Abangares"], ["Costa Rica", "people born here", "Paul Raines"], ["Costa Rica", "contains", "La Selva Biological Station"], ["Costa Rica", "contains", "Jac\u00f3"], ["Costa Rica", "organizations with this scope", "Confederaci\u00f3n de Trabajadores de Costa Rica"], ["Costa Rica", "people born here", "Edgar Mar\u00edn"], ["Costa Rica", "contains", "Mata Redonda Wildlife Refuge"], ["Costa Rica", "contains", "Barra del Colorado Airport"], ["Costa Rica", "form of government", "Constitutional republic"]]}, "answer": ["Based on the world knowledge, the correct answer to the question is \"Costa Rican col\u00f3n\", but the answer is not existing in the graph."], "answer_with_cot": [], "difficulty": "medium", "from": "WebQuestions"}
    #
    # print(json.dumps(example, indent=4))
    #
    # print(example["instruction"])
    #
    # print(example["graph_language"][3: -3])

    structural_ast_dirpath = "./ReVeal/structural_ast"
    prompt_out_filepath = "dataset/ReVeal/prompt.txt"

    projects = os.listdir(structural_ast_dirpath)

    prompt_file = open(prompt_out_filepath, "w")

    for idx, project in enumerate(projects):
        prompt_file.write("=" * 50 + f"[{idx}] {project}" + "=" * 50 + "\n\n")

        code_file_path = f"dataset/ReVeal/raw_data/chrome_debian/{project}.c"
        structural_ast_filepath = f"dataset/ReVeal/structural_ast/{project}/structural_ast.json"

        with open(code_file_path, "r") as f:
            code = f.read()

        with open(structural_ast_filepath, 'r') as f:
            graph = json.load(f)

        prompt = constructPrompt(code, graph)

        prompt_file.write(prompt + "\n\n")

    prompt_file.close()
