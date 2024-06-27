import os
import json
from typing import *


class AstNode:
    def __init__(self, idx: str):
        self.idx = idx
        self.children = []
        self.parent = None

    def addChild(self, idx: str):
        if idx not in self.children:
            self.children.append(idx)

    def setParent(self, idx: str):
        assert self.parent is None
        self.parent = idx


def getVertex(idx: str, vertices: List[Dict]):
    for v in vertices:
        if str(v["id"]) == idx:
            return v


def traversal(idx: str, ast_nodes: Dict, vertices: List[Dict]) -> Dict:
    v = getVertex(idx, vertices)
    v["children"] = []
    for child in ast_nodes[idx].children:
        v["children"].append(traversal(child, ast_nodes, vertices))
    return v


def rearrangeAST(parent: Dict):

    if len(parent["children"]) == 0:
        return

    parent["children"].sort(key=lambda x: (x["order"], x["id"]))

    for child in parent["children"]:
        rearrangeAST(child)


def reconstruct_structural_ast(rcpg_dirpath: str, structural_ast_dirpath: str):

    dirs = os.listdir(rcpg_dirpath)

    for idx, project in enumerate(dirs):
        print(f'Processing {idx + 1}/{len(dirs)}: {project}')

        project_dirpath = os.path.join(rcpg_dirpath, project)
        rcpg = os.listdir(project_dirpath)[0]

        with open(os.path.join(project_dirpath, rcpg), 'r') as f:
            data = json.load(f)

        vertices = data['vertices']
        edges = data['edges']

        if len(edges) == 0 or len(vertices) == 0:
            continue

        ast_nodes: Dict[str: AstNode] = {}
        for edge in edges:
            if edge["type"] == "AST":

                inVIdx = str(edge["inV"])
                outVIdx = str(edge["outV"])

                if inVIdx not in ast_nodes:
                    ast_nodes[inVIdx] = AstNode(inVIdx)

                if outVIdx not in ast_nodes:
                    ast_nodes[outVIdx] = AstNode(outVIdx)

                if ast_nodes[inVIdx].parent is None:
                    ast_nodes[inVIdx].setParent(outVIdx)
                elif ast_nodes[inVIdx].parent == outVIdx:
                    pass
                else:
                    raise RuntimeError("Conflicting Parent Nodes")

                ast_nodes[outVIdx].addChild(inVIdx)

        structural_ast = {}
        for node in ast_nodes.values():
            if node.parent is None:
                structural_ast["ast"] = traversal(node.idx, ast_nodes, vertices)
                break

        rearrangeAST(structural_ast["ast"])

        assert len(structural_ast) != 0

        project_structural_ast_out_dirpath = os.path.join(structural_ast_dirpath, project)
        if not os.path.exists(project_structural_ast_out_dirpath):
            os.makedirs(project_structural_ast_out_dirpath, exist_ok=True)

        with open(os.path.join(project_structural_ast_out_dirpath, 'structural_ast.json'), 'w') as f:
            json.dump(structural_ast, f, indent=4)


if __name__ == '__main__':

    rcpg_dirpath = './ReVeal/rcpg'
    structural_ast_dirpath = './ReVeal/structural_ast'

    reconstruct_structural_ast(rcpg_dirpath, structural_ast_dirpath)
