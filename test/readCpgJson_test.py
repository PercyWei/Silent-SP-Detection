import os
import json

from ../test/readCpgJson
from tools.dependency import readCpgJson


def get_diff_list(old_list, new_list):
    diff = [item for item in new_list if item not in old_list]

    return diff

def readCpgJsonAndDiff(cpgJson_dirpath):

    dirs = os.listdir(cpgJson_dirpath)

    dir_idx = -1
    for idx, dir in enumerate(dirs):
        if dir not in ["<empty>", "<includes>"]:
            dir_idx = idx
            break

    global_vertices = []
    global_edges = []
    for j in range(len(dirs)):
        current_dirpath = os.path.join(cpgJson_dirpath, dirs[(dir_idx + j) % len(dirs)])

        files = os.listdir(current_dirpath)

        file_idx = -1
        for idx, file in enumerate(files):
            if file == "_global_.json":
                file_idx = idx
                break

        for i in range(len(files)):
            current_filepath = os.path.join(current_dirpath, files[(file_idx + i) % len(files)])

            with open(current_filepath, 'r') as f:
                data = json.load(f)

            tmp_vertices = []
            tmp_edges = []

            for vertice in data["@value"]["vertices"]:
                tmp_vertices.append(vertice["id"]["@value"])

            for edge in data["@value"]["edges"]:
                tmp_edges.append(edge["id"]["@value"])

            print("=" * 100)
            print(current_filepath)
            if i == 0 and j == 0:
                global_vertices = tmp_vertices
                global_edges = tmp_edges

                print(f"Vertices: {global_vertices}\nlength: {len(global_vertices)}\nEdges: {global_edges}\nlength: {len(global_edges)}")
            else:
                add_vertices = get_diff_list(global_vertices, tmp_vertices)
                less_vertices = get_diff_list(tmp_vertices, global_vertices)
                add_edges = get_diff_list(global_edges, tmp_edges)
                less_edges = get_diff_list(tmp_edges, global_edges)

                print(f"Add vertices: {add_vertices}\nlength: {len(add_vertices)}")
                print(f"less vertices: {less_vertices}\nlength: {len(less_vertices)}")
                print(f"Add vertices: {add_edges}\nlength: {len(add_edges)}")
                print(f"less vertices: {less_edges}\nlength: {len(less_edges)}")


def exam_readCpgJson(cpgJson_dirpath, out_dirpath):



    print(f"Vertex number: {len(all_vertices)}, Edge number: {len(all_edges)}")

    # Exam
    lost_vertices_idxs = []
    for i in range(len(all_vertices)):
        if i not in all_vertices_idxs:
            lost_vertices_idxs.append(i)

    lost_edges_idxs = []
    for i in range(len(all_edges)):
        if i not in all_edges_idxs:
            lost_edges_idxs.append(i)
    print(f"All vertices idxs: {sorted(all_vertices_idxs)}")
    print(f"Lost vertices idxs: {lost_vertices_idxs}\nLost edges idxs: {lost_edges_idxs}")

    lost_edge_vertices_idxs = []
    for edge in all_edges:
        if edge["inV"] not in all_vertices_idxs:
            lost_edge_vertices_idxs.append(edge["inV"])

        if edge["outV"] not in all_vertices_idxs:
            lost_edge_vertices_idxs.append(edge["outV"])
    print(f"Lost edge vertices idxs: {lost_edge_vertices_idxs}")


if __name__ == '__main__':

    cpgJson_dirpath = "./ReVeal/cpg"
    out_dirpath = "./ReVeal/rcpg"

    # readCpgJsonAndDiff(cpgJson_dirpath)

    readCpgJson(cpgJson_dirpath, out_dirpath)
