import json

from typing import *


def check_py_items_cwe_id():
    cwe_entry_fpath = "/root/projects/VDTest/agent_app/CWE/CWE_1003_entries.json"

    with open(cwe_entry_fpath, "r") as f:
        cwe_entries = json.load(f)

    cwe_1003_ids = []
    for entry in cwe_entries:
        cwe_id = "CWE-" + entry["CWE-ID"]
        cwe_1003_ids.append(cwe_id)

    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items_v1.json"

    with open(py_items_fpath, "r") as f:
        py_items = json.load(f)

    not_cwe_1003_cve = []
    for py_item in py_items:
        if py_item["cwe_id"] is not None:
            if py_item["cwe_id"] not in cwe_1003_ids:
                not_cwe_1003_cve.append(py_item["cve_list"])

    print(json.dumps(not_cwe_1003_cve, indent=4))


def add_cwe_list():
    cwe_tree_fpath = "/root/projects/VDTest/agent_app/CWE/CWE_1003_tree.json"

    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items_v1.json"

    with open(py_items_fpath, "r") as f:
        py_items = json.load(f)

    def find_cwe_paths(_cwe_id: str) -> List[List[str]]:
        all_father_paths: List[List[str]] = []

        fathers = cwe_tree[_cwe_id]["VIEW-1003"]["father"]
        if fathers:
            for father in fathers:
                paths = find_cwe_paths(father)
                for path in paths:
                    all_father_paths.append(path)
        else:
            all_father_paths.append([])

        all_paths: List[List[str]] = []
        for father_path in all_father_paths:
            father_path.append(_cwe_id)
            all_paths.append(father_path)

        return all_paths

    for i, py_item in enumerate(py_items):
        if py_item["cwe_id"] is not None:
            cwe_id = py_item["cwe_id"].split("-")[-1]

            cwe_paths = find_cwe_paths(cwe_id)

            py_item["cwe_list"] = cwe_paths

        py_items[i] = py_item

    with open(py_items_fpath, "w") as f:
        json.dump(py_items, f, indent=4)


def check_cwe_list():
    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items_v1.json"

    with open(py_items_fpath, "r") as f:
        py_items = json.load(f)

    cwe_lists_items = []
    cwe_list_num = 0
    for py_item in py_items:
        if py_item["cwe_id"] is not None:
            if len(py_item["cwe_list"]) > 1:
                cwe_lists_items.append(py_item["cve_list"])
            else:
                cwe_list_num += 1

    print(cwe_list_num)
    print(json.dumps(cwe_lists_items, indent=4))


def mod_cwe_list():
    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items_v1.json"

    with open(py_items_fpath, "r") as f:
        py_items = json.load(f)

    for i, py_item in enumerate(py_items):
        if py_item["cwe_id"] is not None:
            assert len(py_item["cwe_list"]) == 1
            py_item["cwe_list"] = py_item["cwe_list"][0]
        py_items[i] = py_item

    with open(py_items_fpath, "w") as f:
        json.dump(py_items, f, indent=4)


mod_cwe_list()
