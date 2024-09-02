import csv
import json
import os
from collections import defaultdict

from typing import *


"""CWE ENTRIES"""


def read_cwe_csv(csv_path: str, save_dpath: str):
    cwe_entries: List[Dict] = []

    with open(csv_path) as f:
        reader = csv.reader(f)
        title = next(reader)

        for i, row in enumerate(reader):
            cwe_entry = {}
            for v, attr in zip(row, title):
                cwe_entry[attr] = v
            cwe_entries.append(cwe_entry)

    cwe_entries_fpath = os.path.join(save_dpath, 'CWE_entries.json')
    with open(cwe_entries_fpath, "w") as f:
        f.write(json.dumps(cwe_entries, indent=4))


"""CWE TREE"""
# FIXME: This section is not yet complete


def build_cwe_tree(cwe_entries_fpath: str, save_dpath: str):
    with open(cwe_entries_fpath, "r") as f:
        cwe_entries = json.load(f)

    cwe_tree: Dict[str, Dict] = {}

    father_childs_list = []
    left_items = []
    for cwe_entry in cwe_entries:
        father = None
        current = str(cwe_entry["CWE-ID"])
        relations = cwe_entry["Related Weaknesses"]

        diff_view_relations = relations.split("::")
        for view_relations in diff_view_relations:
            if "VIEW ID:1003" in view_relations:
                rels = view_relations.split(':')
                for i, rel in enumerate(rels):
                    if rel == "ChildOf":
                        assert father is None
                        father = str(rels[i+2])

        if father is not None:
            left_flag = True
            for father_childs in father_childs_list:
                if father in father_childs:
                    left_flag = False
                    father_childs[father].append(current)
                    break
            if left_flag:
                left_items.append([father, current])
        else:
            for father_childs in father_childs_list:
                assert current not in father_childs

            father_childs_list.append({current: []})

    while left_items:
        current = left_items.pop()
        for father_childs in father_childs_list:
            if current[0] in father_childs:
                father_childs[current[0]].append(current[1])
                break

    root = "1003"
    cwe_tree[root] = father_childs_list


def extract_view_rels_from_csv(csv_path, save_dpath):
    focus_view_ids = ['1000', '699']

    cwe_items_dict = {}
    cwe_simple_item_dict = {}

    with open(csv_path) as f:
        reader = csv.reader(f)
        title = next(reader)

        for i, row in enumerate(reader):
            cwe_id = None
            cwe_item = {}
            cwe_simple_item = {}
            for v, attr in zip(row, title):
                # Full info
                cwe_item[attr] = v

                # Simplified info
                if attr == 'CWE-ID':
                    cwe_simple_item[attr] = v
                    cwe_id = v
                elif attr == 'Related Weaknesses':
                    for view_id in focus_view_ids:
                        cwe_simple_item['VIEW-' + view_id] = {'father': [],
                                                              'children': []}

                    rels = v.split("::")
                    for rel in rels:
                        if rel == '':
                            continue

                        rel_items = rel.split(':')
                        if rel_items[5] in focus_view_ids:
                            current_view_attr = 'VIEW-' + rel_items[5]
                            rel_name = rel_items[1]
                            rel_cwe_id = rel_items[3]

                            if rel_name == 'ChildOf' or rel_name == 'MemberOf':
                                cwe_simple_item[current_view_attr]['father'].append(rel_cwe_id)
                            elif rel_name == 'ParentOf' or rel_name == 'HasMember':
                                cwe_simple_item[current_view_attr]['children'].append(rel_cwe_id)
                            elif rel_name in cwe_simple_item[current_view_attr]:
                                cwe_simple_item[current_view_attr][rel_name].append(rel_cwe_id)
                            else:
                                cwe_simple_item[current_view_attr][rel_name] = [rel_cwe_id]
                else:
                    pass

            assert cwe_id is not None
            cwe_items_dict[cwe_id] = cwe_item
            cwe_simple_item_dict[cwe_id] = cwe_simple_item

    for view_id in focus_view_ids:
        update_full_rels(cwe_simple_item_dict, view_id)
        break

    # Save
    if not os.path.exists(save_dpath):
        os.makedirs(save_dpath, exist_ok=True)

    prefix = csv_path.split('/')[-1][:-4]

    cwe_items_fpath = os.path.join(save_dpath, 'VIEW-' + prefix + '_CWEItems' + '.json')
    cwe_simple_items_fpath = os.path.join(save_dpath, 'VIEW-' + prefix + '_CWESimpleItems' + '.json')

    with open(cwe_items_fpath, "w") as f:
        f.write(json.dumps(cwe_items_dict, indent=4))

    with open(cwe_simple_items_fpath, "w") as f:
        f.write(json.dumps(cwe_simple_item_dict, indent=4))


def can_add(fathers: List, qualified_cwe_id_list: List) -> bool:
    flag = True
    for father in fathers:
        if father not in qualified_cwe_id_list:
            flag = False
            break

    return flag


def update_qualified_cwe_item(
        child, fathers: List,
        view_id: str,
        qualified_cwe_id_list: List,
        cwe_simple_item_dict: Dict
):
    """
        :param child: CWE-ID of CWE item to be added
        :param fathers: CWE-ID list of fathers of CWE item to be added
        :param view_id: VIEW ID
        :param qualified_cwe_id_list: CWE-ID list of all qualified CWE items
        :param cwe_simple_item_dict: List of all CWE items with simplified info

        Update a qualified CWE item, including `qualified_cwe_id_list` and `cwe_simple_item_list`
    """
    qualified_cwe_id_list.append(child)
    for father in fathers:
        # Add info about the child
        if child not in cwe_simple_item_dict[father]["VIEW-" + view_id]["children"]:
            cwe_simple_item_dict[father]["VIEW-" + view_id]["children"].append(child)


def update_full_rels(cwe_simple_item_dict: Dict, view_id: str = "1000"):
    """
        :param cwe_simple_item_dict: Each element is like -> CWE-ID: {attr1: v1, attr2: v2, ...}
        :param view_id: VIEW ID, by default = "1000"

         CWE items in `cwe_simple_item_list` only have complete father information,
         need update their children information.
         Note: VIEW-1000 and VIEW-699 only.
    """
    # By default, all item's father information is complete.

    qualified_cwe_id_list = []
    left_cwe_id_list = []

    for current_id, cwe_simple_item in cwe_simple_item_dict.items():

        if len(cwe_simple_item["VIEW-" + view_id]["father"]) == 0:
            qualified_cwe_id_list.append(current_id)
        else:
            can_add_flag = can_add(cwe_simple_item["VIEW-" + view_id]["father"], qualified_cwe_id_list)

            if can_add_flag:
                update_qualified_cwe_item(child=current_id, fathers=cwe_simple_item["VIEW-" + view_id]["father"],
                                          view_id=view_id,
                                          qualified_cwe_id_list=qualified_cwe_id_list,
                                          cwe_simple_item_dict=cwe_simple_item_dict)
            else:
                left_cwe_id_list.append(current_id)

    while left_cwe_id_list:
        current_id = left_cwe_id_list.pop(0)
        can_add_flag = can_add(cwe_simple_item_dict[current_id]["VIEW-" + view_id]["father"], qualified_cwe_id_list)

        if can_add_flag:
            update_qualified_cwe_item(child=current_id, fathers=cwe_simple_item_dict[current_id]["VIEW-" + view_id]["father"],
                                      view_id=view_id,
                                      qualified_cwe_id_list=qualified_cwe_id_list,
                                      cwe_simple_item_dict=cwe_simple_item_dict)
        else:
            left_cwe_id_list.append(current_id)


"""CWE PATH"""


def find_cwe_paths(cwe_id: str, cwe_tree: Dict[str, Dict]) -> List[List[str]]:
    if len(cwe_tree[cwe_id]["father"]) == 0:
        return [[cwe_id]]
    else:
        paths: List[List[str]] = []
        for father_id in cwe_tree[cwe_id]["father"]:
            father_paths = find_cwe_paths(father_id, cwe_tree)
            for father_path in father_paths:
                path = father_path + [cwe_id]
                paths.append(path)
        return paths


def refine_cwe_tree_with_paths(cwe_tree_fpath: str) -> None:
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    for cwe_id, data in cwe_tree.items():
        cwe_paths = find_cwe_paths(cwe_id, cwe_tree)
        cwe_tree[cwe_id]["cwe_paths"] = cwe_paths
    
    with open(cwe_tree_fpath, "w") as f:
        json.dump(cwe_tree, f, indent=4)


def check_cwe_paths_and_print(cwe_tree_fpath: str) -> None:
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    for cwe_id, data in cwe_tree.items():
        # Find CWE with multiple paths with different length (< 3)
        if len(data["cwe_paths"]) > 1:
            depth_3_flag = False
            depth_2_flag = False
            for path in data["cwe_paths"]:
                if len(path) == 3:
                    depth_3_flag = True
                if len(path) <= 2:
                    depth_2_flag = True
            if depth_3_flag and depth_2_flag:
                print(cwe_id)


def find_diff_depth_cwe(cwe_tree_fpath: str, save_dir: str, max_depth: int = 3) -> None:
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    # depth -> [cwe_id]
    diff_depth_cwe_ids: Dict[int, List[str]] = defaultdict(list)
    depths = list(range(1, max_depth + 1))

    for cwe_id, data in cwe_tree.items():
        # TODO: For CWE with multiple paths, we only focus on one of those paths, i.e. the one with the shortest length
        #       This problem exists under VIEW-1000 (not under view VIEW-1003)
        min_path = min(data["cwe_paths"], key=len)
        if len(min_path) in depths:
            diff_depth_cwe_ids[len(min_path)].append(cwe_id)

    for depth, cwe_ids in diff_depth_cwe_ids.items():
        if len(cwe_ids) > 0:
            save_fpath = os.path.join(save_dir, f"CWE_depth_{depth}.json")
            with open(save_fpath, "w") as f:
                json.dump(cwe_ids, f, indent=4)


if __name__ == '__main__':
    save_dir = "/root/projects/VDTest/data/CWE/VIEW_1000"
    # save_dir = "/root/projects/VDTest/data/CWE/VIEW_1003"

    ## Build CWE entries file
    csv_file = "/root/projects/VDTest/data/CWE/1000.csv"
    # csv_file = "/root/projects/VDTest/data/CWE/1003.csv"
    # read_cwe_csv(csv_file, save_dir)

    ## Refine CWE tree
    cwe_tree_file = os.path.join(save_dir, "CWE_tree.json")
    # refine_cwe_tree_with_paths(cwe_tree_file)
    # check_cwe_paths_and_print(cwe_tree_file)

    ## Extract CWE ids in different depths
    find_diff_depth_cwe(cwe_tree_file, save_dir)
