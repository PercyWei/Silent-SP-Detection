import csv
import json
import os
from typing import *

from utils.logging import start_with_logger


def csv2cweTree(csv_path, save_filepath, save=False):
    cweTree = {}
    cwe_items_list = []

    with open(csv_path) as f:
        reader = csv.reader(f)
        title = next(reader)

        for i, row in enumerate(reader):

            cwe_item = {}
            for v, attr in zip(row, title):
                cwe_item[attr] = v

            cwe_items_list.append(cwe_item)

    father_childs_list = []
    left_items = []
    for cwe_item in cwe_items_list:
        father = None
        current = str(cwe_item["CWE-ID"])
        relations = cwe_item["Related Weaknesses"]

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
    cweTree[root] = father_childs_list

    if not os.path.exists(save_filepath) or (os.path.exists(save_filepath) and save):
        with open(save_filepath, "w") as f:
            f.write(json.dumps(cwe_items_list, indent=4))

    print(json.dumps(cweTree, indent=4))


def extract_view_rels_from_csv(csv_path, save_dpath):
    logger.info(f"Extracting CWE relations from file: {csv_path}.")

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

    logger.info(f"Successfully extract {len(cwe_simple_item_dict)} detailed / simplified CWE items.")

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

    logger.info(f"CWE items' detailed information save in f{cwe_items_fpath}.")
    logger.info(f"CWE items' simplified Detailed information save in f{cwe_simple_items_fpath}.")


def can_add(fathers: List, qualified_cwe_id_list: List) -> bool:
    flag = True
    for father in fathers:
        if father not in qualified_cwe_id_list:
            flag = False
            break

    return flag


def update_qualified_cwe_item(child, fathers: List,
                              view_id: str,
                              qualified_cwe_id_list: List, cwe_simple_item_dict: Dict):
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
            logger.info("Add child CWE '" + child + "' to CWE '" + father + "'.")
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
    logger.info("Update all CWE items' father and children information in VIEW-" + view_id + ".")

    qualified_cwe_id_list = []
    left_cwe_id_list = []

    for current_id, cwe_simple_item in cwe_simple_item_dict.items():

        if len(cwe_simple_item["VIEW-" + view_id]["father"]) == 0:
            logger.info("CWE '" + current_id + "' is child of CWE " + view_id + ".")
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


if __name__ == '__main__':
    logger = start_with_logger(__name__, log_fname="csv2cweTree")

    save_dpath = './data/csv'

    # cwe1003_csv_path = "./data/1003.csv"
    # save_filepath = "./data/1003-CWEItems.json"
    # csv2cweTree(cwe1003_csv_path, save_filepath)

    cwe1000_csv_path = "./data/csv/1000.csv"
    extract_view_rels_from_csv(cwe1000_csv_path, save_dpath)
