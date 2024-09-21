import os
import json

from typing import *

from preprocess.util import clone_repo, is_commit_exist_in_repo, get_cwe_depth
from utils import insert_key_value


def build_treevul_vulfix_in_view_1000():
    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/TreeVul&VulFix/py_vul_tasks_treevul&vulfix.json"
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    print(len(dataset))

    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    updt_cve_items = []
    for cve_item in dataset:
        updt_cwe_list = []

        full_cwe_id = cve_item['cwe_id']
        cwe_id = full_cwe_id.split('-')[-1]

        depth = get_cwe_depth(cwe_id)
        if depth is None:
            continue

        if depth > 3:
            for cwe_path in cwe_tree[cwe_id]['cwe_paths']:
                updt_cwe_list.append("CWE-" + cwe_path[2])
        else:
            updt_cwe_list.append(full_cwe_id)

        updt_cwe_list = list(set(updt_cwe_list))

        del cve_item['cwe_id']
        cve_item = insert_key_value(cve_item, 'cwe_list', updt_cwe_list, index=3)

        updt_cve_items.append(cve_item)

    print(len(updt_cve_items))

    updt_dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/TreeVul&VulFix/py_vul_tasks_treevul&vulfix_view1000.json"
    with open(updt_dataset_fpath, 'w') as f:
        json.dump(updt_cve_items, f, indent=4)


def check_treevul_vulfix_in_view_1000():
    """
    For CVE items labeled with multiple CWE-IDs, check whether they have multiple CWE-IDs in the same path
    """
    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/TreeVul&VulFix/py_vul_tasks_treevul&vulfix_view1000.json"
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    updt_cve_items = []
    for cve_item in dataset:
        depth_cwe_ids = [[], [], []]
        for full_cwe_id in cve_item["cwe_list"]:
            cwe_id = full_cwe_id.split('-')[-1]
            depth = get_cwe_depth(cwe_id)
            assert depth
            depth_cwe_ids[depth - 1].append(cwe_id)

        cve_item["depth_cwe_ids"] = depth_cwe_ids
        updt_cve_items.append(cve_item)

    # print(json.dumps(updt_cve_items, indent=4))


    def check_depth_cwe_ids(curr_depth_cwe_ids: List[str], below_depth_cwe_ids: List[str]) -> bool:
        for curr_cwe_id in curr_depth_cwe_ids:
            cwe_paths = cwe_tree[curr_cwe_id]['cwe_paths']
            for cwe_path in cwe_paths:
                for below_cwe_id in below_depth_cwe_ids:
                    if below_cwe_id in cwe_path:
                        return True
        return False


    filter_items = []
    for cve_item in updt_cve_items:
        if len(cve_item["cwe_list"]) > 1:
            # Check depth 3
            res = check_depth_cwe_ids(
                cve_item["depth_cwe_ids"][2], cve_item["depth_cwe_ids"][1] + cve_item["depth_cwe_ids"][0]
            )
            if res:
                filter_items.append(cve_item)
                continue
            # Check depth 2
            res = check_depth_cwe_ids(cve_item["depth_cwe_ids"][1], cve_item["depth_cwe_ids"][0])
            if res:
                filter_items.append(cve_item)
                continue

    print(len(filter_items))
    print(json.dumps(filter_items, indent=4))


def separate_nvdvul_in_view_1000():
    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/TreeVul&VulFix/py_vul_tasks_treevul&vulfix_view1000.json"
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    sig_depth_cwes_items = []
    mul_depth_cwes_items = []
    for cve_item in dataset:
        cwe_list = cve_item["cwe_list"]
        depths = []
        for full_cwe_id in cwe_list:
            cwe_id = full_cwe_id.split('-')[-1]
            depth = get_cwe_depth(cwe_id)
            depths.append(depth)
        depths = list(set(depths))
        if len(depths) > 1:
            cve_item = insert_key_value(cve_item, "cwe_depth", None, 4)
            mul_depth_cwes_items.append(cve_item)
        else:
            cve_item = insert_key_value(cve_item, "cwe_depth", depths[0], 4)
            sig_depth_cwes_items.append(cve_item)

    print(f"Number of CVE items with single depth CWE-IDs: {len(sig_depth_cwes_items)}")
    print(f"Number of CVE items with multiple depths CWE-IDs: {len(mul_depth_cwes_items)}")

    dataset_v1_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_treevul&vulfix_view1000_v1.json"
    with open(dataset_v1_fpath, 'w') as f:
        json.dump(sig_depth_cwes_items, f, indent=4)

    dataset_v2_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_treevul&vulfix_view1000_v2.json"
    with open(dataset_v2_fpath, 'w') as f:
        json.dump(mul_depth_cwes_items, f, indent=4)


if __name__ == '__main__':
    pass

    # build_treevul_vulfix_in_view_1000()
    # check_treevul_vulfix_in_view_1000()
    # separate_nvdvul_in_view_1000()
