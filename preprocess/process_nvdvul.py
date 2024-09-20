import os
import json

from typing import *

from preprocess.util import clone_repo, is_commit_exist_in_repo, get_cwe_depth
from utils import insert_key_value

def check_ori_nvdvul():
    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks.json"
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    cwe_entry_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(cwe_entry_fpath, 'r') as f:
        cwe_entries = json.load(f)

    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    cwe_ids = []
    for entry in cwe_entries:
        cwe_ids.append(entry["CWE-ID"])

    print(f"Dataset len: {len(dataset)}")

    mul_cwes_items = []
    supported_items = []
    for cve_item in dataset:
        save_flag = False
        for full_cwe_id in cve_item["cwe_list"]:
            cwe_id = full_cwe_id.split('-')[-1]
            if cwe_id in cwe_ids:
                save_flag = True
                break

        if len(cve_item["cwe_list"]) > 1:
            mul_cwes_items.append(cve_item)

        if save_flag:
            supported_items.append(cve_item)

    print(f"CVE item with multiple CWE-IDs num: {len(mul_cwes_items)}/{len(dataset)}")
    print(f"CVE item with supported CWE-ID num: {len(supported_items)}/{len(dataset)}")

    too_detailed_items = []
    for cve_item in supported_items:
        add_flag = False
        for full_cwe_id in cve_item["cwe_list"]:
            cwe_id = full_cwe_id.split('-')[-1]
            if cwe_id in cwe_ids:
                depth = get_cwe_depth(cwe_id)
                assert depth
                if depth > 3:
                    add_flag = True
                    break

        if add_flag:
            too_detailed_items.append(cve_item)

    print(f"CVE item with too detailed CWE-ID num: {len(too_detailed_items)}/{len(supported_items)}")


def build_nvdvul_in_view_1000():
    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks.json"
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    updt_num = 0
    updt_cve_items = []
    for cve_item in dataset:
        updt_cwe_list = []

        updt_flag = False
        for full_cwe_id in cve_item["cwe_list"]:
            cwe_id = full_cwe_id.split('-')[-1]
            depth = get_cwe_depth(cwe_id)
            assert depth
            if depth > 3:
                updt_flag = True
                for cwe_path in cwe_tree[cwe_id]['cwe_paths']:
                    updt_cwe_list.append("CWE-" + cwe_path[2])
            else:
                updt_cwe_list.append(full_cwe_id)

        updt_cwe_list = list(set(updt_cwe_list))

        if updt_flag:
            updt_num += 1
            cve_item['cwe_list'] = updt_cwe_list
            updt_cve_items.append(cve_item)
        else:
            updt_cve_items.append(cve_item)

    print(updt_num)

    updt_dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_view1000.json"
    with open(updt_dataset_fpath, 'w') as f:
        json.dump(updt_cve_items, f, indent=4)


def clone_nvdvul_all_repos():
    token = os.getenv('TOKEN', '')

    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks.json"
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    root = "/root/projects/clone_projects"
    repos = []
    for cve_item in dataset:
        repo = cve_item["repo"]
        repo_dir = os.path.join(root, repo.replace('/', '_'))
        if not os.path.exists(repo_dir) and repo not in repos:
            repos.append(repo)

    print(json.dumps(repos, indent=4))

    # failed_repos = []
    # for repo in repos:
    #     print("=" * 100 + "\n\n")
    #     repo_dpath = os.path.join(root, repo.replace('/', '_'))
    #     res = clone_repo(repo, repo_dpath, token=token, timeout=60)
    #
    #     if not res:
    #         failed_repos.append(repo)
    #
    # with open("/root/failed_repos.json", "w") as f:
    #     json.dump(failed_repos, f, indent=4)


def check_nvdvul_in_view_1000():
    """
    For CVE items labeled with multiple CWE-IDs, check whether they have multiple CWE-IDs in the same path
    """
    dataset_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000.json"
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
    dataset_fpath = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_view1000.json"
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

    dataset_v1_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000_v1.json"
    with open(dataset_v1_fpath, 'w') as f:
        json.dump(sig_depth_cwes_items, f, indent=4)

    dataset_v2_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000_v2.json"
    with open(dataset_v2_fpath, 'w') as f:
        json.dump(mul_depth_cwes_items, f, indent=4)



if __name__ == "__main__":
    pass

    # Step 1: count
    # check_ori_nvdvul()

    # Step 2: build
    # build_nvdvul_in_view_1000()

    # check_nvdvul_in_view_1000()
    # separate_nvdvul_in_view_1000()

    # clone_nvdvul_all_repos()
