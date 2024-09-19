import os
import json

from preprocess.util import clone_repo, is_commit_exist_in_repo, get_cwe_depth


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

    updt_dataset_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000.json"
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

    for repo in repos:
        print("=" * 100 + "\n\n")
        repo_dpath = os.path.join(root, repo.replace('/', '_'))
        clone_repo(repo, repo_dpath, token=token, timeout=60)


if __name__ == "__main__":
    pass

    # Step 1: count
    check_ori_nvdvul()

    # Step 2: build
    # build_nvdvul_in_view_1000()

