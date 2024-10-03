import os
import json

from typing import *
from copy import deepcopy
from unidiff import PatchSet

from preprocess.util import (
    show_commit_content,
    show_commit_file_names, parse_commit_name_status,
    show_commit_parents, parse_commit_parents
)
from utils import insert_key_value


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


def count_cwe_list_len():
    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items_v1.json"

    with open(py_items_fpath, "r") as f:
        py_items = json.load(f)

    normal_patch = 0
    level_1_cwe_list_num = 0
    level_2_cwe_list_num = 0
    for py_item in py_items:
        if py_item["cwe_id"] is not None:
            if len(py_item["cwe_list"]) == 1:
                level_1_cwe_list_num += 1
            elif len(py_item["cwe_list"]) == 2:
                level_2_cwe_list_num += 1
            else:
                raise RuntimeError
        else:
            normal_patch += 1


def combine_vulfix_treevul():
    sim_py_vulfix_fpath = "/root/projects/VDTest/output/dataset/sim_py_vulfix.json"
    with open(sim_py_vulfix_fpath, 'r') as f:
        sim_py_vulfix = json.load(f)

    sim_treevul_fpath = "/root/projects/VDTest/output/dataset/sim_treevul.json"
    with open(sim_treevul_fpath, 'r') as f:
        sim_treevul = json.load(f)

    # NOTE: For security patches, this dataset only collects the original dataset (VulFix, TreeVul) entries
    #       with CVE-ID that have been found so far, and each CVE only contains single commit.
    record_cve_repo_commit = {}
    for item in sim_py_vulfix:
        if item["commit_type"] == 1 and isinstance(item["cve_list"], list):
            assert len(item["cve_list"]) == 1
            cve_id = item["cve_list"][0]
            if cve_id not in record_cve_repo_commit:
                record_cve_repo_commit[cve_id] = []

            repo_commit = item["repo"] + "_" + item["commit_hash"]
            assert repo_commit not in record_cve_repo_commit[cve_id]
            record_cve_repo_commit[cve_id].append(repo_commit)

    cve_commit_num = {}
    for cve_id, repo_commit in record_cve_repo_commit.items():
        cve_commit_num[cve_id] = len(repo_commit)

    commit_items = {}
    # VulFix
    for item in sim_py_vulfix:
        append_flag = False
        if item["commit_type"] == 0:
            append_flag = True
        else:
            if isinstance(item["cve_list"], list):
                cve_id = item["cve_list"][0]
                if cve_commit_num[cve_id] == 1:
                    append_flag = True

        if append_flag and item["commit_hash"] not in commit_items:
            item["source"] = "vulfix"
            commit_items[item["commit_hash"]] = item

    # TreeVul
    for item in sim_treevul:
        if item["PL_list"] == ["Python"] and item["commit_hash"] not in commit_items:
            item["source"] = "treevul"
            commit_items[item["commit_hash"]] = item

    items = list(commit_items.values())

    # Count
    vul_num = 0
    non_vul_num = 0
    for item in items:
        if item["commit_type"] == 1:
            vul_num += 1
        else:
            non_vul_num += 1

    print(f"Vul number: {vul_num}")
    print(f"Non-Vul number: {non_vul_num}")

    py_items_fpath = "/root/projects/VDTest/output/dataset/py_items.json"
    with open(py_items_fpath, 'w') as f:
        json.dump(items, f, indent=4)


"""DATASET CONSTRUCTION"""


def build_novul_tasks_from_vulfix():
    # TODO-1: For now, we only focus on Python tasks.

    # Ref to TODO-1
    vulfix_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/py_cleaned_novul.json"

    with open(vulfix_fpath, 'r') as f:
        vulfix_tasks = json.load(f)

    record_commits = []
    novul_tasks = []
    for task in vulfix_tasks:
        # TODO: Due to the large number of novul tasks, we did not verify the reproducibility of each commit,
        #       but left the verification process to the execution of specific tasks.
        if task["commit_hash"] not in record_commits:
            novul_tasks.append(
                {
                    "source": "vulfix",
                    "cve_id": task["cve_id"],
                    "commit_type": task["commit_type"],
                    "cwe_id": task["cwe_id"],
                    "path_list": task["path_list"],
                    "repo": task["repo"],
                    "commit_hash": task["commit_hash"]
                }
            )

    save_fpath = "/root/projects/VDTest/dataset/Final/py_novul_tasks.json"
    with open(save_fpath, 'w') as f:
        json.dump(novul_tasks, f, indent=4)


def build_vul_tasks_without_cwe_from_vulfix():
    # TODO-1: For now, we only focus on Python tasks.

    # Ref to TODO-1
    vulfix_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/py_cleaned_vul_v1.json"

    with open(vulfix_fpath, 'r') as f:
        vulfix_tasks = json.load(f)

    record_commits = []
    vul_tasks_without_cwe = []
    for task in vulfix_tasks:
        # Extract all valid tasks
        if task["reproducibility"] and task["commit_hash"] not in record_commits:
            vul_tasks_without_cwe.append(
                {
                    "source": "vulfix",
                    "cve_id": task["cve_id"],
                    "commit_type": task["commit_type"],
                    "cwe_id": task["cwe_id"],
                    "path_list": task["path_list"],
                    "repo": task["repo"],
                    "commit_hash": task["commit_hash"]
                }
            )

    save_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_v1.json"
    with open(save_fpath, 'w') as f:
        json.dump(vul_tasks_without_cwe, f, indent=4)


def build_vul_tasks_with_cwe_from_vulfix_treevul():
    # TODO-1: For now, we only focus on Python tasks.
    # TODO-2: For now, we only focus on CVE containing single commits.

    # Ref to TODO-1
    vulfix_fpath = "/root/projects/VDTest/dataset/Intermediate/VulFix/py_cleaned_vul_v2.json"
    treevul_fpath = "/root/projects/VDTest/dataset/Intermediate/TreeVul/treevul_cleaned.json"

    vul_tasks_with_cwe = []

    ## (1) VulFix
    with open(vulfix_fpath, 'r') as f:
        vulfix_tasks = json.load(f)

    for task in vulfix_tasks:
        # Ref to TODO-2
        if len(task["commits"]) == 1:
            vul_tasks_with_cwe.append(
                {
                    "source": "vulfix",
                    "cve_id": task["cve_id"],
                    "commit_type": task["commit_type"],
                    "cwe_id": task["cwe_id"],
                    "path_list": task["path_list"],
                    "repo": task["commits"][0]["repo"],
                    "commit_hash": task["commits"][0]["commit_hash"]
                }
            )

    ## (2) TreeVul
    with open(treevul_fpath, 'r') as f:
        treevul_tasks = json.load(f)

    for task in treevul_tasks:
        # Ref to TODO-1 TODO-2
        if task["PL_list"] == ["Python"] and len(task["commits"]) == 1 and task["commits"][0]["reproducibility"]:
            vul_tasks_with_cwe.append(
                {
                    "source": "treevul",
                    "cve_id": task["cve_id"],
                    "commit_type": task["commit_type"],
                    "cwe_id": task["cwe_id"],
                    "path_list": task["path_list"],
                    "repo": task["commits"][0]["repo"],
                    "commit_hash": task["commits"][0]["commit_hash"]
                }
            )

    ## (3) Delete duplicate
    # TODO: Need manual checking and deduplication
    record_cves = []
    for task in vul_tasks_with_cwe:
        if task["cve_id"] not in record_cves:
            record_cves.append(task["cve_id"])
        else:
            print(task["cve_id"])

    save_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_v2.json"
    with open(save_fpath, 'w') as f:
        json.dump(vul_tasks_with_cwe, f, indent=4)


def complete_vul_tasks_with_cwe_with_path_list():
    # TODO-1: For now, we only focus on Python tasks.
    # TODO-2: For now, we consider CWE VIEW-1000.

    # Ref to TODO-1
    vul_tasks_with_cwe_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_v2.json"
    with open(vul_tasks_with_cwe_fpath, 'r') as f:
        vul_tasks = json.load(f)

    # Ref to TODO-2
    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    updt_tasks = []
    for task in vul_tasks:
        updt_task = {
            "source": task["source"],
            "cve_id": task["cve_id"],
            "commit_type": task["commit_type"],
            "cwe_id": task["cwe_id"],
            "cwe_paths": [],
            "repo": task["repo"],
            "commit_hash": task["commit_hash"]
        }

        cwe_id = task["cwe_id"].split("-")[-1]
        path_list = task["path_list"]
        assert len(path_list) <= 1

        if cwe_id in cwe_tree:
            cwe_paths = cwe_tree[cwe_id]["cwe_paths"]

            if len(path_list) == 1:
                id_path = [x.split('-')[-1] for x in path_list[0]]
                if id_path not in cwe_paths:
                    print(f"{id_path} {cwe_paths}")

            paths = []
            for cwe_path in cwe_paths:
                paths.append([f"CWE-{x}" for x in cwe_path])
            updt_task["cwe_paths"] = paths
            updt_tasks.append(updt_task)
        else:
            print(cwe_id)


    # Ref to TODO-2
    save_fpath = "/root/projects/VDTest/dataset/Final/py_vul_tasks_v2_view1000.json"
    with open(save_fpath, 'w') as f:
        json.dump(updt_tasks, f, indent=4)


"""OTHER"""


def count_commit_file(dataset_fpath: str, suffix: List[str] | None = None):
    if suffix is None:
        suffix = ['.py']

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    repos_root = "/root/projects/clone_projects"

    failure_items = {}
    updt_dataset = []

    updt_flag = True
    for i, cve_item in enumerate(dataset):
        repo_dpath = os.path.join(repos_root, cve_item["repo"].replace('/', "_"))
        commit_hash = cve_item["commit_hash"]

        res = show_commit_file_names(repo_dpath, commit_hash)

        # (1) Filter out invalid commit hashes
        if res is None:
            updt_flag = False
            failure_items[cve_item['cve_id']] = [
                cve_item['repo'],
                commit_hash,
                f"https://github.com/{cve_item['repo']}/commit/{commit_hash}"
            ]
            continue

        flag, commit_files = parse_commit_name_status(res)

        # (2) Filter out unresolvable commit hashes
        if not flag:
            updt_flag = False
            print(f"\n{res}\n")
            continue

        # (3) Count commit files
        file_count = 0
        for file in commit_files["modified_files"]:
            if any(file.endswith(sf) for sf in suffix):
                file_count += 1

        for file in commit_files["added_files"]:
            if any(file.endswith(sf) for sf in suffix):
                file_count += 1

        for file in commit_files["deleted_files"]:
            if any(file.endswith(sf) for sf in suffix):
                file_count += 1

        for _, new_file in commit_files["renamed_files"]:
            if any(new_file.endswith(sf) for sf in suffix):
                file_count += 1

        # (4) Filter out empty commit hashes
        if file_count == 0:
            commit_parents = show_commit_parents(repo_dpath, commit_hash)
            assert commit_parents is not None
            parent_hashes = parse_commit_parents(commit_parents)

            # NOTE: When the commit is a merge commit, it is allowed to contain empty filenames.
            if len(parent_hashes) <= 1:
                updt_flag = False
                print(f"\nhttps://github.com/{cve_item['repo']}/commit/{commit_hash}\n")
                continue
            else:
                file_count = "NOT COUNT"

        # (5) Update original dataset
        cve_item["file_count"] = file_count
        updt_dataset.append(cve_item)

    out_root = "/root/projects/VDTest/data"
    if failure_items:
        with open(os.path.join(out_root, "commit_file_count_failure.json"), 'w') as f:
            json.dump(failure_items, f, indent=4)

    if updt_flag:
        with open(dataset_fpath, 'w') as f:
            json.dump(updt_dataset, f, indent=4)


def filter_dataset_and_save(dataset_fpath: str):
    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    new_dataset = {}
    for i, task in enumerate(dataset):
        task_id = f"{i}-{task['source']}"
        new_dataset[task_id] = task

    invalid_task_ids = {

    }

    filter_dataset = {}
    for task_id, task in new_dataset.items():
        id = task_id.split("-")[0]
        if id in invalid_task_ids:
            cve_id = invalid_task_ids[id].replace(' ', '')
            assert task['cve_id'] == cve_id
        else:
            filter_dataset[task_id] = task

    save_fpath = "/root/filter_dataset.json"
    with open(save_fpath, 'w') as f:
        json.dump(filter_dataset, f, indent=4)


def filter_dataset_for_baseline_treevul(dataset_fpath: str):
    repos_root = "/root/projects/clone_projects"

    valid_cwes_fpath = "/root/projects/TreeVul/data/valid_cwes.json"
    with open(valid_cwes_fpath, 'r') as f:
        valid_cwes = json.load(f)

    with open(dataset_fpath, 'r') as f:
        dataset = json.load(f)

    print(f"Original dataset: {len(dataset)}")

    ## Step 1: Filter
    filter_dataset = []
    for item in dataset:
        if item["cwe_depth"] == 3 and item["cwe_id"] in valid_cwes[2] and item["file_count"] != "NOT COUNT":
            filter_dataset.append(item)

    print(f"Filtered dataset: {len(filter_dataset)}")

    ## Step 2: Build new dataset (follow TreeVul)
    cwe_paths_fpath = "/root/projects/TreeVul/data/cwe_path.json"
    with open(cwe_paths_fpath, 'r') as f:
        cwe_paths = json.load(f)

    save_flag = True

    extent2lang = {
        ".py": "Python"
    }

    composed_patch = 0
    new_dataset = []

    for item in filter_dataset:
        new_item = dict()
        new_item["cve_list"] = item["cve_id"]
        new_item["cwe_list"] = item["cwe_id"]

        assert new_item["cwe_list"] in cwe_paths
        cwe_path = cwe_paths[new_item["cwe_list"]]
        assert len(cwe_path) == 3
        new_item["path_list"] = [cwe_path]

        new_item["repo"] = item["repo"]
        new_item["commit_id"] = item["commit_hash"]

        local_repo_dpath = os.path.join(repos_root, new_item["repo"].replace('/', "_"))
        commit_content = show_commit_content(local_repo_dpath, new_item["commit_id"])
        assert commit_content is not None

        try:
            patch = PatchSet.from_string(commit_content)
        except Exception as e:
            save_flag = False
            print("\n" + "=" * 100 + "\n")
            print(commit_content + "\n\n")
            print(e)
            continue

        new_item["Total_LOC_REM"] = patch.removed
        new_item["Total_LOC_ADD"] = patch.added
        new_item["Total_LOC_MOD"] = new_item["Total_LOC_ADD"] + new_item["Total_LOC_REM"]
        new_item["Total_NUM_FILE"] = len(set(f.path for f in patch))
        if len(set(f.path for f in patch)) < len(patch):
            composed_patch += 1

        new_item["Total_NUM_HUNK"] = sum([len(f) for f in patch])

        # (1) Remove large commits (perform at the commit-level)
        thres_file_num = 100
        thres_LOC = 10000

        if new_item["Total_NUM_FILE"] > thres_file_num or new_item["Total_LOC_MOD"] > thres_LOC:
            continue

        # (2) Add dataset item for each file in commits
        for f in (patch.modified_files + patch.removed_files + patch.added_files):
            if f.is_binary_file:
                continue

            if len(f) == 0:
                if not f.is_rename:
                    raise ValueError("0 change, not renamed")
                continue

            if '.' not in f.path:
                continue

            extension = '.' + f.path.split('.')[-1]
            if extension not in extent2lang:
                continue

            new_item["file_name"] = f.path

            if f.is_modified_file:
                new_item["file_type"] = "modified"
            elif f.is_added_file:
                new_item["file_type"] = "added"
            elif f.is_removed_file:
                new_item["file_type"] = "removed"

            new_item["PL"] = extent2lang[extension]

            new_item["LOC_REM"] = f.removed
            new_item["LOC_ADD"] = f.added
            new_item["LOC_MOD"] = new_item["LOC_ADD"] + new_item["LOC_REM"]

            new_item["NUM_HUNK"] = len(f)

            rem_lines = list()
            add_lines = list()

            for hunk in f:
                # hunk-level
                l_rem = ''.join([str(l)[1:] for l in hunk.source_lines() if not l.is_context])
                l_add = ''.join([str(l)[1:] for l in hunk.target_lines() if not l.is_context])
                for s in ['\r\n', '\r', '\n']:
                    # preprocess code exactly the same as the CodeBERT
                    l_rem = l_rem.replace(s, ' ')
                    l_add = l_add.replace(s, ' ')
                l_rem = ' '.join(l_rem.split())
                l_add = ' '.join(l_add.split())

                rem_lines.append(l_rem)
                add_lines.append(l_add)

            # hunk-level
            new_item["REM_DIFF"] = rem_lines
            new_item["ADD_DIFF"] = add_lines

            new_dataset.append(deepcopy(new_item))

    print(f"New dataset: {len(new_dataset)}")
    print(f"Composed patch: {composed_patch}")

    ## Step 3: Save
    if save_flag:
        save_fpath = "/root/projects/TreeVul/dataset/py_vul_tasks_vulfix.json"
        with open(save_fpath, 'w') as f:
            json.dump(new_dataset, f, indent=4)


if __name__ == '__main__':
    pass

    # build_novul_tasks_from_vulfix()
    # build_vul_tasks_without_cwe_from_vulfix()
    # build_vul_tasks_with_cwe_from_vulfix_treevul()
    # complete_vul_tasks_with_cwe_with_path_list()

    dataset_file = "/root/projects/VDTest/dataset/Final/py_vul_tasks_vulfix_view1000_v1.json"
    # count_commit_file(dataset_file)

    filter_dataset_for_baseline_treevul(dataset_file)

    # exps_root = "/root/projects/VDTest/output/agent/vul_2024-09-24T09:58:55_SAVE"
    # exps = os.listdir(exps_root)
    # exps = [exp for exp in exps if exp[0].isdigit()]
    # for exp in exps:
    #     pass
        # ori_fpath = os.path.join(exps_root, exp)
        #
        # ori_task_id = exp.split('_')[0]
        # ori_index = ori_task_id.split('-')[0]
        #
        # meta_fpath = os.path.join(ori_fpath, "meta.json")
        # with open(meta_fpath, 'r') as f:
        #     meta = json.load(f)
        # assert filter_dataset[ori_task_id]["cve_id"] == meta['task_info']['cve_id']
        #
        # new_index = filter_dataset_list.index(ori_task_id)
        #
        # new_fpath = os.path.join(exps_root, str(new_index) + exp[len(ori_index):])
        #
        # os.rename(ori_fpath, new_fpath)


        # meta_fpath = os.path.join(exps_root, exp, "meta.json")
        # with open(meta_fpath, 'r') as f:
        #     meta = json.load(f)
        #
        # task_id = exp.split("_")[0]
        # meta["task_info"]["instance_id"] = task_id
        # with open(meta_fpath, 'w') as f:
        #     json.dump(meta, f, indent=4)



