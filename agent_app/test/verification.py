
import re
import os
import ast
import json
import glob
import time
from collections import defaultdict

from typing import *
from loguru import logger


def process_baseline_treevul_test_results():
    ## Step 1: Split results of items in Python
    # test_set_fpath = "/root/projects/TreeVul/dataset/test_set.json"
    # with open(test_set_fpath, 'r') as f:
    #     dataset = json.load(f)
    #
    # commit2pl: Dict[str, List] = defaultdict(list)
    # for item in dataset:
    #     commit_id = item["commit_id"]
    #     pl = item["PL"]
    #     if pl not in commit2pl[commit_id]:
    #         commit2pl[commit_id].append(pl)
    #
    # test_result_fpath = "/root/projects/TreeVul/model/test_results/treevul_result.json"
    # with open(test_result_fpath, 'r') as f:
    #     results = f.readlines()
    #
    # new_results = []
    # for result in results:
    #     result = result.strip()
    #     json_result = json.loads(result)
    #     if commit2pl[json_result[0]["commit_id"]] == ["Python"]:
    #         new_results.append(result)
    #
    # print(len(new_results))
    #
    # save_fpath = "/root/projects/TreeVul/model/test_results/treevul_py_test_result.json"
    # with open(save_fpath, 'w') as f:
    #     f.write("\n".join(new_results))

    ## Step 2: Calculate metrics
    pass


def group_cwes_in_different_depths():
    """Group CWEs in different depths (under VIEW-1000)."""
    cwe_tree_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_file, 'r') as f:
        cwe_tree = json.load(f)

    valid_cwes = [[], [], []]
    for cwe_id, data in cwe_tree.items():
        for path in data['cwe_paths']:
            if len(path) <= 3:
                valid_cwes[len(path) - 1].append(cwe_id)

    valid_cwes[0] = list(set(valid_cwes[0]))
    valid_cwes[1] = list(set(valid_cwes[1]))
    valid_cwes[2] = list(set(valid_cwes[2]))

    valid_cwes_file = "/root/projects/VDTest/data/CWE/valid_cwes_1000.json"
    with open(valid_cwes_file, 'w') as f:
        json.dump(valid_cwes, f, indent=4)


def check_all_exps(flag: int):
    """Check the results of experiments."""
    exp_dir = "/root/projects/VDTest/output/agent/py_vul_nvdvul_view1000_results_v1"
    exp_tasks = os.listdir(exp_dir)

    ## Check 1: Find tasks without an exp result folder
    if flag == 1:
        exp_task_ids: List[str] = []
        for exp_task in exp_tasks:
            if exp_task[0].isdigit():
                exp_task_ids.append(exp_task.split('_')[0])

        total_task_num = 311  # Need set, default 310 is for dataset NVDVul
        total_task_ids = list(range(total_task_num))
        for task_id in exp_task_ids:
            task_id = int(task_id.split('-')[0])
            assert task_id in total_task_ids
            total_task_ids.remove(task_id)

        print(total_task_ids)

    ## Check 2: Find tasks failed to run
    if flag == 2:
        failed_task_ids: List[str] = []
        for exp_task in exp_tasks:
            if exp_task[0].isdigit() and not os.path.exists(os.path.join(exp_dir, exp_task, 'cost.json')):
                failed_task_ids.append(exp_task.split('_')[0])

        print(failed_task_ids)

    ## Check 3: Summarize all tasks
    if flag == 3:
        cwe_tree_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
        with open(cwe_tree_file, 'r') as f:
            cwe_tree = json.load(f)

        summary_info = ""
        for exp_task in exp_tasks:
            if not exp_task[0].isdigit():
                continue

            task_dir = os.path.join(exp_dir, exp_task)

            # Get ground truth
            meta_file = os.path.join(task_dir, 'meta.json')
            with open(meta_file, 'r') as f:
                meta = json.load(f)
            task_id = meta['task_info']['instance_id']
            cve_id = meta['task_info']['cve_id']
            url = f"https://github.com/{meta['task_info']['repo']}/commit/{meta['task_info']['commit_hash']}"

            tgt_cwe_id = meta['task_info']['cwe_id'].split('-')[-1]
            tgt_cwe_paths = cwe_tree[tgt_cwe_id]['cwe_paths']

            # Get prediction
            result_file = os.path.join(task_dir, 'result.json')
            with open(result_file, 'r') as f:
                task_result = json.load(f)

            if task_result[0]['vulnerability_type'] == '':
                pred_cwe_paths = None
            else:
                pred_cwe_id = task_result[0]['vulnerability_type'].split('-')[-1]
                pred_cwe_paths = cwe_tree[pred_cwe_id]['cwe_paths']

            # Info sequence
            basic_info = f"[{task_id}, {cve_id}, {url}]"
            tgt_cwe_paths_info = '[' + ', '.join(['['+ ', '.join(path) + ']' for path in tgt_cwe_paths]) + ']'
            pred_cwe_paths_info = '[' + ', '.join(['['+ ', '.join(path) + ']' for path in pred_cwe_paths]) + ']' if pred_cwe_paths else 'None'
            summary_info += (f"{basic_info}"
                             f"\n{tgt_cwe_paths_info}"
                             f"\n{pred_cwe_paths_info}"
                             f"\n\n")

        summary_file = os.path.join(exp_dir, 'summary.txt')
        with open(summary_file, 'w') as f:
            f.write(summary_info)

    ## Check 4:
    if flag == 4:
        pass


if __name__ == '__main__':
    pass

    # check_all_exps(4)

    # file = "/root/projects/TreeVul/dataset/test_set.json"
    # with open(file, 'r') as f:
    #     dataset = json.load(f)
    #
    # commit2items: Dict[str, List] = defaultdict(list)
    # for item in dataset:
    #     commit2items[item["commit_id"]].append(item)
    #
    # filter_commit2items = {}
    # for commit, items in commit2items.items():
    #     add_flag = True
    #
    #     for item in items:
    #         if item["PL"] != "Python":
    #             add_flag = False
    #             break
    #
    #     if add_flag:
    #         filter_commit2items[commit] = items
    #
    # print(len(filter_commit2items))
    #
    # filter_commits = []
    # for commit, items in filter_commit2items.items():
    #     if len(items) == 1:
    #         filter_commits.append(commit)
    #
    # print(len(filter_commits))


    # local_repos_dir = "/root/projects/clone_projects"
    # tasks_map_fpath = "/root/projects/VDTest/output/TreeVul/TreeVul_valid_scsfCVE.json"
    # main_test_changed_lines_locations(local_repos_dir, tasks_map_fpath)

    # exps = "/root/projects/VDTest/output/agent/vul_2024-09-08T16:51:25_SAVE"
    # dirs = os.listdir(exps)
    # for dir in dirs:
    #     if not os.path.exists(path = os.path.join(exps, dir, "result.json")):
    #         print(dir.split("_")[0])

    # from utils import insert_key_value
    #
    #
    # v1_file = "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000_v1.json"
    # v2_file = "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000_v2.json"
    #
    # data = {}
    #
    # with open(v1_file, 'r') as f:
    #     v1_data = json.load(f)
    # for cve_item in v1_data:
    #     commit_hash = cve_item["commit_hash"]
    #     assert commit_hash not in data
    #     data[commit_hash] = cve_item
    #
    # with open(v2_file, 'r') as f:
    #     v2_data = json.load(f)
    # for cve_item in v2_data:
    #     commit_hash = cve_item["commit_hash"]
    #     assert commit_hash not in data
    #     data[commit_hash] = cve_item
    #
    # exp_root = "/root/projects/VDTest/output/agent/vul_2024-09-18T02:33:39"
    # dirs = os.listdir(exp_root)
    # for dir in dirs:
    #     if dir[0].isdigit():
    #         meta_fpath = os.path.join(exp_root, dir, "meta.json")
    #         with open(meta_fpath, 'r') as f:
    #             meta = json.load(f)
    #
    #         task_info = meta["task_info"]
    #         cwe_depth = data[task_info["commit_hash"]]["cwe_depth"]
    #         task_info = insert_key_value(task_info, "cwe_depth", cwe_depth, 2)
    #         meta["task_info"] = task_info
    #
    #         with open(meta_fpath, 'w') as f:
    #             json.dump(meta, f, indent=4)

    # treevul_cwe_path_file = "/root/projects/TreeVul/data/cwe_path.json"
    # with open(treevul_cwe_path_file, 'r') as f:
    #     treevul_cwe_paths = json.load(f)
    #
    # treevul_new_cwe_paths = {}
    # for full_cwe_id, cwe_path in treevul_cwe_paths.items():
    #     cwe_id = full_cwe_id.split("-")[-1]
    #     cwe_path = [full_cwe_id.split("-")[-1] for full_cwe_id in cwe_path]
    #     treevul_new_cwe_paths[cwe_id] = cwe_path
    #
    # cwe_tree_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    # with open(cwe_tree_file, 'r') as f:
    #     cwe_tree = json.load(f)
    # cwe_paths = {cwe_id: item["cwe_paths"] for cwe_id, item in cwe_tree.items()}
    #
    # diff_cwe_paths = []
    # filter_cwe_paths = {}
    # for cwe_id, cwe_path in treevul_new_cwe_paths.items():
    #     assert cwe_id in cwe_paths
    #     if cwe_path not in cwe_paths[cwe_id]:
    #         diff_cwe_paths.append(cwe_id)
    #     if len(cwe_paths[cwe_id]) > 1:
    #         filter_cwe_paths[cwe_id] = cwe_paths[cwe_id]
    #
    # print(json.dumps(diff_cwe_paths, indent=4))
    # print(json.dumps(filter_cwe_paths, indent=4))

