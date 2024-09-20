import os
import json
import re

from typing import *
from enum import Enum

from agent_app.CWE.cwe_util import get_cwe_depth
from agent_app.log import WIDTH


def tasks_evaluation_with_cwe_1003(
        exps_root: str,
        cwe_tree_fpath: str,
        depth_1_cwe_fpath: str,
        depth_2_cwe_fpath: str
):
    ## Task num
    task_num = 0
    task_with_depth_1_cwe_num = 0
    task_with_depth_2_cwe_num = 0

    ## Identification of commit type
    # Golden match
    commit_type_match_num = 0

    ## Identification of vulnerability type
    # Golden match
    vul_type_top_1_golden_match_num = 0
    vul_type_top_3_golden_match_num = 0
    # depth-1 match
    vul_type_top_1_depth_1_match_num = 0
    vul_type_top_3_depth_1_match_num = 0
    # depth-2 match
    vul_type_top_1_depth_2_match_num = 0
    vul_type_top_3_depth_2_match_num = 0

    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    with open(depth_1_cwe_fpath, 'r') as f:
        depth_1_cwes = json.load(f)

    with open(depth_2_cwe_fpath, 'r') as f:
        depth_2_cwes = json.load(f)

    exps = os.listdir(exps_root)
    exps.remove("expr_args.json")
    for exp in exps:
        meta_fpath = os.path.join(exps_root, exp, "meta.json")
        with open(meta_fpath, 'r') as f:
            meta = json.load(f)

        target_commit_type = meta["task_info"]["commit_type"]
        target_vul_type = meta["task_info"]["cwe_id"]
        target_cwe_id = target_vul_type.split("-")[-1]
        # assert len(cwe_tree[target_cwe_id]["cwe_paths"]) == 1
        # target_cwe_path = cwe_tree[target_cwe_id]["cwe_paths"][0]
        target_cwe_path = min(cwe_tree[target_cwe_id]["cwe_paths"], key=len)

        eval_result_fpath = os.path.join(exps_root, exp, "evaluation.json")
        final_hyp_fpath = os.path.join(exps_root, exp, "result.json")

        if os.path.exists(eval_result_fpath) and os.path.exists(final_hyp_fpath):
            with open(eval_result_fpath, 'r') as f:
                eval_result = json.load(f)

            with open(final_hyp_fpath, 'r') as f:
                final_hyps = json.load(f)

            ## (1) Task number
            task_num += 1

            target_cwe_id_depth_1 = None
            target_cwe_id_depth_2 = None
            is_task_with_depth_1_cwe = False
            is_task_with_depth_2_cwe = False

            if target_cwe_id in depth_1_cwes:
                is_task_with_depth_1_cwe = True

                target_cwe_id_depth_1 = target_cwe_id

                task_with_depth_1_cwe_num += 1
            elif target_cwe_id in depth_2_cwes:
                is_task_with_depth_2_cwe = True

                target_cwe_id_depth_1 = cwe_tree[target_cwe_id]["father"][0]
                target_cwe_id_depth_2 = target_cwe_id

                task_with_depth_2_cwe_num += 1
            else:
                raise RuntimeError

            final_result = eval_result["final_result"]

            ## (2) Identification of commit type
            # Golden match
            if final_result["commit_type_match_rank"] == 1:
                commit_type_match_num += 1

            ## (3) Identification of vulnerability type
            # Golden match
            if final_result["vul_type_match_rank"] is not None:
                if final_result["vul_type_match_rank"] == 1:
                    vul_type_top_1_golden_match_num += 1

                if final_result["vul_type_match_rank"] <= 3:
                    vul_type_top_3_golden_match_num += 1

            # depth-1 match
            if is_task_with_depth_1_cwe:
                assert target_cwe_id_depth_1 is not None
                for i, hyp in enumerate(final_hyps):
                    if hyp["commit_type"] == "vulnerability_patch":
                        cwe_id = hyp["vulnerability_type"].split("-")[-1]
                        if cwe_id in depth_1_cwes and cwe_id == target_cwe_id_depth_1:
                            if i + 1 == 1:
                                vul_type_top_1_depth_1_match_num += 1
                            if i + 1 <= 3:
                                vul_type_top_3_depth_1_match_num += 1
                            break

                        if cwe_id in depth_2_cwes and cwe_tree[cwe_id]["father"][0] == target_cwe_id_depth_1:
                            if i + 1 == 1:
                                vul_type_top_1_depth_1_match_num += 1
                            if i + 1 <= 3:
                                vul_type_top_3_depth_1_match_num += 1
                            break

            # depth-2 match
            if is_task_with_depth_2_cwe:
                assert target_cwe_id_depth_1 is not None and target_cwe_id_depth_2 is not None
                for i, hyp in enumerate(final_hyps):
                    if hyp["commit_type"] == "vulnerability_patch":
                        cwe_id = hyp["vulnerability_type"].split("-")[-1]
                        if cwe_id in depth_2_cwes and cwe_id == target_cwe_id_depth_2:
                            if i + 1 == 1:
                                vul_type_top_1_depth_2_match_num += 1
                            if i + 1 <= 3:
                                vul_type_top_3_depth_2_match_num += 1
                            break

                        if cwe_id in depth_2_cwes and cwe_tree[cwe_id]["father"][0] == target_cwe_id_depth_1:
                            if i + 1 == 1:
                                vul_type_top_1_depth_1_match_num += 1
                            if i + 1 <= 3:
                                vul_type_top_3_depth_1_match_num += 1
                            break

                        if cwe_id in depth_1_cwes and cwe_id == target_cwe_id_depth_1:
                            if i + 1 == 1:
                                vul_type_top_1_depth_1_match_num += 1
                            if i + 1 <= 3:
                                vul_type_top_3_depth_1_match_num += 1
                            break


    print(f"commit type match: {commit_type_match_num} / {task_num}")
    print(f"vul type top-1 match: {vul_type_top_1_golden_match_num} / {task_num}")
    print(f"vul type top-3 match: {vul_type_top_3_golden_match_num} / {task_num}")
    print(f"depth-1 vul type top-1 match: {vul_type_top_1_depth_1_match_num} / {task_with_depth_1_cwe_num}")
    print(f"depth-1 vul type top-3 match: {vul_type_top_3_depth_1_match_num} / {task_with_depth_1_cwe_num}")
    print(f"depth-2 vul type top-1 match: {vul_type_top_1_depth_2_match_num} / {task_with_depth_2_cwe_num}")
    print(f"depth-2 vul type top-3 match: {vul_type_top_3_depth_2_match_num} / {task_with_depth_2_cwe_num}")


def get_top_k_cwe_ids_from_hyps(hyps: List[Dict], k: int = 1) -> List[str]:
    """
    Extract the predicted CWE-IDs in the top-k (ordered by confidence score) hypothesis.
    NOTE: The output CWE-IDs are all numbers only, like '20' but not 'CWE-20'.
    """
    cwe_ids: List[str] = []
    for hyp in hyps[:k]:
        vul_type = hyp["vulnerability_type"]
        if vul_type != "":
            assert re.fullmatch(r"CWE-\d+", vul_type)
            cwe_id = vul_type.split("-")[-1]
            assert cwe_id not in cwe_ids
            cwe_ids.append(cwe_id)
    return cwe_ids


def get_depth_k_cwe_ids_from_cwes(cwe_tree: Dict, cwe_ids: List[str], k: int = 1) -> List[str]:
    """
    Given some CWE-IDs, extract the CWE-IDs of depth k according to the CWE paths in which they are located.
    NOTE: The input and output CWE-IDs are all numbers only, like '20' but not 'CWE-20'.
    """
    depth_k_cwe_ids: List[str] = []
    for cwe_id in cwe_ids:
        cwe_paths = cwe_tree[cwe_id]["cwe_paths"]
        for path in cwe_paths:
            assert len(path) > k
            depth_k_cwe_ids.append(path[k-1])
    return depth_k_cwe_ids


class TaskType(str, Enum):
    WITH_DEPTH_1_CWES = "WITH_DEPTH_1_CWES"
    WITH_DEPTH_2_CWES = "WITH_DEPTH_2_CWES"
    WITH_DEPTH_3_CWES = "WITH_DEPTH_3_CWES"
    OTHER = "OTHER"

    def compare_depth_1(self) -> bool:
        return self in [TaskType.WITH_DEPTH_1_CWES, TaskType.WITH_DEPTH_2_CWES, TaskType.WITH_DEPTH_3_CWES]

    def compare_depth_2(self) -> bool:
        return self in [TaskType.WITH_DEPTH_2_CWES, TaskType.WITH_DEPTH_3_CWES]

    def compare_depth_3(self) -> bool:
        return self in [TaskType.WITH_DEPTH_3_CWES]


def evaluate_vul_tasks_with_view_1000(exps_root: str):
    ## (1) Task number
    task_num = 0
    task_with_depth_1_cwe_num = 0  # For CVE items with only CWE-IDs in depth 1
    task_with_depth_2_cwe_num = 0  # For CVE items with only CWE-IDs in depth 2
    task_with_depth_3_cwe_num = 0  # For CVE items with only CWE-IDs in depth 3
    task_other_num = 0             # For CVE items with CWE-IDs in multiple depths

    ## (2) Identification of commit type
    # Golden match
    commit_type_match_num = 0
    commit_type_match_num_0 = 0  # For CVE items with CWE-IDs in multiple depths
    commit_type_match_num_1 = 0  # For CVE items with only CWE-IDs in depth 1
    commit_type_match_num_2 = 0  # For CVE items with only CWE-IDs in depth 2
    commit_type_match_num_3 = 0  # For CVE items with only CWE-IDs in depth 3

    ## (3) Identification of vulnerability type
    # Golden match
    vul_type_top_1_golden_match_num = 0
    vul_type_top_1_golden_match_num_1 = 0
    vul_type_top_1_golden_match_num_2 = 0
    vul_type_top_1_golden_match_num_3 = 0

    vul_type_top_3_golden_match_num = 0
    vul_type_top_3_golden_match_num_1 = 0
    vul_type_top_3_golden_match_num_2 = 0
    vul_type_top_3_golden_match_num_3 = 0

    # Depth-1 match
    vul_type_top_1_depth_1_match_num = 0
    vul_type_top_1_depth_1_match_num_1 = 0
    vul_type_top_1_depth_1_match_num_2 = 0
    vul_type_top_1_depth_1_match_num_3 = 0

    vul_type_top_3_depth_1_match_num = 0
    vul_type_top_3_depth_1_match_num_1 = 0
    vul_type_top_3_depth_1_match_num_2 = 0
    vul_type_top_3_depth_1_match_num_3 = 0

    # Depth-2 match
    vul_type_top_1_depth_2_match_num = 0
    vul_type_top_1_depth_2_match_num_1 = 0
    vul_type_top_1_depth_2_match_num_2 = 0
    vul_type_top_1_depth_2_match_num_3 = 0

    vul_type_top_3_depth_2_match_num = 0
    vul_type_top_3_depth_2_match_num_1 = 0
    vul_type_top_3_depth_2_match_num_2 = 0
    vul_type_top_3_depth_2_match_num_3 = 0

    # Depth-3 match
    vul_type_top_1_depth_3_match_num = 0
    vul_type_top_1_depth_3_match_num_1 = 0
    vul_type_top_1_depth_3_match_num_2 = 0
    vul_type_top_1_depth_3_match_num_3 = 0

    vul_type_top_3_depth_3_match_num = 0
    vul_type_top_3_depth_3_match_num_1 = 0
    vul_type_top_3_depth_3_match_num_2 = 0
    vul_type_top_3_depth_3_match_num_3 = 0


    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    exps = os.listdir(exps_root)
    exps.remove("expr_args.json")
    for exp in exps:

        if exp == "68-nvdvul_2024-09-18T10:37:59":
            continue

        meta_fpath = os.path.join(exps_root, exp, "meta.json")
        with open(meta_fpath, 'r') as f:
            meta = json.load(f)

        target_commit_type = meta["task_info"]["commit_type"]
        target_full_cwe_ids = meta["task_info"]["cwe_list"]
        target_cwe_ids = [full_cwe_id.split("-")[-1] for full_cwe_id in target_full_cwe_ids]
        target_cwe_depth = meta["task_info"]["cwe_depth"]

        final_hyp_fpath = os.path.join(exps_root, exp, "result.json")

        if os.path.exists(final_hyp_fpath):
            with open(final_hyp_fpath, 'r') as f:
                final_hyps = json.load(f)

            target_depth_1_cwe_ids = []
            target_depth_2_cwe_ids = []
            target_depth_3_cwe_ids = []

            ## (1) Task number
            task_num += 1

            if target_cwe_depth == 1:
                task_type = TaskType.WITH_DEPTH_1_CWES

                task_with_depth_1_cwe_num += 1

                target_depth_1_cwe_ids = target_cwe_ids

            elif target_cwe_depth == 2:
                task_type = TaskType.WITH_DEPTH_2_CWES

                task_with_depth_2_cwe_num += 1

                target_depth_2_cwe_ids = target_cwe_ids
                target_depth_1_cwe_ids = get_depth_k_cwe_ids_from_cwes(cwe_tree, target_depth_2_cwe_ids, k=1)

            elif target_cwe_depth == 3:
                task_type = TaskType.WITH_DEPTH_3_CWES

                task_with_depth_3_cwe_num += 1

                target_depth_3_cwe_ids = target_cwe_ids
                target_depth_2_cwe_ids = get_depth_k_cwe_ids_from_cwes(cwe_tree, target_depth_3_cwe_ids, k=2)
                target_depth_1_cwe_ids = get_depth_k_cwe_ids_from_cwes(cwe_tree, target_depth_3_cwe_ids, k=1)

            else:
                task_type = TaskType.OTHER

                task_other_num += 1


            ## (2) Identification of commit type
            # Golden match
            assert target_commit_type == 1
            if final_hyps[0]["commit_type"] == "vulnerability_patch":
                commit_type_match_num += 1

                if task_type == TaskType.WITH_DEPTH_1_CWES:
                    commit_type_match_num_1 += 1
                elif task_type == TaskType.WITH_DEPTH_2_CWES:
                    commit_type_match_num_2 += 1
                elif task_type == TaskType.WITH_DEPTH_3_CWES:
                    commit_type_match_num_3 += 1
                else:
                    commit_type_match_num_0 += 1


            ## (3) Identification of vulnerability type
            top_1_cwe_ids = get_top_k_cwe_ids_from_hyps(final_hyps, k=1)
            top_3_cwe_ids = get_top_k_cwe_ids_from_hyps(final_hyps, k=3)

            # Golden match
            for cwe_id in top_1_cwe_ids:
                if cwe_id in target_cwe_ids:
                    vul_type_top_1_golden_match_num += 1

                    if task_type == TaskType.WITH_DEPTH_1_CWES:
                        vul_type_top_1_golden_match_num_1 += 1
                    elif task_type == TaskType.WITH_DEPTH_2_CWES:
                        vul_type_top_1_golden_match_num_2 += 1
                    elif task_type == TaskType.WITH_DEPTH_3_CWES:
                        vul_type_top_1_golden_match_num_3 += 1

                    break

            for cwe_id in top_3_cwe_ids:
                if cwe_id in target_cwe_ids:
                    vul_type_top_3_golden_match_num += 1

                    if task_type == TaskType.WITH_DEPTH_1_CWES:
                        vul_type_top_3_golden_match_num_1 += 1
                    elif task_type == TaskType.WITH_DEPTH_2_CWES:
                        vul_type_top_3_golden_match_num_2 += 1
                    elif task_type == TaskType.WITH_DEPTH_3_CWES:
                        vul_type_top_3_golden_match_num_3 += 1

                    break

            # Depth-1 match
            if task_type.compare_depth_1():
                stop_match = False
                for cwe_id in top_1_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 1 and path[0] in target_depth_1_cwe_ids:
                            vul_type_top_1_depth_1_match_num += 1

                            if task_type == TaskType.WITH_DEPTH_1_CWES:
                                vul_type_top_1_depth_1_match_num_1 += 1
                            elif task_type == TaskType.WITH_DEPTH_2_CWES:
                                vul_type_top_1_depth_1_match_num_2 += 1
                            elif task_type == TaskType.WITH_DEPTH_3_CWES:
                                vul_type_top_1_depth_1_match_num_3 += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

                stop_match = False
                for cwe_id in top_3_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 1 and path[0] in target_depth_1_cwe_ids:
                            vul_type_top_3_depth_1_match_num += 1

                            if task_type == TaskType.WITH_DEPTH_1_CWES:
                                vul_type_top_3_depth_1_match_num_1 += 1
                            elif task_type == TaskType.WITH_DEPTH_2_CWES:
                                vul_type_top_3_depth_1_match_num_2 += 1
                            elif task_type == TaskType.WITH_DEPTH_3_CWES:
                                vul_type_top_3_depth_1_match_num_3 += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

            # Depth-2 match
            if task_type.compare_depth_2():
                stop_match = False
                for cwe_id in top_1_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 2 and path[1] in target_depth_2_cwe_ids:
                            vul_type_top_1_depth_2_match_num += 1

                            if task_type == TaskType.WITH_DEPTH_1_CWES:
                                vul_type_top_1_depth_2_match_num_1 += 1
                            elif task_type == TaskType.WITH_DEPTH_2_CWES:
                                vul_type_top_1_depth_2_match_num_2 += 1
                            elif task_type == TaskType.WITH_DEPTH_3_CWES:
                                vul_type_top_1_depth_2_match_num_3 += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

                stop_match = False
                for cwe_id in top_3_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 2 and path[1] in target_depth_2_cwe_ids:
                            vul_type_top_3_depth_2_match_num += 1

                            if task_type == TaskType.WITH_DEPTH_1_CWES:
                                vul_type_top_3_depth_2_match_num_1 += 1
                            elif task_type == TaskType.WITH_DEPTH_2_CWES:
                                vul_type_top_3_depth_2_match_num_2 += 1
                            elif task_type == TaskType.WITH_DEPTH_3_CWES:
                                vul_type_top_3_depth_2_match_num_3 += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

            # Depth-3 match
            if task_type.compare_depth_3():
                stop_match = False
                for cwe_id in top_1_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 3 and path[2] in target_depth_3_cwe_ids:
                            vul_type_top_1_depth_3_match_num += 1

                            if task_type == TaskType.WITH_DEPTH_1_CWES:
                                vul_type_top_1_depth_3_match_num_1 += 1
                            elif task_type == TaskType.WITH_DEPTH_2_CWES:
                                vul_type_top_1_depth_3_match_num_2 += 1
                            elif task_type == TaskType.WITH_DEPTH_3_CWES:
                                vul_type_top_1_depth_3_match_num_3 += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

                stop_match = False
                for cwe_id in top_3_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 3 and path[2] in target_depth_3_cwe_ids:
                            vul_type_top_3_depth_3_match_num += 1

                            if task_type == TaskType.WITH_DEPTH_1_CWES:
                                vul_type_top_3_depth_3_match_num_1 += 1
                            elif task_type == TaskType.WITH_DEPTH_2_CWES:
                                vul_type_top_3_depth_3_match_num_2 += 1
                            elif task_type == TaskType.WITH_DEPTH_3_CWES:
                                vul_type_top_3_depth_3_match_num_3 += 1

                            stop_match = True
                            break

                    if stop_match:
                        break


    print(f"Task total number: {task_num}")
    print(f"Task with depth-1 CWE-ID number: {task_with_depth_1_cwe_num}")
    print(f"Task with depth-2 CWE-ID number: {task_with_depth_2_cwe_num}")
    print(f"Task with depth-3 CWE-ID number: {task_with_depth_3_cwe_num}")
    print(f"Task other number: {task_other_num}")

    print("\n" + "=" * 100 + '\n')

    print(f"commit type match: {commit_type_match_num} / {task_num}")
    print(f"commit type match v0: {commit_type_match_num_0}")
    print(f"commit type match v1: {commit_type_match_num_1}")
    print(f"commit type match v2: {commit_type_match_num_2}")
    print(f"commit type match v3: {commit_type_match_num_3}")

    print("\n" + "=" * 100 + '\n')

    print(f"vul type top-1 match: {vul_type_top_1_golden_match_num}")
    print(f"vul type top-1 match v1: {vul_type_top_1_golden_match_num_1}")
    print(f"vul type top-1 match v2: {vul_type_top_1_golden_match_num_2}")
    print(f"vul type top-1 match v3: {vul_type_top_1_golden_match_num_3}")

    print("\n" + "-" * 100 + '\n')

    print(f"vul type top-3 match: {vul_type_top_3_golden_match_num}")
    print(f"vul type top-3 match v1: {vul_type_top_3_golden_match_num_1}")
    print(f"vul type top-3 match v2: {vul_type_top_3_golden_match_num_2}")
    print(f"vul type top-3 match v3: {vul_type_top_3_golden_match_num_3}")

    print("\n" + "=" * 100 + '\n')

    print(f"depth-1 vul type top-1 match: {vul_type_top_1_depth_1_match_num}")
    print(f"depth-1 vul type top-1 match v1: {vul_type_top_1_depth_1_match_num_1}")
    print(f"depth-1 vul type top-1 match v2: {vul_type_top_1_depth_1_match_num_2}")
    print(f"depth-1 vul type top-1 match v3: {vul_type_top_1_depth_1_match_num_3}")

    print("\n" + "-" * 100 + '\n')

    print(f"depth-1 vul type top-3 match: {vul_type_top_3_depth_1_match_num}")
    print(f"depth-1 vul type top-3 match v1: {vul_type_top_3_depth_1_match_num_1}")
    print(f"depth-1 vul type top-3 match v2: {vul_type_top_3_depth_1_match_num_2}")
    print(f"depth-1 vul type top-3 match v3: {vul_type_top_3_depth_1_match_num_3}")

    print("\n" + "=" * 100 + '\n')

    print(f"depth-2 vul type top-1 match: {vul_type_top_1_depth_2_match_num}")
    print(f"depth-2 vul type top-1 match v1: {vul_type_top_1_depth_2_match_num_1}")
    print(f"depth-2 vul type top-1 match v2: {vul_type_top_1_depth_2_match_num_2}")
    print(f"depth-2 vul type top-1 match v3: {vul_type_top_1_depth_2_match_num_3}")

    print("\n" + "-" * 100 + '\n')

    print(f"depth-2 vul type top-3 match: {vul_type_top_3_depth_2_match_num}")
    print(f"depth-2 vul type top-3 match v1: {vul_type_top_3_depth_2_match_num_1}")
    print(f"depth-2 vul type top-3 match v2: {vul_type_top_3_depth_2_match_num_2}")
    print(f"depth-2 vul type top-3 match v3: {vul_type_top_3_depth_2_match_num_3}")

    print("\n" + "=" * 100 + '\n')

    print(f"depth-3 vul type top-1 match: {vul_type_top_1_depth_3_match_num}")
    print(f"depth-3 vul type top-1 match v1: {vul_type_top_1_depth_3_match_num_1}")
    print(f"depth-3 vul type top-1 match v2: {vul_type_top_1_depth_3_match_num_2}")
    print(f"depth-3 vul type top-1 match v3: {vul_type_top_1_depth_3_match_num_3}")

    print("\n" + "-" * 100 + '\n')

    print(f"depth-3 vul type top-3 match: {vul_type_top_3_depth_3_match_num}")
    print(f"depth-3 vul type top-3 match v1: {vul_type_top_3_depth_3_match_num_1}")
    print(f"depth-3 vul type top-3 match v2: {vul_type_top_3_depth_3_match_num_2}")
    print(f"depth-3 vul type top-3 match v3: {vul_type_top_3_depth_3_match_num_3}")


if __name__ == '__main__':
    exps_root = "/root/projects/VDTest/output/agent/vul_2024-09-18T02:33:39"

    evaluate_vul_tasks_with_view_1000(exps_root)

