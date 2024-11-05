import os
import json
import re
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from typing import *
from enum import Enum
from dataclasses import dataclass, field
from sklearn.metrics import f1_score, matthews_corrcoef

from agent_app.inference import FinalHypothesis, vote_on_result
from agent_app.CWE.cwe_util import get_cwe_depth
from utils import insert_key_value


"""F1 CALCULATION"""


@dataclass(frozen=True)
class MultiCategoryMetrics:
    macro_f1: float
    micro_f1: float
    weighted_f1: float
    mcc: float


def is_square_symmetric_matrix(matrix: pd.DataFrame) -> bool:
    if matrix.shape[0] != matrix.shape[1]:
        return False

    if not (matrix.index.equals(matrix.columns)):
        return False

    return True


def add_new_row_and_column_to_matrix(matrix: pd.DataFrame, cwe_id: str):
    if matrix.shape[0] == 0:
        matrix.loc[cwe_id, cwe_id] = 0
    else:
        # Add new row
        assert cwe_id not in matrix.index
        new_row = [0] * len(matrix.columns)
        matrix.loc[cwe_id] = new_row

        # Add new column
        assert cwe_id not in matrix.columns
        new_col = [0] * len(matrix.index)
        matrix[cwe_id] = new_col


def calculate_multi_category_f1_and_mcc(matrix: pd.DataFrame) -> MultiCategoryMetrics:
    assert is_square_symmetric_matrix(matrix)

    tgts = []
    preds = []

    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            count = matrix.iloc[i, j]
            assert count.is_integer()
            tgts.extend([i] * int(count))
            preds.extend([j] * int(count))

    ## NOTE:
    # (1) Classes with no samples in the dataset are not considered while calculating the F1, i.e. Recall = 0 / 0.
    # (2) While TP + FP = 0, we set Precision = 0.
    nonempty_tgts = list(set(tgts))
    nonempty_tgts.sort()

    macro_f1 = f1_score(tgts, preds, average='macro', labels=nonempty_tgts)
    micro_f1 = f1_score(tgts, preds, average='micro', labels=nonempty_tgts)
    weighted_f1 = f1_score(tgts, preds, average='weighted', labels=nonempty_tgts)
    mcc = matthews_corrcoef(tgts, preds)

    metrics = MultiCategoryMetrics(macro_f1, micro_f1, weighted_f1, mcc)

    return metrics


def plt_and_save_heatmap(matrix: pd.DataFrame, title: str, save_fpath: str, show: bool = False) -> None:
    matrix = matrix.astype(int)
    rows, cols = matrix.shape
    plt.figure(figsize=(cols * 0.6, rows * 0.4))
    sns.heatmap(matrix, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title(title)
    plt.xlabel("Predicted labels")
    plt.ylabel("Target labels")
    plt.yticks(rotation=0)

    plt.savefig(save_fpath, bbox_inches='tight')
    if show:
        plt.show()


"""EVALUATION FOR METRICS UNDER VIEW-1003"""


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


"""EVALUATION FOR METRICS UNDER VIEW-1000"""


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
    TARGET_DEPTH_1_CWES = "TARGET_DEPTH_1_CWES"
    TARGET_DEPTH_2_CWES = "TARGET_DEPTH_2_CWES"
    TARGET_DEPTH_3_CWES = "TARGET_DEPTH_3_CWES"

    def compare_depth_1(self) -> bool:
        return self in [TaskType.TARGET_DEPTH_1_CWES, TaskType.TARGET_DEPTH_2_CWES, TaskType.TARGET_DEPTH_3_CWES]

    def compare_depth_2(self) -> bool:
        return self in [TaskType.TARGET_DEPTH_2_CWES, TaskType.TARGET_DEPTH_3_CWES]

    def compare_depth_3(self) -> bool:
        return self in [TaskType.TARGET_DEPTH_3_CWES]


@dataclass
class TaskTop1VulTypeResult:
    # [(task id, predicted CWE-ID, target CWE-ID)]
    tgt_1_pred_1_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-1; Predicted: depth-1
    tgt_1_pred_2_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-1; Predicted: depth-2
    tgt_1_pred_3_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-1; Predicted: depth-3

    tgt_2_pred_1_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-2; Predicted: depth-1
    tgt_2_pred_2_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-2; Predicted: depth-2
    tgt_2_pred_3_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-2; Predicted: depth-3

    tgt_3_pred_1_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-3; Predicted: depth-1
    tgt_3_pred_2_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-3; Predicted: depth-2
    tgt_3_pred_3_result: List[Tuple[str, str, str]] = field(default_factory=list)  # Target: depth-3; Predicted: depth-3


    @staticmethod
    def _depth_check(*depths):
        for depth in depths:
            assert depth in [1, 2, 3]


    def add_to_tgt_i_pred_j_result(self, new_result: Tuple[str, str, str], tgt_depth: int, pred_depth: int) -> None:
        self._depth_check(tgt_depth, pred_depth)

        tgt_i_pred_j_result = getattr(self, f"tgt_{tgt_depth}_pred_{pred_depth}_result")
        assert new_result not in tgt_i_pred_j_result
        tgt_i_pred_j_result.append(new_result)


    def get_tgt_i_pred_j_result(self, tgt_depth: int, pred_depth: int) -> List[Tuple[str, str, str]] | None:
        self._depth_check(tgt_depth, pred_depth)

        return getattr(self, f"tgt_{tgt_depth}_pred_{pred_depth}_result", None)


def evaluate_vul_tasks_final_hyps_with_view_1000(exps_root: str, init: bool = False):
    ## (1) Task number
    task_tgt_1_num = 0  # For CVE items with target CWE-ID on depth-1
    task_tgt_2_num = 0  # For CVE items with target CWE-ID on depth-2
    task_tgt_3_num = 0  # For CVE items with target CWE-ID on depth-3

    ## (2) Identification of commit type
    commit_type_match_tgt_1_num = 0  # For CVE items with target CWE-ID on depth-1
    commit_type_match_tgt_2_num = 0  # For CVE items with target CWE-ID on depth-2
    commit_type_match_tgt_3_num = 0  # For CVE items with target CWE-ID on depth-3

    ## (3) Identification of vulnerability type
    ## Match on depth-1
    # Top-1
    vul_type_top_1_depth_1_match_tgt_1_num = 0         # Target: depth-1
    vul_type_top_1_depth_1_match_tgt_1_pred_1_num = 0  # Target: depth-1; Predicted: depth-1
    vul_type_top_1_depth_1_match_tgt_1_pred_2_num = 0  # Target: depth-1; Predicted: depth-2
    vul_type_top_1_depth_1_match_tgt_1_pred_3_num = 0  # Target: depth-1; Predicted: depth-3

    vul_type_top_1_depth_1_match_tgt_2_num = 0         # Target: depth-2
    vul_type_top_1_depth_1_match_tgt_2_pred_1_num = 0  # Target: depth-2; Predicted: depth-1
    vul_type_top_1_depth_1_match_tgt_2_pred_2_num = 0  # Target: depth-2; Predicted: depth-2
    vul_type_top_1_depth_1_match_tgt_2_pred_3_num = 0  # Target: depth-2; Predicted: depth-3

    vul_type_top_1_depth_1_match_tgt_3_num = 0         # Target: depth-3
    vul_type_top_1_depth_1_match_tgt_3_pred_1_num = 0  # Target: depth-3; Predicted: depth-1
    vul_type_top_1_depth_1_match_tgt_3_pred_2_num = 0  # Target: depth-3; Predicted: depth-2
    vul_type_top_1_depth_1_match_tgt_3_pred_3_num = 0  # Target: depth-3; Predicted: depth-3

    # Top 3
    vul_type_top_3_depth_1_match_tgt_1_num = 0  # Target: depth-1
    vul_type_top_3_depth_1_match_tgt_2_num = 0  # Target: depth-2
    vul_type_top_3_depth_1_match_tgt_3_num = 0  # Target: depth-3

    ## Match on depth-2
    # Top-1
    vul_type_top_1_depth_2_match_tgt_2_num = 0         # Target: depth-2
    vul_type_top_1_depth_2_match_tgt_2_pred_1_num = 0  # Target: depth-2; Predicted: depth-1 (can't compare)
    vul_type_top_1_depth_2_match_tgt_2_pred_2_num = 0  # Target: depth-2; Predicted: depth-2
    vul_type_top_1_depth_2_match_tgt_2_pred_3_num = 0  # Target: depth-2; Predicted: depth-3

    vul_type_top_1_depth_2_match_tgt_3_num = 0         # Target: depth-3
    vul_type_top_1_depth_2_match_tgt_3_pred_1_num = 0  # Target: depth-3; Predicted: depth-1 (can't compare)
    vul_type_top_1_depth_2_match_tgt_3_pred_2_num = 0  # Target: depth-3; Predicted: depth-2
    vul_type_top_1_depth_2_match_tgt_3_pred_3_num = 0  # Target: depth-3; Predicted: depth-3

    # Top-3
    vul_type_top_3_depth_2_match_tgt_2_num = 0  # Target: depth-2
    vul_type_top_3_depth_2_match_tgt_3_num = 0  # Target: depth-3

    ## Match on depth-3
    # Top-1
    vul_type_top_1_depth_3_match_tgt_3_num = 0         # Target: depth-3
    vul_type_top_1_depth_3_match_tgt_3_pred_1_num = 0  # Target: depth-3; Predicted: depth-1 (can't compare)
    vul_type_top_1_depth_3_match_tgt_3_pred_2_num = 0  # Target: depth-3; Predicted: depth-2 (can't compare)
    vul_type_top_1_depth_3_match_tgt_3_pred_3_num = 0  # Target: depth-3; Predicted: depth-3

    # Top-3
    vul_type_top_3_depth_3_match_tgt_3_num = 0

    ## (4) Metrics on vulnerability type
    task_top_1_vul_type_result = TaskTop1VulTypeResult()


    ############## Preparation ##############
    cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    exps = os.listdir(exps_root)
    for exp in exps:
        if not exp[0].isdigit():
            continue

        task_id = exp.split("_")[0]

        ############## Get ground truth ##############
        meta_fpath = os.path.join(exps_root, exp, "meta.json")
        with open(meta_fpath, 'r') as f:
            meta = json.load(f)

        target_commit_type = meta["task_info"]["commit_type"]
        target_full_cwe_id = meta["task_info"]["cwe_id"]
        target_cwe_id = target_full_cwe_id.split("-")[-1]
        target_cwe_depth = meta["task_info"]["cwe_depth"]

        ############## Get the final predicted results ##############
        final_hyp_fpath = os.path.join(exps_root, exp, "result.json")

        if os.path.exists(final_hyp_fpath):
            if init:
                all_init_unver_hyp_dicts: List[Dict] = []

                proc_1_init_hyp_fpath = os.path.join(exps_root, exp, "process_1", "hypothesis", "init.json")
                with open(proc_1_init_hyp_fpath, 'r') as f:
                    init_hyps = json.load(f)
                    all_init_unver_hyp_dicts.extend(init_hyps["unverified"])

                proc_2_init_hyp_fpath = os.path.join(exps_root, exp, "process_2", "hypothesis", "init.json")
                with open(proc_2_init_hyp_fpath, 'r') as f:
                    init_hyps = json.load(f)
                    all_init_unver_hyp_dicts.extend(init_hyps["unverified"])

                proc_3_init_hyp_fpath = os.path.join(exps_root, exp, "process_3", "hypothesis", "init.json")
                with open(proc_3_init_hyp_fpath, 'r') as f:
                    init_hyps = json.load(f)
                    all_init_unver_hyp_dicts.extend(init_hyps["unverified"])

                final_hyps = vote_on_result(all_init_unver_hyp_dicts, 3)
                final_hyps = [hyp.to_dict() for hyp in final_hyps]

            else:
                with open(final_hyp_fpath, 'r') as f:
                    final_hyps = json.load(f)

            target_depth_1_cwe_ids: List[str] = []
            target_depth_2_cwe_ids: List[str] = []
            target_depth_3_cwe_ids: List[str] = []

            ## (1) Count task number
            if target_cwe_depth == 1:
                task_type = TaskType.TARGET_DEPTH_1_CWES

                task_tgt_1_num += 1

                target_depth_1_cwe_ids = [target_cwe_id]

            elif target_cwe_depth == 2:
                task_type = TaskType.TARGET_DEPTH_2_CWES

                task_tgt_2_num += 1

                target_depth_2_cwe_ids = [target_cwe_id]
                target_depth_1_cwe_ids = get_depth_k_cwe_ids_from_cwes(cwe_tree, target_depth_2_cwe_ids, k=1)

            else:
                assert target_cwe_depth == 3
                task_type = TaskType.TARGET_DEPTH_3_CWES

                task_tgt_3_num += 1

                target_depth_3_cwe_ids = [target_cwe_id]
                target_depth_2_cwe_ids = get_depth_k_cwe_ids_from_cwes(cwe_tree, target_depth_3_cwe_ids, k=2)
                target_depth_1_cwe_ids = get_depth_k_cwe_ids_from_cwes(cwe_tree, target_depth_3_cwe_ids, k=1)


            ## (2) Identification of commit type
            # Golden match
            assert target_commit_type == 1
            if final_hyps[0]["commit_type"] == "vulnerability_patch":
                if task_type == TaskType.TARGET_DEPTH_1_CWES:
                    commit_type_match_tgt_1_num += 1
                elif task_type == TaskType.TARGET_DEPTH_2_CWES:
                    commit_type_match_tgt_2_num += 1
                else:
                    assert task_type == TaskType.TARGET_DEPTH_3_CWES
                    commit_type_match_tgt_3_num += 1


            ## (3) Identification of vulnerability type
            top_1_cwe_ids = get_top_k_cwe_ids_from_hyps(final_hyps, k=1)
            if init:
                top_1_cwe_ids = [cwe_id for cwe_id in top_1_cwe_ids if cwe_id in cwe_tree]

            top_3_cwe_ids = get_top_k_cwe_ids_from_hyps(final_hyps, k=3)
            if init:
                top_3_cwe_ids = [cwe_id for cwe_id in top_3_cwe_ids if cwe_id in cwe_tree]

            # Depth-1 match
            if task_type.compare_depth_1():
                stop_match = False
                for cwe_id in top_1_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 1 and path[0] in target_depth_1_cwe_ids:

                            if task_type == TaskType.TARGET_DEPTH_1_CWES:
                                vul_type_top_1_depth_1_match_tgt_1_num += 1
                            elif task_type == TaskType.TARGET_DEPTH_2_CWES:
                                vul_type_top_1_depth_1_match_tgt_2_num += 1
                            else:
                                assert task_type == TaskType.TARGET_DEPTH_3_CWES
                                vul_type_top_1_depth_1_match_tgt_3_num += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

                stop_match = False
                for cwe_id in top_3_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 1 and path[0] in target_depth_1_cwe_ids:

                            if task_type == TaskType.TARGET_DEPTH_1_CWES:
                                vul_type_top_3_depth_1_match_tgt_1_num += 1
                            elif task_type == TaskType.TARGET_DEPTH_2_CWES:
                                vul_type_top_3_depth_1_match_tgt_2_num += 1
                            else:
                                assert task_type == TaskType.TARGET_DEPTH_3_CWES
                                vul_type_top_3_depth_1_match_tgt_3_num += 1

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

                            if task_type == TaskType.TARGET_DEPTH_2_CWES:
                                vul_type_top_1_depth_2_match_tgt_2_num += 1
                            else:
                                assert task_type == TaskType.TARGET_DEPTH_3_CWES
                                vul_type_top_1_depth_2_match_tgt_3_num += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

                stop_match = False
                for cwe_id in top_3_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 2 and path[1] in target_depth_2_cwe_ids:

                            if task_type == TaskType.TARGET_DEPTH_2_CWES:
                                vul_type_top_3_depth_2_match_tgt_2_num += 1
                            else:
                                assert task_type == TaskType.TARGET_DEPTH_3_CWES
                                vul_type_top_3_depth_2_match_tgt_3_num += 1

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

                            assert task_type == TaskType.TARGET_DEPTH_3_CWES
                            vul_type_top_1_depth_3_match_tgt_3_num += 1

                            stop_match = True
                            break

                    if stop_match:
                        break

                stop_match = False
                for cwe_id in top_3_cwe_ids:
                    for path in cwe_tree[cwe_id]["cwe_paths"]:
                        if len(path) >= 3 and path[2] in target_depth_3_cwe_ids:

                            assert task_type == TaskType.TARGET_DEPTH_3_CWES
                            vul_type_top_3_depth_3_match_tgt_3_num += 1

                            stop_match = True
                            break

                    if stop_match:
                        break


            ## (4) Metrics
            if not init and final_hyps[0]["commit_type"] == "vulnerability_patch":
                ## Collect tasks by predicted CWE-ID
                top_1_cwe_ids = get_top_k_cwe_ids_from_hyps(final_hyps, k=1)
                assert len(top_1_cwe_ids) == 1

                top_1_cwe_id = top_1_cwe_ids[0]
                top_1_cwe_depth = get_cwe_depth(top_1_cwe_id)
                assert target_cwe_depth in [1, 2, 3] and top_1_cwe_depth in [1, 2, 3]

                task_top_1_vul_type_result.add_to_tgt_i_pred_j_result(
                    new_result=(task_id, top_1_cwe_id, target_cwe_id),
                    tgt_depth=target_cwe_depth,
                    pred_depth=top_1_cwe_depth
                )


    def target_i_pred_j_tasks_compare_on_depth_k(matrix: pd.DataFrame, tgt_depth: int, pred_depth: int, cmp_depth: int):
        """
        For task with target depth i and predicted depth j, compare it on depth k.
        NOTE 1: Compare depth k <= Target depth i.
        NOTE 2: Compare depth i <= Predicted depth j.
        """
        assert tgt_depth in [1, 2, 3] and pred_depth in [1, 2, 3] and cmp_depth in [1, 2, 3]
        assert tgt_depth >= cmp_depth and pred_depth >= cmp_depth

        tgt_i_pred_j_result = task_top_1_vul_type_result.get_tgt_i_pred_j_result(tgt_depth, pred_depth)

        for task_id, pred_j_cwe_id, tgt_i_cwe_id in tgt_i_pred_j_result:
            # (1) Get the parent CWE-IDs of the predicted CWE-ID
            # - Predicted CWE-ID: depth j
            # - Parent CWE-ID: depth k (k <= j)
            pred_k_cwe_ids: List[str] = []
            for path in cwe_tree[pred_j_cwe_id]["cwe_paths"]:
                assert len(path) >= pred_depth
                pred_k_cwe_id = path[cmp_depth - 1]
                if pred_k_cwe_id not in pred_k_cwe_ids:
                    pred_k_cwe_ids.append(pred_k_cwe_id)

            # (2) Get the parent CWE-ID of the target CWE-ID
            # - Target CWE-ID: depth i
            # - Parent CWE-ID: depth k (k <= i)
            # TODO: When multiple CWE paths are encountered while getting the parent CWE-ID of the target CWE-ID,
            #       choose the shortest path in the CWE tree in the default order.
            # Method 1:
            min_path = min(cwe_tree[tgt_i_cwe_id]["cwe_paths"], key=len)
            tgt_cwe_id = min_path[cmp_depth - 1]
            # Method 2:
            # tgt_k_cwe_ids: List[str] = []
            # for path in cwe_tree[tgt_i_cwe_id]["cwe_paths"]:
            #     assert len(path) >= tgt_depth
            #     tgt_k_cwe_id = path[cmp_depth - 1]
            #     if tgt_k_cwe_id not in tgt_k_cwe_ids:
            #         tgt_k_cwe_ids.append(tgt_k_cwe_id)

            # (3) Determine whether the pred_cwe_id is the same as the tgt_cwe_id
            # Method 1:
            if tgt_cwe_id in pred_k_cwe_ids:
                pred_cwe_id = tgt_cwe_id
            else:
                pred_cwe_id = pred_k_cwe_ids[0]
            # Method 2:
            # tgt_cwe_id = None
            # pred_cwe_id = None
            # for tgt_k_cwe_id in tgt_k_cwe_ids:
            #     if tgt_k_cwe_id in pred_k_cwe_ids:
            #         tgt_cwe_id = tgt_k_cwe_id
            #         pred_cwe_id = tgt_cwe_id
            #         break
            # if tgt_cwe_id is None:
            #     tgt_cwe_id = min(cwe_tree[tgt_i_cwe_id]["cwe_paths"], key=len)[cmp_depth - 1]
            # if pred_cwe_id is None:
            #     pred_cwe_id = pred_k_cwe_ids[0]

            # (4) Complement the matrix with the missing tgt_cwe_id or pred_cwe_id.
            if tgt_cwe_id not in matrix.index:
                add_new_row_and_column_to_matrix(matrix, tgt_cwe_id)
            if pred_cwe_id not in matrix.columns:
                add_new_row_and_column_to_matrix(matrix, pred_cwe_id)

            # (5) Update matrix
            matrix.at[tgt_cwe_id, pred_cwe_id] += 1


    def build_target_i_compare_k_tgt2pred_matrix(tgt_depth: int, cmp_depth: int) -> pd.DataFrame:
        assert tgt_depth in [1, 2, 3] and cmp_depth in [1, 2, 3]
        assert tgt_depth >= cmp_depth

        tgt2pred_matrix = pd.DataFrame()

        # When comparing on depth k, we can only use tasks with predicted on depth j (k <= j <= 3)
        pred_depths = list(range(cmp_depth, 4))
        for pred_depth in pred_depths:
            target_i_pred_j_tasks_compare_on_depth_k(tgt2pred_matrix, tgt_depth, pred_depth, cmp_depth)
        
        return tgt2pred_matrix


    # -------------------- Top-1 Vulnerability Type Metrics -------------------- #
    if not init:
        ## (1) Evaluate on tasks with target of depth-1 CWE-ID
        # 1.1 Compare on depth-1
        tgt_1_cmp_1_tgt2pred_matrix = build_target_i_compare_k_tgt2pred_matrix(tgt_depth=1, cmp_depth=1)

        tgt_1_cmp_1_metrics = calculate_multi_category_f1_and_mcc(tgt_1_cmp_1_tgt2pred_matrix)
        matrix_title = "Target-1 Compare-1 Matrix"
        save_fpath = os.path.join(exps_root, matrix_title.replace(" ", "_") + ".pdf")
        plt_and_save_heatmap(tgt_1_cmp_1_tgt2pred_matrix, matrix_title, save_fpath)

        ## (2) Evaluate on tasks with target of depth-2 CWE-ID
        # 2.1 Compare on depth-1
        tgt_2_cmp_1_tgt2pred_matrix = build_target_i_compare_k_tgt2pred_matrix(tgt_depth=2, cmp_depth=1)

        tgt_2_cmp_1_metrics = calculate_multi_category_f1_and_mcc(tgt_2_cmp_1_tgt2pred_matrix)
        matrix_title = "Target-2 Compare-1 Matrix"
        save_fpath = os.path.join(exps_root, matrix_title.replace(" ", "_") + ".pdf")
        plt_and_save_heatmap(tgt_2_cmp_1_tgt2pred_matrix, matrix_title, save_fpath)

        # 2.2 Compare on depth-2
        tgt_2_cmp_2_tgt2pred_matrix = build_target_i_compare_k_tgt2pred_matrix(tgt_depth=2, cmp_depth=2)

        tgt_2_cmp_2_metrics = calculate_multi_category_f1_and_mcc(tgt_2_cmp_2_tgt2pred_matrix)
        matrix_title = "Target-2 Compare-2 Matrix"
        save_fpath = os.path.join(exps_root, matrix_title.replace(" ", "_") + ".pdf")
        plt_and_save_heatmap(tgt_2_cmp_2_tgt2pred_matrix, matrix_title, save_fpath)

        ## (3) Evaluate on tasks with target of depth-3 CWE-ID
        # 3.1 Compare on depth-1
        tgt_3_cmp_1_tgt2pred_matrix = build_target_i_compare_k_tgt2pred_matrix(tgt_depth=3, cmp_depth=1)

        tgt_3_cmp_1_metrics = calculate_multi_category_f1_and_mcc(tgt_3_cmp_1_tgt2pred_matrix)
        matrix_title = "Target-3 Compare-1 Matrix"
        save_fpath = os.path.join(exps_root, matrix_title.replace(" ", "_") + ".pdf")
        plt_and_save_heatmap(tgt_3_cmp_1_tgt2pred_matrix, matrix_title, save_fpath)

        # 3.2 Compare on depth-2
        tgt_3_cmp_2_tgt2pred_matrix = build_target_i_compare_k_tgt2pred_matrix(tgt_depth=3, cmp_depth=2)

        tgt_3_cmp_2_metrics = calculate_multi_category_f1_and_mcc(tgt_3_cmp_2_tgt2pred_matrix)
        matrix_title = "Target-3 Compare-2 Matrix"
        save_fpath = os.path.join(exps_root, matrix_title.replace(" ", "_") + ".pdf")
        plt_and_save_heatmap(tgt_3_cmp_2_tgt2pred_matrix, matrix_title, save_fpath)

        # 3.3 Compare on depth-3
        tgt_3_cmp_3_tgt2pred_matrix = build_target_i_compare_k_tgt2pred_matrix(tgt_depth=3, cmp_depth=3)

        tgt_3_cmp_3_metrics = calculate_multi_category_f1_and_mcc(tgt_3_cmp_3_tgt2pred_matrix)
        matrix_title = "Target-3 Compare-3 Matrix"
        save_fpath = os.path.join(exps_root, matrix_title.replace(" ", "_") + ".pdf")
        plt_and_save_heatmap(tgt_3_cmp_3_tgt2pred_matrix, matrix_title, save_fpath)

        ############## Print ##############

        print("Target-1"
              f"\nDepth-1 - macro-F1: {tgt_1_cmp_1_metrics.macro_f1:.2f}, weighted-F1: {tgt_1_cmp_1_metrics.weighted_f1:.2f}, mcc: {tgt_1_cmp_1_metrics.mcc:.2f}")

        print("\n\nTarget-2"
              f"\nDepth-1 - macro-F1: {tgt_2_cmp_1_metrics.macro_f1:.2f}, weighted-F1: {tgt_2_cmp_1_metrics.weighted_f1:.2f}, mcc: {tgt_2_cmp_1_metrics.mcc:.2f}"
              f"\nDepth-2 - macro-F1: {tgt_2_cmp_2_metrics.macro_f1:.2f}, weighted-F1: {tgt_2_cmp_2_metrics.weighted_f1:.2f}, mcc: {tgt_2_cmp_2_metrics.mcc:.2f}")

        print("\n\nTarget-3"
              f"\nDepth-1 - macro-F1: {tgt_3_cmp_1_metrics.macro_f1:.2f}, weighted-F1: {tgt_3_cmp_1_metrics.weighted_f1:.2f}, mcc: {tgt_3_cmp_1_metrics.mcc:.2f}"
              f"\nDepth-2 - macro-F1: {tgt_3_cmp_2_metrics.macro_f1:.2f}, weighted-F1: {tgt_3_cmp_2_metrics.weighted_f1:.2f}, mcc: {tgt_3_cmp_2_metrics.mcc:.2f}"
              f"\nDepth-3 - macro-F1: {tgt_3_cmp_3_metrics.macro_f1:.2f}, weighted-F1: {tgt_3_cmp_3_metrics.weighted_f1:.2f}, mcc: {tgt_3_cmp_3_metrics.mcc:.2f}")

        print("\n" + "=" * 100 + '\n')


    ############## Print ##############
    print(f"Task with depth-1 CWE-ID: {task_tgt_1_num}")
    print(f"Task with depth-2 CWE-ID: {task_tgt_2_num}")
    print(f"Task with depth-3 CWE-ID: {task_tgt_3_num}")

    print("\n" + "=" * 100 + '\n')

    print(f"commit type match tgt-1: {commit_type_match_tgt_1_num}")
    print(f"commit type match tgt-2: {commit_type_match_tgt_2_num}")
    print(f"commit type match tgt-3: {commit_type_match_tgt_3_num}")

    print("\n" + "=" * 100 + '\n')

    print(f"depth-1 vul type top-1 match tgt-1: {vul_type_top_1_depth_1_match_tgt_1_num}")
    print(f"depth-1 vul type top-1 match tgt-2: {vul_type_top_1_depth_1_match_tgt_2_num}")
    print(f"depth-1 vul type top-1 match tgt-3: {vul_type_top_1_depth_1_match_tgt_3_num}")

    print("\n" + "-" * 100 + '\n')

    print(f"depth-1 vul type top-3 match tgt-1: {vul_type_top_3_depth_1_match_tgt_1_num}")
    print(f"depth-1 vul type top-3 match tgt-2: {vul_type_top_3_depth_1_match_tgt_2_num}")
    print(f"depth-1 vul type top-3 match tgt-3: {vul_type_top_3_depth_1_match_tgt_3_num}")

    print("\n" + "=" * 100 + '\n')

    print(f"depth-2 vul type top-1 match tgt-2: {vul_type_top_1_depth_2_match_tgt_2_num}")
    print(f"depth-2 vul type top-1 match tgt-3: {vul_type_top_1_depth_2_match_tgt_3_num}")

    print("\n" + "-" * 100 + '\n')

    print(f"depth-2 vul type top-3 match tgt-2: {vul_type_top_3_depth_2_match_tgt_2_num}")
    print(f"depth-2 vul type top-3 match tgt-3: {vul_type_top_3_depth_2_match_tgt_3_num}")

    print("\n" + "=" * 100 + '\n')

    print(f"depth-3 vul type top-1 match tgt-3: {vul_type_top_1_depth_3_match_tgt_3_num}")

    print("\n" + "-" * 100 + '\n')

    print(f"depth-3 vul type top-3 match tgt-3: {vul_type_top_3_depth_3_match_tgt_3_num}")


"""EVALUATION FOR PROCESS ABNORMAL ACTION"""


def collect_tasks_with_process_abnormal_actions(exps_root: str):
    task_records = [
        ["Task ID", "Patch Extraction", "Unsupported Hypothesis Modification", "Too Detailed Hypothesis Modification",
         "TypeError API Calls", "Post Process Rank", "Finish Process"]
    ]


    def add_proc_id_to_task_data(pid: str, data: List, index: int):
        if data[index] is None:
            data[index] = pid
        else:
            assert isinstance(data[index], str)
            data[index] += f" {pid}"


    total_proc_num = 0
    # (1) Patch extraction (PE)
    pe_proc_num = 0
    invalid_pe_proc_num = 0
    # (2) Unsupported hypothesis modification (UHM)
    uhm_proc_num = 0
    none_res_uhm_num = 0
    same_res_uhm_num = 0
    uns_res_uhm_num = 0
    good_res_uhm_num = 0
    # (3) Too detailed hypothesis modification (TDHM)
    tdhm_proc_num = 0
    tdhm_num = 0
    # (4) TypeError api calls (TAC)
    tac_proc_num = 0
    tac_num = 0
    # (5) Post process rank (PPR)
    ppr_proc_num = 0
    invalid_ppr_proc_num = 0

    exps = os.listdir(exps_root)
    for exp in exps:
        if not exp[0].isdigit():
            continue

        task_id = exp.split('_')[0]

        meta_fpath = os.path.join(exps_root, exp, "meta.json")
        with open(meta_fpath, 'r') as f:
            meta = json.load(f)

        processes_status = meta["completion_info"]["processes_status"]
        if processes_status:
            task_data = [None] * 6

            finish_num = 0
            for proc_num, proc_info in processes_status.items():
                proc_id = proc_num.split('_')[-1]

                if not proc_info["finish"]:
                    continue
                total_proc_num += 1
                finish_num += 1

                # (1) Patch extraction
                assert sum(proc_info["patch_extraction"]) <= 1
                pe_proc_num += sum(proc_info["patch_extraction"])
                invalid_pe_proc_num += proc_info["patch_extraction"][1]

                if proc_info["patch_extraction"][1] > 0:
                    add_proc_id_to_task_data(proc_id, task_data, index=0)

                # (2) Unsupported hypothesis modification
                if sum(proc_info["unsupported_hyp_modification"]) > 0:
                    uhm_proc_num += 1
                none_res_uhm_num += proc_info["unsupported_hyp_modification"][0]
                same_res_uhm_num += proc_info["unsupported_hyp_modification"][1]
                uns_res_uhm_num += proc_info["unsupported_hyp_modification"][2]
                good_res_uhm_num += proc_info["unsupported_hyp_modification"][3]

                if proc_info["unsupported_hyp_modification"][0] > 0 or \
                        proc_info["unsupported_hyp_modification"][1] > 0 or \
                        proc_info["unsupported_hyp_modification"][2] > 0:
                    add_proc_id_to_task_data(proc_id, task_data, index=1)

                # (3) Too detailed hypothesis modification
                if proc_info["too_detailed_hyp_modification"] > 0:
                    add_proc_id_to_task_data(proc_id, task_data, index=2)
                    tdhm_proc_num += 1
                tdhm_num += proc_info["too_detailed_hyp_modification"]

                # (4) TypeError api calls
                if proc_info["typeerror_api_calls"] > 0:
                    add_proc_id_to_task_data(proc_id, task_data, index=3)
                    tac_proc_num += 1
                tac_num += proc_info["typeerror_api_calls"]

                # (4) Post process rank
                assert sum(proc_info["post_process_rank"]) <= 1
                ppr_proc_num += sum(proc_info["post_process_rank"])
                invalid_ppr_proc_num += proc_info["post_process_rank"][1]

                if proc_info["post_process_rank"][1] > 0:
                    add_proc_id_to_task_data(proc_id, task_data, index=4)

            task_data[5] = finish_num

            task_records.append([task_id] + task_data)
        else:
            task_records.append([task_id] + [None] * 6)


    print("Patch extraction")
    print(f"Process number (invalid / do / total): {invalid_pe_proc_num}/{pe_proc_num}/{total_proc_num}")
    print("\n" + "-" * 100 + "\n")
    print("Unsupported hypothesis modification")
    print(f"Process number (do / total): {uhm_proc_num}/{total_proc_num}")
    print("Number (none result / same result / unsupported result / good result): "
          f"{none_res_uhm_num}/ {same_res_uhm_num} / {uns_res_uhm_num} / {good_res_uhm_num}")
    print("\n" + "-" * 100 + "\n")
    print("Too detailed hypothesis modification")
    print(f"Process number (do / total): {tdhm_proc_num}/{total_proc_num}")
    print(f"Number: {tdhm_num}")
    print("\n" + "-" * 100 + "\n")
    print("TypeError api calls")
    print(f"Process number (do / total): {tac_proc_num}/{total_proc_num}")
    print(f"Number: {tac_num}")
    print("\n" + "-" * 100 + "\n")
    print("Post process rank")
    print(f"Process number (invalid / do / total): {invalid_ppr_proc_num}/{ppr_proc_num}/{total_proc_num}")


    output_fpath = os.path.join(exps_root, "task_process_actions.csv")
    df = pd.DataFrame(task_records, columns=['c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7'])
    df.to_csv(output_fpath, index=False)


if __name__ == '__main__':
    exps_root = "/root/projects/VDTest/output/agent/py_vul_nvdvul_view1000_results_v1"

    evaluate_vul_tasks_final_hyps_with_view_1000(exps_root, init=True)
    print("\n" + "#" * 100 + "\n")
    evaluate_vul_tasks_final_hyps_with_view_1000(exps_root)
    print("\n" + "#" * 100 + "\n")

    collect_tasks_with_process_abnormal_actions(exps_root)
