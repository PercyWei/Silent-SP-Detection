import os
import json
import pandas as pd

from typing import *

from agent_app.evaluation import (
    add_new_row_and_column_to_matrix,
    calculate_multi_category_f1_and_mcc, plt_and_save_heatmap
)


RESULTS_DIR = "/root/projects/TreeVul/model/test_results"
SAVE_DIR = "/root/projects/VDTest/baselines/TreeVul"


def evaluation_on_depth_k(
        result_lines: List[str],
        cwe_paths: Dict[str, List[str]],
        prefix_fname: str = "treevul",
        depth: int = 1
) -> Tuple[float, float, float, float]:
    tgt2pred_matrix = pd.DataFrame()

    for line in result_lines:
        result = json.loads(line)[0]

        tgt_cwe_id = result['path'][depth - 1].split('-')[-1]
        pred_2_cwe_id = result['predict_2'][0].split('-')[-1]
        pred_cwe_id = cwe_paths[pred_2_cwe_id][depth - 1]

        if tgt_cwe_id not in tgt2pred_matrix.index:
            add_new_row_and_column_to_matrix(tgt2pred_matrix, tgt_cwe_id)
        if pred_cwe_id not in tgt2pred_matrix.columns:
            add_new_row_and_column_to_matrix(tgt2pred_matrix, pred_cwe_id)

        tgt2pred_matrix.at[tgt_cwe_id, pred_cwe_id] += 1

    metrics = calculate_multi_category_f1_and_mcc(tgt2pred_matrix)

    matrix_title = f"Depth-{depth}_Matrix"

    save_fpath = os.path.join(SAVE_DIR, f"{prefix_fname}_{matrix_title.lower()}.pdf")
    plt_and_save_heatmap(tgt2pred_matrix, matrix_title, save_fpath)

    return metrics.macro_f1, metrics.micro_f1, metrics.weighted_f1, metrics.mcc


def evaluation_on_depths(
        result_lines: List[str],
        cwe_paths: Dict[str, List[str]],
        prefix_fname: str = "treevul"
) -> Dict[str, float]:
    depth_1_maf, depth_1_mif, depth_1_wf, depth_1_mcc = evaluation_on_depth_k(result_lines, cwe_paths, prefix_fname, depth=1)
    depth_2_maf, depth_2_mif, depth_2_wf, depth_2_mcc = evaluation_on_depth_k(result_lines, cwe_paths, prefix_fname, depth=2)
    depth_3_maf, depth_3_mif, depth_3_wf, depth_3_mcc = evaluation_on_depth_k(result_lines, cwe_paths, prefix_fname, depth=3)

    metrics = {
        "Depth-1 macro-F1": depth_1_maf,
        "Depth-1 micro-F1": depth_1_mif,
        "Depth-1 weighted-F1": depth_1_wf,
        "Depth-1 MCC": depth_1_mcc,
        "Depth-2 macro-F1": depth_2_maf,
        "Depth-2 micro-F1": depth_2_mif,
        "Depth-2 weighted-F1": depth_2_wf,
        "Depth-2 MCC": depth_2_mcc,
        "Depth-3 macro-F1": depth_3_maf,
        "Depth-3 micro-F1": depth_3_mif,
        "Depth-3 weighted-F1": depth_3_wf,
        "Depth-3 MCC": depth_3_mcc
    }

    return metrics


def evaluation_on_results(
        result_fnames: List[str],
        cwe_paths_fpath: str = "/root/projects/TreeVul/data/cwe_path.json"
):
    ## Step 1: Get CWE paths
    with open(cwe_paths_fpath, "r") as f:
        full_cwe_paths = json.load(f)

    cwe_paths: Dict[str, List[str]] = {}
    for full_cwe_id, full_cwe_path in full_cwe_paths.items():
        cwe_id = full_cwe_id.split('-')[-1]
        cwe_path = [c.split('-')[-1] for c in full_cwe_path]
        cwe_paths[cwe_id] = cwe_path

    ## Step 2: Calculate metrics on different depths
    result_lines = []
    for result_fname in result_fnames:
        result_fpath = os.path.join(RESULTS_DIR, result_fname)
        assert os.path.exists(result_fpath)
        with open(result_fpath, 'r') as f:
            result_lines.extend(f.readlines())

    if len(result_fnames) > 1:
        prefix_fname = "treevul_all"
    else:
        result_fname = result_fnames[0]
        assert "_result" in result_fname
        prefix_fname = result_fname.split('_result')[0]

    metrics = evaluation_on_depths(result_lines, cwe_paths, prefix_fname)

    ## Step 3: Save
    with open(os.path.join(SAVE_DIR, f"{prefix_fname}_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=4)


if __name__ == '__main__':
    os.makedirs(SAVE_DIR, exist_ok=True)

    result_files = [
        # "treevul_py_test_result.json",
        # "treevul_vulfix_result.json",
        "treevul_nvdvul_result.json"
    ]
    evaluation_on_results(result_files)
