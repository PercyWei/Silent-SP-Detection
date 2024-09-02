import os
import json


def tasks_evaluation_with_cwe_1003(exps_root: str, cwe_1003_tree_fpath: str):
    ## Task num
    task_num = 0
    task_with_father_vul_num = 0
    task_with_child_vul_num = 0

    ## Identification of commit type
    # Golden match
    commit_type_match_num = 0

    ## Identification of vulnerability type
    # Golden match
    vul_type_top_1_golden_match_num = 0
    vul_type_top_3_golden_match_num = 0
    # Father match (only for task_with_child)
    vul_type_top_1_father_match_num = 0
    vul_type_top_3_father_match_num = 0

    with open(cwe_1003_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    exps = os.listdir(exps_root)
    for exp in exps:
        eval_result_fpath = os.path.join(exps_root, exp, "evaluation.json")
        final_hyp_fpath = os.path.join(exps_root, exp, "result.json")

        if os.path.exists(eval_result_fpath) and os.path.exists(final_hyp_fpath):
            with open(eval_result_fpath, 'r') as f:
                eval_result = json.load(f)

            with open(final_hyp_fpath, 'r') as f:
                final_hyps = json.load(f)

            pass

            ## (1) Task number
            task_num += 1

            target_vul_type = eval_result['target_vul_type']
            target_vul_id = target_vul_type.split('-')[-1]

            assert target_vul_id in cwe_tree

            task_with_child_flag = False
            if len(cwe_tree[target_vul_id]["father"]) == 0:
                task_with_father_vul_num += 1
            else:
                task_with_father_flag = True
                task_with_child_vul_num += 1

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

            # Father match
            if task_with_child_flag:
                target_father_vul_id = cwe_tree[target_vul_id]["father"][0]




    print(f"commit type match: {commit_type_match_num} / {task_num}")
    print(f"vul type top-1 match: {vul_type_top_1_golden_match_num} / {task_num}")
    print(f"vul type top-3 match: {vul_type_top_3_golden_match_num} / {task_num}")


if __name__ == '__main__':
    exps_root = "/root/projects/VDTest/output/agent/safe_2024-08-30T21:10:12"

    tasks_evaluation_with_cwe_1003(exps_root)




