import os
import json


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


def tasks_evaluation_with_cwe_1003(
        exps_root: str,
        cwe_tree_fpath: str,
        depth_1_cwe_fpath: str,
        depth_2_cwe_fpath: str,
        depth_3_cwe_fpath: str
):
    ## Task num
    task_num = 0
    task_with_depth_1_cwe_num = 0
    task_with_depth_2_cwe_num = 0
    task_with_depth_3_cwe_num = 0

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
    # depth-3 match
    vul_type_top_1_depth_3_match_num = 0
    vul_type_top_3_depth_3_match_num = 0

    with open(cwe_tree_fpath, 'r') as f:
        cwe_tree = json.load(f)

    with open(depth_1_cwe_fpath, 'r') as f:
        depth_1_cwes = json.load(f)

    with open(depth_2_cwe_fpath, 'r') as f:
        depth_2_cwes = json.load(f)

    with open(depth_3_cwe_fpath, 'r') as f:
        depth_3_cwes = json.load(f)

    exps = os.listdir(exps_root)
    exps.remove("expr_args.json")
    for exp in exps:
        meta_fpath = os.path.join(exps_root, exp, "meta.json")
        with open(meta_fpath, 'r') as f:
            meta = json.load(f)

        target_commit_type = meta["task_info"]["commit_type"]
        target_vul_type = meta["task_info"]["cwe_id"]
        target_cwe_id = target_vul_type.split("-")[-1]
        # TODO
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
            target_cwe_id_depth_3 = None
            is_task_with_depth_1_cwe = False
            is_task_with_depth_2_cwe = False
            is_task_with_depth_3_cwe = False

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
                is_task_with_depth_3_cwe = True

                target_cwe_id_depth_1 = cwe_tree[target_cwe_id]["father"][0]
                target_cwe_id_depth_2 = target_cwe_id
                target_cwe_id_depth_3 = target_cwe_id

                task_with_depth_3_cwe_num += 1

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


if __name__ == '__main__':
    exps_root = "/root/projects/VDTest/output/agent/vul_2024-09-08T16:51:25_SAVE"

    cwe_1003_tree_file = "/root/projects/VDTest/data/CWE/VIEW_1003/CWE_tree.json"
    cwe_1003_depth_1_file = "/root/projects/VDTest/data/CWE/VIEW_1003/CWE_depth_1.json"
    cwe_1003_depth_2_file = "/root/projects/VDTest/data/CWE/VIEW_1003/CWE_depth_2.json"

    cwe_1000_tree_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    cwe_1000_depth_1_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_depth_1.json"
    cwe_1000_depth_2_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_depth_2.json"
    cwe_1000_depth_3_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_depth_3.json"

    # tasks_evaluation_with_cwe_1003(exps_root, cwe_1000_tree_file, cwe_1000_depth_1_file, cwe_1000_depth_2_file)

    task_num = 0

    ## Identification of commit type
    commit_type_match_num = 0

    ## Identification of vulnerability type
    vul_type_top_1_match_num = 0
    vul_type_top_3_match_num = 0

    exps = os.listdir(exps_root)
    exps.remove("expr_args.json")
    for exp in exps:
        eval_result_fpath = os.path.join(exps_root, exp, "evaluation.json")
        if os.path.exists(eval_result_fpath):
            with open(eval_result_fpath, 'r') as f:
                eval_result = json.load(f)

            task_num += 1

            final_result = eval_result["final_result"]
            if final_result["commit_type_match_rank"] == 1:
                commit_type_match_num += 1

            if final_result["vul_type_match_rank"] is not None:
                if final_result["vul_type_match_rank"] == 1:
                    vul_type_top_1_match_num += 1
                if final_result["vul_type_match_rank"] <= 3:
                    vul_type_top_3_match_num += 1

    print(f"{commit_type_match_num} / {task_num}")
    print(f"{vul_type_top_1_match_num} / {task_num}")
    print(f"{vul_type_top_3_match_num} / {task_num}")
