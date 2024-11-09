# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/main.py

import os
import sys
import json
import time

from typing import *
from pathlib import Path
from argparse import ArgumentParser
from datetime import datetime
from itertools import chain
from concurrent.futures import ProcessPoolExecutor

from loguru import logger

from agent_app import globals, globals_mut, inference, log
from agent_app.data_structures import ProcessStatus
from agent_app.api.manage import PyProcessManager, JavaProcessManager
from agent_app.model import common
from agent_app.model.register import register_all_models
from agent_app.raw_tasks import RawTask, RawLocalTask
from agent_app.task import Task
from agent_app.log import get_timestamp, log_and_always_print, log_and_cprint, always_cprint
from agent_app.util import create_dir_if_not_exists


def get_args():
    parser = ArgumentParser()

    ## Base settings
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Path to the directory that stores the run results.",
    )
    parser.add_argument(
        "--local-repos-dir",
        type=str,
        required=True,
        help="Path to the directory that stores the local repos.",
    )
    parser.add_argument(
        "--tasks-map-file",
        type=str,
        required=True,
        help="Path to json file that stores information about the tasks.",
    )
    parser.add_argument(
        "--expr-type",
        choices=['vul', 'novul'],
        required=True,
        help="Experiment name.",
    )
    parser.add_argument(
        "--lang",
        choices=['Python', 'Java'],
        required=True,
        help="Programming language.",
    )

    ## CWE settings
    parser.add_argument(
        "--view-id",
        choices=['1000', '1003'],
        required=True,
        help="Brief CWE VIEW id.",
    )
    parser.add_argument(
        "--cwe-entry-file",
        type=str,
        required=True,
        help="Path to json file that stores information about the CWE entries in current VIEW.",
    )
    parser.add_argument(
        "--cwe-tree-file",
        type=str,
        required=True,
        help="Path to json file that stores information about the CWE tree in current VIEW.",
    )
    parser.add_argument(
        "--all-weakness-entry-file",
        type=str,
        required=True,
        help="Path to json file that stores information about all Weakness CWE entries.",
    )
    parser.add_argument(
        "--view-cwe-tree-files",
        type=str,
        nargs="+",
        help="Appear in pairs: brief VIEW-ID, CWE tree file"
    )

    ## Model settings
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-3.5-turbo-0125",
        choices=list(common.MODEL_HUB.keys()),
        help="The model to use. Currently only OpenAI models are supported.",
    )
    parser.add_argument(
        "--model-temperature",
        type=float,
        default=0.0,
        help="The model temperature to use, for OpenAI models.",
    )

    ## Process settings
    parser.add_argument(
        "--complete-process-limit",
        type=int,
        default=3,
        help="Complete process limit for each task.",
    )
    parser.add_argument(
        "--state-retry-limit",
        type=int,
        default=3,
        help="Retry limit for the Actor Agent of each state in the process.",
    )
    parser.add_argument(
        "--state-round-limit",
        type=int,
        default=6,
        help="Conversation round limit for the Actor Agent of each state in the process.",
    )
    parser.add_argument(
        "--hypothesis-limit",
        type=int,
        default=3,
        help="Hypothesis proposed limit in the process.",
    )

    ## Print settings
    parser.add_argument(
        "--no-print",
        action="store_true",
        default=False,
        help="Do not print most messages to stdout.",
    )

    ## Implementation settings
    parser.add_argument(
        "--num-processes",
        type=str,
        default=1,
        help="Number of processes to run the tasks in parallel.",
    )

    return parser.parse_args()


def run_task_groups(
        task_groups: Mapping[str, Sequence[RawTask]],
        num_processes: int
):
    """
    Main entry for running tasks.
    """
    all_tasks = list(chain.from_iterable(task_groups.values()))
    num_tasks = len(all_tasks)

    globals_mut.init_total_num_tasks(num_tasks)

    # Print some info about task
    log_and_always_print(f"Total number of tasks: {num_tasks}")
    log_and_always_print(f"Total number of processes: {num_processes}")
    log_and_always_print(f"Task group info: (number of groups: {len(task_groups)})")
    for key, tasks in task_groups.items():
        log_and_always_print(f"\t{key}: {len(tasks)} tasks")

    if num_processes == 1:
        # Single-process mode
        log_and_always_print("Running in single-process mode.")
        run_tasks_serial(all_tasks)
        log_and_always_print("Finished all tasks sequentially.")
    else:
        # Multi-process mode
        log_and_always_print("Running in multi-process mode.")
        run_task_groups_parallel(task_groups, num_processes)


def run_tasks_serial(tasks: List[RawTask]) -> None:
    """Single-process Mode: Run all tasks sequentially."""
    for task in tasks:
        run_task_in_subprocess(task)
        log.print_with_time(globals_mut.inc_task_return_msg())


def run_task_groups_parallel(task_groups: Mapping[str, Sequence[RawTask]], num_processes: int):
    """Multi-process Mode: Run all tasks with multiple processes."""
    num_task_groups = len(task_groups)
    globals_mut.init_total_num_task_groups(num_task_groups)
    num_processes = min(num_processes, num_task_groups)

    task_group_ids_items: List[Tuple[str, Sequence[RawTask]]] = sorted(
        task_groups.items(), key=lambda x: len(x[1]), reverse=True
    )
    log_and_always_print(f"Sorted task groups: {[x[0] for x in task_group_ids_items]}")
    try:
        # Use ProcessPoolExecutor instead of multiprocessing.Pool to support nested sub-processing
        group_ids, group_tasks = zip(*task_group_ids_items)
        with ProcessPoolExecutor(num_processes) as executor:
            executor.map(run_task_group, group_ids, group_tasks)
    finally:
        log_and_always_print("Finishing all tasks in the pool.")


def run_task_group(task_group_id: str, task_group_items: List[RawTask]) -> None:
    """
    Run all tasks in a task group sequentially.
    Main entry to parallel processing.
    """
    log_and_always_print(f"Starting process for task group {task_group_id}. Number of tasks: {len(task_group_items)}.")

    for task in task_group_items:
        # Within a group, the runs are always sequential
        run_task_in_subprocess(task)
        log_and_always_print(globals_mut.inc_task_return_msg())

    log_and_always_print(f"{globals_mut.inc_task_group_return_msg()} Finished task group {task_group_id}.")


def run_task_in_subprocess(task: RawTask) -> None:
    with ProcessPoolExecutor(max_workers=1) as executor:
        res = executor.submit(run_raw_task, task)

        if res.result():
            globals_mut.inc_completed_ok_tasks()


def run_raw_task(task: RawTask, print_callback: Callable[[dict], None] | None = None) -> bool:
    """
    High-level entry for running one task.

    Args:
        task (RawTask): The Task instance to run
        print_callback: Optional callback function for printing task info
    Returns:
        bool: Whether the task completed successfully.
    """
    task_id = task.task_id

    start_time_s = get_timestamp()
    task_output_dpath = os.path.join(globals.expr_dpath, f"{task_id}_{start_time_s}")
    create_dir_if_not_exists(task_output_dpath)

    log_and_always_print("=" * 10 + f" Running task {task_id} " + "=" * 10)

    all_proc_status = None
    try:
        all_proc_status = do_inference(task.to_task(), task_output_dpath, print_callback)

        if all_proc_status:
            run_status_message = f"Task {task_id} completed successfully."
        else:
            run_status_message = f"Task {task_id} failed without exception."
    except Exception as e:
        logger.exception(e)
        run_status_message = f"Task {task_id} failed with exception: {e}."
    finally:
        if all_proc_status is not None:
            completion_info = {}
            for proc_name, status_counts in all_proc_status.items():
                completion_info[proc_name] = {
                    status_name: status_count.to_dict()
                    for status_name, status_count in status_counts.items()
                }
        else:
            completion_info = None

        task.dump_meta_data(task_output_dpath, {"completion_info": completion_info})

    log_and_always_print(run_status_message)

    return all_proc_status is not None


def do_inference(
        task: Task,
        task_output_dir: str,
        print_callback: Callable[[dict], None] | None = None
) -> Dict[str, Dict[str, ProcessStatus]] | None:
    create_dir_if_not_exists(task_output_dir)
    current_task_log_path = os.path.join(task_output_dir, "info.log")

    logger.add(
        current_task_log_path,
        level="DEBUG",
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    )

    start_time = datetime.now()

    if globals.lang == 'Python':
        manager = PyProcessManager(task, task_output_dir)
    elif globals.lang == 'Java':
        manager = JavaProcessManager(task, task_output_dir)
    else:
        raise RuntimeError(f"Language {globals.lang} not supported yet.")

    log_and_cprint(f"Manager preparation: {time.time() - start_time.timestamp()}")

    all_proc_status = None
    try:
        all_proc_status = inference.run_one_task(task.commit_content, manager.output_dpath, manager, print_callback)

        end_time = datetime.now()

        dump_cost(task.repo_name, task.commit_hash, start_time, end_time, task_output_dir)
    finally:
        task.reset_project()

    return all_proc_status


def dump_cost(repo: str, commit_hash: str, start_time: datetime, end_time: datetime, task_output_dir: str):
    model_stats = common.SELECTED_MODEL.get_overall_exec_stats()
    stats = {
        "repo": repo,
        "commit": commit_hash,
        "start_epoch": start_time.timestamp(),
        "end_epoch": end_time.timestamp(),
        "elapsed_seconds": (end_time - start_time).total_seconds(),
    }
    stats.update(model_stats)

    with open(os.path.join(task_output_dir, "cost.json"), "w") as f:
        json.dump(stats, f, indent=4)


def construct_tasks(tasks_map_file: str, local_repos_dpath: str) -> List[RawLocalTask]:
    """Constructs a list of RawLocalTask instances.

    Args:
        tasks_map_file (str): Path to the tasks map file.
        local_repos_dpath (str): Path to the local directory for saving local repos cloned from GitHub.
    """
    valid_tasks = []
    invalid_tasks = []

    #########################################################################################
    #########################################################################################
    # TODO: Only in test
    checked_task_ids: List[str] = []
    checked_task_dirs = [
        "/root/projects/VDTest/output/agent/on_hold_tasks",
        "/root/projects/VDTest/output/agent/ast_failure_tasks"
    ]
    for task_dir in checked_task_dirs:
        task_full_names = os.listdir(task_dir)
        for task_full_name in task_full_names:
            task_id = task_full_name.split("_")[0]
            checked_task_ids.append(task_id)
    #########################################################################################
    #########################################################################################

    with open(tasks_map_file) as f:
        tasks_map = json.load(f)

    log_and_always_print("Adding tasks ...")
    for i, task_info in enumerate(tasks_map):
        commit_type = task_info["commit_type"]
        if (globals.expr_type == "vul" and commit_type == 1) or (globals.expr_type == "novul" and commit_type == 0):
            task_id = task_info["task_id"]
            auth_repo = task_info["repo"]

            # Filter 1
            if task_id in checked_task_ids:
                continue

            # Filter 2
            local_repo_dpath = os.path.join(local_repos_dpath, auth_repo.replace('/', '_'))
            if not os.path.isdir(local_repo_dpath):
                continue

            # Filter 3
            if task_info["file_count"] > 5:
                continue

            task = RawLocalTask(
                task_id=task_id,
                cve_id=task_info["cve_id"],
                commit_type=commit_type,
                cwe_list=task_info["cwe_list"],
                auth_repo=auth_repo,
                commit_hash=task_info["commit_hash"],
                local_repo_dpath=local_repo_dpath
            )

            # Select tasks initialised successfully
            if task.valid:
                valid_tasks.append(task)
                log_and_cprint(f"{task_id}: Done!", style="green")
            else:
                invalid_tasks.append({"task_id": task.task_id, "cve_id": task.cve_id})
                log_and_cprint(f"{task_id}: Failed!", style="red")

            if len(valid_tasks) >= globals.task_limit:
                break

    invalid_task_fpath = os.path.join(globals.expr_dpath, "invalid_tasks.json")
    with open(invalid_task_fpath, "w") as f:
        json.dump(invalid_tasks, f, indent=4)

    return valid_tasks


def group_local_tasks_by_repo(tasks: List[RawLocalTask]) -> Dict[str, List[RawLocalTask]]:
    groups = {}
    for task in tasks:
        auth_repo = task.auth_repo
        if auth_repo not in groups:
            groups[auth_repo] = []
        groups[auth_repo].append(task)
    return groups


def main(args):
    # ------------------------- Set options ------------------------- #
    ## Required path
    # 1. dir to root output
    globals.output_dpath = os.path.abspath(args.output_dir)
    assert os.path.exists(globals.output_dpath)

    # 2. dir to local repos
    globals.local_repos_dpath = os.path.abspath(args.local_repos_dir)
    assert os.path.exists(globals.local_repos_dpath)

    # 3. dir to current experiment
    globals.expr_type = args.expr_type
    expr_name = args.expr_type + "_" + get_timestamp()
    expr_dpath = os.path.join(globals.output_dpath, expr_name)
    globals.expr_dpath = os.path.abspath(expr_dpath)
    create_dir_if_not_exists(globals.expr_dpath)

    ## language
    globals.lang = args.lang

    ## CWE
    globals.view_id = args.view_id
    globals.all_weakness_entry_file = args.all_weakness_entry_file
    globals.cwe_entry_file = args.cwe_entry_file
    globals.cwe_tree_file = args.cwe_tree_file
    if args.view_cwe_tree_files:
        if len(args.view_cwe_tree_files) % 2 != 0:
            always_cprint("Error: The number of strings for --view-cwe-tree-files must be even.", style="red")
            sys.exit(1)
        else:
            view_cwe_tree_files = [(args.view_cwe_tree_files[i], args.view_cwe_tree_files[i + 1])
                                   for i in range(0, len(args.view_cwe_tree_files), 2)]
    else:
        view_cwe_tree_files = []
    globals.view_cwe_tree_files = view_cwe_tree_files

    ## Other
    # number of processes
    num_processes: int = int(args.num_processes)
    # brief or verbose log
    print_stdout: bool = not args.no_print
    log.print_stdout = print_stdout
    # model related
    common.set_model(args.model)
    common.MODEL_TEMP = args.model_temperature
    # acr related
    globals.complete_process_limit = args.complete_process_limit
    globals.state_retry_limit = args.state_retry_limit
    globals.state_round_limit = args.state_round_limit
    globals.hypothesis_limit = args.hypothesis_limit

    # ------------------------- Logger ------------------------- #
    # total_log_path = os.path.join(globals.expr_dpath, "info.log")
    # logger.add(
    #     total_log_path,
    #     level="DEBUG",
    #     format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    # )

    # ------------------------- Save args ------------------------- #
    json_args = vars(args)
    json_args["expr_name"] = expr_name
    expr_args_log = Path(globals.expr_dpath, "expr_args.json")
    expr_args_log.write_text(json.dumps(json_args, indent=4))

    # ------------------------- Construct tasks ------------------------- #
    all_tasks: List[RawLocalTask] = construct_tasks(args.tasks_map_file, args.local_repos_dir)
    task_groups = group_local_tasks_by_repo(all_tasks)

    # ------------------------- Run tasks ------------------------- #
    run_task_groups(task_groups, num_processes)


if __name__ == '__main__':
    logger.remove()
    register_all_models()
    margs = get_args()
    main(margs)
