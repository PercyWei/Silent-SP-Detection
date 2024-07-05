# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/main.py

import os

from typing import *
from os.path import abspath
from datetime import datetime
from itertools import chain
from concurrent.futures import ProcessPoolExecutor

from loguru import logger

from agent_app import globals, globals_mut, log
from agent_app.model import common
from agent_app.model.register import register_all_models
from agent_app.raw_tasks import RawTask, RawLocalTask
from agent_app.task import Task
from agent_app.log import print_with_time, log_and_always_print
from agent_app.utils import get_timestamp, create_dir_if_not_exists



def run_task_groups(
        task_groups: Mapping[str, Sequence[RawTask]],
        num_processes: int,
        organize_output: bool = False
):
    """
    Main entry for running tasks.
    """
    all_tasks = list(chain.from_iterable(task_groups.values()))
    num_tasks = len(all_tasks)

    globals_mut.init_total_num_tasks(num_tasks)

    # Print some info about task
    print_with_time(f"Total number of tasks: {num_tasks}")
    print_with_time(f"Total number of processes: {num_processes}")
    print_with_time(f"Task group info: (number of groups: {len(task_groups)})")
    for key, tasks in task_groups.items():
        print_with_time(f"\t{key}: {len(tasks)} tasks")


    if num_processes == 1:
        # Single-process mode
        print_with_time("Running in single-process mode.")
        run_tasks_serial(all_tasks)
        print_with_time("Finished all tasks sequentially.")
    else:
        # Multi-process mode
        print_with_time("Running in multi-process mode.")
        run_task_groups_parallel(task_groups, num_processes)

    if globals.only_save_sbfl_result:
        log.print_with_time("Only saving SBFL results. Exiting.")
        return

    if organize_output:
        # post-process completed experiments to get input file to SWE-bench
        log.print_with_time("Post-processing completed experiment results.")
        swe_input_file = organize_and_form_input(globals.output_dir)
        log.print_with_time(f"SWE-Bench input file created: {swe_input_file}")


def run_tasks_serial(tasks: List[RawTask]) -> None:
    """
    Single-process Mode: Run all tasks sequentially.

    Args:
        tasks: List of RawTasks to process
    """
    for task in tasks:
        run_task_in_subprocess(task)


def run_task_groups_parallel(task_groups: Mapping[str, Sequence[RawTask]], num_processes: int):
    """
    Multi-process Mode: Run all tasks with multiple processes.

    Args:
        task_groups:
        num_processes:
    """
    # TODO
    pass


def run_task_in_subprocess(task: RawTask) -> None:
    with ProcessPoolExecutor(max_workers=1) as executor:
        executor.submit(run_raw_task, task)


def run_raw_task(task: RawTask, print_callback: Optional[Callable[[dict], None]] = None) -> bool:
    """
    High-level entry for running one task.

    Args:
        task: The Task instance to run
        print_callback: Optional callback function for printing task info
    Returns:
        Whether the task completed successfully.
    """
    task_id = task.task_id

    start_time_s = get_timestamp()
    task_output_dpath = os.path.join(globals.output_dir, f"{task_id}_{start_time_s}")
    create_dir_if_not_exists(task_output_dpath)

    task.dump_meta_data(task_output_dpath)

    log_and_always_print(f"============= Running task {task_id} =============")

    run_ok = False

    #
    try:
        run_ok = do_inference(task.to_task(), task_output_dpath, print_callback)

        if run_ok:
            run_status_message = f"Task {task_id} completed successfully."
        else:
            run_status_message = f"Task {task_id} failed without exception."
    except Exception as e:
        logger.exception(e)
        run_status_message = f"Task {task_id} failed with exception: {e}."

    log_and_always_print(run_status_message)

    final_patch_path = get_final_patch_path(task_output_dpath)
    if final_patch_path is not None:
        log.log_and_always_print(
            f"Please find the generated patch at: {final_patch_path}"
        )
        if isinstance(task, RawSweTask):
            log.log_and_always_print(
                "[SWE-bench mode] Note that the patch may be move to other paths in SWE-bench mode. "
                "Please check the SWE-bench input file containing generated patches for all tasks."
            )
    else:
        log.log_and_always_print("No patch generated. You can try running ACR again.")

    return run_ok


def do_inference(
    python_task: Task,
    task_output_dir: str,
    print_callback: Callable[[dict], None] | None = None,
) -> bool:

    create_dir_if_not_exists(task_output_dir)
    current_task_log_path = os.path.join(task_output_dir, "info.log")

    logger.add(
        current_task_log_path,
        level="DEBUG",
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level>"
            " | <level>{message}</level>"
        ),
    )

    start_time = datetime.now()

    api_manager = ProjectApiManager(python_task, task_output_dir)

    try:
        run_ok = inference.run_one_task(
            api_manager.output_dir,
            api_manager,
            python_task.get_issue_statement(),
            print_callback,
        )

        api_manager.dump_tool_call_sequence_to_file()
        api_manager.dump_tool_call_layers_to_file()

        end_time = datetime.now()

        dump_cost(start_time, end_time, task_output_dir)
    finally:
        python_task.reset_project()

    return run_ok


def main(args):
    ## common options
    globals.output_dir = args.output_dir
    if globals.output_dir is not None:
        globals.output_dir = abspath(globals.output_dir)
    num_processes: int = int(args.num_processes)
    # set whether brief or verbose log
    print_stdout: bool = not args.no_print
    log.print_stdout = print_stdout
    # model related
    common.set_model(args.model)
    # FIXME: make temperature part of the Model class
    common.MODEL_TEMP = args.model_temperature
    # acr related
    globals.conv_round_limit = args.conv_round_limit
    globals.enable_layered = args.enable_layered
    globals.enable_validation = args.enable_validation

    ## Run tasks




if __name__ == '__main__':

    register_all_models()


