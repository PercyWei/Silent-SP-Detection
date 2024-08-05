# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/globals_mut.py

"""
A global store, for values that cna be mutated in multiprocessing, along with their related values.
"""

import multiprocessing

# To be set at beginning
total_num_tasks = 0
num_completed_tasks = multiprocessing.Value("i", 0)


# To be set at beginning
total_num_task_groups = 0
num_completed_task_groups = multiprocessing.Value("i", 0)


num_golden_match_tasks = multiprocessing.Value("i", 0)


def init_total_num_tasks(n: int):
    global total_num_tasks
    total_num_tasks = n


def init_total_num_task_groups(n: int):
    global total_num_task_groups
    total_num_task_groups = n


def inc_completed_tasks() -> int:
    with num_completed_tasks.get_lock():
        num_completed_tasks.value += 1
    return num_completed_tasks.value


def inc_completed_task_groups() -> int:
    with num_completed_task_groups.get_lock():
        num_completed_task_groups.value += 1
    return num_completed_task_groups.value


def inc_task_return_msg() -> str:
    completed = inc_completed_tasks()
    completed_groups = num_completed_task_groups.value
    return f">>> Completed {completed}/{total_num_tasks} tasks. For groups, completed {completed_groups}/{total_num_task_groups} so far."


def inc_task_group_return_msg() -> str:
    completed = inc_completed_task_groups()
    return f">>>>>> Completed {completed}/{total_num_task_groups} task groups."


def inc_golden_match_tasks() -> int:
    with num_golden_match_tasks.get_lock():
        num_golden_match_tasks.value += 1
    return num_golden_match_tasks.value
