
import os
import ast
import json

from typing import *
from loguru import logger


from agent_app.commit.commit_util import (
    extract_commit_content_info, get_file_after_commit, get_file_before_commit,
    analyse_diff_structs_within_file
)
from agent_app.static_analysis.parse import parse_python_file_locations as parse

from agent_app.raw_tasks import RawLocalTask
from agent_app.main import construct_tasks
from agent_app.search.search_util import find_python_files

from agent_app.util import get_commit_content
from utils import LineRange


"""TEST 1"""


def select_python_file_struct_ranges(file_content: str) -> List[int] | None:
    try:
        tree = ast.parse(file_content)
    except Exception:
        # Failed to parse one file, we should ignore it
        return None

    struc_lines: List[int] = []

    for child in ast.iter_child_nodes(tree):
        start_lineno = child.lineno    # 1-based
        end_lineno = child.end_lineno  # 1-based

        if isinstance(child, ast.ClassDef) or \
                isinstance(child, ast.FunctionDef) or \
                isinstance(child, ast.AsyncFunctionDef):
            struc_lines.extend(range(start_lineno, end_lineno + 1))

    return struc_lines


def test1(local_repo_dpath, commit_hash, diff_file_info):
    old_fname = diff_file_info["old_fpath"]
    new_fname = diff_file_info["new_fpath"]
    diff_code_info = diff_file_info["code_diff"]

    # (1) Check old file (before commit)
    old_file_content = get_file_before_commit(local_repo_dpath, commit_hash, old_fname)
    old_structs_lines = select_python_file_struct_ranges(old_file_content)

    if old_structs_lines is not None:
        old_file_not_in_struc_changed_lines = []
        for hunk in diff_code_info:
            old_diff_lines_index2id = hunk["old_diff_lines_index2id"]
            old_diff_line_ids = list(old_diff_lines_index2id.values())  # 1-based

            for diff_line_id in old_diff_line_ids:
                if diff_line_id not in old_structs_lines:
                    old_file_not_in_struc_changed_lines.append(diff_line_id)

        if len(old_file_not_in_struc_changed_lines) > 0:
            logger.info(f"Old file name: {old_fname}")
            logger.info(f"Not in struct line ids: {old_file_not_in_struc_changed_lines}")

    # (2) Check new file (after commit)
    new_file_content = get_file_after_commit(local_repo_dpath, commit_hash, new_fname)
    new_structs_lines = select_python_file_struct_ranges(new_file_content)

    if new_structs_lines is not None:
        new_file_not_in_struc_changed_lines = []
        for hunk in diff_code_info:
            new_diff_lines_index2id = hunk["new_diff_lines_index2id"]
            new_diff_line_ids = list(new_diff_lines_index2id.values())  # 1-based

            for diff_line_id in new_diff_line_ids:
                if diff_line_id not in new_structs_lines:
                    new_file_not_in_struc_changed_lines.append(diff_line_id)

        if len(new_file_not_in_struc_changed_lines) > 0:
            logger.info(f"New file name: {new_fname}")
            logger.info(f"Not in struct line ids: {new_file_not_in_struc_changed_lines}")


"""TEST 2"""


def json_dump_diff_structs(diff_structs_info: Dict[str, LineRange]) -> str:
    seq = ""
    for name, struct_range in diff_structs_info.items():
        seq += f"{name}: {struct_range.start}-{struct_range.end}\n"

    return seq


def json_dump_mod_structs(mod_structs_info: List[List[Tuple[str, LineRange]]]) -> str:
    seq = ""
    for mod_struct in mod_structs_info:
        assert len(mod_struct) == 2
        old_name, old_range = mod_struct[0]
        new_name, new_range = mod_struct[1]
        seq += f"{old_name} -> {new_name}: {old_range.start}-{old_range.end} -> {new_range.start}-{new_range.end}\n"

    return seq


def test2(local_repo_dpath, commit_hash, diff_file_info):
    old_fname = diff_file_info["old_fpath"]
    new_fname = diff_file_info["new_fpath"]

    old_file_content = get_file_before_commit(local_repo_dpath, commit_hash, old_fname)
    new_file_content = get_file_after_commit(local_repo_dpath, commit_hash, new_fname)

    diff_classes_info, diff_funcs_info, diff_asyncFuncs_info = \
        analyse_diff_structs_within_file(old_file_content, new_file_content, diff_file_info)

    if diff_classes_info is not None and diff_funcs_info is not None:
        logger.info("#" * 75)
        logger.info("#" * 75)

        logger.info("-" * 50)
        logger.info(f"Delete classes:\n{json_dump_diff_structs(diff_classes_info['del_classes'])}")
        logger.info("-" * 50)
        logger.info(f"Add classes:\n{json_dump_diff_structs(diff_classes_info['add_classes'])}")
        logger.info("-" * 50)
        logger.info(f"Modify mod classes:\n{json_dump_mod_structs(diff_classes_info['mod_mod_classes'])}")
        logger.info("-" * 50)
        logger.info(f"Modify del classes:\n{json_dump_mod_structs(diff_classes_info['mod_del_classes'])}")
        logger.info("-" * 50)
        logger.info(f"Modify add classes:\n{json_dump_mod_structs(diff_classes_info['mod_add_classes'])}")

        logger.info("#" * 75)
        logger.info("-" * 50)
        logger.info(f"Delete funcs:\n{json_dump_diff_structs(diff_funcs_info['del_funcs'])}")
        logger.info("-" * 50)
        logger.info(f"Add funcs:\n{json_dump_diff_structs(diff_funcs_info['add_funcs'])}")
        logger.info("-" * 50)
        logger.info(f"Modify mod funcs:\n{json_dump_mod_structs(diff_funcs_info['mod_mod_funcs'])}")
        logger.info("-" * 50)
        logger.info(f"Modify del funcs:\n{json_dump_mod_structs(diff_funcs_info['mod_del_funcs'])}")
        logger.info("-" * 50)
        logger.info(f"Modify add funcs:\n{json_dump_mod_structs(diff_funcs_info['mod_add_funcs'])}")

        logger.info("#" * 75)
        logger.info("-" * 50)
        logger.info(f"Delete async funcs:\n{json_dump_diff_structs(diff_asyncFuncs_info['del_asyncFuncs'])}")
        logger.info("-" * 50)
        logger.info(f"Add async funcs:\n{json_dump_diff_structs(diff_asyncFuncs_info['add_asyncFuncs'])}")
        logger.info("-" * 50)
        logger.info(f"Modify mod async funcs:\n{json_dump_mod_structs(diff_asyncFuncs_info['mod_mod_asyncFuncs'])}")
        logger.info("-" * 50)
        logger.info(f"Modify del async funcs:\n{json_dump_mod_structs(diff_asyncFuncs_info['mod_del_asyncFuncs'])}")
        logger.info("-" * 50)
        logger.info(f"Modify add async funcs:\n{json_dump_mod_structs(diff_asyncFuncs_info['mod_add_asyncFuncs'])}")

        logger.info("")


"""TEST 3"""


def test3(local_repo_dpath, commit_hash, diff_file_info):
    old_fname = diff_file_info["old_fpath"]
    new_fname = diff_file_info["new_fpath"]

    old_file_content = get_file_before_commit(local_repo_dpath, commit_hash, old_fname)
    new_file_content = get_file_after_commit(local_repo_dpath, commit_hash, new_fname)

    old_res = parse(old_file_content)
    new_res = parse(new_file_content)


"""TEST 4"""


def test4(tasks_map_file: str, local_repos_dpath: str):
    all_tasks: List[RawLocalTask] = construct_tasks(tasks_map_file, local_repos_dpath)

    for raw_task in all_tasks:
        task = raw_task.to_task()
        logger.info("=" * 100)
        logger.info("=" * 100)
        logger.info(f"Repo: {task.repo_name}\n")
        logger.info(f"Commit hash: {task.commit_hash}\n")
        logger.info(f"Head commit hash: {task.head_commit_hash}\n")

        task.setup_project()

        find_file_num = 0
        abs_py_files = find_python_files(task.local_repo_dpath)
        for abs_py_file in abs_py_files:
            try:
                with open(abs_py_file, "r", encoding='utf-8') as f:
                    c = f.read()
            except Exception as e:
                logger.debug("File read error")
                continue

            try:
                tree = ast.parse(c)

                async_funcs: Dict[str, List[LineRange]] = {}

                for child in ast.iter_child_nodes(tree):
                    name = child.name if hasattr(child, 'name') else type(child).__name__
                    start_lineno = child.lineno  # 1-based
                    end_lineno = child.end_lineno  # 1-based

                    if isinstance(child, ast.AsyncFunctionDef):
                        if name not in async_funcs:
                            async_funcs[name] = []
                        async_funcs[name].append(LineRange(start_lineno, end_lineno))

                for name, ranges in async_funcs.items():
                    if len(ranges) > 1:
                        find_file_num += 1
                        logger.info(f"File: {abs_py_file}")
                        logger.info(f"Async function: {name}:")
                        for r in ranges:
                            logger.info(f"  {r.start}-{r.end}")
                        logger.info("")

            except Exception:
                logger.debug("AST parsing file failed")

        task.reset_project()


def main_test_changed_lines_locations(local_repos_dpath: str, tasks_map_file: str):
    logger.remove()
    logger.add(
        "/root/projects/VDTest/agent_app/test/verification_2.log",
        level="DEBUG",
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level>"
            " | <level>{message}</level>"
        ),
        mode='w'
    )

    # TEST 1 / 2 / 3
    with open(tasks_map_file) as f:
        tasks_map = json.load(f)

    for i, (commit_hash, commit_items) in enumerate(tasks_map.items()):
        item = commit_items[0]
        if "PL" in item and item["PL"] == "Python":
            repo_name = item["repo"]
            assert len(repo_name.split('/')) == 2

            local_repo_dpath = os.path.join(local_repos_dpath, repo_name.replace('/', '_'))
            if not os.path.exists(local_repo_dpath):
                continue

            commit_content = get_commit_content(commit_hash, local_repo_dpath)
            if commit_content is None:
                continue

            commit_info = extract_commit_content_info(commit_content)

            for changed_file_info in commit_info:
                if changed_file_info["file_type"] == "modified":
                    commit_url = f"https://github.com/{repo_name}/commit/{commit_hash}"
                    logger.info("=" * 100)
                    logger.info(f"Commit url: {commit_url}")

                    # test1(local_repo_dpath, commit_hash, changed_file_info)
                    test2(local_repo_dpath, commit_hash, changed_file_info)
                    # test3(local_repo_dpath, commit_hash, changed_file_info)

    # TEST 4
    # test4(tasks_map_file, local_repos_dpath)


if __name__ == '__main__':
    # local_repos_dir = "/root/projects/clone_projects"
    # tasks_map_fpath = "/root/projects/VDTest/output/TreeVul/TreeVul_valid_scsfCVE.json"
    # main_test_changed_lines_locations(local_repos_dir, tasks_map_fpath)

    import ast
    code = """
    
import os
    
s = 1
print(s)
    
    """
    print(code)
    tree = ast.parse(code)
    print(tree)
