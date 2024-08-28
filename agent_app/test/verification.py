
import re
import os
import ast
import json
import glob
import time
import tokenize

from typing import *
from io import StringIO
from loguru import logger


from agent_app.commit.commit_util import extract_commit_content_info, get_code_after_commit, get_code_before_commit
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
    old_file_content = get_code_before_commit(local_repo_dpath, commit_hash, old_fname)
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
    new_file_content = get_code_after_commit(local_repo_dpath, commit_hash, new_fname)
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

    old_file_content = get_code_before_commit(local_repo_dpath, commit_hash, old_fname)
    new_file_content = get_code_after_commit(local_repo_dpath, commit_hash, new_fname)

    diff_classes_info, diff_funcs_info, diff_asyncFuncs_info = \
        match_diff_structs_within_file(old_file_content, new_file_content, diff_file_info)

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

    old_file_content = get_code_before_commit(local_repo_dpath, commit_hash, old_fname)
    new_file_content = get_code_after_commit(local_repo_dpath, commit_hash, new_fname)

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


"""TEST 5"""


def test5():
    # code = ('import os'
    #         '\n"""'
    #         '\nCopyright (c) 2018, <NAME>'
    #         '\n"""'
    #         '\ns = 1'
    #         '\nprint("start"'
    #         '\n      # comment'
    #         '\n      "end")')
    #

    code = """
import ast
import ast as st
import re, sys as sy, ast as aaa
from . import x
from .. import y
from .x import z
from a.b import c as abc, d

a = []
if len(a) > 1:
    print(a["a"])
else:
    a["b"] = 1

def a(n):
    return b+1
"""

    code = """
class item():
    @override_settings(DEBUG=True, ALLOWED_HOSTS=['www.example.com'])
    def test_https_bad_referer(self) -> int:
        req = self._get_POST_request_with_token()
        req._is_secure_override = True
        req.META['HTTP_HOST'] = 'www.example.com'
        req.META['HTTP_REFERER'] = 'https://www.evil.org/somepage'
        req.META['SERVER_PORT'] = '443'
        response = CsrfViewMiddleware().process_view(req, post_form_view, (), {})
        self.assertContains(
            response,
            'Referer checking failed - https://www.evil.org/somepage does not '
            'match any trusted origins.',
            status_code=403,
        )
        return req

if __name__ == "__main__":
    print(a)
"""

    code = """
@skipIf(six.PY2 and salt.utils.platform.is_windows(), "Skipped on windows py2")
class TestCleanPathLink(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.to_path = os.path.join(self.tmpdir, "linkto")
        self.from_path = os.path.join(self.tmpdir, "linkfrom")
        if six.PY2 or salt.utils.platform.is_windows():
            kwargs = {}
        else:
            kwargs = {"target_is_directory": True}
        if salt.utils.platform.is_windows():
            symlink(self.to_path, self.from_path, **kwargs)
        else:
            os.symlink(self.to_path, self.from_path, **kwargs)
    """

    print(code)
    tree = ast.parse(code)
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            class_children = list(ast.iter_child_nodes(node))

            for child in class_children:
                if isinstance(child, ast.FunctionDef):
                    class_function_children = list(ast.iter_child_nodes(child))
                    print(class_function_children)

        # if isinstance(node, ast.FunctionDef):
        #     children = list(ast.iter_child_nodes(node))
        #     print(ast.dump(children))

    print(tree)

    # file = "/root/projects/VDTest/output/dataset/zerver_models.py_before.json"
    # with open(file, 'r') as f:
    #     code = f.read()

    # tree = ast.parse(code)
    # print(ast.dump(tree))


def run_time():
    repo_dpath = "/root/projects/clone_projects/odoo_odoo"
    start = time.time()
    abs_fpaths = glob.glob(os.path.join(repo_dpath, "**/*.py"), recursive=True)
    end = time.time()
    print(time.time() - start)

    regex = re.compile("asdaf")

    start = time.time()
    for abs_fpath in abs_fpaths:
        match = regex.search(abs_fpath)
        if match:
            print(abs_fpath)
    print(time.time() - start)


def test6():
    loop_conv = "/root/projects/VDTest/output/agent/vul_2024-08-21T22:20:17/26-vulfix_2024-08-21T22:20:17/process_1/loop_6_conversations.json"
    with open(loop_conv, 'r') as f:
        conv = json.load(f)

    loop_conv = "/root/projects/VDTest/output/agent/vul_2024-08-21T22:20:17/26-vulfix_2024-08-21T22:20:17/process_1/loop_6.txt"
    with open(loop_conv, 'w') as f:
        for c in conv:
            f.write("-" * 40 + c["role"] + "-" * 40 + "\n")
            f.write(c["content"])
            f.write("\n\n" + "=" * 100 + "\n\n")


def print_conversation():
    conv_path = "/root/projects/VDTest/output/agent/vul_2024-08-28T11:03:41_SAVE/1231-vulfix_2024-08-28T11:03:42/process_1/loop_1_conversations.json"
    with open(conv_path, 'r') as f:
        convs = json.load(f)

    save_path = "/root/projects/VDTest/agent_app/test/conversation.txt"
    with open(save_path, 'w') as f:
        for conv in convs:
            f.write("ROLE: " + conv["role"] + "\n")
            f.write("CONTENT: " + conv["content"] + "\n\n")


if __name__ == '__main__':
    # local_repos_dir = "/root/projects/clone_projects"
    # tasks_map_fpath = "/root/projects/VDTest/output/TreeVul/TreeVul_valid_scsfCVE.json"
    # main_test_changed_lines_locations(local_repos_dir, tasks_map_fpath)

    print_conversation()



