# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/old_utils.py

import os
import tempfile
import ast
import contextlib
import re
import shutil
import glob
import subprocess

from typing import *
from pathlib import Path

from agent_app import globals
from agent_app.log import print_stdout, log_and_print
from utils import run_command as base_run_command


class LanguageNotSupportedError(Exception):
    def __init__(self, lang: str):
        self.lang = lang

    def __str__(self):
        return f"Language {self.lang} is not supported yet"


"""TEMPORARY FILE"""


def make_tmp_file(content: str, suffix: str = ".java") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode='w', dir=globals.temp_dpath) as tmp_file:
        tmp_file.write(content)
        return tmp_file.name


def remove_tmp_file(code_fpath: str):
    try:
        os.remove(code_fpath)
    except FileNotFoundError:
        log_and_print(f"File not found while deleting '{code_fpath}'")
    except PermissionError:
        log_and_print(f"Permission denied while deleting '{code_fpath}'")
    except Exception as e:
        log_and_print(f"Exception {str(e)} while deleting '{code_fpath}'")


""""""

@contextlib.contextmanager
def cd(new_dpath: str):
    """
    Context manager for changing the current working directory

    Args:
        new_dpath: Path to the new directory
    """
    prev_dpath = os.getcwd()
    os.chdir(os.path.expanduser(new_dpath))
    try:
        yield
    finally:
        os.chdir(prev_dpath)


def run_command(command: List[str], raise_error: bool = True, **run_params) -> Optional[subprocess.CompletedProcess]:
    """
    Run a command in the shell.

    Args:
        command : The command to execute
        raise_error : If Ture, raise error when command fails
        run_params: Params to pass to the `subprocess.run`
    Returns:
        Result of running the command, or None if the run failed
    """
    result, _ = base_run_command(command, print_stdout=print_stdout, raise_error=raise_error, **run_params)

    return result


def create_dir_if_not_exists(dpath: str):
    """
    Create a directory if it does not exist.

    Args:
        dpath (str): Path to the directory
    """
    if not os.path.exists(dpath):
        os.makedirs(dpath, exist_ok=True)


def to_relative_path(file_path: str, project_root: str) -> str:
    """Convert an absolute path to a path relative to the project root.

    Args:
        file_path (str): The absolute path to file.
        project_root (str): Absolute path to the project root dir.

    Returns:
        str: The relative path.
    """
    if Path(file_path).is_absolute():
        return str(Path(file_path).relative_to(project_root))
    else:
        return file_path


"""GITHUB REPO AND COMMIT"""


def clone_repo(auth_repo: str, local_repo_dpath: str, timeout: int = 300, token: str = '') -> bool:
    """
    Clone a GitHub repository to local.

    Args:
        auth_repo (str): Form like 'auther_name/repo_name'.
        local_repo_dpath (str): Path to the local dir for saving this repo.
        timeout (int): Timeout in seconds.
        token (str): GitHub OAuth token.

    Returns:
        bool:
            True: Successfully Clone.
            False: Unsuccessfully Clone.
    """
    repo_url = f"https://{token}@github.com/{auth_repo}.git"
    clone_command = ["git", "clone", repo_url, local_repo_dpath]
    res = run_command(clone_command, raise_error=False, timeout=timeout)

    if res is None:
        # Delete local dir for saving this repo
        try:
            shutil.rmtree(local_repo_dpath)
        except Exception as e:
            pass
        return False
    else:
        return True


def get_head_commit_hash(local_repo_dpath: str | None = None) -> str | None:
    cmd = ["git", "rev-parse", "HEAD"]
    res = run_command(cmd, raise_error=False,
                      cwd=local_repo_dpath, text=True, capture_output=True)
    if res is None:
        return None
    return res.stdout.strip()


def get_commit_info(commit_hash: str, local_repo_dpath: str | None = None) -> str | None:
    """
    Output of 'git cat-file -p <commit_hash>' is as follows:
    ---------------------------------------------
    tree <tree_hash>
    parent <parent_commit_hash>
    ...
    parent <parent_commit_hash>
    author <author_name> <email> <timestamp>
    committer <author_name> <email> <timestamp>
    <other_info>
    ---------------------------------------------
    """
    show_cmd = ["git", "cat-file", "-p", commit_hash]
    result = run_command(show_cmd, raise_error=False,
                         cwd=local_repo_dpath, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result is None:
        return None
    return result.stdout


def get_parent_commit_hashes(commit_hash: str, local_repo_dpath: str | None = None) -> List[str] | None:
    commit_info = get_commit_info(commit_hash, local_repo_dpath)
    if commit_info is None:
        return None

    lines = commit_info.splitlines(keepends=False)
    assert re.fullmatch(r"tree\s+([a-f0-9]+)", lines[0])

    parent_hashes: List[str] = []
    for line in lines[1:]:
        match = re.fullmatch(r"parent\s+([a-f0-9]+)", line)
        if match:
            parent_hash = match.group(1)
            parent_hashes.append(parent_hash)
        else:
            break

    return parent_hashes


def get_commit_content(commit_hash: str, local_repo_dpath: str | None = None) -> str | None:
    show_cmd = ["git", "show", "-m", commit_hash]
    result = run_command(show_cmd, raise_error=False,
                         cwd=local_repo_dpath, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result is None:
        return None
    return result.stdout


def repo_reset_and_clean_checkout(commit_hash: str) -> None:
    """
    Run commands to reset repo to the original commit state.
    Cleans both the uncommited changes and the untracked files, and submodule changes.
    Assumption: The current directory is the git repository.
    """
    # NOTE: Do these before `git reset`. This is because some of the removed files below
    # may actually be in version control. So even if we deleted such files here, they
    # will be brought back by `git reset`.
    # Clean files that might be in .gitignore, but could have been created by previous runs

    reset_cmd = ["git", "reset", "--hard", commit_hash]
    clean_cmd = ["git", "clean", "-fd"]
    checkout_cmd = ["git", "checkout", commit_hash]
    run_command(reset_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_command(clean_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Need checkout before submodule init, otherwise submodule may init to another version
    run_command(checkout_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # This is a fail-safe combo to reset any changes to the submodule: first unbind all submodules
    # and then make a fresh checkout of them.
    # Reference: https://stackoverflow.com/questions/10906554/how-do-i-revert-my-changes-to-a-git-submodule
    submodule_unbind_cmd = ["git", "submodule", "deinit", "-f", "."]
    submodule_init_cmd = ["git", "submodule", "update", "--init"]
    run_command(submodule_unbind_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_command(submodule_init_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def repo_checkout(commit_hash: str) -> None:
    checkout_cmd = ["git", "checkout", commit_hash]
    run_command(checkout_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def parse_function_invocation(invocation_str: str) -> Tuple[str, List[str]]:
    try:
        tree = ast.parse(invocation_str)
        expr = tree.body[0]
        assert isinstance(expr, ast.Expr)
        call = expr.value
        assert isinstance(call, ast.Call)
        func = call.func
        assert isinstance(func, ast.Name)
        function_name = func.id
        raw_arguments = [ast.unparse(arg) for arg in call.args]
        # clean up spaces or quotes, just in case
        arguments = [arg.strip().strip("'").strip('"') for arg in raw_arguments]

        try:
            new_arguments = [ast.literal_eval(x) for x in raw_arguments]
            if new_arguments != arguments:
                log_and_print(
                    f"Refactored invocation argument parsing gives different result on "
                    f"{invocation_str!r}: old result is {arguments!r}, new result is {new_arguments!r}"
                )
        except Exception as e:
            log_and_print(
                f"Refactored invocation argument parsing failed on {invocation_str!r}: {e!s}"
            )
    except Exception as e:
        raise ValueError(f"Invalid function invocation: {invocation_str}") from e

    return function_name, arguments




