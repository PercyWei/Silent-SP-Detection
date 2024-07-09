# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/utils.py

import os
import ast
import contextlib
import datetime
import glob
import subprocess

from typing import *


from agent_app.log import log_and_print


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
    try:
        result = subprocess.run(command, check=True, **run_params)
        return result
    except subprocess.CalledProcessError as e:
        log_and_print(f"Error running command: {command}, {e}")
        if raise_error:
            raise e
    except Exception as e:
        log_and_print(f"Error running command: {command}, {e}")
        if raise_error:
            raise e
    return None


def create_dir_if_not_exists(dpath: str):
    """
    Create a directory if it does not exist.

    Args:
        dpath (str): Path to the directory
    """
    if not os.path.exists(dpath):
        os.makedirs(dpath, exist_ok=True)


"""GITHUB REPO AND COMMIT"""


def get_commit_content(commit_hash: str) -> Optional[str]:
    show_cmd = ["git", "show", commit_hash]
    result = run_command(show_cmd, raise_error=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result is None:
        log_and_print(f"Fail to get commit content: {commit_hash}")
        return None
    return result.stdout


def repo_reset_and_clean_checkout(commit_hash: str) -> None:
    """
    Run commands to reset repo to the original commit state.
    Cleans both the uncommited changes and the untracked files, and submodule changes.
    Assumption: The current directory is the git repository.
    """
    # NOTE: do these before `git reset`. This is because some of the removed files below
    # may actually be in version control. So even if we deleted such files here, they
    # will be brought back by `git reset`.
    # Clean files that might be in .gitignore, but could have been created by previous runs
    # TODO: If my project has coverage tests?
    # if os.path.exists(".coverage"):
    #     os.remove(".coverage")
    # if os.path.exists("tests/.coveragerc"):
    #     os.remove("tests/.coveragerc")
    # other_cov_files = glob.glob(".coverage.TSS.*", recursive=True)
    # for f in other_cov_files:
    #     os.remove(f)

    reset_cmd = ["git", "reset", "--hard", commit_hash]
    clean_cmd = ["git", "clean", "-fd"]
    checkout_cmd = ["git", "checkout", commit_hash]
    run_command(reset_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_command(clean_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Need to checkout before submodule init, otherwise submodule may init to another version
    run_command(checkout_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # This is a fail-safe combo to reset any changes to the submodule: first unbind all submodules
    # and then make a fresh checkout of them.
    # Reference: https://stackoverflow.com/questions/10906554/how-do-i-revert-my-changes-to-a-git-submodule
    submodule_unbind_cmd = ["git", "submodule", "deinit", "-f", "."]
    submodule_init_cmd = ["git", "submodule", "update", "--init"]
    run_command(submodule_unbind_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run_command(submodule_init_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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




