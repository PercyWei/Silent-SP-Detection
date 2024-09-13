import os
import subprocess

from typing import *

from logs import base_log_and_cprint


def make_hie_dirs(root: str, *dirs: str) -> str:
    """Make hierarchical directories recursively."""
    new_dpath = os.path.join(root, *dirs)
    if not os.path.exists(new_dpath):
        os.makedirs(new_dpath, exist_ok=True)

    return new_dpath


def run_command(
        command: List[str],
        print_log: bool = True,
        print_stdout: bool = True,
        raise_error: bool = True,
        **run_params
) -> Tuple[Optional[subprocess.CompletedProcess], Optional[str]]:
    """
    Run a command in the shell.

    Args:
        command (List(str)): The command to run.
        print_log (bool): If True, print details to the log.
        print_stdout (bool): If True, print details to the stdout.
        raise_error (bool): If Ture, raise error when command failed.
        run_params: Params to pass to the `subprocess.run`.
    Returns:
        subprocess.CompletedProcess | None: Result of running the command, or None if the run failed.
        str | None: Error message, or None if the run succeed.
    """
    try:
        result = subprocess.run(command, check=True, **run_params)
        return result, None

    except subprocess.CalledProcessError as e:
        error_msg = f"Error running command: {command}, {e}"
        base_log_and_cprint(error_msg, print_log=print_log, print_stdout=print_stdout)
        if raise_error:
            raise e
        return None, str(e)

    except Exception as e:
        error_msg = f"Error running command: {command}, {e}"
        base_log_and_cprint(error_msg, print_log=print_log, print_stdout=print_stdout)
        if raise_error:
            raise e
        return None, str(e)

