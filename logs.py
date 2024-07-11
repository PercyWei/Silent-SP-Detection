import os
import datetime

from rich.console import Console

from loguru import logger


console = Console()


def get_timestamp() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')


def terminal_width():
    return os.get_terminal_size().columns


def base_log_and_cprint(msg, print_log: bool = True, print_stdout: bool = True, **kwargs):
    if print_log:
        logger.info(msg)
    if print_stdout:
        console.print(msg, **kwargs)
