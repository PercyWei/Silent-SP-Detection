# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/log.py

import os

from loguru import logger
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from agent_app.utils import get_timestamp


def terminal_width():
    return os.get_terminal_size().columns


WIDTH = min(120, terminal_width() - 10)

console = Console()

print_stdout = True


def log_exception(exception):
    logger.exception(exception)


def print_banner(msg: str) -> None:
    if not print_stdout:
        return

    banner = f" {msg} ".center(WIDTH, "=")
    console.print()
    console.print(banner, style="bold")
    console.print()


def log_and_print(msg):
    logger.info(msg)
    if print_stdout:
        console.print(msg)


def log_and_cprint(msg, **kwargs):
    logger.info(msg)
    if print_stdout:
        console.print(msg, **kwargs)


def log_and_always_print(msg):
    """
    A mode which always print to stdout.
    Useful when running multiple tasks, and we just want to see the important information.
    """
    logger.info(msg)
    # always include time for important messages
    console.print(f"\n[{get_timestamp()}] {msg}")


def print_with_time(msg):
    """
    Print a msg to console with timestamp.
    """
    console.print(f"\n[{get_timestamp()}] {msg}")
