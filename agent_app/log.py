# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/log.py

import os
import datetime

from typing import *
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from loguru import logger


def get_timestamp() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')


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


def replace_html_tags(content: str):
    """
    Helper method to process the content before printing to markdown.
    """
    # FIXME: Need update!
    replace_dict = {
        "<file>": "[file]",
        "<class>": "[class]",
        "<func>": "[func]",
        "<method>": "[method]",
        "<code>": "[code]",
        "<original>": "[original]",
        "<patched>": "[patched]",
        "</file>": "[/file]",
        "</class>": "[/class]",
        "</func>": "[/func]",
        "</method>": "[/method]",
        "</code>": "[/code]",
        "</original>": "[/original]",
        "</patched>": "[/patched]",
    }
    for key, value in replace_dict.items():
        content = content.replace(key, value)
    return content


def print_acr(msg: str, desc="", print_callback: Optional[Callable[[Dict], None]] = None) -> None:
    """
    Print message provided by User
    """
    if not print_stdout:
        return

    msg = replace_html_tags(msg)
    markdown = Markdown(msg)

    name = "Silent Patch Identification User"
    if desc:
        title = f"{name} ({desc})"
    else:
        title = name

    panel = Panel(
        markdown, title=title, title_align="left", border_style="magenta", width=WIDTH
    )
    console.print(panel)

    if print_callback:
        print_callback(
            {
                "title": f"{name} ({desc})",
                "message": msg,
                "category": "silent_patch_identification"
            }
        )


def print_retrieval(msg: str, desc="", print_callback: Optional[Callable[[Dict], None]] = None) -> None:
    """
    Print message provided by the Context Retrieval Agent
    """
    if not print_stdout:
        return

    msg = replace_html_tags(msg)
    markdown = Markdown(msg)

    name = "Context Retrieval Agent"
    if desc:
        title = f"{name} ({desc})"
    else:
        title = name

    panel = Panel(
        markdown, title=title, title_align="left", border_style="blue", width=WIDTH
    )
    console.print(panel)

    if print_callback:
        print_callback(
            {
                "title": f"{name} ({desc})",
                "message": msg,
                "category": "context_retrieval_agent"
            }
        )


def print_commit_content(content: str, verbose: bool = False) -> None:
    if not print_stdout:
        return

    if not verbose:
        # TODO: Need finer handling later
        content = '\n'.join(content.split('\n')[:7])

    title = "Commit content"
    panel = Panel(
        content, title=title, title_align="left", border_style="red", width=WIDTH
    )
    console.print(panel)


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
