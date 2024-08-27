# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/log.py

import os
import json
import datetime

from typing import *
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from functools import partial

from loguru import logger

from logs import get_timestamp, terminal_width


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
        "<...>": "[...]",
        "<null>": "[null]",
        "<commit>": "[commit]",
        "<file>": "[file]",
        "<old_file>": "[old_file]",
        "<new_file>": "[new_file]",
        "<class>": "[class]",
        "<func>": "[func]",
        "<method>": "[method]",
        "<hunk>": "[hunk]",
        "<code>": "[code]",
        "<original>": "[original]",
        "<patched>": "[patched]",
        "</...>": "[/...]",
        "</null>": "[/null]",
        "</commit>": "[/commit]",
        "</file>": "[/file]",
        "</ld_file>": "[/old_file]",
        "</new_file>": "[/new_file]",
        "</class>": "[/class]",
        "</func>": "[/func]",
        "</method>": "[/method]",
        "</hunk>": "[/hunk]",
        "</code>": "[/code]",
        "</original>": "[/original]",
        "</patched>": "[/patched]",
    }
    for key, value in replace_dict.items():
        content = content.replace(key, value)
    return content


"""ROLE CONVERSATION PRINT"""


def print_role(
        role: str,
        msg: str,
        border_style: str = "blue",
        desc: str = "",
        print_callback: Optional[Callable[[Dict], None]] = None
) -> None:
    """
    Print message provided by Role (system / user / actor agent / proxy agent)
    """
    if not print_stdout:
        return

    if desc:
        title = f"{role} ({desc})"
    else:
        title = role

    panel = Panel(msg, title=title, title_align="left", border_style=border_style, width=WIDTH)
    console.print(panel)

    if print_callback:
        print_callback(
            {
                "title": f"{title}",
                "message": msg,
                "category": "silent_patch_identification"
            }
        )


print_system = partial(print_role, role="System", border_style="green")


print_user = partial(print_role, role="User", border_style="magenta")


print_actor = partial(print_role, role="Actor Agent", border_style="blue")


print_proxy = partial(print_role, role="Proxy Agent", border_style="yellow")


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


def always_cprint(msg, **kwargs):
    console.print(msg, **kwargs)

