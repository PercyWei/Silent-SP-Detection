# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/log.py

import os
import json
import datetime

from typing import *
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

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


def print_user(msg: str, desc="", print_callback: Optional[Callable[[Dict], None]] = None) -> None:
    """
    Print message provided by User
    """
    if not print_stdout:
        return

    # msg = replace_html_tags(msg)
    # markdown = Markdown(msg)

    name = "User"
    if desc:
        title = f"{name} ({desc})"
    else:
        title = name

    panel = Panel(
        msg, title=title, title_align="left", border_style="magenta", width=WIDTH
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


def print_actor(msg: str, desc="", print_callback: Optional[Callable[[Dict], None]] = None) -> None:
    """
    Print message provided by the Actor Agent
    """
    if not print_stdout:
        return

    # msg = replace_html_tags(msg)
    # markdown = Markdown(msg)

    name = "Actor Agent"
    if desc:
        title = f"{name} ({desc})"
    else:
        title = name

    panel = Panel(
        msg, title=title, title_align="left", border_style="blue", width=WIDTH
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


def print_proxy(msg: str, desc="", print_callback: Optional[Callable[[Dict], None]] = None) -> None:
    """
    Print message provided by Proxy Agent
    """
    if not print_stdout:
        return

    # msg = replace_html_tags(msg)
    # markdown = Markdown(msg)

    text = Text(json.dumps(msg, indent=4))

    name = "Proxy Agent"
    if desc:
        title = f"{name} ({desc})"
    else:
        title = name

    panel = Panel(
        msg, title=title, title_align="left", border_style="yellow", width=WIDTH
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

