import os
import json

from typing import *

from agent_app import globals, log
from agent_app.data_structures import ProxyTask, MessageThread
from agent_app.model import common
from agent_app.api.manage import ProcessManager
from agent_app.util import LanguageNotSupportedError


"""PROMPT"""


def get_system_prompt() -> str:
    return ("You are a software developer developing based on a large open source project."
            "\nYou are facing a commit to this open source project."
            "\nThe commit contains some code changes marked between <commit> and </commit>."
            "\nThe names of the code files involved are marked between <file> and </file>."
            "\nIf the code lines are in a class or function, the class name or function name is marked between <class> and </class> or <func> and </func>, respectively."
            "\nNOTE: A commit may contain multiple changed files, and a changed file may contain multiple changed code lines."
            "\n\nYour task is to determine whether the commit fixes the vulnerability, and if so, give the most likely type of vulnerability, which is denoted by CWE-ID."
            "\nTo achieve this, you need to make some reasonable hypothesis, and then use the search API calls to gather relevant context and verify the correctness of them.")


def get_hyp_def_prompt() -> str:
    return ("A hypothesis contains three attributes: commit type, vulnerability type and confidence score."
            "\n- commit type: It indicates whether the commit fixes a vulnerability. Choose answer from 'vulnerability_patch' and 'non_vulnerability_patch'."
            "\n- vulnerability type: It indicates the type of vulnerability that was fixed by this commit. Use CWE-ID as the answer, and leave it empty if you choose 'non_vulnerability_patch' for commit type."
            "\n- confidence score: It indicates the level of reliability of the hypothesis. Choose an integer between 1 and 10 as the answer."
            f"\n\nNOTE: The predicted CWE-ID should be limited to the range of weaknesses included in View-{globals.view_id}.")


def get_api_calls_prompt(lang: Literal['Python', 'Java']) -> str:
    if lang == 'Python':
        return ("You can use the following search APIs to get more context."
                "\n- search_class(class_name: str): Search for a class in the repo"
                "\n- search_class_in_file(class_name: str, file_name: str): Search for a class in the given file"
                "\n- search_method_in_file(method_name: str, file_name: str): Search for a method in the given file, including regular functions and class methods"
                "\n- search_method_in_class(method_name: str, class_name: str): Search for a method in the given class, i,e. class methods only"
                "\n- search_method_in_class_in_file(method_name: str, class_name: str, file_name: str): Search for a method in the given class of the given file, i,e. class methods only"
                "\n\nNOTE: You can use MULTIPLE search APIs in one round.")
    elif lang == 'Java':
        return ("You can use the following search APIs to get more context."
                "\n- search_interface(iface_name: str): Search for an interface in the repo"
                "\n- search_class(class_name: str): Search for a class in the repo"
                "\n- search_interface_in_file(iface_name: str, file_name: str): Search for an interface in the given file"
                "\n- search_class_in_file(class_name: str, file_name: str): Search for a class in the given file"
                "\n- search_type_in_class(ttype: ['interface', 'class', 'method'], type_name: str, class_name: str): Search for a type in the given class, while type indicates interface, class or method."
                "\n- search_type_in_class_in_file(ttype: ['interface', 'class', 'method'], type_name: str, class_name: str, file_name: str): Search for a type in the given class of the given file, while type indicates interface, class or method."
                "\n\nNOTE: You can use MULTIPLE search APIs in one round.")
    else:
        raise LanguageNotSupportedError(lang)


"""ACTION WITH LLM"""


def _add_system_msg_and_print(
        system_msg: str,
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> None:
    msg_thread.add_system(system_msg)
    log.print_system(msg=system_msg, desc=print_desc, print_callback=print_callback)


def _add_usr_msg_and_print(
        usr_msg: str,
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> None:
    msg_thread.add_user(usr_msg)
    log.print_user(msg=usr_msg, desc=print_desc, print_callback=print_callback)


def _ask_actor_agent_and_print(
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> str:
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg())
    msg_thread.add_model(respond_text, tools=[])
    log.print_actor(msg=respond_text, desc=print_desc, print_callback=print_callback)
    return respond_text


def _ask_proxy_agent_and_print(
        task: ProxyTask,
        text: str,
        manager: ProcessManager,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> Tuple[str | None, str | None, List[MessageThread]]:
    # TODO: Consider whether to add the Proxy Agent extraction failure summary while
    #       asking the Actor Agent in the new retry.
    json_text, failure_summary, proxy_msg_threads = manager.call_proxy_llm(globals.lang, text, task)
    log.print_proxy(msg=json_text, desc=print_desc, print_callback=print_callback)
    return json_text, failure_summary, proxy_msg_threads


def _save_proxy_msg(
        proxy_msg_threads: List[MessageThread],
        proxy_conv_fpath: str
) -> None:
    proxy_messages = [thread.to_msg() for thread in proxy_msg_threads]

    convs = []
    if os.path.exists(proxy_conv_fpath):
        with open(proxy_conv_fpath, "r") as f:
            convs = json.load(f)

    convs.append({len(convs) + 1: proxy_messages})

    with open(proxy_conv_fpath, "w") as f:
        json.dump(convs, f, indent=4)
