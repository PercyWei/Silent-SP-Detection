# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/inference.py

import os
import json
import inspect

from typing import *
from pathlib import Path
from termcolor import colored

from loguru import logger

from agent_app import globals, globals_mut
from agent_app.api.manage import ProjectApiManager
from agent_app.api.commit import extract_useful_commit_content_info
from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import FunctionCallIntent, MessageThread
from agent_app.log import (
    print_banner, print_acr, print_retrieval, print_commit_content,
    log_and_print, log_and_cprint
)
from agent_app.util import parse_function_invocation

# FIXME: the system prompt should be different for stratified/state machine.
SYSTEM_PROMPT = """
You are a software developer developing based on a large open source project.
For a new commit to this open source project, you are determining the possible impact of it.
The changed code snippet corresponding to the commit is between <commit> and </commit>.
Your task is to determine whether the commit fixes the vulnerability, 
and if so, give the most likely type of vulnerability, which is denoted by CWE-ID.
To achieve this, you need to keep making hypothesis based on the information you already have, 
and then use a few search API calls to gather relevant information and verify that the hypothesis is correct. 
Finally, choose that hypothesis that you think is most likely as the result.
"""


def prepare_commit_prompt(commit_content: str) -> str:
    """
    Given the raw commit content, sanitize it and prepare the commit prompt.
    Args:
        commit_content (str): The raw commit content.
            Assumption: This commit content is the full content generated directly from cmd 'git show <commit_id> >'
    Returns:
        str: The commit prompt.
    """
    # TODO: The current form of the commit prompt is the simplest, without adding any contextual information!
    commit_info = extract_useful_commit_content_info(commit_content)

    # FIXME: Not complete!

    # add tags
    commit_prompt = "<commit>\n" + commit_prompt + "\n</commit>"
    return commit_prompt


def start_conversation_round_stratified(
    output_dpath: str,
    msg_thread: MessageThread,
    api_manager: ProjectApiManager,
    start_round_no: int = 0,
    print_callback: Optional[Callable[[dict], None]] = None,
) -> bool:
    """
    This version uses json data to process API calls, instead of using the OpenAI function calling.
    Advantage is that multiple API calls can be made in a single round.
    """
    prompt = (
        "Based on the files, classes, methods, and code statements from the issue related to the bug, you can use the following search APIs to get more context of the project."
        "\n- search_class(class_name: str): Search for a class in the codebase"
        "\n- search_method_in_file(method_name: str, file_path: str): Search for a method in a given file"
        "\n- search_method_in_class(method_name: str, class_name: str): Search for a method in a given class"
        "\n- search_method(method_name: str): Search for a method in the entire codebase"
        "\n- search_code(code_str: str): Search for a code snippet in the entire codebase"
        "\n- search_code_in_file(code_str: str, file_path: str): Search for a code snippet in a given file file"
        "\n\nNote that you can use multiple search APIs in one round."
        "\n\nNow analyze the issue and select necessary APIs to get more context of the project. Each API call must have concrete arguments as inputs."
    )
    msg_thread.add_user(prompt)

    round_no = start_round_no
    for round_no in range(start_round_no, globals.conv_round_limit + 1):
        api_manager.start_new_tool_call_layer()

        conversation_fpath = os.path.join(output_dpath, f"round_{round_no}_conversation.json")
        # save current state before starting a new round
        msg_thread.save_to_file(conversation_fpath)

        print_banner(f"CONTEXT RETRIEVAL ROUND {round_no}")

        # FIXME:
        #  1. Why 'start_round_no' not 'round_no'?
        #  2. Why print prompt each round? However, the prompt only happens before rounds
        print_acr(
            msg=prompt,
            desc=f"context retrieval round {start_round_no}",
            print_callback=print_callback
        )

        # Ask the Context Retrieval Agent
        respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg())
        msg_thread.add_model(respond_text, tools=[])
        print_retrieval(
            msg=respond_text,
            desc=f"round {round_no}",
            print_callback=print_callback
        )

        # Ask another agent to extract the api function calls from the current response
        selected_apis, _, proxy_msg_threads = api_manager.proxy_apis(respond_text)

        proxy_log = Path(output_dpath, f"{round_no}_agent_proxy.json")
        proxy_messages = [thread.to_msg() for thread in proxy_msg_threads]
        proxy_log.write_text(json.dumps(proxy_messages, indent=4))

        # Start a new round conversation if api function calls extraction failed
        if selected_apis is None:
            retry_msg = "The search API calls seem not valid. Please check the arguments you give carefully and try again."
            msg_thread.add_user(retry_msg)
            print_acr(
                msg=retry_msg,
                desc=f"context retrieval round {round_no}",
                print_callback=print_callback
            )
            continue

        selected_apis_json = json.loads(selected_apis)

        json_api_calls = selected_apis_json.get("API_calls", [])
        # FIXME: We do not need bug_locations but patch_locations maybe
        buggy_locations = selected_apis_json.get("bug_locations", [])

        formatted = []
        if json_api_calls:
            formatted.append("API calls:")
            for call in json_api_calls:
                formatted.extend([f"\n- `{call}`"])

        # FIXME: Need to change also
        """ START """
        if buggy_locations:
            formatted.append("\n\nBug locations")
            for location in buggy_locations:
                s = ", ".join(f"{k}: `{v}`" for k, v in location.items())
                formatted.extend([f"\n- {s}"])

        print_acr(
            "\n".join(formatted),
            "Agent-selected API calls",
            print_callback=print_callback
        )

        # collected enough information to write patch
        if buggy_locations and (not json_api_calls):
            collated_tool_response = "Here is the code in buggy locations:\n\n"
            # provide the buggy locations to the model
            for bug_location in buggy_locations:
                tool_output, *_ = search_for_bug_location(
                    api_manager, msg_thread, bug_location
                )
                collated_tool_response += f"\n\n{tool_output}\n"

            if (
                "Unknown function" not in collated_tool_response
                and "Could not" not in collated_tool_response
            ):
                msg_thread.add_user(collated_tool_response)

                print_banner("PATCH GENERATION")
                logger.debug("Gathered enough information. Invoking write_patch.")
                print_acr(
                    collated_tool_response,
                    "patch generation round 1",
                    print_callback=print_callback
                )
                break

            retry_msg = "The buggy locations is not precise. You may need to check whether the arguments are correct and search more information."
            msg_thread.add_user(retry_msg)
            print_acr(
                msg=retry_msg,
                desc=f"context retrieval round {round_no}",
                print_callback=print_callback,
            )
            continue

        """ END """

        # Invoke tools and prepare response according to api function calls
        collated_tool_response = ""

        for api_call in json_api_calls:
            func_name, func_arg_values = parse_function_invocation(api_call)

            func_arg_spec = inspect.getfullargspec(getattr(SearchManager, func_name))
            func_arg_names = func_arg_spec.args[1:]  # first parameter is self

            assert len(func_arg_values) == len(func_arg_names), f"Number of argument is wrong in API call: {api_call}"

            func_arg_kwargs = dict(zip(func_arg_names, func_arg_values))
            intent = FunctionCallIntent(func_name, func_arg_kwargs, None)
            tool_output, _, _ = api_manager.dispatch_intent(intent, msg_thread)

            collated_tool_response += f"Result of {api_call}:\n\n"
            collated_tool_response += tool_output + "\n\n"

        msg_thread.add_user(collated_tool_response)
        print_acr(
            collated_tool_response,
            f"context retrieval round {round_no}",
            print_callback=print_callback
        )

        analyze_context_msg = "Let's analyze collected context first"
        msg_thread.add_user(analyze_context_msg)
        print_acr(
            msg=analyze_context_msg,
            desc=f"context retrieval round {round_no}",
            print_callback=print_callback
        )

        respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg())
        msg_thread.add_model(respond_text, tools=[])
        print_retrieval(
            msg=respond_text,
            desc=f"round {round_no}",
            print_callback=print_callback
        )

        if round_no < globals.conv_round_limit:
            decide_next_action_msg = (
                "Based on your analysis, answer below questions:"
                "\n Q1- Do we need more context to verify the hypothesis: only answer with 'Yes' or 'No'"
                "\n Q2- How to construct search API calls to get more context of the project: leave it empty if you answer Q1 with 'Yes'"
            )
            # FIXME: Does this same thing happen with my questions? If so, update the prompt
            if isinstance(common.SELECTED_MODEL, ollama.OllamaModel):
                # llama models tend to always output search APIs and buggy locations.
                decide_next_action_msg += "\n\nNOTE: If you have already identified the bug locations, do not make any search API calls."
            msg_thread.add_user(decide_next_action_msg)
            print_acr(
                msg=decide_next_action_msg,
                desc=f"context retrieval round {round_no}",
                print_callback=print_callback
            )
    else:
        logger.info("Too many rounds. Try writing patch anyway.")

    round_no += 1

    api_manager.start_new_tool_call_layer()

    # FIXME: Update!
    write_patch_intent = FunctionCallIntent("write_patch", {}, None)
    api_manager.dispatch_intent(
        write_patch_intent, msg_thread, print_callback=print_callback
    )

    conversation_fpath = os.path.join(output_dpath, f"round_{round_no}_conversation.json")
    msg_thread.save_to_file(conversation_fpath)

    logger.info("Invoked write_patch. Ending workflow.")

    return True


def add_step_trigger(orig_prompt: str, is_first: bool = False) -> str:
    """
    Given the original prompt, add the trigger question for the next step.
    Args:
        orig_prompt (str): The original prompt.
        is_first (bool): Whether the trigger is for the first step.
    Returns:
        str: The prompt with trigger question.
    """
    if is_first:
        trigger = "What is the first step?"
    else:
        trigger = "What's the next step to complete the task? Be reminded that you are solving the initial issue."
    return orig_prompt + "\n" + trigger


def start_conversation_round_state_machine(
    output_dpath: str,
    msg_thread: MessageThread,
    api_manager: ProjectApiManager,
    start_round_no: int = 0,
) -> bool:
    """
    Start the actual rounds of conversations with model.

    Args:
        output_dpath (str): Path to the output directory.
        msg_thread (MessageThread): The message thread to be used.
        api_manager (ProjectApiManager): The API manager to be used.
        start_round_no (int): The round number to start with.
    """
    round_no = start_round_no
    for round_no in range(start_round_no, globals.conv_round_limit + 1):
        conversation_file = os.path.join(output_dpath, f"round_{round_no}_conversation.json")
        # save current state before starting a new round
        msg_thread.save_to_file(conversation_file)
        log_and_cprint(f"\n========== Conversation Round {round_no} ==========", style="red bold")
        log_and_print(f"{colored('Current message thread:', 'green')}\n{msg_thread}")

        allowed_tools = api_manager.next_tools()
        # TODO: configure the list of tools based on state machine
        tools = ProjectApiManager.get_full_funcs_for_openai(allowed_tools)

        log_and_cprint(f"Current tool: {api_manager.curr_tool}", style="yellow")
        log_and_cprint(f"Allowed next tools: {allowed_tools}", style="yellow")

        # Create a new iteration of conversation
        res_text, raw_tool_calls, func_call_intents, *_ = common.SELECTED_MODEL.call(
            msg_thread.to_msg(), tools=tools
        )
        log_and_print(
            f"{colored('This round model response (text):', 'blue')} {res_text}"
        )
        # Model can decide whether to create a function call
        # FIXME: Can model only give one tool at a time?
        if len(func_call_intents) == 1:
            # Good case in which we can check function call
            func_call_intent: FunctionCallIntent = func_call_intents[0]
            log_and_print(
                f"{colored('This round model response (function call):', 'blue')} {func_call_intent}"
            )
            # Dispatch this function call
            this_model_response = res_text
            this_model_tools = raw_tool_calls
            # Add previous call information to user message
            tool_output, summary, _ = api_manager.dispatch_intent(func_call_intent, msg_thread)
        else:
            # No function call, let's force the model to make one
            this_model_response = res_text
            this_model_tools = []
            tool_output = ""
            summary = "There is no function call in your previous response. Make sure you include one function call. "

        next_user_message = add_step_trigger(summary)

        # form message thread for next round. should include what the model said as well
        msg_thread.add_model(this_model_response, this_model_tools)
        if this_model_tools:
            tool_call_id = this_model_tools[0].id
            msg_thread.add_tool(tool_output, tool_call_id)
            msg_thread.add_user(next_user_message)
        else:
            msg_thread.add_user(next_user_message)

        if len(func_call_intents) == 1:
            func_call_name = func_call_intents[0].func_name
            if func_call_name == "write_patch":
                log_and_print("Ending workflow. write_patch has been invoked.")
                break

        log_and_print("Going to next round ..........")
    else:
        log_and_print("Too many rounds. Try writing patch anyway.")
        write_patch_intent = FunctionCallIntent("write_patch", {}, None)
        api_manager.dispatch_intent(write_patch_intent, msg_thread)

    round_no += 1

    # if we end the workflow normally, there is one more round of conversation to store
    conversation_file = os.path.join(output_dpath, f"round_{round_no}_conversation.json")
    msg_thread.save_to_file(conversation_file)
    return True


def run_one_task(
    output_dpath: str,
    api_manager: ProjectApiManager,
    commit_content: str,
    print_callback: Optional[Callable[[dict], None]] = None,
) -> bool:
    """
    Main entry point to run inference on one task.

    Args:
        output_dpath (str): Path to the output directory.
        api_manager (ProjectApiManager): The already-initialized API manager.
        commit_content (str): The original commit content submitted to the task issue.
        print_callback:
    """
    print_banner("Starting AutoCodeRover on the following issue")
    print_commit_content(commit_content)
    msg_thread = MessageThread()

    system_prompt = SYSTEM_PROMPT
    if (not globals.enable_layered) and common.SELECTED_MODEL.parallel_tool_call:
        # these models support parallel tool calls, let's try to make them not do it
        system_prompt += " In your response, DO NOT make more than one tool call."

    msg_thread.add_system(system_prompt)
    init_prompt = prepare_commit_prompt(commit_content)
    msg_thread.add_user(init_prompt)

    if globals.enable_layered:
        return start_conversation_round_stratified(
            output_dpath, msg_thread, api_manager, print_callback=print_callback
        )
    else:
        return start_conversation_round_state_machine(
            output_dpath, msg_thread, api_manager
        )
