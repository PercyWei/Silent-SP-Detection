import os
import json
import inspect

from typing import *

from agent_app import globals, globals_opt, log
from agent_app.data_structures import ProxyTask, ToolCallIntent, MessageThread, SearchStatus
from agent_app.api.manage import FlowManager
from agent_app.search.search_manage import PySearchManager, JavaSearchManager
from agent_app.flow_control.flow_recording import State, ProcOutPaths, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_usr_msg_and_print,
    _ask_actor_agent_and_print,
    _ask_proxy_agent_and_print,
    _save_proxy_msg,
    get_api_calls_prompt
)
from agent_app.util import LanguageNotSupportedError, parse_function_invocation


def _get_retrieval_prompt(round_no: int, retry_flag: bool) -> str:
    api_calls_des = get_api_calls_prompt(globals.lang)
    if round_no == 1:
        # Initial round
        retrieval_prompt = (
            "Before conducting a formal analysis of the current hypothesis, you must get enough contextual code information."
            "\nSo in this step, based on the hypothesis and the existing code snippets, please select the necessary search APIs for more background information related to this commit."
            f"\n{api_calls_des}"
        )
    elif not retry_flag:
        # Normal round
        retrieval_prompt = (
            "Based on the extracted code snippets related to the commit, answer the question below:"
            "\n - Do we need more context: construct search API calls to get more context of the project. (leave it empty if you don't need more context)"
            f"\n{api_calls_des}"
        )
    else:
        # Retry round
        retrieval_prompt = "The search API calls seem not invalid. Please check the arguments you give carefully and try again."

    return retrieval_prompt


def call_search_apis(
        process_no: int,
        loop_no: int,
        round_no: int,
        retry_flag: bool,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> Tuple[bool, bool]:
    """Return continue flag and retry flag."""
    round_print_desc = f"process {process_no} | state {State.CONTEXT_RETRIEVAL_STATE} | loop {loop_no} | round {round_no}"

    # For recording tool calls in current round
    manager.start_new_tool_call_layer()

    # ------------------ (1) Prepare the prompt ------------------ #
    retrieval_prompt = _get_retrieval_prompt(round_no, retry_flag)
    _add_usr_msg_and_print(retrieval_prompt, msg_thread, round_print_desc, print_callback)

    # ------------------ (2) Ask the LLM ------------------ #
    response = _ask_actor_agent_and_print(msg_thread, round_print_desc, print_callback)

    json_calls, _, proxy_msg_threads = _ask_proxy_agent_and_print(
        ProxyTask.CONTEXT_RETRIEVAL, response, manager, round_print_desc, print_callback
    )

    proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_context_retrieval.json")
    _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

    # ------------------ (3) Decide next step ------------------ #
    # (1) Whether to retry
    if json_calls is None:
        manager.action_status_records.update_tool_call_extraction_status(False)
        return True, True
    else:
        manager.action_status_records.update_tool_call_extraction_status(True)

    # (2) Whether to continue searching
    raw_tool_calls = json.loads(json_calls)["api_calls"]
    if len(raw_tool_calls) == 0:
        return False, False

    # ------------------ (4) Invoke tool calls and prepare the response ------------------ #
    collated_tool_response = ""

    # [(tool call statement, tool call reason)]
    executable_tool_calls: List[Tuple[str, str]] = []

    for tool_call_stmt, tool_call_reason in raw_tool_calls:
        # 1. Parse and invoke the tool call
        tool_name, tool_arg_values = parse_function_invocation(tool_call_stmt)

        if globals.lang == 'Python':
            tool_arg_spec = inspect.getfullargspec(getattr(PySearchManager, tool_name))
        elif globals.lang == 'Java':
            tool_arg_spec = inspect.getfullargspec(getattr(JavaSearchManager, tool_name))
        else:
            raise LanguageNotSupportedError(globals.lang)

        tool_arg_names = tool_arg_spec.args[1:]  # first parameter is self

        tool_arg2values = dict(zip(tool_arg_names, tool_arg_values))

        intent = ToolCallIntent(tool_name, tool_arg_names, tool_call_stmt, tool_arg2values, None)
        tool_output, search_status, all_search_res = manager.dispatch_intent(intent)


        # 2. Handle non-executable tool call
        # TODO: HOW TO HANDLE DIFFERENT SATUS?
        #       Consider whether to modify the conversation to make it clean.
        #       mtd1: Replace the original response from the Actor Agent with the result extracted by the Proxy Agent.
        #       mtd2: When the response of the Actor Agent is wrong and a formatted valid response is obtained after
        #               questioning, replace the original response with the final valid response.
        if search_status in [SearchStatus.WIDE_SEARCH_RANGE, SearchStatus.FIND_NONE,
                             SearchStatus.FIND_IMPORT, SearchStatus.FIND_CODE]:
            executable_tool_calls.append((tool_call_stmt, tool_call_reason))
        elif search_status in [SearchStatus.WRONG_ARGUMENT, SearchStatus.INVALID_ARGUMENT]:
            executable_tool_calls.append((tool_call_stmt, tool_call_reason))
        elif search_status == SearchStatus.DUPLICATE_CALL:
            pass
        elif search_status == SearchStatus.UNKNOWN_SEARCH_API:
            pass
        else:
            assert search_status == SearchStatus.DISPATCH_ERROR
            pass


        # 3. Record
        # (loop) tool call records
        manager.update_loop_tool_call_records(intent)
        # (process) executable tool calls
        if search_status in [SearchStatus.WIDE_SEARCH_RANGE, SearchStatus.FIND_NONE,
                             SearchStatus.FIND_IMPORT, SearchStatus.FIND_CODE]:
            manager.update_process_exec_tool_calls(intent)

        # Tool call response
        collated_tool_response += (f"Result of {tool_call_stmt}:"
                                   f"\n\n{tool_output}\n\n")

        # Extracted code snippet
        if intent.tool_name in ['search_top_level_function', 'search_class', 'search_interface'] and \
                globals_opt.opt_to_ctx_retrieval_detailed_search_struct_tool:
            proc_all_hypothesis.code_context.extend(all_search_res)

    collated_tool_response.rstrip()

    _add_usr_msg_and_print(collated_tool_response, msg_thread, round_print_desc, print_callback)

    return True, False


def analyse_collected_context(
        process_no: int,
        loop_no: int,
        round_no: int,
        msg_thread: MessageThread,
        print_callback: Callable[[dict], None] | None = None
):
    round_print_desc = f"process {process_no} | state {State.CONTEXT_RETRIEVAL_STATE} | loop {loop_no} | round {round_no}"

    analyze_context_msg = "First, let's briefly analyze the collected context to see if there are still unclear but important code snippets."

    _add_usr_msg_and_print(analyze_context_msg, msg_thread, round_print_desc, print_callback)

    _ = _ask_actor_agent_and_print(msg_thread, round_print_desc, print_callback)


def run_in_context_retrieval_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
):
    # Open a new recording the new loop
    manager.reset_loop_tool_call_records()

    retry_flag = False
    for round_no in range(1, globals.state_round_limit + 1):

        ## Step 1: Search the context
        continue_flag, retry_flag = call_search_apis(
            process_no=process_no,
            loop_no=loop_no,
            round_no=round_no,
            retry_flag=retry_flag,
            proc_all_hypothesis=proc_all_hypothesis,
            curr_proc_outs=curr_proc_outs,
            msg_thread=msg_thread,
            manager=manager,
            print_callback=print_callback
        )

        if not continue_flag:
            break

        ## Step 2: Analyze collected context before getting more context
        # TODO: Consider if necessary?
        if round_no < globals.state_round_limit and globals_opt.opt_to_ctx_retrieval_analysis:
            analyse_collected_context(
                process_no=process_no,
                loop_no=loop_no,
                round_no=round_no,
                msg_thread=msg_thread,
                print_callback=print_callback
            )
    else:
        log.log_and_print("Too many rounds. Try to verify the hypothesis anyway.")

    manager.dump_loop_tool_call_sequence_to_file(curr_proc_outs.tool_call_dpath, str(loop_no))
    manager.dump_loop_tool_call_layers_to_file(curr_proc_outs.tool_call_dpath, str(loop_no))

    return proc_all_hypothesis
