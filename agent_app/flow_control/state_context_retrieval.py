import os
import json
import inspect

from typing import *

from agent_app import globals, log
from agent_app.data_structures import ProxyTask, FunctionCallIntent, MessageThread
from agent_app.api.manage import ProcessManager
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


def run_in_context_retrieval_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
):
    # Open a new recording the new loop
    manager.reset_too_call_recordings()

    # TODO: Consider whether to modify the conversation to make it clean.
    #       mtd1: Replace the original response from the Actor Agent with the result extracted by the Proxy Agent.
    #       mtd2: When the response of the Actor Agent is wrong and a formatted valid response is obtained after
    #               questioning, replace the original response with the final valid response.

    #############################
    # STEP 2: Context retrieval #
    #############################

    retry_flag = False
    for round_no in range(1, globals.state_round_limit + 1):
        round_print_desc = f"process {process_no} | state {State.CONTEXT_RETRIEVAL_STATE} | loop {loop_no} | round {round_no}"

        # For recording tool calls in current round
        manager.start_new_tool_call_layer()

        # ------------------ 1.1 Prepare the prompt ------------------ #
        api_calls_des = get_api_calls_prompt(globals.lang)
        if round_no == 1:
            # Init round
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
            retrieval_prompt = "The search API calls seem not valid. Please check the arguments you give carefully and try again."
        _add_usr_msg_and_print(retrieval_prompt, msg_thread, round_print_desc, print_callback)

        # ------------------ 1.2 Ask the LLM ------------------ #
        response = _ask_actor_agent_and_print(msg_thread, round_print_desc, print_callback)

        json_apis, _, proxy_msg_threads = _ask_proxy_agent_and_print(
            ProxyTask.CONTEXT_RETRIEVAL, response, manager, round_print_desc, print_callback
        )

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_context_retrieval.json")
        _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

        # ------------------ 1.3 Decide next step ------------------ #
        # (1) Whether to retry
        if json_apis is None:
            retry_flag = True
            continue
        else:
            retry_flag = False

        raw_apis = json.loads(json_apis)["api_calls"]

        # (2) Whether to stop searching
        if len(raw_apis) == 0:
            break

        # ------------------ 1.4 Invoke tools and prepare the response ------------------ #
        collated_tool_response = ""

        for api_call in raw_apis:
            func_name, func_arg_values = parse_function_invocation(api_call)

            if globals.lang == 'Python':
                func_arg_spec = inspect.getfullargspec(getattr(PySearchManager, func_name))
            elif globals.lang == 'Java':
                func_arg_spec = inspect.getfullargspec(getattr(JavaSearchManager, func_name))
            else:
                raise LanguageNotSupportedError(globals.lang)

            func_arg_names = func_arg_spec.args[1:]  # first parameter is self

            func_arg_kwargs = dict(zip(func_arg_names, func_arg_values))
            intent = FunctionCallIntent(func_name, func_arg_names, api_call, func_arg_kwargs, None)
            tool_output, search_status, all_search_res = manager.dispatch_intent(intent)

            # TODO: For searches that do not meet the requirements, i.e. search_status = DISPATCH_ERROR /
            #       INVALID_ARGUMENT / NON_UNIQUE_FILE, consider whether to ask separately first to get the
            #       format api calls and then return the results together

            # (1) Collect str response
            collated_tool_response += (f"Result of {api_call}:"
                                       f"\n\n{tool_output}\n\n")

            # (2) Collect code snippet extracted
            proc_all_hypothesis.code_context.extend(all_search_res)

        collated_tool_response.rstrip()

        _add_usr_msg_and_print(collated_tool_response, msg_thread, round_print_desc, print_callback)

        # TODO: Consider whether to analyse before continuing to search for context?
        # Before getting more context, analyze whether it is necessary to continue
        # analyze_context_msg = ("First, let's briefly analyze the collected context to see if there are "
        #                        "still unclear but important code snippets.")
        # _add_usr_msg_and_print(
        #     msg_thread=msg_thread,
        #     usr_msg=analyze_context_msg,
        #     print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
        #     print_callback=print_callback
        # )
        #
        # _ = _ask_actor_agent_and_print_response(
        #     msg_thread=msg_thread,
        #     print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
        #     print_callback=print_callback
        # )
    else:
        log.log_and_print("Too many rounds. Try to verify the hypothesis anyway.")

    ############################################
    # STEP 3: Save the called search API calls #
    ############################################

    manager.dump_tool_call_sequence_to_file(curr_proc_outs.tool_call_dpath, f"loop_{loop_no}")
    manager.dump_tool_call_layers_to_file(curr_proc_outs.tool_call_dpath, f"loop_{loop_no}")

    return proc_all_hypothesis
