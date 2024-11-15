
from typing import *

from agent_app import globals
from agent_app.data_structures import MessageThread
from agent_app.api.manage import FlowManager
from agent_app.flow_control.flow_recording import State, ProcOutPaths, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_system_msg_and_print,
    _add_usr_msg_and_print,
    get_system_prompt
)
from agent_app.flow_control.hypothesis import get_hyp_description


def run_in_reflexion_state(
        process_no: int,
        loop_no: int,
        curr_proc_hyps: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
):
    """
    In order to prevent the forgetting problem caused by too many rounds of interaction with LLM,
    we open a new round conversation after a complete loop (make hypothesis -> context retrieval -> verify hypothesis)
    """
    print_desc = f"process {process_no} | state {State.REFLEXION_STATE} | loop {loop_no}"

    if loop_no != 1:
        # Open a new conversation for current loop
        msg_thread.reset()

        ## (1) System prompt
        system_prompt = get_system_prompt(globals.lang)
        _add_system_msg_and_print(system_prompt, msg_thread, print_desc, print_callback)

        ## (2) Commit content prompt
        commit_desc = manager.commit_manager.describe_commit_files()
        commit_prompt = ("The content of the commit is as follows:"
                         f"\n{commit_desc}")

        _add_usr_msg_and_print(commit_prompt, msg_thread, print_desc, print_callback)

        ## (3) Reflexion prompt
        # 2.1 Summary about description and analysis of verified hypothesis
        verified_hyps_summary = "In the previous analysis, you have made and analysed the following hypothesis:"

        curr_proc_hyps.sort_verified()
        for i, hyp in enumerate(curr_proc_hyps.verified):
            hyp_desc = get_hyp_description(hyp)
            verified_hyps_summary += (f"\n\nHypothesis id {i + 1}:"
                                      f"\n(1) Description: {hyp_desc}"
                                      f"\n(2) Analysis:")
            for line in hyp.get_analysis().split("\n"):
                verified_hyps_summary += f"\n    {line}"

        # 2.2 Code snippets of patch and context
        # TODO: Consider how to add the patch code snippets.
        code_snippet_desc = ("Besides, by calling the search APIs, you have got the following code snippets which help with analysis."
                             f"\n\n{curr_proc_hyps.context_to_str()}")

        reflexion_prompt = f"{verified_hyps_summary}\n\n{code_snippet_desc}"

        _add_usr_msg_and_print(reflexion_prompt, msg_thread, print_desc, print_callback)
