
from typing import *

from agent_app.data_structures import MessageThread
from agent_app.api.manage import ProcessManager
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
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
):
    """
    In order to prevent the forgetting problem caused by too many rounds of interaction with LLM,
    we open a new round conversation after a complete loop (make hypothesis -> context retrieval -> verify hypothesis)
    """
    print_desc = f"process {process_no} | state {State.REFLEXION_STATE} | loop {loop_no}"

    #####################
    # STEP 1: Reflexion #
    #####################

    if loop_no != 1:
        # Open a new conversation
        msg_thread.reset()

        # ------------------ 1.1 Prepare the prompt ------------------ #
        ## (1) System prompt
        system_prompt = get_system_prompt()
        _add_system_msg_and_print(system_prompt, msg_thread, print_desc, print_callback)

        ## (2) Reflexion prompt
        # 2.1 Commit content
        commit_desc = manager.commit_manager.describe_commit_files()
        commit_prompt = ("The content of the commit is as follows:"
                         f"\n{commit_desc}")

        # 2.2 Summary about description and analysis of verified hypothesis
        proc_all_hypothesis.sort_verified()

        # TODO: Consider how to briefly summarize the analysis of previous hypothesis.
        loop_summary = "In the previous analysis, you have made and analysed the following hypothesis:"
        for i, hyp in enumerate(proc_all_hypothesis.verified):
            desc = get_hyp_description(hyp)
            loop_summary += (f"\n\nHypothesis id {i + 1}:"
                             f"\n - Description: {desc}"
                             f"\n - Analysis: {hyp.analysis}")

        # 2.3 Code snippets of patch and context
        # TODO: Consider how to add the patch code snippets.
        code_snippet_desc = (
            "Besides, by calling the search APIs, you have got the following code snippets which help with analysis."
            f"\n\n{proc_all_hypothesis.context_to_str()}")

        reflexion_prompt = f"{commit_prompt}\n\n{loop_summary}\n\n{code_snippet_desc}"

        _add_usr_msg_and_print(reflexion_prompt, msg_thread, print_desc, print_callback)
