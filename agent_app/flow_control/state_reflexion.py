
from typing import *

from agent_app import globals
from agent_app.data_structures import MessageThread
from agent_app.api.manage import FlowManager
from agent_app.flow_control.flow_recording import State, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_system_msg_and_print,
    _add_usr_msg_and_print,
    get_system_prompt
)
from agent_app.flow_control.hypothesis import get_hyp_description
from agent_app.util import LanguageNotSupportedError


def run_in_reflexion_state(
        process_no: int,
        loop_no: int,
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

        manager.cur_proc_all_hyps.sort_verified()
        for i, hyp in enumerate(manager.cur_proc_all_hyps.verified):
            hyp_desc = get_hyp_description(hyp)
            verified_hyps_summary += (f"\n\nHypothesis id {i + 1}:"
                                      f"\n(1) Description: {hyp_desc}"
                                      f"\n(2) Analysis:")
            for line in hyp.get_analysis().split("\n"):
                verified_hyps_summary += f"\n    {line}"

        # 2.2 Code snippets of context collected
        # code_snippet_desc = ("In the previous analysis, by calling search APIs, you have got the following code snippets which help with analysis."
        #                      f"\n\n{manager.cur_proc_all_hyps.context_to_str()}")

        code_snippet_desc = ("In the previous analysis, by calling search APIs, you have got the following code snippets which help with analysis:"
                             f"\n{manager.cur_proc_code_context.get_all_struct_description()}"
                             f"\n\nThe detailed context collected is shown below:"
                             f"\n{manager.cur_proc_code_context.get_all_context(manager.search_manager.merge_code)}")

        if globals.lang == "Python":
            code_snippet_desc += ("\n\nNOTE:"
                                  "\n(1) For collected classes, we only extract their signature, including declaration statements and inclass method signatures."
                                  "\n(2) For collected functions and inclass methods, we extract their entire code snippets.")
        elif globals.lang == "Java":
            code_snippet_desc += ("\n\nNOTE:"
                                  "\n(1) For collected classes, we only extract their signature, including declaration statements and inclass type signatures."
                                  "\n(2) For collected interfaces and inclass types, we extract their entire code snippets."
                                  "\n(3) The 'inclass type' mentioned above include 'inclass interface', 'inclass class' and 'inclass method'."
                                  "\n(4) Here, we treat 'annotation' as 'interface', and 'enum' and 'record' as class.")
        else:
            raise LanguageNotSupportedError(globals.lang)

        reflexion_prompt = f"{verified_hyps_summary}\n\n{code_snippet_desc}"

        _add_usr_msg_and_print(reflexion_prompt, msg_thread, print_desc, print_callback)
