import os
import json

from typing import *

from agent_app import globals, log
from agent_app.data_structures import CommitType, ProxyTask, MessageThread
from agent_app.api.manage import ProcessManager
from agent_app.flow_control.flow_recording import State, ProcOutPaths, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_usr_msg_and_print,
    _ask_actor_agent_and_print,
    _ask_proxy_agent_and_print,
    _save_proxy_msg
)
from agent_app.flow_control.hypothesis import get_hyp_description, update_hyp_with_analysis


def run_in_hyp_verification_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    print_desc = f"process {process_no} | state {State.HYPOTHESIS_VERIFY_STATE} | loop {loop_no}"

    #################################
    # STEP 1: Verify the hypothesis #
    #################################

    assert proc_all_hypothesis.cur_hyp is not None

    # ------------------ 1.1 Prepare the prompt ------------------ #
    if proc_all_hypothesis.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        suffix_prompt = (
            "For each modified code snippet involved in the commit, please complete the following tasks:\n"
            "(1) Analyze the purpose of the modification.\n"
            "(2) Determine whether the modification is unrelated to the vulnerability fix.")
    else:
        full_cwe_id = proc_all_hypothesis.cur_hyp.vulnerability_type
        cwe_id = full_cwe_id.split('-')[-1]
        cwe_description = manager.cwe_manager.get_weakness_description(cwe_id)
        cwe_description_seq = f"The description of {full_cwe_id} is: {cwe_description}\n" if cwe_description else ""

        suffix_prompt = (f"{cwe_description_seq}"
                         "Please complete the following tasks:\n"
                         "(1) Analyze the key variables and fix methods commonly involved in this CWE.\n"
                         "(2) Find the corresponding key variables and fix methods in the code snippet involved in this commit.")

    cur_hyp_str = get_hyp_description(proc_all_hypothesis.cur_hyp)
    hyp_verify_prompt = (
        "Now you have enough context, please re-analyze the correctness of your previous hypothesis.\n"
        f"Your hypothesis is: {cur_hyp_str}.\n"
        f"{suffix_prompt}")
    _add_usr_msg_and_print(hyp_verify_prompt, msg_thread, print_desc, print_callback)

    # ------------------ 1.2 Ask the LLM ------------------ #
    analysis_text = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

    ###################################
    # STEP 2: Re-score the hypothesis #
    ###################################

    # ------------------ 2.1 Prepare the prompt ------------------ #
    score_prompt = (
        f"Based on the above analysis, please give the confidence score for this hypothesis (0-10). "
        f"The previous score was {proc_all_hypothesis.cur_hyp.confidence_score}/10.")
    _add_usr_msg_and_print(score_prompt, msg_thread, print_desc, print_callback)

    # ------------------ 2.2 Ask the LLM ------------------ #
    retry = 0
    while True:
        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_score, _, proxy_msg_threads = _ask_proxy_agent_and_print(
            ProxyTask.SCORE, response, manager, print_desc, print_callback
        )

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_score_update.json")
        _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

        if json_score is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = f"The given confidence score seems invalid. Please try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
        else:
            break

    # TODO: We believe that this extraction is too simple and should not go wrong
    assert json_score is not None

    #####################################
    # STEP 3: Update all the hypothesis #
    #####################################

    # (1) Update the confidence score of the current hypothesis
    proc_all_hypothesis.cur_hyp.confidence_score = json.loads(json_score)["confidence_score"]

    # (2) Update the current hypothesis from unverified to verified
    ver_hyp = update_hyp_with_analysis(proc_all_hypothesis.cur_hyp, analysis_text)
    proc_all_hypothesis.verified.append(ver_hyp)
    proc_all_hypothesis.cur_hyp = None

    ###############################
    # STEP 4: End of current loop #
    ###############################

    # ------------------ 4.1 Save the conversation of the current loop ------------------ #
    curr_loop_conversation_file = os.path.join(curr_proc_outs.root, f"loop_{loop_no}_conversations.json")
    msg_thread.save_to_file(curr_loop_conversation_file)

    # ------------------ 4.2 Decide next step ------------------ #
    if len(proc_all_hypothesis.verified) >= globals.hypothesis_limit:
        log.log_and_print("Too many verified hypothesis. End anyway.")
        return False

    return True
