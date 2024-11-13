import os
import json

from typing import *

from agent_app import globals, log
from agent_app.data_structures import CommitType, ProxyTask, MessageThread
from agent_app.api.manage import FlowManager
from agent_app.CWE.cwe_util import WeaknessAttrs
from agent_app.flow_control.flow_recording import State, ProcOutPaths, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_usr_msg_and_print,
    _ask_actor_agent_and_print,
    _ask_proxy_agent_and_print,
    _save_proxy_msg
)
from agent_app.flow_control.hypothesis import VulAnalysis, get_hyp_description, update_hyp_with_analysis


def verify_current_hypothesis(
        print_desc: str,
        loop_no: int,
        curr_proc_hyps: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> VulAnalysis | str:
    assert curr_proc_hyps.cur_hyp is not None

    cur_hyp_desc = get_hyp_description(curr_proc_hyps.cur_hyp)
    hyp_verify_prompt = ("Now you have enough context, please re-analyse your previous hypothesis."
                         f"\nThe hypothesis is: {cur_hyp_desc}.")

    if curr_proc_hyps.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        # For hypothesis of non vulnerability patch
        task_prompt = ("For each modified file involved in the commit, please complete the following tasks:"
                       "\n1. Analyze the purpose of the each modification."
                       "\n2. Analyse the confidence scores (1-10) that each modification is a non-vulnerability patch.")

        hyp_verify_prompt += "\n" + task_prompt

        _add_usr_msg_and_print(hyp_verify_prompt, msg_thread, print_desc, print_callback)

        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        return response

    else:
        # For hypothesis of vulnerability patch
        full_cwe_id = curr_proc_hyps.cur_hyp.vulnerability_type
        cwe_id = full_cwe_id.split('-')[-1]

        # 1. CWE basic description
        cwe_desc = manager.cwe_manager.get_weakness_description(cwe_id)
        assert cwe_desc is not None

        # 2. Weakness attributes
        weakness_attrs: WeaknessAttrs = manager.cwe_manager.get_weakness_attrs(cwe_id)
        trigger_action_str = weakness_attrs.trigger_action
        key_variables_str = ', '.join(weakness_attrs.key_variables)

        task_prompt = (f"The description of {full_cwe_id} is: {cwe_desc}"
                       "\n\nBesides, please focus on the 'trigger action' and 'key variable' of the vulnerability, both of which are defined below:"
                       f"\n - Trigger Action: {WeaknessAttrs.trigger_action_def()}."
                       f"\n - Key Variables: {WeaknessAttrs.key_variable_def()}."
                       f"\n\nWhile the two attributes of {full_cwe_id} are as below:"
                       f"\n - Trigger Action: {trigger_action_str}"
                       f"\n - Key Variables: {key_variables_str}."
                       "\n\nPlease refer to the above and complete the following tasks:"
                       "\n1. Find the corresponding key variables in the commit."
                       "\n2. Analyze the corresponding trigger action in the commit."
                       "\n3. Summarize the fix method in this commit."
                       "\n4. Analyze how the fix method prevent the trigger action, i.e. establish the relationship between fix method, trigger action and key variables."
                       "\n\nNOTE: For a vulnerability, NOT all key variables will be present at the same time.")

        hyp_verify_prompt += "\n" + task_prompt
        _add_usr_msg_and_print(hyp_verify_prompt, msg_thread, print_desc, print_callback)

        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_vul_analysis, _, proxy_msg_threads = _ask_proxy_agent_and_print(
            ProxyTask.VUL_ANALYSIS, response, manager, print_desc, print_callback
        )

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_vul_analysis.json")
        _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

        vul_analysis_dict = json.loads(json_vul_analysis)

        vul_analysis = VulAnalysis(
            cwe_id=int(cwe_id),
            key_variables=vul_analysis_dict['key_variables'],
            trigger_action=vul_analysis_dict['trigger_action'],
            fix_method=vul_analysis_dict['fix_method'],
            relationship=vul_analysis_dict['relationship']
        )

        return vul_analysis


def rescore_current_hypothesis(
        print_desc: str,
        loop_no: int,
        curr_proc_hyps: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> int:
    # ------------------ 1. Prepare the prompt ------------------ #
    score_prompt = f"Based on the above analysis, please give the confidence score for this hypothesis (0-10). The previous score was {curr_proc_hyps.cur_hyp.confidence_score}/10."
    _add_usr_msg_and_print(score_prompt, msg_thread, print_desc, print_callback)

    # ------------------ 2. Ask the LLM ------------------ #
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

    conf_score = json.loads(json_score)["confidence_score"]

    return int(conf_score)


def update_current_hypothesis(
        conf_score: int,
        novul_analysis: str | None,
        vul_analysis: VulAnalysis | None,
        curr_proc_hyps: ProcHypothesis
) -> None:
    assert (curr_proc_hyps.cur_hyp is not None) ^ (novul_analysis is not None)

    # (1) Update the confidence score of the current hypothesis
    curr_proc_hyps.cur_hyp.confidence_score = conf_score

    # (2) Update the current hypothesis from unverified to verified
    ver_hyp = update_hyp_with_analysis(curr_proc_hyps.cur_hyp, novul_analysis, vul_analysis)
    curr_proc_hyps.verified.append(ver_hyp)
    curr_proc_hyps.cur_hyp = None


"""MAIN STATE"""


def run_in_hyp_verification_state(
        process_no: int,
        loop_no: int,
        curr_proc_hyps: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    print_desc = f"process {process_no} | state {State.HYPOTHESIS_VERIFY_STATE} | loop {loop_no}"

    ## Step 1: Verify the hypothesis
    analysis = verify_current_hypothesis(
        print_desc=print_desc,
        loop_no=loop_no,
        curr_proc_hyps=curr_proc_hyps,
        curr_proc_outs=curr_proc_outs,
        msg_thread=msg_thread,
        manager=manager,
        print_callback=print_callback
    )

    # Step 2: Re-score the hypothesis
    conf_score = rescore_current_hypothesis(
        print_desc=print_desc,
        loop_no=loop_no,
        curr_proc_hyps=curr_proc_hyps,
        curr_proc_outs=curr_proc_outs,
        msg_thread=msg_thread,
        manager=manager,
        print_callback=print_callback
    )

    ## Step 3: Update the hypothesis
    if isinstance(analysis, VulAnalysis):
        update_current_hypothesis(conf_score, None, analysis, curr_proc_hyps)
    else:
        assert isinstance(analysis, str)
        update_current_hypothesis(conf_score, analysis, None, curr_proc_hyps)

    ## Step 4: Loop end
    # (1) Save the conversation of the current loop
    curr_loop_conversation_file = os.path.join(curr_proc_outs.root, f"loop_{loop_no}_conversations.json")
    msg_thread.save_to_file(curr_loop_conversation_file)

    # (2) Decide next step
    if len(curr_proc_hyps.verified) >= globals.hypothesis_limit:
        log.log_and_print("Too many verified hypothesis. End anyway.")
        return False

    return True
