import os
import json

from typing import *

from agent_app import globals
from agent_app.data_structures import CommitType, ProxyTask, MessageThread
from agent_app.api.manage import ProcessManager
from agent_app.flow_control.flow_recording import State, ProcOutPaths, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_usr_msg_and_print,
    _ask_actor_agent_and_print,
    _ask_proxy_agent_and_print,
    _save_proxy_msg,
    get_hyp_def_prompt
)
from agent_app.flow_control.hypothesis import build_basic_hyp, get_hyp_description


def run_in_hyp_checking_state(
        process_no: int,
        loop_no: int,
        curr_proc_hyps: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    print_desc = f"process {process_no} | state {State.HYPOTHESIS_CHECK_STATE} | loop {loop_no}"

    ###############################
    # STEP 1: Make new hypothesis #
    ###############################

    if len(curr_proc_hyps.unverified) == 0:
        # ------------------ 1.1 Prepare the prompt ------------------ #
        hyp_def = get_hyp_def_prompt()
        hyp_prop_prompt = (f"Based on the previous hypothesis and analyses, answer the below question:"
                           f"\n- Are there any better hypothesis: make hypothesis that differ from those already made. (leave it empty if there is no more appropriate hypothesis)"
                           f"{hyp_def}"
                           f"\nNOTE: You can make multiple new hypothesis one time.")

        _add_usr_msg_and_print(hyp_prop_prompt, msg_thread, print_desc, print_callback)

        # ------------------ 1.2 Ask the LLM ------------------ #
        retry = 0
        while True:
            response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

            json_hyps, _, proxy_msg_threads = _ask_proxy_agent_and_print(
                ProxyTask.HYP_PROPOSAL, response, manager, f"{print_desc} | retry {retry}", print_callback
            )

            proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_hypothesis_proposal.json")
            _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

            if json_hyps is None and retry < globals.state_retry_limit:
                retry += 1
                retry_msg = "The given hypothesis seems invalid. Please try again."
                _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
            else:
                break

        if json_hyps is None:
            return False

        # ------------------ 1.3 Collect new hypothesis ------------------ #
        raw_hyps = json.loads(json_hyps)["hypothesis_list"]

        # Filter verified hypothesis
        for hyp in raw_hyps:
            hyp = build_basic_hyp(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])
            curr_proc_hyps.add_new_unverified(hyp)

    if len(curr_proc_hyps.unverified) == 0:
        # No more new hypothesis
        return False

    #####################################################
    # STEP 2: Select an unverified hypothesis to verify #
    #####################################################

    ##############################################################
    # Step 2-1: Process hypothesis containing unsupported CWE-ID #
    ##############################################################

    bad_case_summary = None
    good_case_summary = None

    while True:
        # ------------------ 1.1 Select an unverified hypothesis ------------------ #
        if len(curr_proc_hyps.unverified) == 0:
            # No valid unverified hypothesis
            return False

        curr_proc_hyps.update_cur_hyp()
        assert curr_proc_hyps.cur_hyp is not None

        # ------------------ 1.2 Check the hypothesis ------------------ #
        cur_hyp_desc = get_hyp_description(curr_proc_hyps.cur_hyp)
        cur_full_cwe_id = curr_proc_hyps.cur_hyp.vulnerability_type
        cur_cwe_id = cur_full_cwe_id.split("-")[-1]

        # (1) Non-vulnerability patch
        if cur_full_cwe_id == "":
            # Good case 1: no modification required <- non-vulnerability patch
            assert good_case_summary is None
            if bad_case_summary is None:
                good_case_summary = (f"In this step, we select an unverified hypothesis: {cur_hyp_desc}."
                                     f"\nSince this hypothesis does not involve CWE-ID, so it needs no modification.")
            else:
                good_case_summary = (f"{bad_case_summary}"
                                     f"\nNow we select an unverified hypothesis: {cur_hyp_desc}."
                                     f"\nSince this hypothesis does not involve CWE-ID, so it needs no modification.")

        # (2) Vulnerability patch with supported CWE-ID
        elif cur_cwe_id in manager.cwe_manager.cwe_ids:
            # Good case 2: no modification required <- vulnerability patch with supported CWE-ID
            assert good_case_summary is None
            if bad_case_summary is None:
                good_case_summary = (f"In this step, we select an unverified hypothesis: {cur_hyp_desc}."
                                     f"\nThe predicted vulnerability type {cur_full_cwe_id} is within our consideration.")
            else:
                good_case_summary = (f"{bad_case_summary}"
                                     f"\nNow we select an unverified hypothesis: {cur_hyp_desc}."
                                     f"\nThe predicted vulnerability type {cur_full_cwe_id} is within our consideration.")

        # (3) Vulnerability patch with unsupported CWE-ID
        else:
            if bad_case_summary is None:
                bad_case_summary = (f"In this step, we select an unverified hypothesis: {cur_hyp_desc}."
                                    f"\nSince the predicted vulnerability type {cur_full_cwe_id} is not within our consideration, so you need to modify it.")
            else:
                bad_case_summary = (f"{bad_case_summary}"
                                    f"Now we select an unverified hypothesis: {cur_hyp_desc}."
                                    f"\nSince the predicted vulnerability type {cur_full_cwe_id} is not within our consideration, so you need to modify it.")

            # ------------------ 1.2.1 Prepare the prompt ------------------ #
            assert bad_case_summary is not None
            valid_check_prompt = bad_case_summary

            if cur_cwe_id in manager.cwe_manager.all_weakness_entries:
                # (1) Weakness definition
                weakness_desc = f"The definition of {cur_full_cwe_id} is: " + manager.cwe_manager.get_weakness_description(cur_cwe_id)
                assert weakness_desc is not None
                # (2) Weakness attributes
                weakness_view_desc = manager.cwe_manager.get_weakness_view_description(cur_cwe_id)
                assert weakness_view_desc is not None

                valid_check_prompt += f"\n{weakness_desc}\n{weakness_view_desc}"
            elif cur_cwe_id in manager.cwe_manager.all_category_entries:
                # (1) Category definition
                category_desc = f"The type of {cur_full_cwe_id} is Category. " + manager.cwe_manager.get_category_description(cur_cwe_id)
                assert category_desc is not None

                valid_check_prompt += f"\n{category_desc}"
            else:
                # NOTE: For CWE that has no record, we only use a general prompt.
                pass

            valid_check_prompt += f"\nNow please choose a CWE-ID in View-{globals.view_id} to replace the original vulnerability type."
            _add_usr_msg_and_print(valid_check_prompt, msg_thread, print_desc, print_callback)

            # ------------------ 1.2.2 Ask the LLM ------------------ #
            response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

            # TODO: The extraction work is simple, so we do not ask with retires. (Require Verification)
            json_full_cwe_id, _, proxy_msg_threads = _ask_proxy_agent_and_print(
                ProxyTask.HYP_CHECK, response, manager, print_desc, print_callback
            )

            proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_hypothesis_check.json")
            _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

            # ------------------ 1.2.3 Check the modification result ------------------ #
            if json_full_cwe_id is None:
                # TODO: Bad result. This should not happen. (Require Verification)
                # Bad case 1: modification failed <- invalid response
                manager.action_status_count.add_unsupported_hyp_modification_case(
                    none_result=True, same_result=False, uns_result=False, good_result=False
                )

                bad_case_summary = "It seems that you did not provide a new valid CWE-ID, so we must delete this hypothesis and select a new one."

            else:
                mod_full_cwe_id = json.loads(json_full_cwe_id)["cwe_id"]
                mod_cwe_id = mod_full_cwe_id.split("-")[-1]
                if mod_cwe_id == cur_cwe_id:
                    # TODO: Bad result. This should not happen. (Require Verification)
                    # Bad case 2: modification failed <- modified CWE-ID is the same as before
                    manager.action_status_count.add_unsupported_hyp_modification_case(
                        none_result=False, same_result=True, uns_result=False, good_result=False
                    )

                    bad_case_summary = "It seems that you did not modify the given CWE-ID, so we must delete this hypothesis and select a new one."

                else:
                    prefix = f"You replace the original vulnerability type with {mod_full_cwe_id}"

                    # FIXME: Check if it still works properly under VIEW-1003.
                    # We follow the strict condition: keep the hypothesis only if the modified CWE-ID is within the consideration.
                    if mod_cwe_id not in manager.cwe_manager.cwe_ids:
                        # Bad case 3: modification failed <- modified CWE-ID is still unsupported
                        manager.action_status_count.add_unsupported_hyp_modification_case(
                            none_result=False, same_result=False, uns_result=True, good_result=False
                        )

                        bad_case_summary = f"{prefix}, however, this CWE-ID is still not within our consideration, so we must delete this hypothesis and select a new one."

                    else:
                        # Good case 3: modification successful <- modified CWE-ID is supported.
                        manager.action_status_count.add_unsupported_hyp_modification_case(
                            none_result=False, same_result=False, uns_result=False, good_result=True
                        )

                        curr_proc_hyps.cur_hyp.vulnerability_type = f"CWE-{mod_cwe_id}"

                        good_case_summary = f"{prefix}, and, this CWE-ID is within our consideration, so we will retain this modification."

        if good_case_summary is None:
            curr_proc_hyps.cur_hyp = None
            continue
        else:
            break

    ###############################################################
    # Step 2-2: Process hypothesis containing too detailed CWE-ID #
    ###############################################################
    assert curr_proc_hyps.cur_hyp is not None and good_case_summary is not None

    cur_full_cwe_id = curr_proc_hyps.cur_hyp.vulnerability_type
    cur_cwe_id = cur_full_cwe_id.split("-")[-1]

    if cur_full_cwe_id == "":
        check_summary = good_case_summary

    elif not manager.cwe_manager.is_too_detailed_weakness(cur_cwe_id):
        check_summary = (f"{good_case_summary}"
                         "\nBesides, this CWE-ID is moderately detailed, so it needs no more modification.")

    else:
        manager.action_status_count.update_too_detailed_hyp_modification_case()

        # ------------------ 2.1 Get father CWEs at the specified depth ------------------ #
        fathers = manager.cwe_manager.get_depth_k_fathers_of_weakness(cur_cwe_id)
        assert len(fathers) >= 1

        fathers_desc = ", ".join([f"CWE-{f}" for f in fathers])
        check_summary = (f"{good_case_summary}"
                         f"\nBesides, CWE-{cur_cwe_id} is too detailed. We update the original hypothesis by creating corresponding new hypotheses based on its parent CWEs, including {fathers_desc}.")

        # ------------------ 2.2 Update ------------------ #
        for i, father in enumerate(fathers):
            hyp = build_basic_hyp(
                commit_type=CommitType.VulnerabilityPatch,
                vul_type=f"CWE-{father}",
                conf_score=curr_proc_hyps.cur_hyp.confidence_score
            )

            if i == 0:
                # Select the first new unverified hypothesis to verify
                curr_proc_hyps.cur_hyp = hyp
            else:
                # Collect the rest new unverified hypothesis
                curr_proc_hyps.add_new_unverified(hyp)

    _add_usr_msg_and_print(check_summary, msg_thread, print_desc, print_callback)

    ##################################
    # STEP 3: Prepare summary prompt #
    ##################################

    assert curr_proc_hyps.cur_hyp is not None
    cur_hyp_desc = get_hyp_description(curr_proc_hyps.cur_hyp)
    next_step_prompt = f"Now your target is to justify the hypothesis: {cur_hyp_desc}."

    suffix_prompt = "In the subsequent context retrieval and analysis process, "
    if curr_proc_hyps.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        suffix_prompt += "please analyze the functionality of each code snippet in the commit to determine if it is not relevant to vulnerability fixing."
    else:
        # TODO: Consider whether to repeat the previously extracted patch code in the prompt.
        suffix_prompt += "please focus on code snippets that most likely to be the patch."
        # suffix_prompt = (
        #     "The code snippets most likely to be the patch are as follows:"
        #     f"\n\n```"
        #     f"\n{proc_all_hypothesis.patch_to_str()}"
        #     f"\n```"
        # )

    next_step_prompt += f"\n{suffix_prompt}"
    _add_usr_msg_and_print(next_step_prompt, msg_thread, print_desc, print_callback)

    return True
