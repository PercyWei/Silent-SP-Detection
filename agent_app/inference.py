import os
import json

from typing import *

from agent_app import globals, log
from agent_app.data_structures import MessageThread
from agent_app.api.manage import FlowManager
from agent_app.flow_control.hypothesis import FinalHypothesis
from agent_app.flow_control.state_start import run_in_start_state
from agent_app.flow_control.state_reflexion import run_in_reflexion_state
from agent_app.flow_control.state_hyp_checking import run_in_hyp_checking_state
from agent_app.flow_control.state_context_retrieval import run_in_context_retrieval_state
from agent_app.flow_control.state_hyp_verification import run_in_hyp_verification_state
from agent_app.flow_control.state_end import run_in_end_state
from agent_app.flow_control.state_post_process import vote_on_result, run_in_post_process_state
from utils import make_hie_dirs


def start_conversation_round_stratified(
        output_dpath: str,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> Dict[str, Dict[str, Dict]]:
    """
    This version uses json data to process API calls, instead of using the OpenAI function calling.
    Advantage is that multiple API calls can be made in a single round.
    """

    ############################################
    # STEP 1: Perform identification processes #
    ############################################

    for proc_no in range(1, globals.complete_process_limit + 1):
        log.print_banner(f"COMPLETE PROCESS {proc_no}")

        # ------------------------------------ 1.1 Preparation ------------------------------------ #
        cur_proc_name = f"process_{proc_no}"

        # 1. Manager
        manager.prepare_for_new_process(output_dpath, cur_proc_name)

        # 2. Message thread
        msg_thread = MessageThread()

        # ------------------------------------ 1.2 Workflow ------------------------------------ #
        ## State switching process:
        # - Complete loop: hypothesis_check -> context_retrieval -> hypothesis_verify
        # - Complete process: start -> loop -> ( reflexion -> loop ) -> ... -> ( reflexion -> loop ) -> end

        ########## Start State ##########
        cont_flag = run_in_start_state(proc_no, msg_thread, manager, print_callback)

        if not cont_flag:
            continue

        loop_no = 0
        while True:
            loop_no += 1

            ########## (1) Reflexion State ##########
            run_in_reflexion_state(proc_no, loop_no, msg_thread, manager, print_callback)

            ########## (2) Hypothesis Check State ##########
            cont_flag = run_in_hyp_checking_state(proc_no, loop_no, msg_thread, manager, print_callback)

            if not cont_flag:
                break

            ########## (3) Context Retrieval State ##########
            run_in_context_retrieval_state(proc_no, loop_no, msg_thread, manager, print_callback)

            ########## (4) Hypothesis Verify State ##########
            cont_flag = run_in_hyp_verification_state(proc_no, loop_no, msg_thread, manager, print_callback)

            if not cont_flag:
                break

        ########## End State ##########
        finish = run_in_end_state(proc_no, msg_thread, manager, print_callback)

        # ------------------------------------ 1.3 Update and save ------------------------------------ #
        # Update action status count
        manager.cur_proc_action_status.update_finish_status(success_flag=finish)

        # Save all status of current process
        manager.save_current_process_all_status(cur_proc_name)

    #####################################
    # STEP 2: Vote for the final result #
    #####################################

    valid_proc_dpaths = [os.path.join(output_dpath, proc_name)
                         for proc_name, status in manager.flow_all_status.items() if status]

    all_ver_hyp_dicts: List[Dict] = []
    for proc_dpath in valid_proc_dpaths:
        proc_final_hyp_fpath = os.path.join(proc_dpath, "hypothesis", "final.json")
        with open(proc_final_hyp_fpath, "r") as f:
            ver_hyps = json.load(f)["verified"]
            all_ver_hyp_dicts.extend(ver_hyps)

    final_hyps: List[FinalHypothesis] = vote_on_result(all_ver_hyp_dicts, len(valid_proc_dpaths))

    #########################################
    # STEP 3: Post process the final result #
    #########################################

    post_output_dpath = make_hie_dirs(output_dpath, "post_process")
    # FIXME: proc_all_hyp 用的是最后一次 process 的，而不是所有 process 的，但是无伤大雅
    final_hyps = run_in_post_process_state(final_hyps, manager.cur_proc_all_hyps, post_output_dpath, manager, print_callback)

    final_res_fpath = os.path.join(output_dpath, "result.json")
    with open(final_res_fpath, "w") as f:
        json.dump([hyp.to_dict() for hyp in final_hyps], f, indent=4)

    log.log_and_print("Ending workflow.")

    return manager.flow_all_status


def run_one_task(
        raw_commit_content: str,
        output_dpath: str,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None,
) -> Dict[str, Dict[str, Dict]]:
    """Main entry point to run inference on one task."""
    log.print_banner("Starting Silent Patch Identification on the following commit")
    log.print_commit_content(raw_commit_content)

    return start_conversation_round_stratified(output_dpath, manager, print_callback)
