import os

from typing import *

from agent_app.data_structures import MessageThread
from agent_app.api.manage import FlowManager
from agent_app.flow_control.flow_recording import ProcHypothesis


def run_in_end_state(
        process_no: int,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    # Save end hypothesis
    manager.cur_proc_all_hyps.sort_verified()
    manager.cur_proc_all_hyps.sort_unverified()

    hyp_fpath = os.path.join(manager.cur_proc_outs.hyp_dpath, "final.json")
    manager.cur_proc_all_hyps.save_hyp_to_file(hyp_fpath)

    # Reset
    manager.reset_loop_tool_call_records()
    manager.reset_process_exec_tool_calls()

    if len(manager.cur_proc_all_hyps.verified) == 0:
        return False
    else:
        return True
