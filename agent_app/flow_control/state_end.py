import os

from typing import *

from agent_app.data_structures import MessageThread
from agent_app.api.manage import ProcessManager
from agent_app.flow_control.flow_recording import ProcOutPaths, ProcHypothesis


def run_in_end_state(
        process_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    # Save end hypothesis
    proc_all_hypothesis.sort_verified()
    proc_all_hypothesis.sort_unverified()

    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "final.json")
    proc_all_hypothesis.save_hyp_to_file(hyp_fpath)

    if len(proc_all_hypothesis.verified) == 0:
        return False
    else:
        return True
