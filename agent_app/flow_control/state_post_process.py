import os
import json
import math

from typing import *
from collections import defaultdict

from agent_app import globals
from agent_app.data_structures import CommitType, ProxyTask, MessageThread
from agent_app.api.manage import FlowManager
from agent_app.flow_control.flow_recording import State, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_system_msg_and_print,
    _add_usr_msg_and_print,
    _ask_actor_agent_and_print,
    _ask_proxy_agent_and_print,
    _save_proxy_msg,
    get_system_prompt
)
from agent_app.flow_control.hypothesis import (
    Hypothesis,
    FinalHypothesis,
    update_hyp_with_count,
    get_hyp_description
)


def calculate_final_confidence_score(
        all_hyps: List[Hypothesis],
        proc_num: int,
        cal_type: int = 0
) -> List[FinalHypothesis]:
    """Calculate the final confidence score of hypothesis based on multi-processes.

    Args:
        all_hyps (List[Dict]):
        proc_num (int):
        cal_type (int): Calculation strategy.
            - 0: General average
            - 1: Improved linear weighted average
            - 2: Weighted average considering position
    Returns:
        List[Dict]: Hypothesis with final confidence score.
    """

    def _normalize(_score: int) -> float:
        # 0-10 -> 0-1
        return _score * 0.1

    def _denormalize(_score: float) -> float:
        # 0-1 -> 0-10
        return _score * 10

    def _round_score(_score: float) -> float:
        return round(_score, 3)

    ## CASE 1: Process number = 1
    if proc_num == 1:
        all_hyps = sorted(all_hyps, key=lambda x: x.confidence_score, reverse=True)
        final_hyps: List[FinalHypothesis] = [update_hyp_with_count(hyp, 1) for hyp in all_hyps]
        return final_hyps

    ## CASE 2: Process number > 1
    hyp_conds = defaultdict(lambda: {"count": 0, "total_score": 0, "final_score": 0.})

    if cal_type == 0:
        for hyp in all_hyps:
            hyp_name = hyp.commit_type + "." + hyp.vulnerability_type
            hyp_conds[hyp_name]["count"] += 1
            hyp_conds[hyp_name]["total_score"] += _normalize(hyp.confidence_score)

        for hyp_name, data in hyp_conds.items():
            ave_score = data["total_score"] / proc_num
            hyp_conds[hyp_name]["final_score"] = _round_score(_denormalize(ave_score))
    elif cal_type == 1:
        for hyp in all_hyps:
            hyp_name = hyp.commit_type + "." + hyp.vulnerability_type
            hyp_conds[hyp_name]["count"] += 1
            hyp_conds[hyp_name]["total_score"] += _normalize(hyp.confidence_score)

        for hyp_name, data in hyp_conds.items():
            ave_score = (data["total_score"] / data["count"]) * (1 + math.log(data["count"] + 1))
            hyp_conds[hyp_name]["final_score"] = _round_score(_denormalize(ave_score))
    elif cal_type == 2:
        # TODO: Not complete
        pass
    else:
        raise RuntimeError

    final_hyps: List[FinalHypothesis] = [
        FinalHypothesis(commit_type=hyp_name.split('.')[0],
                        vulnerability_type=hyp_name.split('.')[1],
                        confidence_score=data["final_score"],
                        count=data["count"])
        for hyp_name, data in hyp_conds.items()
    ]
    final_hyps = sorted(final_hyps, key=lambda x: x.confidence_score, reverse=True)

    return final_hyps


def vote_on_result(all_hyp_dicts: List[Dict], proc_num: int) -> List[FinalHypothesis]:
    all_hyps: List[Hypothesis] = []

    for hyp_dict in all_hyp_dicts:
        hyp = Hypothesis(hyp_dict["commit_type"], hyp_dict["vulnerability_type"], hyp_dict["confidence_score"])
        all_hyps.append(hyp)

    final_hyps = calculate_final_confidence_score(all_hyps, proc_num)

    return final_hyps


def run_in_post_process_state(
        final_hyps: List[FinalHypothesis],
        proc_all_hypothesis: ProcHypothesis,
        post_output_dpath: str,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> List[FinalHypothesis]:
    print_desc = f"state {State.POST_PROCESS_STATE}"

    # Message thread
    msg_thread = MessageThread()

    ################################################
    # STEP 1: Process hypothesis based on CWE tree #
    ################################################

    pass

    ##############################################################
    # STEP 2: Process hypothesis with the same confidence score #
    ##############################################################

    # TODO: For now, we are only interested in hypothesis with the highest confidence score
    # ------------------ 2.1 Select the hypothesis with the highest confidence score ------------------ #
    final_hyps = sorted(final_hyps, key=lambda x: x.confidence_score, reverse=True)

    max_conf_score = None
    pending_hyps: List[FinalHypothesis] = []
    for hyp in final_hyps:
        if max_conf_score is None:
            max_conf_score = hyp.confidence_score
            pending_hyps.append(hyp)
        elif max_conf_score == hyp.confidence_score:
            pending_hyps.append(hyp)
        else:
            break

    if len(pending_hyps) > 1:
        # ------------------ 2.2 Prepare the prompt ------------------ #
        ## (1) System prompt
        system_prompt = get_system_prompt(globals.lang)
        _add_system_msg_and_print(system_prompt, msg_thread, print_desc, print_callback)

        ## (2) Summary prompt
        # 2.1 Commit content
        commit_desc = manager.commit_manager.describe_commit_files()
        commit_prompt = ("The content of the commit is as follows:"
                         f"\n{commit_desc}")

        # 2.2 Code snippets of patch and context
        # TODO: Consider how to add the patch code snippets?
        code_snippet_desc = (
            "In the previous analysis, by calling the search APIs, you have got the following code snippets:"
            f"\n\n{proc_all_hypothesis.context_to_str()}")

        # 2.3 Description of hypothesis with the same confidence score
        hyp_desc = f"After analysing and verifying, you give the following hypothesis the same high score {max_conf_score}/10:"
        for i, hyp in enumerate(pending_hyps):
            desc = get_hyp_description(hyp, with_score=False)
            hyp_desc += f"\nHypothesis id {i + 1}: {desc}"

        # 2.4 Instruction
        instruction = ("Now you need to carefully analyse the commit and its context code again, and give a ranking to the hypotheses above."
                       "\n\nNOTE: Please denote the corresponding hypothesis by id and give a ranking of the form like [id1, ..., idn]")

        summary_prompt = (f"{commit_prompt}"
                          f"\n\n{code_snippet_desc}"
                          f"\n\n{hyp_desc}"
                          f"\n\n{instruction}")

        _add_usr_msg_and_print(summary_prompt, msg_thread, print_desc, print_callback)

        # ------------------ 2.3 Ask the LLM ------------------ #
        retry = 0
        while True:
            response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

            json_ranking, _, proxy_msg_threads = _ask_proxy_agent_and_print(
                ProxyTask.RANK, response, manager, f"{print_desc} | retry {retry}", print_callback
            )

            proxy_conv_fpath = os.path.join(post_output_dpath, "rank.json")
            _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

            retry_msg = ""
            if retry < globals.state_retry_limit:
                if json_ranking is None:
                    retry_msg = "The given ranking seems invalid. Please try again."
                else:
                    raw_ranking = json.loads(json_ranking)["ranking"]
                    ranking_hyp_ids = sorted(raw_ranking)
                    pending_hyp_ids = list(range(1, len(pending_hyps) + 1))

                    if pending_hyp_ids != ranking_hyp_ids:
                        missing_hyp_ids = sorted(list(set(pending_hyp_ids) - set(ranking_hyp_ids)))
                        extra_hyp_ids = sorted(list(set(ranking_hyp_ids) - set(pending_hyp_ids)))

                        pending_hyp_ids_str = ", ".join(map(str, pending_hyp_ids))
                        missing_hyp_ids_str = ", ".join(map(str, missing_hyp_ids))
                        extra_hyp_ids_str = ", ".join(map(str, extra_hyp_ids))

                        retry_msg = (f"The given ranking {raw_ranking} seems invalid."
                                     f"\nSpecifically, the ids of hypothesis that need to be ranked are {pending_hyp_ids_str}, while the ids {missing_hyp_ids_str} are missing, and the ids {extra_hyp_ids_str} do not exist."
                                     f"\nPlease try again.")

            if retry_msg:
                retry += 1
                _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
            else:
                break

        # ------------------ 2.4 Rank the final hypothesis ------------------ #
        if json_ranking is None:
            manager.action_status_records.update_post_process_rank_status(success_flag=False)

            # TODO: Heuristic: 1) more occurrences -> higher ranking; 2) vulnerability fix > non-vulnerability fix
            commit_type_priority = {CommitType.VulnerabilityPatch: 1, CommitType.NonVulnerabilityPatch: 0}
            ranking_hyps = sorted(
                pending_hyps,
                key=lambda x: (x.count, commit_type_priority[x.commit_type]),
                reverse=True
            )
        else:
            manager.action_status_records.update_post_process_rank_status(success_flag=True)

            raw_ranking = json.loads(json_ranking)["ranking"]
            ranking_hyps = [pending_hyps[i - 1] for i in raw_ranking]
        final_hyps = ranking_hyps + final_hyps[len(pending_hyps):]

    return final_hyps
