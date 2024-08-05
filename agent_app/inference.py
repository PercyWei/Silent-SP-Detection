# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/inference.py

import os
import json
import math
import inspect
import re
import copy

from typing import *
from pathlib import Path
from collections import defaultdict

from loguru import logger

from agent_app import globals, globals_mut
from agent_app.api.manage import ProjectStateManager
from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import State, CommitType, Hypothesis, FunctionCallIntent, MessageThread
from agent_app.log import (
    print_banner, print_user, print_actor, print_proxy,
    print_commit_content,
    log_and_print, log_and_cprint
)
from agent_app.util import parse_function_invocation
from utils import make_hie_dirs

SYSTEM_PROMPT = """You are a software developer developing based on a large open source project.
You are facing a commit to this open source project.

The commit contains some code changes marked between <commit> and </commit>.
The old name and the new name of the renamed code files are marked between <old_file> and </old_file> or <new_file> and </new_file>, respectively, and the names of the remaining code files are marked between <file> and </file>.
If the code lines are in a class or function, the class name or function name is marked between <class> and </class> or <func> and </func>, respectively.
NOTE: A commit may involve multiple changed files, and a changed file may have multiple changed code lines.

Your task is to determine whether the commit fixes the vulnerability, and if so, give the most likely type of vulnerability, which is denoted by CWE-ID.
To achieve this, you need to keep making hypothesis based on the information you already have, and then use a few search API calls to gather relevant information and verify that the hypothesis is correct. 
Finally, choose that hypothesis that you think is most likely as the result.
"""

START_INSTRUCTION = """In this step, first, you need to answer the following three questions in order based on the raw commit contents, then summarise the hypothesis based on the answers.
1.
 - Question: What is the commit type?
 - Description: Judge if the commit fixes the vulnerability.
 - Constraints: Choose answer from "vulnerability_patch" and "non_vulnerability_patch".
2. 
 - Question: Where is the patch located?
 - Description: Go through the files involved in the commit one by one, and select the code that might be a patch.
 - Constraints: 
  - If you choose "non_vulnerability_patch" for question 1, leave this question empty.
  - If you choose "vulnerability_patch" for question 1, provide at least one location.
  - For each location provided, you should at least indicate its "file_name" and "code", and "class_name" and "func_name" are not required.
3. 
 - Question: What types of vulnerabilities might it address?
 - Description: Give the type of vulnerability that was fixed by this commit and the level of reliability (confidence score) of that answer. The vulnerability type is denoted by CWE-ID. 
 - Constraints: 
  - If you choose "non_vulnerability_patch" for question 1, leave this question empty. 
  - If you are not sure about the vulnerability type, provide multiple CWE-IDs and the corresponding confidence scores (1-10), otherwise provide only one CWE-ID with a confidence score of value 10.
"""

API_CALLS_DESCRIPTION = """You can use the following search APIs to get more context.
- search_class(class_name: str): Search for a class in the codebase
- search_class_in_file(class_name: str, file_name: str): Search for a class in a given file
- search_method_in_file(method_name: str, file_name: str): Search for a method in a given file
- search_method_in_class(method_name: str, class_name: str): Search for a method in a given class
- search_method_in_class_in_file(method_name: str, class_name: str, file_name: str): Search for a method in a given class which is in a given file

NOTE: You can use multiple search APIs in one round.
"""


"""Hypothesis"""


def hypothesis_to_seq(hyp: Hypothesis) -> str:
    """
    Describe the given hypothesis.
    """
    if hyp.commit_type == CommitType.NonVulnerabilityPatch:
        hyp_str = ("The given commit does not fix a vulnerability"
                   f"with a confidence score of {hyp.confidence_score}/10")
    else:
        hyp_str = (f"The given commit fixes a vulnerability of type {hyp.vulnerability_type} "
                   f"with a confidence score of {hyp.confidence_score}/10")
    return hyp_str


def hypothesis_list_to_json(hyp_list: List[Hypothesis]) -> List[Dict]:
    json_hyp_list: List[Dict] = []
    for hyp in hyp_list:
        json_hyp_list.append({
            "commit_type": hyp.commit_type,
            "vulnerability_type": hyp.vulnerability_type,
            "confidence_score": hyp.confidence_score
        })

    return json_hyp_list


def format_raw_hyp(
        commit_type: str,
        vul_type: str,
        conf_score: int
) -> Hypothesis:
    assert commit_type in CommitType.attributes()
    assert re.fullmatch(r"CWE-(\d+)", vul_type)
    assert isinstance(conf_score, int)
    conf_score = min(10, max(1, int(conf_score)))

    return Hypothesis(commit_type=commit_type,
                      vulnerability_type=vul_type,
                      confidence_score=conf_score)


"""Interact with Agent"""


def _add_usr_msg_and_print(
        msg_thread: MessageThread,
        usr_msg: str,
        print_desc: str,
        print_callback: Optional[Callable[[dict], None]] = None
) -> None:
    msg_thread.add_user(usr_msg)
    print_user(
        msg=usr_msg,
        desc=print_desc,
        print_callback=print_callback
    )


def _ask_actor_agent_and_print_response(
        msg_thread: MessageThread,
        print_desc: str,
        print_callback: Optional[Callable[[dict], None]] = None
) -> str:
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg())
    msg_thread.add_model(respond_text, tools=[])
    print_actor(
        msg=respond_text,
        desc=print_desc,
        print_callback=print_callback
    )
    return respond_text


def _ask_proxy_agent_and_save_msg(
        state_manager: ProjectStateManager,
        actor_respond_text: str,
        msg_save_path: str,
        msg_desc: str,
) -> str:
    # Ask Proxy Agent
    json_text, _, proxy_msg_threads = state_manager.call_proxy_apis(actor_respond_text)

    # Save conversations with Proxy Agent
    proxy_messages = [thread.to_msg() for thread in proxy_msg_threads]
    with open(msg_save_path, "a") as f:
        f.write(msg_desc + "\n\n")
        json.dump(proxy_messages, f, indent=4)
        f.write("\n\n")

    return json_text


def _ask_actor_and_proxy_with_retries(
        state_manager: ProjectStateManager,
        msg_thread: MessageThread,
        process_no: int,
        proxy_extract_item: str,
        proxy_conv_save_fpath: str,
        print_callback: Optional[Callable[[dict], None]] = None
) -> str | None:
    retry = 0
    while True:
        # (1) Ask the Actor Agent
        respond_text = _ask_actor_agent_and_print_response(
            msg_thread=msg_thread,
            print_desc=f"process {process_no} - state {state_manager.curr_state}",
            print_callback=print_callback
        )

        # (2) Ask the Proxy Agent to extract standard JSON format hypothesis from the current response
        proxy_json_output = _ask_proxy_agent_and_save_msg(
            state_manager=state_manager,
            actor_respond_text=respond_text,
            msg_save_path=proxy_conv_save_fpath,
            msg_desc=f"Retry {retry + 1}/{globals.state_retry_limit}:"
        )

        # (3) Whether retry
        if proxy_json_output is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = f"The {proxy_extract_item} seems invalid. Please try again."
            _add_usr_msg_and_print(
                msg_thread=msg_thread,
                usr_msg=retry_msg,
                print_desc=f"process {process_no} - state {state_manager.curr_state} - retry {retry}",
                print_callback=print_callback
            )
        else:
            break

    return proxy_json_output


"""Evaluation"""


def compare_init_and_end_hypothesis(
        init_hyps: List[Dict],
        end_hyps: List[Dict]
) -> bool:
    """
    Compare init hypothesis and end hypothesis to find out if there are different hypotheses.
    NOTE: We do not consider the confidence score.

    Args:
        init_hyps (List[Dict]): :
        end_hyps (List[Dict]):
    Returns:
        bool: True if different, False otherwise.
    """
    if len(init_hyps) != len(end_hyps):
        return True

    rest_hyp_list = copy.deepcopy(end_hyps)
    for hyp in init_hyps:
        for i in range(len(rest_hyp_list)):
            end_hyp = rest_hyp_list[i]
            if hyp["commit_type"] == end_hyp["commit_type"] and \
                    hyp["vulnerability_type"] == end_hyp["vulnerability_type"]:
                rest_hyp_list.pop(i)
                break

    if len(rest_hyp_list) > 0:
        return True
    else:
        return False


def calculate_final_confidence_score(all_hyps: List[Dict], proc_num: int, cal_type: int = 0) -> List[Dict]:
    """
    Calculate the final confidence score of hypothesis based on multi-round processes.

    Args:
        all_hyps (List[Dict]):
        proc_num (int):
        cal_type (int): Calculation strategy.
            - 0: General weighted average
            - 1: Improved linear weighted average
            - 2: Weighted average considering position
    Returns:
        List[Dict]: Hypothesis with final confidence score.
    """

    def _normalize(_score):
        # 1-10 -> 0.1-1
        return 0.1 + (_score - 1) * 0.1 / 9.0

    def _denormalize(_score):
        # 0.1-1 -> 1-10
        return 1 + (_score - 0.1) * 9.0 / 0.9

    hyp_score = defaultdict(lambda: {"count": 0, "total_score": 0})

    if cal_type == 0:
        for hyp in all_hyps:
            hyp_name = hyp["commit_type"] + "." + hyp["vulnerability_type"]
            hyp_score[hyp_name]["count"] += 1
            hyp_score[hyp_name]["total_score"] += _normalize(hyp["confidence_score"])

        hyp_final_score = {
            hyp_name: (data["total_score"] / data["count"]) * (1 + data["count"] / proc_num)
            for hyp_name, data in hyp_score.items()
        }
    elif cal_type == 1:
        for hyp in all_hyps:
            hyp_name = hyp["commit_type"] + "." + hyp["vulnerability_type"]
            hyp_score[hyp_name]["count"] += 1
            hyp_score[hyp_name]["total_score"] += _normalize(hyp["confidence_score"])

        hyp_final_score = {
            hyp_name: (data["total_score"] / data["count"]) * (1 + math.log(data["count"] + 1))
            for hyp_name, data in hyp_score.items()
        }
    elif cal_type == 2:
        # FIXME: Complete
        hyp_final_score = {}
        pass
    else:
        raise RuntimeError

    hyp_final_score = {
        hyp_name: _denormalize(score)
        for hyp_name, score in hyp_final_score.items()
    }

    final_hyps = [{"commit_type": hyp_name.split('.')[0],
                   "vulnerability_type": hyp_name.split('.')[1],
                   "confidence_score": score
                   } for hyp_name, score in hyp_final_score.items()]

    final_hyps = sorted(final_hyps, key=lambda x: x["confidence_score"], reverse=True)

    return final_hyps


def hypothesis_evaluation(
        target_commit_type: int,
        target_vul_type: str,
        hyp_list: List[Dict]
) -> Tuple[bool, Dict]:

    golden_match = False
    if hyp_list[0]["vulnerability_type"] == target_vul_type:
        golden_match = True

    match_rank = None
    for i, hyp in enumerate(hyp_list):
        if hyp["vulnerability_type"] == target_vul_type:
            match_rank = i + 1

    return golden_match, {"hypothesis_number": len(hyp_list),
                          "golden_match": golden_match,
                          "match_rank": match_rank}


def evaluation(
        proc_dpath_list: List[str],
        target_vul_type: str,
) -> Dict:
    # Step 1: Evaluate each process result
    diff_num = 0
    all_end_hyps: List[Dict] = []
    for proc_dpath in proc_dpath_list:
        proc_hyp_dpath = os.path.join(proc_dpath, "hypothesis")

        golden_match_num = 0

        init_hyp_fpath = os.path.join(proc_hyp_dpath, "init.json")
        with open(init_hyp_fpath, "r") as f:
            init_hyps = json.load(f)["hypothesis"]

            _, init_hyp_count = hypothesis_evaluation(1, target_vul_type, init_hyps)

        end_hyp_fpath = os.path.join(proc_hyp_dpath, "end.json")
        with open(end_hyp_fpath, "r") as f:
            end_hyps = json.load(f)["hypothesis"]

            all_end_hyps.extend(end_hyps)

            end_golden_match, end_hyp_count = hypothesis_evaluation(1, target_vul_type, end_hyps)

        if end_golden_match:
            golden_match_num += 1

        diff = compare_init_and_end_hypothesis(init_hyps, end_hyps)
        if diff:
            diff_num += 1

    # Step 2: Evaluate based on the end hypothesis of all processes
    final_hyps = calculate_final_confidence_score(all_end_hyps, len(proc_dpath_list))

    golden_match = False
    if final_hyps[0]["vulnerability_type"] == target_vul_type:
        golden_match = True

    match_rank = None
    for i, hyp in enumerate(final_hyps):
        if hyp["commit_type"] == target_vul_type:
            match_rank = i + 1
            break

    result = {
        "golden_match": golden_match,
        "match_rank": match_rank,
        "hyp_diff_num": diff_num
    }

    if golden_match:
        globals_mut.inc_golden_match_tasks()
        log_and_cprint("Golden match: True.", style="bold green")
    else:
        log_and_cprint("Golden match: False.", style="bold red")

    return result


"""Task Process"""


def start_conversation_round_stratified(
        output_dpath: str,
        msg_thread: MessageThread,
        state_manager: ProjectStateManager,
        print_callback: Optional[Callable[[dict], None]] = None,
) -> bool:
    """
    This version uses json data to process API calls, instead of using the OpenAI function calling.
    Advantage is that multiple API calls can be made in a single round.
    """
    process_status: Dict[int, bool] = {}

    ## Get the description of the diff code in the commit
    commit_prompt = state_manager.commit_manager.commit_files_info_seq()

    ## STEP 1: Execute the entire process multiple times and get the results with more votes
    for process_no in range(1, globals.complete_process_limit + 1):
        print_banner(f"COMPLETE PROCESS {process_no}")

        state_manager.reset_state()

        # FIXME: Add Reflexion Module to remind Agent the following info:
        #  (1) Previous successful process: previous hypothesis and analysis.
        #  (2) Previous failed process: failed reason.

        cur_hyp: Hypothesis | None = None
        cur_impt_code: List[Dict] | None = None
        cur_hyp_str: str | None = None

        verified_hypothesis: List[Hypothesis] = []
        unverified_hypothesis: List[Hypothesis] = []

        curr_loop = 0  # = number of current hypothesis being verified
        curr_proc_success = False
        curr_proc_dpath = make_hie_dirs(output_dpath, f"process_{process_no}")
        curr_proc_proxy_dpath = make_hie_dirs(curr_proc_dpath, f"proxy_agent")
        curr_proc_hyp_dpath = make_hie_dirs(curr_proc_dpath, f"hypothesis")
        curr_proc_tool_call_dpath = make_hie_dirs(curr_proc_dpath, "tool_calls")

        ## State switching process:
        # (1) start -> hypothesis_check
        # (2) hypothesis_check -> context_retrieval / end
        # (3) context_retrieval -> hypothesis_verify
        # (4) hypothesis_verify -> hypothesis_check
        while True:

            if state_manager.curr_state == State.START_STATE:
                ########## STEP I: Prepare init prompt (commit + instruction) ##########
                init_prompt = commit_prompt + "\n" + START_INSTRUCTION
                _add_usr_msg_and_print(
                    msg_thread=msg_thread,
                    usr_msg=init_prompt,
                    print_desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                ########## STEP II: Ask the actor agent to get init hypothesis ##########
                proxy_conv_save_fpath = os.path.join(curr_proc_proxy_dpath, f"init_hypothesis_propose.json")
                raw_hypothesis = _ask_actor_and_proxy_with_retries(state_manager=state_manager,
                                                                   msg_thread=msg_thread,
                                                                   process_no=process_no,
                                                                   proxy_extract_item="hypothesis",
                                                                   proxy_conv_save_fpath=proxy_conv_save_fpath,
                                                                   print_callback=print_callback)

                if raw_hypothesis is None:
                    # Failed to make valid hypothesis with retries
                    break

                print_proxy(
                    msg=raw_hypothesis,
                    desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                ##################### STEP III: Collect init hypothesis #####################
                raw_hyp_json = json.loads(raw_hypothesis)
                commit_type = raw_hyp_json["commit_type"]
                assert commit_type in CommitType.attributes()
                if commit_type == CommitType.NonVulnerabilityPatch:
                    unverified_hypothesis.append(
                        Hypothesis(commit_type=commit_type,
                                   vulnerability_type="",
                                   confidence_score=10)
                    )
                else:
                    # (1) Init hypothesis
                    for vul_type in raw_hyp_json["vulnerability_types"]:
                        hyp = format_raw_hyp(commit_type=commit_type,
                                             vul_type=vul_type[0],
                                             conf_score=vul_type[1])

                        unverified_hypothesis.append(hyp)

                    ## (2) Init patch locations
                    # Extract important code snippet related to the commit
                    raw_patch_locations = raw_hyp_json["patch_locations"]
                    # FIXME: Agent answer about locations may not be clear, need activate search.
                    #        Use state_manager.commit_manager
                    cur_impt_code = raw_patch_locations

                assert len(unverified_hypothesis) > 0

                # Save init hypothesis
                hypothesis_log = Path(curr_proc_hyp_dpath, f"init.json")
                save_hypothesis = {
                    "hypothesis": hypothesis_list_to_json(unverified_hypothesis),
                    "impt_code": cur_impt_code
                }
                hypothesis_log.write_text(json.dumps(save_hypothesis, indent=4))

                ##################### Step IV: Switch to next state #####################
                state_manager.switch_state(State.HYPOTHESIS_CHECK_STATE)

            elif state_manager.curr_state == State.HYPOTHESIS_CHECK_STATE:

                if len(verified_hypothesis) > globals.hypothesis_limit:
                    log_and_print("Too many verified hypothesis. End anyway.")
                    state_manager.switch_state(State.END_STATE)
                    continue

                if len(unverified_hypothesis) > 0:
                    ########## Case 1: There are still unverified hypothesis
                    curr_loop += 1

                    ########## Step 1-I: Select the unverified hypothesis with the highest confidence score ##########
                    unverified_hypothesis = sorted(unverified_hypothesis, key=lambda x: x.confidence_score, reverse=True)
                    cur_hyp = unverified_hypothesis[0]

                    ########## Step 1-II: Prepare prompt to describe the hypothesis ##########
                    if cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
                        # Describe the justify process
                        suffix_prompt = (
                            "Then you need to analyze the functionality of each code snippet in the commit "
                            "to see if it is irrelevant to the vulnerability fix."
                        )
                    else:
                        # Describe the important code snippet which is related to the vulnerability patch
                        # FIXME: For the important code snippet provided by Actor Agent, do we need to search again
                        #        to get a more accurate snippet?
                        assert cur_impt_code is not None
                        impt_code_seq = ""
                        for item in cur_impt_code:
                            file = item["file"]
                            code = item["code"]
                            code_class = item["class"] if "class" in item else None
                            code_func = item["func"] if "func" in item else None

                            item_seq = f"<file>{file}</file>\n"
                            if code_class is not None:
                                item_seq += f"<class>{code_class}</class> "
                            if code_func is not None:
                                item_seq += f"<func>{code_func}</func>"
                            item_seq += f"\n<code>\n{code}\n</code>\n\n"

                            impt_code_seq += item_seq

                        suffix_prompt = (
                            "The important code snippets and locations in this commit which are related to the vulnerability patch are as follows."
                            f"\n\n```"
                            f"\n{impt_code_seq}"
                            f"\n```"
                        )

                    cur_hyp_str = hypothesis_to_seq(cur_hyp)
                    hyp_select_prompt = (
                        f"Now your target is to justify the hypothesis: {cur_hyp_str}."
                        f"\n{suffix_prompt}"
                    )
                    _add_usr_msg_and_print(
                        msg_thread=msg_thread,
                        usr_msg=hyp_select_prompt,
                        print_desc=f"process {process_no} - state {state_manager.curr_state}",
                        print_callback=print_callback
                    )

                    ########## Step 1-III: Switch to next state ##########
                    state_manager.switch_state(State.CONTEXT_RETRIEVAL_STATE)

                else:
                    ########## Case 2: There is no unverified hypothesis
                    assert len(verified_hypothesis) > 0

                    ########## Step I: Collate all verified hypothesis ##########
                    verified_hypothesis = sorted(verified_hypothesis, key=lambda x: x.confidence_score, reverse=True)

                    ver_hyp_seq = ""
                    for i, hyp in enumerate(verified_hypothesis):
                        hyp_str = hypothesis_to_seq(hyp)
                        ver_hyp_seq += f"Hypothesis {i + 1}: {hyp_str}\n"

                    ########## Step II: Ask Actor Agent to make new hypothesis ##########
                    hyp_disc_prompt = ("So far you have proved the following hypothesis:"
                                       f"\n{ver_hyp_seq}"
                                       f"Based on the previous hypothesis and analyses, answer the below question:"
                                       f"\n- Are there better hypothesis: make hypothesis that differ from those already made. (leave it empty if there is no more appropriate hypothesis)"
                                       f"\n\nNOTE 1: A hypothesis contains three attributes, which are commit type, vulnerability type and confidence score."
                                       f"\ncommit type indicates if the commit fixes the vulnerability. Choose 'vulnerability_patch' or 'non_vulnerability_patch' as the answer."
                                       f"\nvulnerability type indicates the type of vulnerability that was fixed by this commit. Use CWE-ID as the answer, and leave it empty if you choose 'non_vulnerability_patch' for commit type."
                                       f"\nconfidence score indicates the level of reliability of this hypothesis. Choose an integer between 1 and 10 as the answer."
                                       f"\n\nNOTE 2: You can make multiple new hypothesis one time.")
                    _add_usr_msg_and_print(
                        msg_thread=msg_thread,
                        usr_msg=hyp_disc_prompt,
                        print_desc=f"process {process_no} - state {state_manager.curr_state}",
                        print_callback=print_callback
                    )

                    proxy_conv_save_fpath = os.path.join(curr_proc_proxy_dpath,
                                                         f"new_hypothesis_propose_loop_{curr_loop}.json")
                    raw_hypothesis = _ask_actor_and_proxy_with_retries(state_manager=state_manager,
                                                                       msg_thread=msg_thread,
                                                                       process_no=process_no,
                                                                       proxy_extract_item="hypothesis",
                                                                       proxy_conv_save_fpath=proxy_conv_save_fpath,
                                                                       print_callback=print_callback)

                    ########## Step III: Choose next step: end / continue verify ##########
                    if raw_hypothesis is None:
                        # Extract hypothesis with retries failed
                        state_manager.switch_state(State.END_STATE)
                        continue

                    json_hypothesis = json.loads(raw_hypothesis)
                    hypothesis_list = json_hypothesis["hypothesis_list"]

                    if len(hypothesis_list) == 0:
                        # No more new hypothesis
                        state_manager.switch_state(State.END_STATE)
                        continue

                    # Filter verified hypothesis
                    for hyp in hypothesis_list:
                        assert hyp["commit_type"] in CommitType.attributes()

                        # Check if verified
                        verified_flag = False
                        if hyp["commit_type"] == CommitType.NonVulnerabilityPatch:
                            for v_hyp in verified_hypothesis:
                                if v_hyp.commit_type == CommitType.NonVulnerabilityPatch:
                                    verified_flag = True
                                    break
                        else:
                            for v_hyp in verified_hypothesis:
                                if v_hyp.vulnerability_type == hyp["vulnerability_type"]:
                                    verified_flag = True
                                    break

                        # Add new hypothesis to unverified hypothesis
                        if not verified_flag:
                            hyp = format_raw_hyp(commit_type=hyp["commit_type"],
                                                 vul_type=hyp["vulnerability_type"],
                                                 conf_score=hyp["confidence_score"])
                            unverified_hypothesis.append(hyp)

            elif state_manager.curr_state == State.CONTEXT_RETRIEVAL_STATE:
                ## Prepare the init retrieval prompt
                init_retrieval_prompt = (
                    "Before conducting a formal analysis of the current hypothesis, "
                    "you must get enough contextual code information."
                    "\nSo in this step, based on the hypothesis and the existing code snippets, please select "
                    "the necessary application interfaces for more background information related to this commit."
                    f"\n{API_CALLS_DESCRIPTION}"
                )
                _add_usr_msg_and_print(
                    msg_thread=msg_thread,
                    usr_msg=init_retrieval_prompt,
                    print_desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                for state_round_no in range(1, globals.state_round_limit + 1):
                    # For recording tool calls in current round
                    state_manager.start_new_tool_call_layer()

                    # Ask the Actor Agent to use search api calls
                    respond_text = _ask_actor_agent_and_print_response(
                        msg_thread=msg_thread,
                        print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                        print_callback=print_callback
                    )

                    # Ask the Proxy Agent to extract standard JSON format api calls from the current response
                    proxy_conv_save_fpath = os.path.join(curr_proc_proxy_dpath,
                                                         f"context_retrieval_loop_{curr_loop}.json")
                    selected_apis = _ask_proxy_agent_and_save_msg(
                        state_manager=state_manager,
                        actor_respond_text=respond_text,
                        msg_save_path=proxy_conv_save_fpath,
                        msg_desc=f"Round {state_round_no}/{globals.state_round_limit}:"
                    )

                    # Retry
                    if selected_apis is None:
                        retry_msg = "The search API calls seem not valid. Please check the arguments you give carefully and try again."
                        _add_usr_msg_and_print(
                            msg_thread=msg_thread,
                            usr_msg=retry_msg,
                            print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                            print_callback=print_callback
                        )
                        continue

                    print_proxy(
                        msg=selected_apis,
                        desc=f"complete loop {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                        print_callback=print_callback
                    )

                    selected_apis_json = json.loads(selected_apis)
                    json_api_calls = selected_apis_json["api_calls"]

                    ## Case 1: Stop searching
                    if len(json_api_calls) == 0:
                        break

                    ## Case 2: Valid api calls, continue searching
                    # Invoke tools and prepare response according to api function calls
                    collated_tool_response = ""
                    for api_call in json_api_calls:
                        func_name, func_arg_values = parse_function_invocation(api_call)

                        func_arg_spec = inspect.getfullargspec(getattr(SearchManager, func_name))
                        func_arg_names = func_arg_spec.args[1:]  # first parameter is self

                        assert len(func_arg_values) == len(func_arg_names), \
                            f"Number of argument is wrong in API call: {api_call}"

                        func_arg_kwargs = dict(zip(func_arg_names, func_arg_values))
                        intent = FunctionCallIntent(func_name, func_arg_kwargs, None)
                        tool_output, _, _ = state_manager.dispatch_intent(intent, msg_thread)

                        collated_tool_response += f"Result of {api_call}:\n\n"
                        collated_tool_response += tool_output + "\n\n"

                    _add_usr_msg_and_print(
                        msg_thread=msg_thread,
                        usr_msg=collated_tool_response,
                        print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                        print_callback=print_callback
                    )

                    # Before getting more context, analyze whether it is necessary to continue
                    analyze_context_msg = ("First, let's briefly analyze the collected context to see if there are "
                                           "still unclear but important code snippets.")
                    _add_usr_msg_and_print(
                        msg_thread=msg_thread,
                        usr_msg=analyze_context_msg,
                        print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                        print_callback=print_callback
                    )

                    _ = _ask_actor_agent_and_print_response(
                        msg_thread=msg_thread,
                        print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                        print_callback=print_callback
                    )

                    if state_round_no < globals.state_round_limit:
                        decide_next_action_msg = (
                            "Based on your analysis, answer the question below:"
                            "\n - Do we need more context: construct search API calls to get more context of the project. (leave it empty if you don't need more context)"
                            f"\n{API_CALLS_DESCRIPTION}"
                        )
                        _add_usr_msg_and_print(
                            msg_thread=msg_thread,
                            usr_msg=decide_next_action_msg,
                            print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
                            print_callback=print_callback
                        )
                else:
                    logger.info("Too many rounds. Try to verify the hypothesis anyway.")

                # Switch to next state
                state_manager.switch_state(State.HYPOTHESIS_VERIFY_STATE)

            elif state_manager.curr_state == State.HYPOTHESIS_VERIFY_STATE:
                assert cur_hyp is not None and cur_hyp_str is not None

                ##################### Step I: Verify the hypothesis #####################
                # Prepare hypothesis verify prompt
                if cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
                    suffix_prompt = (
                        "For each modified code snippet involved in the commit, please complete the following tasks:\n"
                        "(1) Analyze the purpose of the modification.\n"
                        "(2) Determine whether the modification is unrelated to the vulnerability fix.")
                else:
                    cwe_description = state_manager.cwe_manager.get_cwe_description(cur_hyp.vulnerability_type)
                    cwe_description_seq = f"The description of {cur_hyp.vulnerability_type} is: {cwe_description}\n" \
                        if cwe_description else ""

                    suffix_prompt = (f"{cwe_description_seq}"
                                     "Please complete the following tasks:\n"
                                     "(1) Analyze the key variables and fix methods commonly involved in this CWE.\n"
                                     "(2) Find the corresponding key variables and fix methods in the code snippet involved in this commit.")

                hyp_verify_prompt = (
                    "Now you have enough context, please re-analyze the correctness of your previous hypothesis.\n"
                    f"Your hypothesis is: {cur_hyp_str}.\n"
                    f"{suffix_prompt}")
                _add_usr_msg_and_print(
                    msg_thread=msg_thread,
                    usr_msg=hyp_verify_prompt,
                    print_desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                # Ask the Actor Agent
                _ = _ask_actor_agent_and_print_response(
                    msg_thread=msg_thread,
                    print_desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                ##################### Step II: Re-score the hypothesis #####################
                # Prepare re-score prompt
                score_prompt = (
                    f"Based on the above analysis, please give the confidence score for this hypothesis (0-10). "
                    f"The previous score was {cur_hyp.confidence_score}/10.")
                _add_usr_msg_and_print(
                    msg_thread=msg_thread,
                    usr_msg=score_prompt,
                    print_desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                proxy_conv_save_fpath = os.path.join(curr_proc_proxy_dpath, f"score_update_loop_{curr_loop}.json")
                score = _ask_actor_and_proxy_with_retries(
                    state_manager=state_manager,
                    msg_thread=msg_thread,
                    process_no=process_no,
                    proxy_extract_item="confidence score",
                    proxy_conv_save_fpath=proxy_conv_save_fpath,
                    print_callback=print_callback
                )

                # This extraction is too simple and should not go wrong.
                assert score is not None
                print_proxy(
                    msg=score,
                    desc=f"process {process_no} - state {state_manager.curr_state}",
                    print_callback=print_callback
                )

                # Update confidence score of this hypothesis
                cur_hyp.confidence_score = json.loads(score)["confidence_score"]

                # Current hypothesis is verified
                verified_hypothesis.append(cur_hyp)
                unverified_hypothesis.pop(0)

                ##################### Step III: Switch to next state #####################
                state_manager.switch_state(State.HYPOTHESIS_CHECK_STATE)

            elif state_manager.curr_state == State.END_STATE:
                # Save end hypothesis
                hypothesis_log = Path(curr_proc_hyp_dpath, f"end.json")
                save_hypothesis = {
                    "hypothesis": hypothesis_list_to_json(verified_hypothesis),
                    "impt_code": cur_impt_code
                }
                hypothesis_log.write_text(json.dumps(save_hypothesis, indent=4))

                # Save the called search API calls
                state_manager.dump_tool_call_sequence_to_file(curr_proc_tool_call_dpath)
                state_manager.dump_tool_call_layers_to_file(curr_proc_tool_call_dpath)

                curr_proc_success = True
                break

        # Save current process state before starting a new process
        curr_loop_conversation_file = os.path.join(curr_proc_dpath, f"conversations.json")
        msg_thread.save_to_file(curr_loop_conversation_file)

        process_status[process_no] = curr_proc_success

        # Print the whole conversation in current process
        logger.info(f"\n========== Complete Process {process_no} ==========")
        logger.info(f"Current message thread:\n{msg_thread}")

    ## STEP 2: Evaluate the processes completed successfully
    proc_dpath_list = [os.path.join(output_dpath, f"process_{proc_id}") for proc_id, flag in process_status.items() if flag]
    eval_result = evaluation(proc_dpath_list, state_manager.task.cwe_id)
    eval_result.update({"process_count": len(proc_dpath_list),
                        "process_status": process_status})

    eval_res_path = Path(output_dpath, "evaluation.json")
    eval_res_path.write_text(json.dumps(eval_result, indent=4))

    logger.info("Ending workflow.")

    return True


def run_one_task(
        raw_commit_content: str,
        output_dpath: str,
        state_manager: ProjectStateManager,
        print_callback: Optional[Callable[[dict], None]] = None,
) -> bool:
    """
    Main entry point to run inference on one task.

    Args:
        raw_commit_content (str): The original commit content submitted to the task.
        output_dpath (str): Path to the output directory.
        state_manager (ProjectStateManager): The already-initialized API manager.
        print_callback:
    """
    print_banner("Starting Silent Patch Identification on the following commit")
    print_commit_content(raw_commit_content)
    msg_thread = MessageThread()

    system_prompt = SYSTEM_PROMPT
    msg_thread.add_system(system_prompt)

    return start_conversation_round_stratified(
        output_dpath, msg_thread, state_manager, print_callback=print_callback
    )
