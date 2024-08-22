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
from dataclasses import dataclass, field

from loguru import logger

from agent_app import globals, globals_mut
from agent_app.api.manage import ProcessManager
from agent_app.api.agent_proxy import ProxyTask
from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import State, CommitType, FunctionCallIntent, MessageThread, SearchStatus
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
The names of the code files involved are marked between <file> and </file>.
If the code lines are in a class or function, the class name or function name is marked between <class> and </class> or <func> and </func>, respectively.
NOTE: A commit may contain multiple changed files, and a changed file may contain multiple changed code lines.

Your task is to determine whether the commit fixes the vulnerability, and if so, give the most likely type of vulnerability, which is denoted by CWE-ID.
To achieve this, you need to make some reasonable hypothesis, and then use the search API calls to gather relevant context and verify the correctness of them. 
"""

START_INSTRUCTION = """In this step, first, you need to answer the following three questions in order based on the raw commit contents, then summarise the correctness of the hypothesis.
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

NOTE: You can use MULTIPLE search APIs in one round.
"""


"""EVALUATION"""


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


def task_evaluation(
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


"""HYPOTHESIS"""


@dataclass
class CodeSnippet:
    """Dataclass to hold code snippet."""
    file_path: str  # This is RELATIVE path
    class_name: str | None
    func_name: str | None
    code: str

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "class_name": self.class_name,
            "func_name": self.func_name,
            "code": self.code
        }

    def to_str(self) -> str:
        seq = f"<file>{self.file_path}</file>\n"
        if self.class_name is not None:
            seq += f"<class>{self.class_name}</class> "
        if self.func_name is not None:
            seq += f"<func>{self.func_name}</func>"
        seq += f"\n<code>\n{self.code}\n</code>"

        return seq


@dataclass
class Hypothesis:
    """Dataclass to hold hypothesis."""
    commit_type: CommitType
    vulnerability_type: str
    confidence_score: int

    def to_dict(self) -> Dict:
        return {
            "commit_type": self.commit_type,
            "vulnerability_type": self.vulnerability_type,
            "confidence_score": self.confidence_score
        }

    def to_str(self) -> str:
        return (f"- commit type: {self.commit_type}"
                f"\n- vulnerability type: {self.vulnerability_type}"
                f"\n- confidence_score: {self.confidence_score}")


@dataclass
class VerifiedHypothesis(Hypothesis):
    analysis: str

    def to_dict(self) -> Dict:
        info = super().to_dict()
        info.update({"analysis": self.analysis})

        return info

    def to_str(self) -> str:
        seq = super().to_str()
        seq += f"\n- analysis: {self.analysis}"

        return seq


def get_unverified_hypothesis(commit_type: str, vul_type: str, conf_score: int) -> Hypothesis:
    # (1) Check commit type
    assert commit_type in CommitType.attributes()

    # (2) Check vulnerability type (CWE-ID)
    if commit_type == CommitType.VulnerabilityPatch:
        assert re.fullmatch(r"CWE-(\d+)", vul_type)
    else:
        assert vul_type == ""

    # (3) Check confidence score
    assert isinstance(conf_score, int)
    conf_score = min(10, max(1, int(conf_score)))

    return Hypothesis(commit_type, vul_type, conf_score)


def describe_hypothesis(hyp: Hypothesis) -> str:
    """
    Describe the given hypothesis (unverified / verified).
    """
    if hyp.commit_type == CommitType.NonVulnerabilityPatch:
        desc = f"The given commit does not fix a vulnerability, and the confidence score is {hyp.confidence_score}/10"
    else:
        desc = f"The given commit fixes a vulnerability of type {hyp.vulnerability_type}, and the confidence score is {hyp.confidence_score}/10"

    return desc


def verify_hypothesis(hyp: Hypothesis, analysis: str) -> VerifiedHypothesis:
    ver_hyp = VerifiedHypothesis(
        commit_type=hyp.commit_type,
        vulnerability_type=hyp.vulnerability_type,
        confidence_score=hyp.confidence_score,
        analysis=analysis
    )
    return ver_hyp


"""ACTION WITH AGENT"""


def _add_usr_msg_and_print(
        usr_msg: str,
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Optional[Callable[[dict], None]] = None
) -> None:
    msg_thread.add_user(usr_msg)
    print_user(msg=usr_msg, desc=print_desc, print_callback=print_callback)


def _ask_actor_agent_and_print_response(
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Optional[Callable[[dict], None]] = None
) -> str:
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg())
    msg_thread.add_model(respond_text, tools=[])
    print_actor(msg=respond_text, desc=print_desc, print_callback=print_callback)
    return respond_text


def _ask_proxy_agent_and_save_msg(
        task: ProxyTask,
        manager: ProcessManager,
        actor_respond_text: str,
        proxy_conv_title: str,
        proxy_conv_fpath: str
) -> str | None:
    # (1) Ask the Proxy Agent
    json_text, _, proxy_msg_threads = manager.call_proxy_apis(actor_respond_text, task)

    # (2) Save the conversations with the Proxy Agent
    proxy_messages = [thread.to_msg() for thread in proxy_msg_threads]
    with open(proxy_conv_fpath, "a") as f:
        f.write(f"{proxy_conv_title}\n\n")
        json.dump(proxy_messages, f, indent=4)
        f.write("\n\n")

    return json_text


def _ask_actor_and_proxy_with_retries(
        task: ProxyTask,
        manager: ProcessManager,
        msg_thread: MessageThread,
        proxy_conv_save_fpath: str,
        print_desc: str = "",
        print_callback: Optional[Callable[[dict], None]] = None
) -> str | None:
    retry = 0
    while True:
        ############ (1) Ask the Actor Agent ############
        respond_text = _ask_actor_agent_and_print_response(msg_thread, print_desc, print_callback)

        ############ (2) Ask the Proxy Agent to extract standard JSON format data ############
        proxy_json_output = _ask_proxy_agent_and_save_msg(
            task=task,
            manager=manager,
            actor_respond_text=respond_text,
            proxy_conv_title=f"Retry {retry + 1}/{globals.state_retry_limit}",
            proxy_conv_fpath=proxy_conv_save_fpath
        )

        ############ (3) Whether to retry ############
        if proxy_json_output is None and retry < globals.state_retry_limit:
            retry += 1

            retry_msg = f"The given {task.task_target()} seems invalid. Please try again."
            print_desc = f"{print_desc} | retry {retry}" if print_desc != "" else f"retry {retry}"

            _add_usr_msg_and_print(retry_msg, msg_thread, print_desc, print_callback)
        else:
            break

    return proxy_json_output


"""SUB-PROCESS"""


@dataclass
class ProcessOutputDirs:
    """For recording all relevant output dir paths in current process."""
    root: str
    proxy_dpath: str
    hyp_dpath: str
    tool_call_dpath: str


@dataclass
class ProcHypothesis:
    """For recording all relevant info about hypothesis in current process."""
    cur_hyp: Hypothesis | None = None
    impt_code: List[CodeSnippet] = field(default_factory=list)
    unverified: List[Hypothesis] = field(default_factory=list)
    verified: List[VerifiedHypothesis] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "unverified": [hyp.to_dict() for hyp in self.unverified],
            "verified": [hyp.to_dict() for hyp in self.verified]
        }

    def sort_unverified(self):
        sorted_hyps = sorted(self.unverified, key=lambda x: x.confidence_score, reverse=True)
        self.unverified = sorted_hyps

    def sort_verified(self):
        sorted_hyps = sorted(self.verified, key=lambda x: x.confidence_score, reverse=True)
        self.verified = sorted_hyps


def run_in_start_state(
        process_no: int,
        curr_proc_dirs: ProcessOutputDirs,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> ProcHypothesis:
    print_desc = f"state {State.START_STATE} | process {process_no}"

    ###################################################
    ########## STEP I: Prepare system prompt ##########
    ###################################################

    msg_thread.add_system(SYSTEM_PROMPT)

    #########################################################################
    ########## STEP II: Prepare init prompt (commit + instruction) ##########
    #########################################################################

    commit_desc = manager.commit_manager.commit_files_info_seq()
    init_prompt = commit_desc + "\n" + START_INSTRUCTION
    _add_usr_msg_and_print(init_prompt, msg_thread, print_desc, print_callback)

    ####################################################
    ########## STEP III: Make init hypothesis ##########
    ####################################################

    proc_all_hypothesis: ProcHypothesis = ProcHypothesis()

    proxy_conv_save_fpath = os.path.join(curr_proc_dirs.proxy_dpath, f"init_hypothesis_proposal.json")
    raw_hypothesis = _ask_actor_and_proxy_with_retries(
        task=ProxyTask.INIT_HYP_PROPOSAL,
        manager=manager,
        msg_thread=msg_thread,
        proxy_conv_save_fpath=proxy_conv_save_fpath,
        print_desc=print_desc,
        print_callback=print_callback
    )

    if raw_hypothesis is None:
        # Failed to make valid hypothesis with retries
        return proc_all_hypothesis

    print_proxy(raw_hypothesis, print_desc, print_callback)

    ############################################################################
    ##################### STEP IV: Collect init hypothesis #####################
    ############################################################################

    # Collate init hypothesis
    raw_hyp_json = json.loads(raw_hypothesis)
    commit_type = raw_hyp_json["commit_type"]
    assert commit_type in CommitType.attributes()
    if commit_type == CommitType.NonVulnerabilityPatch:
        hyp = Hypothesis(commit_type=commit_type, vulnerability_type="", confidence_score=10)
        proc_all_hypothesis.unverified.append(hyp)
    else:
        for vul_type in raw_hyp_json["vulnerability_types"]:
            hyp = get_unverified_hypothesis(commit_type=commit_type, vul_type=vul_type[0], conf_score=vul_type[1])
            proc_all_hypothesis.unverified.append(hyp)

        # Extract important code snippet in the commit
        raw_patch_locations = raw_hyp_json["patch_locations"]
        # FIXME: Agent answer about locations may not be clear, need activate search. Use state_manager.commit_manager
        for loc in raw_patch_locations:
            fpath = loc["file"]
            class_name = loc.get("class_name", None)
            func_name = loc.get("func_name", None)
            code = loc["code"]
            code_snip = CodeSnippet(fpath, class_name, func_name, code)
            proc_all_hypothesis.impt_code.append(code_snip)

    assert len(proc_all_hypothesis.unverified) > 0

    # Save init hypothesis
    hypothesis_log = Path(curr_proc_dirs.hyp_dpath, f"init.json")
    hypothesis_log.write_text(json.dumps(proc_all_hypothesis.to_dict(), indent=4))

    return proc_all_hypothesis


def run_in_reflexion_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutputDirs,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> MessageThread:
    print_desc = f"state {State.REFLEXION_STATE} | process {process_no} | loop {loop_no}"

    #######################################
    ########## CASE 1: In loop 1 ##########
    #######################################

    if loop_no == 1:
        return msg_thread

    ###############################################
    ########## CASE 2: In loop i (i > 1) ##########
    ###############################################

    # Open a new conversation
    msg_thread = MessageThread()

    # Prepare system prompt
    msg_thread.add_system(SYSTEM_PROMPT)

    # Prepare the summary of all previous loops
    loop_summary = "In the previous analysis, you have made and analysed the following hypothesis:"

    # (1) Hypothesis description and analysis
    proc_all_hypothesis.sort_verified()

    for i, hyp in enumerate(proc_all_hypothesis.verified):
        desc = describe_hypothesis(hyp)
        loop_summary += (f"\nHypothesis {i + 1}: "
                         f"\n - Description: {desc}"
                         f"\n - Analysis: {hyp.analysis}")

    # (2) Code snippets
    loop_summary += "\n\nBesides, by calling the search APIs, you got the following code snippets which help with analysis."
    for c in proc_all_hypothesis.impt_code:
        loop_summary += "\n\n" + c.to_str()

    _add_usr_msg_and_print(loop_summary, msg_thread, print_desc, print_callback)

    return msg_thread


def run_in_hypothesis_check_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutputDirs,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> bool:
    print_desc = f"state {State.HYPOTHESIS_CHECK_STATE} | process {process_no} | loop {loop_no}"

    ############################################################
    ########## Step I: Whether to make new hypothesis ##########
    ############################################################
    if len(proc_all_hypothesis.unverified) == 0:
        assert len(proc_all_hypothesis.verified) > 0

        ######################################################################
        ########## Step I-1: Ask Actor Agent to make new hypothesis ##########
        ######################################################################

        make_hyp_prompt = (f"Based on the previous hypothesis and analyses, answer the below question:"
                           f"\n- Are there better hypothesis: make hypothesis that differ from those already made. (leave it empty if there is no more appropriate hypothesis)"
                           f"\n\nNOTE 1: A hypothesis contains three attributes: commit type, vulnerability type and confidence score."
                           f"\ncommit type indicates if the commit fixes the vulnerability. Choose 'vulnerability_patch' or 'non_vulnerability_patch' as the answer."
                           f"\nvulnerability type indicates the type of vulnerability that was fixed by this commit. Use CWE-ID as the answer, and leave it empty if you choose 'non_vulnerability_patch' for commit type."
                           f"\nconfidence score indicates the level of reliability of this hypothesis. Choose an integer between 1 and 10 as the answer."
                           f"\n\nNOTE 2: You can make multiple new hypothesis one time."
                           f"\n\nNOTE 3: DO NOT mention hypothesis you have made.")
        _add_usr_msg_and_print(make_hyp_prompt, msg_thread, print_desc, print_callback)

        proxy_conv_fpath = os.path.join(curr_proc_dirs.proxy_dpath, f"loop_{loop_no}_new_hypothesis_proposal.json")
        raw_hypothesis = _ask_actor_and_proxy_with_retries(
            task=ProxyTask.NEW_HYP_PROPOSAL,
            manager=manager,
            msg_thread=msg_thread,
            proxy_conv_save_fpath=proxy_conv_fpath,
            print_desc=print_desc,
            print_callback=print_callback
        )

        if raw_hypothesis is None:
            # Extract hypothesis with retries failed
            return False

        #######################################################################
        ########## Step I-2: Choose next step: end / continue verify ##########
        #######################################################################

        print_proxy(raw_hypothesis, print_desc, print_callback)

        json_hypothesis = json.loads(raw_hypothesis)
        hypothesis_list = json_hypothesis["hypothesis_list"]

        if len(hypothesis_list) == 0:
            # No more new hypothesis
            return False

        # Filter verified hypothesis
        for hyp in hypothesis_list:
            assert hyp["commit_type"] in CommitType.attributes()

            # Check if verified
            verified_flag = False
            if hyp["commit_type"] == CommitType.NonVulnerabilityPatch:
                for v_hyp in proc_all_hypothesis.verified:
                    if v_hyp.commit_type == CommitType.NonVulnerabilityPatch:
                        verified_flag = True
                        break
            else:
                for v_hyp in proc_all_hypothesis.verified:
                    if v_hyp.vulnerability_type == hyp["vulnerability_type"]:
                        verified_flag = True
                        break

            # Add new hypothesis to unverified hypothesis
            if not verified_flag:
                hyp = get_unverified_hypothesis(commit_type=hyp["commit_type"],
                                                vul_type=hyp["vulnerability_type"],
                                                conf_score=hyp["confidence_score"])
                proc_all_hypothesis.unverified.append(hyp)

    ########################################################################
    ########## Step II: Select an unverified hypothesis to verify ##########
    ########################################################################

    proc_all_hypothesis.sort_unverified()
    proc_all_hypothesis.cur_hyp = proc_all_hypothesis.unverified[0]

    #########################################################################
    ########## Step III: Prepare prompt to describe the hypothesis ##########
    #########################################################################

    if proc_all_hypothesis.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        # Describe the justify process
        suffix_prompt = "Then you need to analyze the functionality of each code snippet in the commit to determine if it is not relevant to vulnerability fixing."
    else:
        # Describe the important code snippet which is related to the vulnerability patch
        # FIXME: For the important code snippet provided by Actor Agent, do we need to search again
        #       to get a more accurate snippet?
        assert proc_all_hypothesis.impt_code is not None

        impt_code_seq = ""
        for item in proc_all_hypothesis.impt_code:
            impt_code_seq += item.to_str() + "\n\n"

        suffix_prompt = (
            "The important code snippets and locations in this commit which are related to the vulnerability patch are as follows."
            f"\n\n```"
            f"{impt_code_seq}"
            f"\n```"
        )

    cur_hyp_str = describe_hypothesis(proc_all_hypothesis.cur_hyp)
    hyp_select_prompt = (
        f"Now your target is to justify the hypothesis: {cur_hyp_str}."
        f"\n{suffix_prompt}"
    )
    _add_usr_msg_and_print(hyp_select_prompt, msg_thread, print_desc, print_callback)

    return True


def run_in_context_retrieval_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutputDirs,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
):
    print_desc = f"state {State.CONTEXT_RETRIEVAL_STATE} | process {process_no} | loop {loop_no}"

    ###############################################################
    ########## Step I: Prepare the init retrieval prompt ##########
    ###############################################################

    init_retrieval_prompt = (
        "Before conducting a formal analysis of the current hypothesis, you must get enough contextual code information."
        "\nSo in this step, based on the hypothesis and the existing code snippets, please select the necessary search APIs for more background information related to this commit."
        f"\n{API_CALLS_DESCRIPTION}"
    )
    _add_usr_msg_and_print(init_retrieval_prompt, msg_thread, print_desc, print_callback)

    ############################################################
    ########## Step II: Multi-round context retrieval ##########
    ############################################################

    manager.reset_too_call_recordings()

    for round_no in range(1, globals.state_round_limit + 1):
        round_print_desc = f"{print_desc} | round {round_no}"
        # For recording tool calls in current round
        manager.start_new_tool_call_layer()

        # Ask the Actor Agent to use search api calls
        respond_text = _ask_actor_agent_and_print_response(msg_thread, round_print_desc, print_callback)

        # Ask the Proxy Agent to extract standard JSON format api calls from the current response
        proxy_conv_fpath = os.path.join(curr_proc_dirs.proxy_dpath, f"loop_{loop_no}_context_retrieval.json")
        selected_apis = _ask_proxy_agent_and_save_msg(
            task=ProxyTask.CONTEXT_RETRIEVAL,
            manager=manager,
            actor_respond_text=respond_text,
            proxy_conv_title=f"Round {round_no}/{globals.state_round_limit}",
            proxy_conv_fpath=proxy_conv_fpath
        )

        ##############################################
        ########### Case 1: Invalid respond ##########
        ##############################################

        if selected_apis is None:
            retry_msg = "The search API calls seem not valid. Please check the arguments you give carefully and try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, round_print_desc, print_callback)
            continue

        #############################################
        ########### Case 2: Valid respond ###########
        #############################################

        print_proxy(selected_apis, round_print_desc, print_callback)

        selected_apis_json = json.loads(selected_apis)
        json_api_calls = selected_apis_json["api_calls"]

        ########### Case 2-1: Stop searching ###########
        if len(json_api_calls) == 0:
            break

        ########### Case 2-2: Continue searching ###########
        # Invoke tools and prepare response according to api function calls
        collated_tool_response = ""

        # deal_special = False
        #
        # detail_instruction = "The file name in the following calls is not detailed enough, please select the more precise file name and then provide the full form of these calls.\n\n"
        # special_case_response = ""

        for api_call in json_api_calls:
            func_name, func_arg_values = parse_function_invocation(api_call)

            func_arg_spec = inspect.getfullargspec(getattr(SearchManager, func_name))
            func_arg_names = func_arg_spec.args[1:]  # first parameter is self

            assert len(func_arg_values) == len(func_arg_names), f"Number of argument is wrong in API call: {api_call}"

            func_arg_kwargs = dict(zip(func_arg_names, func_arg_values))
            intent = FunctionCallIntent(func_name, func_arg_kwargs, None)
            tool_output, search_status, all_search_res = manager.dispatch_intent(intent)

            # FIXME: Complete procedure processing calls with file name not detailed enough
            # Consider special case -> the iven file name points to a file that is not unique
            # if search_status == SearchStatus.NON_UNIQUE_FILE:
            #     deal_special = True
            #     special_case_response += f"Result of {api_call}:\n\n"
            #     collated_tool_response += tool_output + "\n\n"
            # else:
            #     collated_tool_response += f"Result of {api_call}:\n\n"
            #     collated_tool_response += tool_output + "\n\n"

            # (1) Collect str response
            collated_tool_response += f"Result of {api_call}:\n\n"
            collated_tool_response += tool_output + "\n\n"

            # (2) Collect code snippet extracted
            for res in all_search_res:
                code_snip = CodeSnippet(res.file_path, res.class_name, res.func_name, res.code)
                proc_all_hypothesis.impt_code.append(code_snip)

        # if deal_special:
        #     _add_usr_msg_and_print(
        #         msg_thread=msg_thread,
        #         usr_msg=special_case_response,
        #         print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
        #         print_callback=print_callback
        #     )
        #
        #     respond_text = _ask_actor_agent_and_print_response(
        #         msg_thread=msg_thread,
        #         print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
        #         print_callback=print_callback
        #     )

        _add_usr_msg_and_print(collated_tool_response, msg_thread, round_print_desc, print_callback)

        # TODO: Whether to analyse before continuing to search for context ?
        # Before getting more context, analyze whether it is necessary to continue
        # analyze_context_msg = ("First, let's briefly analyze the collected context to see if there are "
        #                        "still unclear but important code snippets.")
        # _add_usr_msg_and_print(
        #     msg_thread=msg_thread,
        #     usr_msg=analyze_context_msg,
        #     print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
        #     print_callback=print_callback
        # )
        #
        # _ = _ask_actor_agent_and_print_response(
        #     msg_thread=msg_thread,
        #     print_desc=f"process {process_no} - state {state_manager.curr_state} - round {state_round_no}",
        #     print_callback=print_callback
        # )

        if round_no < globals.state_round_limit:
            retrieval_msg = (
                "Based on the extracted code snippets related to the commit, answer the question below:"
                "\n - Do we need more context: construct search API calls to get more context of the project. (leave it empty if you don't need more context)"
                f"\n{API_CALLS_DESCRIPTION}"
            )
            _add_usr_msg_and_print(retrieval_msg, msg_thread, round_print_desc, print_callback)
    else:
        logger.info("Too many rounds. Try to verify the hypothesis anyway.")

    ################################################################
    ########## Step III: Save the called search API calls ##########
    ################################################################

    manager.dump_tool_call_sequence_to_file(curr_proc_dirs.tool_call_dpath, f"loop_{loop_no}")
    manager.dump_tool_call_layers_to_file(curr_proc_dirs.tool_call_dpath, f"loop_{loop_no}")

    return proc_all_hypothesis


def run_in_hypothesis_verify_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutputDirs,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> bool:
    print_desc = f"state {State.HYPOTHESIS_VERIFY_STATE} | process {process_no} | loop {loop_no}"

    ###################################################
    ########## Step I: Verify the hypothesis ##########
    ###################################################

    assert proc_all_hypothesis.cur_hyp is not None

    # Prepare hypothesis verify prompt
    if proc_all_hypothesis.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        suffix_prompt = (
            "For each modified code snippet involved in the commit, please complete the following tasks:\n"
            "(1) Analyze the purpose of the modification.\n"
            "(2) Determine whether the modification is unrelated to the vulnerability fix.")
    else:
        cwe_type = proc_all_hypothesis.cur_hyp.vulnerability_type
        cwe_description = manager.cwe_manager.get_cwe_description(cwe_type)
        cwe_description_seq = f"The description of {cwe_type} is: {cwe_description}\n" if cwe_description else ""

        suffix_prompt = (f"{cwe_description_seq}"
                         "Please complete the following tasks:\n"
                         "(1) Analyze the key variables and fix methods commonly involved in this CWE.\n"
                         "(2) Find the corresponding key variables and fix methods in the code snippet involved in this commit.")

    cur_hyp_str = describe_hypothesis(proc_all_hypothesis.cur_hyp)
    hyp_verify_prompt = (
        "Now you have enough context, please re-analyze the correctness of your previous hypothesis.\n"
        f"Your hypothesis is: {cur_hyp_str}.\n"
        f"{suffix_prompt}")
    _add_usr_msg_and_print(hyp_verify_prompt, msg_thread, print_desc, print_callback)

    # Ask the Actor Agent
    analysis_text = _ask_actor_agent_and_print_response(msg_thread, print_desc, print_callback)

    ######################################################
    ########## Step II: Re-score the hypothesis ##########
    ######################################################

    # Prepare re-score prompt
    score_prompt = (
        f"Based on the above analysis, please give the confidence score for this hypothesis (0-10). "
        f"The previous score was {proc_all_hypothesis.cur_hyp.confidence_score}/10.")
    _add_usr_msg_and_print(score_prompt, msg_thread, print_desc, print_callback)

    # Ask the Actor Agent and Proxy Agent
    proxy_conv_save_fpath = os.path.join(curr_proc_dirs.proxy_dpath, f"loop_{loop_no}_score_update.json")
    score = _ask_actor_and_proxy_with_retries(
        task=ProxyTask.SCORE,
        manager=manager,
        msg_thread=msg_thread,
        proxy_conv_save_fpath=proxy_conv_save_fpath,
        print_callback=print_callback
    )

    # This extraction is too simple and should not go wrong.
    assert score is not None
    print_proxy(score, print_desc, print_callback)

    #########################################################
    ########## Step III: Update all the hypothesis ##########
    #########################################################

    # (1) Update the confidence score of the current hypothesis
    proc_all_hypothesis.cur_hyp.confidence_score = json.loads(score)["confidence_score"]

    # (2) Update the current hypothesis from unverified to verified
    ver_hyp = verify_hypothesis(proc_all_hypothesis.cur_hyp, analysis_text)

    proc_all_hypothesis.verified.append(ver_hyp)
    proc_all_hypothesis.unverified.pop(0)

    ####################################################
    ########## Step IV: Save the conversation ##########
    ####################################################

    # Save the conversation of the current loop
    curr_loop_conversation_file = os.path.join(curr_proc_dirs.root, f"loop_{loop_no}_conversations.json")
    msg_thread.save_to_file(curr_loop_conversation_file)

    ##############################################
    ########## Step V: Decide next step ##########
    ##############################################

    if len(proc_all_hypothesis.verified) > globals.hypothesis_limit:
        log_and_print("Too many verified hypothesis. End anyway.")
        return False

    return True


def run_in_end_state(
        process_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutputDirs,
        msg_thread: MessageThread,
        state_manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
):
    # Save end hypothesis
    proc_all_hypothesis.sort_verified()
    proc_all_hypothesis.sort_unverified()

    hypothesis_log = Path(curr_proc_dirs.hyp_dpath, f"end.json")
    hypothesis_log.write_text(json.dumps(proc_all_hypothesis.to_dict(), indent=4))


"""MAIN PROCESS"""


def start_conversation_round_stratified(
        output_dpath: str,
        state_manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> bool:
    """
    This version uses json data to process API calls, instead of using the OpenAI function calling.
    Advantage is that multiple API calls can be made in a single round.
    """
    process_status: Dict[int, bool] = {}

    ################################################################
    #################### STEP 1: Identification ####################
    ################################################################

    for process_no in range(1, globals.complete_process_limit + 1):
        print_banner(f"COMPLETE PROCESS {process_no}")

        # FIXME: Add Reflexion Module to remind Agent the following info:
        #  (1) Previous successful process: previous hypothesis and analysis.
        #  (2) Previous failed process: failed reason.

        ## I. Preparation
        process_status[process_no] = False

        curr_proc_dpath = make_hie_dirs(output_dpath, f"process_{process_no}")
        curr_proc_proxy_dpath = make_hie_dirs(curr_proc_dpath, f"proxy_agent")
        curr_proc_hyp_dpath = make_hie_dirs(curr_proc_dpath, f"hypothesis")
        curr_proc_tool_call_dpath = make_hie_dirs(curr_proc_dpath, "tool_calls")

        curr_proc_dirs = ProcessOutputDirs(
            root=curr_proc_dpath,
            proxy_dpath=curr_proc_proxy_dpath,
            hyp_dpath=curr_proc_hyp_dpath,
            tool_call_dpath=curr_proc_tool_call_dpath,
        )

        msg_thread = MessageThread()

        ## II. Workflow
        ########## START ##########
        proc_all_hyp = run_in_start_state(process_no, curr_proc_dirs, msg_thread, state_manager, print_callback)

        if len(proc_all_hyp.unverified) == 0:
            continue

        ## State switching process:
        # Complete loop: hypothesis_check -> context_retrieval -> hypothesis_verify
        # Complete process: start -> loop -> ( reflexion -> loop ) -> ... -> ( reflexion -> loop ) -> end
        loop_no = 0

        while True:
            loop_no += 1

            ########## (1) Reflexion ##########
            msg_thread = run_in_reflexion_state(
                process_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, state_manager, print_callback)

            ########## (2) Hypothesis check ##########
            continue_loop = run_in_hypothesis_check_state(
                process_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, state_manager, print_callback)

            if not continue_loop:
                break

            ########## (3) Context retrieval ##########
            run_in_context_retrieval_state(
                process_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, state_manager, print_callback)

            ########## (4) Hypothesis verify ##########
            continue_loop = run_in_hypothesis_verify_state(
                process_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, state_manager, print_callback)

            print(len(proc_all_hyp.verified))

            if not continue_loop:
                break

        ########## END ##########
        run_in_end_state(process_no, proc_all_hyp, curr_proc_dirs, msg_thread, state_manager, print_callback)

        ## III. Record
        process_status[process_no] = True

        # Print the whole conversation in current process
        logger.info(f"\n========== Complete Process {process_no} ==========")
        logger.info(f"Current message thread:\n{msg_thread}")

    ############################################################
    #################### STEP 2: Evaluation ####################
    ############################################################

    proc_dpath_list = [os.path.join(output_dpath, f"process_{proc_id}") for proc_id, flag in process_status.items() if flag]
    eval_result = task_evaluation(proc_dpath_list, state_manager.task.cwe_id)
    eval_result.update({"process_count": len(proc_dpath_list),
                        "process_status": process_status})

    eval_res_path = Path(output_dpath, "evaluation.json")
    eval_res_path.write_text(json.dumps(eval_result, indent=4))

    logger.info("Ending workflow.")

    return True


def run_one_task(
        raw_commit_content: str,
        output_dpath: str,
        state_manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None,
) -> bool:
    """
    Main entry point to run inference on one task.

    Args:
        raw_commit_content (str): The original commit content submitted to the task.
        output_dpath (str): Path to the output directory.
        state_manager (ProcessManager): The already-initialized API manager.
        print_callback:
    """
    print_banner("Starting Silent Patch Identification on the following commit")
    print_commit_content(raw_commit_content)

    return start_conversation_round_stratified(output_dpath, state_manager, print_callback)
