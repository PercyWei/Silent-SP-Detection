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
from agent_app.data_structures import State, CommitType, CodeSnippetLocation, FunctionCallIntent, MessageThread, SearchStatus
from agent_app.log import (
    print_banner,
    print_system, print_user, print_actor, print_proxy,
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


HYP_DEF = """
A hypothesis contains three attributes: commit type, vulnerability type and confidence score.
- commit type: It indicates whether the commit fixes a vulnerability. Choose answer from "vulnerability_patch" and "non_vulnerability_patch".
- vulnerability type: It indicates the type of vulnerability that was fixed by this commit. Use CWE-ID as the answer, and leave it empty if you choose 'non_vulnerability_patch' for commit type.
- confidence score: It indicates the level of reliability of the hypothesis. Choose an integer between 1 and 10 as the answer.
"""


START_INSTRUCTION = """In this step, first, you need to make hypothesis about the functionality of the commit.
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


@dataclass
class EvalResult:
    target_commit_type: int
    target_vul_type: str | None
    commit_type_match_rank: int | None = None
    vul_type_match_rank: int | None = None

    def full_to_dict(self):
        return {
            "target_commit_type": self.target_commit_type,
            "target_vul_type": self.target_vul_type,
            "commit_type_match_rank": self.commit_type_match_rank,
            "vul_type_match_rank": self.vul_type_match_rank
        }

    def rank_to_dict(self):
        return {
            "commit_type_match_rank": self.commit_type_match_rank,
            "vul_type_match_rank": self.vul_type_match_rank
        }


def hypothesis_rank_evaluation(
        target_commit_type: int,
        target_vul_type: str | None,
        hyp_list: List[Dict]
) -> EvalResult:

    eval_res = EvalResult(target_commit_type, target_vul_type)

    hyp_list = sorted(hyp_list, key=lambda x: x["confidence_score"], reverse=True)

    target_commit_type = "vulnerability_patch" if target_commit_type == 1 else "non_vulnerability_patch"

    for i, hyp in enumerate(hyp_list):
        # (1) Evaluate commit type
        if hyp["commit_type"] == target_commit_type and eval_res.commit_type_match_rank is None:
            eval_res.commit_type_match_rank = i + 1

        # (2) Evaluate vulnerability type
        if target_vul_type is not None and \
                hyp["vulnerability_type"] == target_vul_type and \
                eval_res.vul_type_match_rank is None:
            eval_res.vul_type_match_rank = i + 1

    return eval_res


def task_evaluation(
        target_commit_type: int,
        target_vul_type: str | None,
        proc_dpath_list: List[str],
        final_res_fpath: str
) -> Dict:
    all_res = {
        "target_commit_type": target_commit_type,
        "target_vul_type": target_vul_type,
    }

    proc_results = {}
    # Step 1: Evaluate each process results
    for proc_dpath in proc_dpath_list:
        proc_name = proc_dpath.split("/")[-1]
        proc_hyp_dpath = os.path.join(proc_dpath, "hypothesis")

        # (1) Process init hypothesis
        init_hyp_fpath = os.path.join(proc_hyp_dpath, "init.json")
        with open(init_hyp_fpath, "r") as f:
            proc_init_hyps = json.load(f)["unverified"]
            proc_init_res = hypothesis_rank_evaluation(target_commit_type, target_vul_type, proc_init_hyps)

        # (2) Process final hypothesis
        end_hyp_fpath = os.path.join(proc_hyp_dpath, "final.json")
        with open(end_hyp_fpath, "r") as f:
            proc_final_hyps = json.load(f)["verified"]
            proc_final_res = hypothesis_rank_evaluation(target_commit_type, target_vul_type, proc_final_hyps)

        proc_results[proc_name] = {
            "init": proc_init_res.rank_to_dict(),
            "final": proc_final_res.rank_to_dict()
        }

    all_res["process_results"] = proc_results

    # Step 2: Evaluate the final results
    with open(final_res_fpath, "r") as f:
        final_hyps = json.load(f)
    final_res = hypothesis_rank_evaluation(target_commit_type, target_vul_type, final_hyps)

    all_res["final_result"] = final_res.rank_to_dict()

    return all_res


"""HYPOTHESIS"""


@dataclass
class CodeContext(CodeSnippetLocation):
    """Dataclass to hold the locations of searched code snippet."""

    def to_str(self) -> str:
        return self.to_tagged_str()


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


def _add_system_msg_and_print(
        system_msg: str,
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Optional[Callable[[dict], None]] = None
) -> None:
    msg_thread.add_system(system_msg)
    print_system(msg=system_msg, desc=print_desc, print_callback=print_callback)


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

    convs = []
    if os.path.exists(proxy_conv_fpath):
        with open(proxy_conv_fpath, "r") as f:
            convs = json.load(f)

    convs.append({proxy_conv_title: proxy_messages})

    with open(proxy_conv_fpath, "w") as f:
        json.dump(convs, f, indent=4)

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


"""POST-PROCESS"""


def calculate_final_confidence_score(all_hyps: List[Dict], proc_num: int, cal_type: int = 0) -> List[Dict]:
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

    def _normalize(_score):
        # 0-10 -> 0-1
        return _score * 0.1

    def _denormalize(_score):
        # 0-1 -> 0-10
        return _score * 10

    ## CASE 1: Process number = 1
    if proc_num == 1:
        all_hyps = sorted(all_hyps, key=lambda x: x["confidence_score"], reverse=True)
        return all_hyps

    ## CASE 2: Process number > 1
    hyp_score = defaultdict(lambda: {"count": 0, "total_score": 0})

    if cal_type == 0:
        for hyp in all_hyps:
            hyp_name = hyp["commit_type"] + "." + hyp["vulnerability_type"]
            hyp_score[hyp_name]["count"] += 1
            hyp_score[hyp_name]["total_score"] += _normalize(hyp["confidence_score"])

        hyp_final_score = {
            hyp_name: data["total_score"] / proc_num
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
                   "confidence_score": score}
                  for hyp_name, score in hyp_final_score.items()]

    final_hyps = sorted(final_hyps, key=lambda x: x["confidence_score"], reverse=True)

    return final_hyps


def vote_on_result(proc_dpaths: List[str]) -> List[Dict]:
    all_ver_hyps: List[Dict] = []

    for proc_dpath in proc_dpaths:
        proc_final_hyp_fpath = os.path.join(proc_dpath, "hypothesis", "final.json")

        with open(proc_final_hyp_fpath, "r") as f:
            end_hyps = json.load(f)["verified"]
            all_ver_hyps.extend(end_hyps)

    final_hyps = calculate_final_confidence_score(all_ver_hyps, proc_num=len(proc_dpaths))

    return final_hyps


"""SUB-PROCESS"""


@dataclass
class ProcessOutPaths:
    """For recording all relevant output paths in current process."""
    root: str
    hyp_dpath: str
    proxy_dpath: str
    tool_call_dpath: str


@dataclass
class ProcHypothesis:
    """For recording all relevant info about hypothesis in current process."""
    cur_hyp: Hypothesis | None = None
    unverified: List[Hypothesis] = field(default_factory=list)
    verified: List[VerifiedHypothesis] = field(default_factory=list)
    patch: List[CodeContext] = field(default_factory=list)
    code_context: List[CodeContext] = field(default_factory=list)

    def hyp_to_dict(self) -> Dict:
        return {
            "unverified": [hyp.to_dict() for hyp in self.unverified],
            "verified": [hyp.to_dict() for hyp in self.verified]
        }

    def code_to_str(self) -> str:
        code_seq_list = []
        for c in self.code_context:
            code_seq_list.append(c.to_str())
        return "\n\n".join(code_seq_list)

    def patch_to_str(self) -> str:
        code_seq_list = []
        for c in self.patch:
            code_seq_list.append(c.to_str())
        return "\n\n".join(code_seq_list)

    def sort_unverified(self) -> None:
        sorted_hyps = sorted(self.unverified, key=lambda x: x.confidence_score, reverse=True)
        self.unverified = sorted_hyps

    def sort_verified(self) -> None:
        sorted_hyps = sorted(self.verified, key=lambda x: x.confidence_score, reverse=True)
        self.verified = sorted_hyps

    def in_unverified(self, hyp: Hypothesis) -> bool:
        for u_hyp in self.unverified:
            if u_hyp.commit_type == hyp.commit_type and u_hyp.vulnerability_type == hyp.vulnerability_type:
                return True
        return False

    def in_verified(self, hyp: Hypothesis) -> bool:
        for v_hyp in self.verified:
            if v_hyp.commit_type == hyp.commit_type and v_hyp.vulnerability_type == hyp.vulnerability_type:
                return True
        return False

    def save_hyp_to_file(self, fpath: str) -> None:
        with open(fpath, "w") as f:
            json.dump(self.hyp_to_dict(), f, indent=4)


def run_in_start_state(
        process_no: int,
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> ProcHypothesis | None:
    print_desc = f"state {State.START_STATE} | process {process_no}"

    ##########################
    # STEP I: Prepare prompt #
    ##########################

    # (1) System prompt
    _add_system_msg_and_print(SYSTEM_PROMPT, msg_thread, print_desc, print_callback)

    # (2) Hypothesis proposal prompt
    commit_desc = manager.commit_manager.describe_commit_files()
    hyp_prop_prompt = ("The content of the commit is as follows:"
                       f"\n{commit_desc}"
                       "\n\nIn this step, based on the raw commit content, you need to make hypothesis about the functionality of the commit."
                       f"{HYP_DEF}"
                       f"\n\nNOTE: You can make multiple new hypothesis one time.")

    _add_usr_msg_and_print(hyp_prop_prompt, msg_thread, print_desc, print_callback)

    ##################################################
    # STEP II: Ask the Agent to make init hypothesis #
    ##################################################

    proxy_conv_save_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"init_hypothesis_proposal.json")
    raw_hypothesis = _ask_actor_and_proxy_with_retries(
        task=ProxyTask.HYP_PROPOSAL,
        manager=manager,
        msg_thread=msg_thread,
        proxy_conv_save_fpath=proxy_conv_save_fpath,
        print_desc=print_desc,
        print_callback=print_callback
    )

    if raw_hypothesis is None:
        # Failed to make valid hypothesis with retries
        return None

    print_proxy(msg=raw_hypothesis, desc=print_desc, print_callback=print_callback)

    #####################################
    # STEP III: Collect init hypothesis #
    #####################################

    proc_all_hypothesis: ProcHypothesis = ProcHypothesis()

    json_hyp = json.loads(raw_hypothesis)
    hyp_list = json_hyp["hypothesis_list"]
    for hyp in hyp_list:
        hyp = get_unverified_hypothesis(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])
        if not proc_all_hypothesis.in_unverified(hyp):
            proc_all_hypothesis.unverified.append(hyp)

    assert len(proc_all_hypothesis.unverified) > 0

    proc_all_hypothesis.sort_unverified()
    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "init.json")
    proc_all_hypothesis.save_hyp_to_file(hyp_fpath)

    ###################################
    # STEP V: Extract patch locations #
    ###################################

    # Determine whether we need to extract the exact patch locations
    patch_exist = False
    for hyp in proc_all_hypothesis.unverified:
        if hyp.commit_type == CommitType.VulnerabilityPatch:
            patch_exist = True
            break

    if patch_exist:
        #############################################
        # Step V-1: Prepare patch extraction prompt #
        #############################################

        patch_extraction_prompt = ("Since your hypothesis include the case that the commit fixes a vulnerability, we need to extract the code snippets that might be the patch from the original commit."
                                   "\n\nNOTE: For each extracted code snippet, you should at least provide its 'file_name' and 'code', while 'class_name' and 'func_name' are not required.")

        _add_usr_msg_and_print(patch_extraction_prompt, msg_thread, print_desc, print_callback)

        ######################################################
        # Step V-2: Ask the Agent to extract patch locations #
        ######################################################

        proxy_conv_save_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"patch_extraction.json")
        patch_locations = _ask_actor_and_proxy_with_retries(
            task=ProxyTask.PATCH_EXTRACTION,
            manager=manager,
            msg_thread=msg_thread,
            proxy_conv_save_fpath=proxy_conv_save_fpath,
            print_desc=print_desc,
            print_callback=print_callback
        )

        #####################################
        # Step V-3: Collect patch locations #
        #####################################

        if patch_locations is not None:
            print_proxy(msg=patch_locations, desc=print_desc, print_callback=print_callback)

            json_patch_locations = json.loads(patch_locations)
            raw_patch_locations = json_patch_locations["patch_locations"]
            # TODO: Agent answer about locations may not be clear, need activate search. Use state_manager.commit_manager
            for loc in raw_patch_locations:
                fpath = loc["file"]
                class_name = loc.get("class_name", None)
                func_name = loc.get("func_name", None)
                code = loc["code"]
                code_snip = CodeContext(fpath, class_name, func_name, code)
                proc_all_hypothesis.patch.append(code_snip)

    return proc_all_hypothesis


def run_in_reflexion_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> MessageThread:
    """
    In order to prevent the forgetting problem caused by too many rounds of interaction with LLM,
    we open a new round conversation after a complete loop (make hypothesis -> context retrieval -> verify hypothesis)
    """
    print_desc = f"state {State.REFLEXION_STATE} | process {process_no} | loop {loop_no}"

    if loop_no == 1:
        return msg_thread

    # Open a new conversation
    msg_thread = MessageThread()

    ################################
    # Prepare the reflexion prompt #
    ################################

    # (1) System prompt
    _add_system_msg_and_print(SYSTEM_PROMPT, msg_thread, print_desc, print_callback)

    # (2) Commit content
    commit_desc = manager.commit_manager.describe_commit_files()
    commit_prompt = ("The content of the commit is as follows:"
                     f"\n{commit_desc}")

    # (3) Summary of all previous loops
    # 3.1 Hypothesis description and analysis
    proc_all_hypothesis.sort_verified()

    # TODO: Briefly summary the analysis of previous hypothesis?

    loop_summary = "In the previous analysis, you have made and analysed the following hypothesis:"
    for i, hyp in enumerate(proc_all_hypothesis.verified):
        desc = describe_hypothesis(hyp)
        loop_summary += (f"\nHypothesis {i + 1}: "
                         f"\n - Description: {desc}"
                         f"\n - Analysis: {hyp.analysis}")

    # 3.2 Code snippets of patch and context
    # TODO: How do we add the contents of patch locations?
    code_snippet_prompt = ("Besides, by calling the search APIs, you have got the following code snippets which help with analysis."
                           f"\n\n{proc_all_hypothesis.code_to_str()}")

    reflexion_prompt = (f"{commit_prompt}"
                        f"\n{loop_summary}"
                        f"\n{code_snippet_prompt}")

    _add_usr_msg_and_print(reflexion_prompt, msg_thread, print_desc, print_callback)

    return msg_thread


def run_in_hypothesis_check_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> bool:
    print_desc = f"state {State.HYPOTHESIS_CHECK_STATE} | process {process_no} | loop {loop_no}"

    ##########################################
    # Step I: Whether to make new hypothesis #
    ##########################################
    if len(proc_all_hypothesis.unverified) == 0:
        assert len(proc_all_hypothesis.verified) > 0

        ####################################################
        # Step I-1: Ask Actor Agent to make new hypothesis #
        ####################################################

        hyp_prop_prompt = (f"Based on the previous hypothesis and analyses, answer the below question:"
                           f"\n- Are there any better hypothesis: make hypothesis that differ from those already made. (leave it empty if there is no more appropriate hypothesis)"
                           f"{HYP_DEF}"
                           f"\n\nNOTE: You can make multiple new hypothesis one time.")

        _add_usr_msg_and_print(hyp_prop_prompt, msg_thread, print_desc, print_callback)

        proxy_conv_fpath = os.path.join(curr_proc_dirs.proxy_dpath, f"loop_{loop_no}_hypothesis_proposal.json")
        raw_hypothesis = _ask_actor_and_proxy_with_retries(
            task=ProxyTask.HYP_PROPOSAL,
            manager=manager,
            msg_thread=msg_thread,
            proxy_conv_save_fpath=proxy_conv_fpath,
            print_desc=print_desc,
            print_callback=print_callback
        )

        if raw_hypothesis is None:
            # Extract hypothesis with retries failed
            return False

        print_proxy(msg=raw_hypothesis, desc=print_desc, print_callback=print_callback)

        #####################################################
        # Step I-2: Choose next step: end / continue verify #
        #####################################################

        json_hypothesis = json.loads(raw_hypothesis)
        hypothesis_list = json_hypothesis["hypothesis_list"]

        # Filter verified hypothesis
        for hyp in hypothesis_list:
            hyp = get_unverified_hypothesis(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])

            if not proc_all_hypothesis.in_verified(hyp):
                proc_all_hypothesis.unverified.append(hyp)

    if len(proc_all_hypothesis.unverified) == 0:
        # No more new hypothesis
        return False

    ######################################################
    # Step II: Select an unverified hypothesis to verify #
    ######################################################

    proc_all_hypothesis.sort_unverified()
    proc_all_hypothesis.cur_hyp = proc_all_hypothesis.unverified[0]

    #######################################################
    # Step III: Prepare prompt to describe the hypothesis #
    #######################################################

    if proc_all_hypothesis.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        suffix_prompt = "Then you need to analyze the functionality of each code snippet in the commit to determine if it is not relevant to vulnerability fixing."
    else:
        # TODO: For now, we believe that the model will be highly consistent in the selection of patch code snippets
        suffix_prompt = (
            "The code snippets most likely to be the patch are as follows:"
            f"\n\n```"
            f"\n{proc_all_hypothesis.patch_to_str()}"
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
        curr_proc_dirs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
):
    print_desc = f"state {State.CONTEXT_RETRIEVAL_STATE} | process {process_no} | loop {loop_no}"

    #############################################
    # Step I: Prepare the init retrieval prompt #
    #############################################

    # TODO: We can simplify the conversation by modifying what we asked before after getting the desired code context

    init_retrieval_prompt = (
        "Before conducting a formal analysis of the current hypothesis, you must get enough contextual code information."
        "\nSo in this step, based on the hypothesis and the existing code snippets, please select the necessary search APIs for more background information related to this commit."
        f"\n{API_CALLS_DESCRIPTION}"
    )
    _add_usr_msg_and_print(init_retrieval_prompt, msg_thread, print_desc, print_callback)

    ##########################################
    # Step II: Multi-round context retrieval #
    ##########################################

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

        # Retry
        if selected_apis is None:
            retry_msg = "The search API calls seem not valid. Please check the arguments you give carefully and try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, round_print_desc, print_callback)
            continue

        print_proxy(msg=selected_apis, desc=print_desc, print_callback=print_callback)

        selected_apis_json = json.loads(selected_apis)
        json_api_calls = selected_apis_json["api_calls"]

        # Stop searching
        if len(json_api_calls) == 0:
            break

        # Invoke tools and prepare response according to api function calls
        collated_tool_response = ""

        for api_call in json_api_calls:
            func_name, func_arg_values = parse_function_invocation(api_call)

            func_arg_spec = inspect.getfullargspec(getattr(SearchManager, func_name))
            func_arg_names = func_arg_spec.args[1:]  # first parameter is self

            func_arg_kwargs = dict(zip(func_arg_names, func_arg_values))
            intent = FunctionCallIntent(api_call, func_name, func_arg_kwargs, None)
            tool_output, search_status, all_search_res = manager.dispatch_intent(intent)

            # TODO: For searches that do not meet the requirements, i.e. search_status = DISPATCH_ERROR /
            #       INVALID_ARGUMENT / NON_UNIQUE_FILE, consider whether to ask separately first to get the
            #       format api calls and then return the results together

            # (1) Collect str response
            collated_tool_response += f"Result of {api_call}:\n\n"
            collated_tool_response += tool_output + "\n\n"

            # (2) Collect code snippet extracted
            for res in all_search_res:
                code_snip = CodeContext(res.file_path, res.class_name, res.func_name, res.code)
                proc_all_hypothesis.code_context.append(code_snip)

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

    ##############################################
    # Step III: Save the called search API calls #
    ##############################################

    manager.dump_tool_call_sequence_to_file(curr_proc_dirs.tool_call_dpath, f"loop_{loop_no}")
    manager.dump_tool_call_layers_to_file(curr_proc_dirs.tool_call_dpath, f"loop_{loop_no}")

    return proc_all_hypothesis


def run_in_hypothesis_verify_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_dirs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> bool:
    print_desc = f"state {State.HYPOTHESIS_VERIFY_STATE} | process {process_no} | loop {loop_no}"

    #################################
    # Step I: Verify the hypothesis #
    #################################

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

    ####################################
    # Step II: Re-score the hypothesis #
    ####################################

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
    print_proxy(msg=score, desc=print_desc, print_callback=print_callback)

    #######################################
    # Step III: Update all the hypothesis #
    #######################################

    # (1) Update the confidence score of the current hypothesis
    proc_all_hypothesis.cur_hyp.confidence_score = json.loads(score)["confidence_score"]

    # (2) Update the current hypothesis from unverified to verified
    ver_hyp = verify_hypothesis(proc_all_hypothesis.cur_hyp, analysis_text)

    proc_all_hypothesis.verified.append(ver_hyp)
    proc_all_hypothesis.unverified.pop(0)

    ##################################
    # Step IV: Save the conversation #
    ##################################

    # Save the conversation of the current loop
    curr_loop_conversation_file = os.path.join(curr_proc_dirs.root, f"loop_{loop_no}_conversations.json")
    msg_thread.save_to_file(curr_loop_conversation_file)

    ############################
    # Step V: Decide next step #
    ############################

    if len(proc_all_hypothesis.verified) >= globals.hypothesis_limit:
        log_and_print("Too many verified hypothesis. End anyway.")
        return False

    return True


def run_in_end_state(
        process_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
):
    # Save end hypothesis
    proc_all_hypothesis.sort_verified()
    proc_all_hypothesis.sort_unverified()

    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "final.json")
    proc_all_hypothesis.save_hyp_to_file(hyp_fpath)


"""MAIN PROCESS"""


def start_conversation_round_stratified(
        output_dpath: str,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None
) -> Dict:
    """
    This version uses json data to process API calls, instead of using the OpenAI function calling.
    Advantage is that multiple API calls can be made in a single round.
    """
    # -------------------------------- Identification -------------------------------- #

    ## Step I: Perform multiple independent and complete processes
    # process_name -> status
    proc_status: Dict[str, bool] = {}

    for proc_no in range(1, globals.complete_process_limit + 1):
        print_banner(f"COMPLETE PROCESS {proc_no}")

        # TODO: Add Reflexion Module to remind Agent the following info:
        #  (1) Previous successful process: previous hypothesis and analysis.
        #  (2) Previous failed process: failed reason.

        ## 1. Preparation

        # Root
        curr_proc_name = f"process_{proc_no}"
        curr_proc_dpath = make_hie_dirs(output_dpath, curr_proc_name)
        # Dirs
        curr_proc_hyp_fpath = make_hie_dirs(curr_proc_dpath, f"hypothesis")
        curr_proc_proxy_dpath = make_hie_dirs(curr_proc_dpath, f"proxy_agent")
        curr_proc_tool_call_dpath = make_hie_dirs(curr_proc_dpath, "tool_calls")

        curr_proc_dirs = ProcessOutPaths(
            root=curr_proc_dpath,
            hyp_dpath=curr_proc_hyp_fpath,
            proxy_dpath=curr_proc_proxy_dpath,
            tool_call_dpath=curr_proc_tool_call_dpath,
        )

        proc_status[curr_proc_name] = False

        msg_thread = MessageThread()

        ## 2. Workflow
        ########## START ##########
        proc_all_hyp = run_in_start_state(proc_no, curr_proc_dirs, msg_thread, manager, print_callback)

        if proc_all_hyp is None:
            continue

        ## State switching process:
        # - Complete loop: hypothesis_check -> context_retrieval -> hypothesis_verify
        # - Complete process: start -> loop -> ( reflexion -> loop ) -> ... -> ( reflexion -> loop ) -> end
        loop_no = 0

        while True:
            loop_no += 1

            ########## (1) Reflexion ##########
            msg_thread = run_in_reflexion_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, manager, print_callback)

            ########## (2) Hypothesis check ##########
            continue_loop = run_in_hypothesis_check_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, manager, print_callback)

            if not continue_loop:
                break

            ########## (3) Context retrieval ##########
            run_in_context_retrieval_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, manager, print_callback)

            ########## (4) Hypothesis verify ##########
            continue_loop = run_in_hypothesis_verify_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_dirs, msg_thread, manager, print_callback)

            if not continue_loop:
                break

        ########## END ##########
        run_in_end_state(proc_no, proc_all_hyp, curr_proc_dirs, msg_thread, manager, print_callback)

        ## 3. Post-process
        # TODO: Need to consider if there are other cases that could cause failure
        proc_status[curr_proc_name] = True

        # Record the whole conversation in current process
        logger.info(f"\n========== Complete Process {proc_no} ==========")
        logger.info(f"Current message thread:\n{msg_thread}")

    ## Step II: Get the final results based on multiple process results
    # Vote the final results
    valid_proc_dpaths = [os.path.join(output_dpath, proc_name) for proc_name, status in proc_status.items() if status]
    final_res = vote_on_result(valid_proc_dpaths)
    # Save
    final_res_fpath = os.path.join(output_dpath, "result.json")
    with open(final_res_fpath, "w") as f:
        json.dump(final_res, f, indent=4)

    # -------------------------------- Evaluation -------------------------------- #

    eval_result = task_evaluation(manager.task.commit_type, manager.task.cwe_id, valid_proc_dpaths, final_res_fpath)
    eval_result["process_status"] = proc_status

    eval_res_path = Path(output_dpath, "evaluation.json")
    eval_res_path.write_text(json.dumps(eval_result, indent=4))

    logger.info("Ending workflow.")

    return proc_status


def run_one_task(
        raw_commit_content: str,
        output_dpath: str,
        manager: ProcessManager,
        print_callback: Optional[Callable[[dict], None]] = None,
) -> Dict:
    """
    Main entry point to run inference on one task.

    Args:
        raw_commit_content (str): The original commit content submitted to the task.
        output_dpath (str): Path to the output directory.
        manager (ProcessManager): The already-initialized API manager.
        print_callback:
    """
    print_banner("Starting Silent Patch Identification on the following commit")
    print_commit_content(raw_commit_content)

    return start_conversation_round_stratified(output_dpath, manager, print_callback)
