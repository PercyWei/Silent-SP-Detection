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

from agent_app import globals
from agent_app.api.manage import ProcessManager
from agent_app.api.agent_proxy import ProxyTask
from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import (
    State, ProcessActionStatus,
    CommitType,
    CodeSnippetLocation,
    FunctionCallIntent,
    MessageThread
)
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
    """Dataclass to hold the basic hypothesis."""
    commit_type: CommitType
    vulnerability_type: str
    confidence_score: int | float

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
    """Dataclass to hold the verified hypothesis with its analysis."""
    analysis: str

    def to_dict(self) -> Dict:
        info = super().to_dict()
        info.update({"analysis": self.analysis})
        return info

    def to_str(self) -> str:
        seq = super().to_str()
        seq += f"\n- analysis: {self.analysis}"
        return seq


@dataclass
class FinalHypothesis(Hypothesis):
    """Dataclass to hold the final hypothesis obtained from the results of multiple processes."""
    count: int

    def to_dict(self) -> Dict:
        info = super().to_dict()
        info.update({"count": self.count})
        return info

    def to_str(self) -> str:
        seq = super().to_str()
        seq += f"\n- count: {self.count}"
        return seq


def get_hyp_description(hyp: Hypothesis, with_score: bool = True) -> str:
    """Describe the given hypothesis."""
    if hyp.commit_type == CommitType.NonVulnerabilityPatch:
        desc = f"The given commit does not fix a vulnerability"
    else:
        desc = f"The given commit fixes a vulnerability of type {hyp.vulnerability_type}"

    if with_score:
        desc += f", and the confidence score is {hyp.confidence_score}/10"

    return desc


def get_basic_hyp(commit_type: str, vul_type: str, conf_score: int) -> Hypothesis:
    # (1) Check commit type
    try:
        commit_type = CommitType(commit_type)
    except ValueError:
        raise ValueError(f"CommitType {commit_type} is not valid")

    # (2) Check vulnerability type (CWE-ID)
    if commit_type == CommitType.VulnerabilityPatch:
        assert re.fullmatch(r"CWE-(\d+)", vul_type)
    else:
        assert vul_type == ""

    # (3) Check confidence score
    assert isinstance(conf_score, int)
    conf_score = min(10, max(1, int(conf_score)))

    return Hypothesis(commit_type, vul_type, conf_score)


def update_hyp_with_analysis(hyp: Hypothesis, analysis: str) -> VerifiedHypothesis:
    ver_hyp = VerifiedHypothesis(
        commit_type=hyp.commit_type,
        vulnerability_type=hyp.vulnerability_type,
        confidence_score=hyp.confidence_score,
        analysis=analysis
    )
    return ver_hyp


def update_hyp_with_count(hyp: Hypothesis, count: int) -> FinalHypothesis:
    final_hyp = FinalHypothesis(
        commit_type=hyp.commit_type,
        vulnerability_type=hyp.vulnerability_type,
        confidence_score=hyp.confidence_score,
        count=count
    )
    return final_hyp


"""ACTION WITH AGENT"""


def _add_system_msg_and_print(
        system_msg: str,
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> None:
    msg_thread.add_system(system_msg)
    print_system(msg=system_msg, desc=print_desc, print_callback=print_callback)


def _add_usr_msg_and_print(
        usr_msg: str,
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> None:
    msg_thread.add_user(usr_msg)
    print_user(msg=usr_msg, desc=print_desc, print_callback=print_callback)


def _ask_actor_agent_and_print(
        msg_thread: MessageThread,
        print_desc: str = "",
        print_callback: Callable[[dict], None] | None = None
) -> str:
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg())
    msg_thread.add_model(respond_text, tools=[])
    print_actor(msg=respond_text, desc=print_desc, print_callback=print_callback)
    return respond_text


def _ask_proxy_agent_and_save_msg(
        task: ProxyTask,
        manager: ProcessManager,
        text: str,
        proxy_conv_title: str | int,
        proxy_conv_fpath: str
) -> Tuple[str | None, str | None]:
    # (1) Ask the Proxy Agent
    # TODO: Consider whether to add the Proxy Agent extraction failure summary while
    #       asking the Actor Agent in the new retry.
    json_text, failure_summary, proxy_msg_threads = manager.call_proxy_apis(text, task)

    # (2) Save the conversations with the Proxy Agent
    proxy_messages = [thread.to_msg() for thread in proxy_msg_threads]

    convs = []
    if os.path.exists(proxy_conv_fpath):
        with open(proxy_conv_fpath, "r") as f:
            convs = json.load(f)

    convs.append({proxy_conv_title: proxy_messages})

    with open(proxy_conv_fpath, "w") as f:
        json.dump(convs, f, indent=4)

    return json_text, failure_summary


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
        print_callback: Callable[[dict], None] | None = None
) -> ProcHypothesis | None:
    print_desc = f"state {State.START_STATE} | process {process_no}"

    ################################
    # STEP 1: Make init hypothesis #
    ################################

    # ------------------ 1.1 Prepare the prompt ------------------ #
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

    # ------------------ 1.2 Ask the LLM ------------------ #
    proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"init_hypothesis_proposal.json")

    retry = 0
    while True:
        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_hyps, _ = _ask_proxy_agent_and_save_msg(ProxyTask.HYP_PROPOSAL, manager, response, retry, proxy_conv_fpath)

        if json_hyps is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = "The given hypothesis seems invalid. Please try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
        else:
            break

    if json_hyps is None:
        return None

    print_proxy(msg=json_hyps, desc=print_desc, print_callback=print_callback)

    # ------------------ 1.3 Collect init hypothesis ------------------ #
    proc_all_hypothesis: ProcHypothesis = ProcHypothesis()

    raw_hyps = json.loads(json_hyps)["hypothesis_list"]
    for hyp in raw_hyps:
        hyp = get_basic_hyp(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])
        if not proc_all_hypothesis.in_unverified(hyp):
            proc_all_hypothesis.unverified.append(hyp)

    assert len(proc_all_hypothesis.unverified) > 0

    proc_all_hypothesis.sort_unverified()
    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "init.json")
    proc_all_hypothesis.save_hyp_to_file(hyp_fpath)

    ###################################
    # STEP 2: Extract patch locations #
    ###################################

    # ------------------ 2.1 Determine the patch existence ------------------ #
    patch_exist = False
    for hyp in proc_all_hypothesis.unverified:
        if hyp.commit_type == CommitType.VulnerabilityPatch:
            patch_exist = True
            break

    if patch_exist:
        # TODO: We believe that the extracted patch locations is not very closely related to the vulnerability types
        #       in the hypothesis, so we only ask once.

        # ------------------ 2.2 Prepare the prompt ------------------ #
        patch_extraction_prompt = (
            "Since your hypothesis include the case that the commit fixes a vulnerability, we need to extract the code snippets that might be the patch from the original commit."
            "\n\nNOTE: For each extracted code snippet, you should at least provide its 'file_name' and 'code', while 'class_name' and 'func_name' are not required.")

        _add_usr_msg_and_print(patch_extraction_prompt, msg_thread, print_desc, print_callback)

        # ------------------ 2.3 Ask the LLM ------------------ #
        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"patch_extraction.json")

        retry = 0
        while True:
            response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

            json_patches, _ = \
                _ask_proxy_agent_and_save_msg(ProxyTask.PATCH_EXTRACTION, manager, response, retry, proxy_conv_fpath)

            if json_patches is None and retry < globals.state_retry_limit:
                retry += 1
                retry_msg = "The given patch code seems invalid. Please try again."
                _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
            else:
                break

        # ------------------ 2.4 Collect patch locations ------------------ #
        if json_patches is None:
            # FIXME: Check whether the situation where the patch locations cannot be successfully extracted would occur.
            manager.proc_action_status.start_patch_extraction = True
        else:
            print_proxy(msg=json_patches, desc=print_desc, print_callback=print_callback)

            raw_patches = json.loads(json_patches)["patch_locations"]

            # TODO: Consider whether to activate search since the LLM response about locations may not be clear.
            for patch_loc in raw_patches:
                fpath = patch_loc["file"]
                class_name = patch_loc.get("class_name", None)
                func_name = patch_loc.get("func_name", None)
                code = patch_loc["code"]
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
        print_callback: Callable[[dict], None] | None = None
):
    """
    In order to prevent the forgetting problem caused by too many rounds of interaction with LLM,
    we open a new round conversation after a complete loop (make hypothesis -> context retrieval -> verify hypothesis)
    """
    print_desc = f"state {State.REFLEXION_STATE} | process {process_no} | loop {loop_no}"

    #####################
    # STEP 1: Reflexion #
    #####################

    if loop_no != 1:
        # Open a new conversation
        msg_thread.reset()

        # ------------------ 1.1 Prepare the prompt ------------------ #
        ## (1) System prompt
        _add_system_msg_and_print(SYSTEM_PROMPT, msg_thread, print_desc, print_callback)

        ## (2) Reflexion prompt
        # 2.1 Commit content
        commit_desc = manager.commit_manager.describe_commit_files()
        commit_prompt = ("The content of the commit is as follows:"
                         f"\n{commit_desc}")

        # 2.2 Summary about description and analysis of verified hypothesis
        proc_all_hypothesis.sort_verified()

        # TODO: Consider how to briefly summarize the analysis of previous hypothesis.
        loop_summary = "In the previous analysis, you have made and analysed the following hypothesis:"
        for i, hyp in enumerate(proc_all_hypothesis.verified):
            desc = get_hyp_description(hyp)
            loop_summary += (f"\n\nHypothesis id {i + 1}:"
                             f"\n - Description: {desc}"
                             f"\n - Analysis: {hyp.analysis}")

        # 2.3 Code snippets of patch and context
        # TODO: Consider how to add the patch code snippets.
        code_snippet_desc = (
            "Besides, by calling the search APIs, you have got the following code snippets which help with analysis."
            f"\n\n{proc_all_hypothesis.code_to_str()}")

        reflexion_prompt = f"{commit_prompt}\n\n{loop_summary}\n\n{code_snippet_desc}"

        _add_usr_msg_and_print(reflexion_prompt, msg_thread, print_desc, print_callback)


def run_in_hypothesis_check_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    print_desc = f"state {State.HYPOTHESIS_CHECK_STATE} | process {process_no} | loop {loop_no}"

    ###############################
    # STEP 1: Make new hypothesis #
    ###############################

    if len(proc_all_hypothesis.unverified) == 0:
        assert len(proc_all_hypothesis.verified) > 0

        # ------------------ 1.1 Prepare the prompt ------------------ #
        hyp_prop_prompt = (f"Based on the previous hypothesis and analyses, answer the below question:"
                           f"\n- Are there any better hypothesis: make hypothesis that differ from those already made. (leave it empty if there is no more appropriate hypothesis)"
                           f"{HYP_DEF}"
                           f"\n\nNOTE: You can make multiple new hypothesis one time.")

        _add_usr_msg_and_print(hyp_prop_prompt, msg_thread, print_desc, print_callback)

        # ------------------ 1.2 Ask the LLM ------------------ #
        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_hypothesis_proposal.json")

        retry = 0
        while True:
            response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

            json_hyps, _ = \
                _ask_proxy_agent_and_save_msg(ProxyTask.HYP_PROPOSAL, manager, response, retry, proxy_conv_fpath)

            if json_hyps is None and retry < globals.state_retry_limit:
                retry += 1
                retry_msg = "The given hypothesis seems invalid. Please try again."
                _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
            else:
                break

        if json_hyps is None:
            return False

        print_proxy(msg=json_hyps, desc=print_desc, print_callback=print_callback)

        # ------------------ 1.3 Collect new hypothesis ------------------ #
        raw_hyps = json.loads(json_hyps)["hypothesis_list"]

        # Filter verified hypothesis
        for hyp in raw_hyps:
            hyp = get_basic_hyp(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])
            if not proc_all_hypothesis.in_verified(hyp):
                proc_all_hypothesis.unverified.append(hyp)

    if len(proc_all_hypothesis.unverified) == 0:
        # No more new hypothesis
        return False

    #####################################################
    # STEP 2: Select an unverified hypothesis to verify #
    #####################################################

    # ------------------ 2.1 Select a hypothesis ------------------ #
    proc_all_hypothesis.sort_unverified()
    proc_all_hypothesis.cur_hyp = proc_all_hypothesis.unverified[0]

    # ------------------ 2.2 Prepare the prompt ------------------ #
    if proc_all_hypothesis.cur_hyp.commit_type == CommitType.NonVulnerabilityPatch:
        suffix_prompt = "Then you need to analyze the functionality of each code snippet in the commit to determine if it is not relevant to vulnerability fixing."
    elif proc_all_hypothesis.patch:
        suffix_prompt = (
            "The code snippets most likely to be the patch are as follows:"
            f"\n\n```"
            f"\n{proc_all_hypothesis.patch_to_str()}"
            f"\n```"
        )
    else:
        # Just in case
        suffix_prompt = ""

    cur_hyp_str = get_hyp_description(proc_all_hypothesis.cur_hyp)
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
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
):

    # Open a new recording the new loop
    manager.reset_too_call_recordings()

    # TODO: Consider whether to modify the conversation to make it clean.
    #       mtd1: Replace the original response from the Actor Agent with the result extracted by the Proxy Agent.
    #       mtd2: When the response of the Actor Agent is wrong and a formatted valid response is obtained after
    #               questioning, replace the original response with the final valid response.

    #############################
    # STEP 1: Context retrieval #
    #############################

    retry_flag = False
    for round_no in range(1, globals.state_round_limit + 1):
        round_print_desc = f"state {State.CONTEXT_RETRIEVAL_STATE} | process {process_no} | loop {loop_no} | round {round_no}"

        # For recording tool calls in current round
        manager.start_new_tool_call_layer()

        # ------------------ 1.1 Prepare the prompt ------------------ #
        if round_no == 1:
            # Init round
            retrieval_prompt = (
                "Before conducting a formal analysis of the current hypothesis, you must get enough contextual code information."
                "\nSo in this step, based on the hypothesis and the existing code snippets, please select the necessary search APIs for more background information related to this commit."
                f"\n{API_CALLS_DESCRIPTION}"
            )
        elif not retry_flag:
            # Normal round
            retrieval_prompt = (
                "Based on the extracted code snippets related to the commit, answer the question below:"
                "\n - Do we need more context: construct search API calls to get more context of the project. (leave it empty if you don't need more context)"
                f"\n{API_CALLS_DESCRIPTION}"
            )
        else:
            # Retry round
            retrieval_prompt = "The search API calls seem not valid. Please check the arguments you give carefully and try again."
        _add_usr_msg_and_print(retrieval_prompt, msg_thread, round_print_desc, print_callback)

        # ------------------ 1.2 Ask the LLM ------------------ #
        response = _ask_actor_agent_and_print(msg_thread, round_print_desc, print_callback)

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_context_retrieval.json")
        json_apis, _ = \
            _ask_proxy_agent_and_save_msg(ProxyTask.CONTEXT_RETRIEVAL, manager, response, round_no, proxy_conv_fpath)

        # ------------------ 1.3 Decide next step ------------------ #
        # (1) Whether to retry
        if json_apis is None:
            retry_flag = True
            continue
        else:
            retry_flag = False

        print_proxy(msg=json_apis, desc=round_print_desc, print_callback=print_callback)

        raw_apis = json.loads(json_apis)["api_calls"]

        # (2) Whether to stop searching
        if len(raw_apis) == 0:
            break

        # ------------------ 1.4 Invoke tools and prepare the response ------------------ #
        collated_tool_response = ""

        for api_call in raw_apis:
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

        # TODO: Consider whether to analyse before continuing to search for context?
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
    else:
        logger.info("Too many rounds. Try to verify the hypothesis anyway.")

    ############################################
    # STEP 2: Save the called search API calls #
    ############################################

    manager.dump_tool_call_sequence_to_file(curr_proc_outs.tool_call_dpath, f"loop_{loop_no}")
    manager.dump_tool_call_layers_to_file(curr_proc_outs.tool_call_dpath, f"loop_{loop_no}")

    return proc_all_hypothesis


def run_in_hypothesis_verify_state(
        process_no: int,
        loop_no: int,
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> bool:
    print_desc = f"state {State.HYPOTHESIS_VERIFY_STATE} | process {process_no} | loop {loop_no}"

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
        cwe_type = proc_all_hypothesis.cur_hyp.vulnerability_type
        cwe_description = manager.cwe_manager.get_cwe_description(cwe_type)
        cwe_description_seq = f"The description of {cwe_type} is: {cwe_description}\n" if cwe_description else ""

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
    proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"loop_{loop_no}_score_update.json")

    retry = 0
    while True:
        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_score, _ = _ask_proxy_agent_and_save_msg(ProxyTask.SCORE, manager, response, retry, proxy_conv_fpath)

        if json_score is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = f"The given confidence score seems invalid. Please try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
        else:
            break

    # TODO: We believe that this extraction is too simple and should not go wrong
    assert json_score is not None
    print_proxy(msg=json_score, desc=print_desc, print_callback=print_callback)

    #####################################
    # STEP 3: Update all the hypothesis #
    #####################################

    # (1) Update the confidence score of the current hypothesis
    proc_all_hypothesis.cur_hyp.confidence_score = json.loads(json_score)["confidence_score"]

    # (2) Update the current hypothesis from unverified to verified
    ver_hyp = update_hyp_with_analysis(proc_all_hypothesis.cur_hyp, analysis_text)

    proc_all_hypothesis.verified.append(ver_hyp)
    proc_all_hypothesis.unverified.pop(0)

    ###############################
    # STEP 4: End of current loop #
    ###############################

    # ------------------ 4.1 Save the conversation of the current loop ------------------ #
    curr_loop_conversation_file = os.path.join(curr_proc_outs.root, f"loop_{loop_no}_conversations.json")
    msg_thread.save_to_file(curr_loop_conversation_file)

    # ------------------ 4.2 Decide next step ------------------ #
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
        print_callback: Callable[[dict], None] | None = None
):
    # Save end hypothesis
    proc_all_hypothesis.sort_verified()
    proc_all_hypothesis.sort_unverified()

    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "final.json")
    proc_all_hypothesis.save_hyp_to_file(hyp_fpath)


"""POST-PROCESS"""


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


def vote_on_result(proc_dpaths: List[str]) -> List[FinalHypothesis]:
    all_ver_hyps: List[Hypothesis] = []

    for proc_dpath in proc_dpaths:
        proc_final_hyp_fpath = os.path.join(proc_dpath, "hypothesis", "final.json")

        with open(proc_final_hyp_fpath, "r") as f:
            ver_hyps = json.load(f)["verified"]
            for ver_hyp in ver_hyps:
                hyp = Hypothesis(ver_hyp["commit_type"], ver_hyp["vulnerability_type"], ver_hyp["confidence_score"])
                all_ver_hyps.append(hyp)

    final_hyps = calculate_final_confidence_score(all_ver_hyps, proc_num=len(proc_dpaths))

    return final_hyps


def post_process(
        final_hyps: List[FinalHypothesis],
        proc_all_hypothesis: ProcHypothesis,
        curr_proc_outs: ProcessOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> List[FinalHypothesis]:
    print_desc = f"state {State.POST_PROCESS_STATE}"

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
        # Open a new conversation
        msg_thread.reset()

        # ------------------ 2.2 Prepare the prompt ------------------ #
        ## (1) System prompt
        _add_system_msg_and_print(SYSTEM_PROMPT, msg_thread, print_desc, print_callback)

        ## (2) Summary prompt
        # 2.1 Commit content
        commit_desc = manager.commit_manager.describe_commit_files()
        commit_prompt = ("The content of the commit is as follows:"
                         f"\n{commit_desc}")

        # 2.2 Code snippets of patch and context
        # TODO: Consider how to add the patch code snippets?
        code_snippet_desc = (
            "In the previous analysis, by calling the search APIs, you have got the following code snippets:"
            f"\n\n{proc_all_hypothesis.code_to_str()}")

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
        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"rank.json")

        retry = 0
        while True:
            response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

            json_ranking, _ = _ask_proxy_agent_and_save_msg(ProxyTask.RANK, manager, response, retry, proxy_conv_fpath)

            retry_flag = False
            if retry < globals.state_retry_limit:
                if json_ranking is None:
                    retry_flag = True
                    retry_msg = "The given ranking seems invalid. Please try again."
                else:
                    raw_ranking = json.loads(json_ranking)["ranking"]
                    ranking_hyp_ids = sorted(raw_ranking)
                    pending_hyp_ids = list(range(1, len(pending_hyps) + 1))

                    if pending_hyp_ids != ranking_hyp_ids:
                        retry_flag = True

                        missing_hyp_ids = sorted(list(set(pending_hyp_ids) - set(ranking_hyp_ids)))
                        extra_hyp_ids = sorted(list(set(ranking_hyp_ids) - set(pending_hyp_ids)))

                        pending_hyp_ids_str = ", ".join(map(str, pending_hyp_ids))
                        missing_hyp_ids_str = ", ".join(map(str, missing_hyp_ids))
                        extra_hyp_ids_str = ", ".join(map(str, extra_hyp_ids))

                        retry_msg = (f"The given ranking {raw_ranking} seems invalid."
                                     f"\nSpecifically, the ids of hypothesis that need to be ranked are {pending_hyp_ids_str}, while the ids {missing_hyp_ids_str} are missing, and the ids {extra_hyp_ids_str} do not exist."
                                     f"\nPlease try again.")

            if retry_flag:
                retry += 1
                _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
            else:
                break

        # ------------------ 2.4 Rank the final hypothesis ------------------ #
        if json_ranking is None:
            # FIXME: Check whether the ranking failure could occur.
            manager.proc_action_status.post_process_rank = True

            # TODO: Heuristic: 1. more occurrences -> higher ranking
            #                  2. vulnerability fix > non-vulnerability fix
            commit_type_priority = {CommitType.VulnerabilityPatch: 1, CommitType.NonVulnerabilityPatch: 0}
            ranking_hyps = sorted(
                pending_hyps,
                key=lambda x: (x.count, commit_type_priority[x.commit_type]),
                reverse=True
            )
        else:
            raw_ranking = json.loads(json_ranking)["ranking"]
            ranking_hyps = [pending_hyps[i - 1] for i in raw_ranking]
        final_hyps = ranking_hyps + final_hyps[len(pending_hyps):]

    return final_hyps


"""MAIN PROCESS"""


def start_conversation_round_stratified(
        output_dpath: str,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> Dict[str, ProcessActionStatus]:
    """
    This version uses json data to process API calls, instead of using the OpenAI function calling.
    Advantage is that multiple API calls can be made in a single round.
    """

    ############################################
    # STEP 1: Perform identification processes #
    ############################################

    # process_name -> status
    all_proc_status: Dict[str, ProcessActionStatus] = {}

    for proc_no in range(1, globals.complete_process_limit + 1):
        print_banner(f"COMPLETE PROCESS {proc_no}")

        # TODO: Consider whether to add Reflexion Module to remind Agent the following info:
        #  (1) Previous successful process: previous hypothesis and analysis.
        #  (2) Previous failed process: failed reason.

        # ------------------------------------ 1.1 Preparation ------------------------------------ #
        curr_proc_name = f"process_{proc_no}"

        # Root
        curr_proc_dpath = make_hie_dirs(output_dpath, curr_proc_name)
        # Dirs
        curr_proc_hyp_fpath = make_hie_dirs(curr_proc_dpath, f"hypothesis")
        curr_proc_proxy_dpath = make_hie_dirs(curr_proc_dpath, f"proxy_agent")
        curr_proc_tool_call_dpath = make_hie_dirs(curr_proc_dpath, "tool_calls")

        curr_proc_outs = ProcessOutPaths(
            root=curr_proc_dpath,
            hyp_dpath=curr_proc_hyp_fpath,
            proxy_dpath=curr_proc_proxy_dpath,
            tool_call_dpath=curr_proc_tool_call_dpath,
        )

        # Process action status
        manager.reset_proc_action_status()
        all_proc_status[curr_proc_name] = manager.proc_action_status

        # Message thread
        msg_thread = MessageThread()

        # ------------------------------------ 1.2 Workflow ------------------------------------ #
        ## State switching process:
        # - Complete loop: hypothesis_check -> context_retrieval -> hypothesis_verify
        # - Complete process: start -> loop -> ( reflexion -> loop ) -> ... -> ( reflexion -> loop ) -> end

        ########## Start State ##########
        proc_all_hyp = run_in_start_state(proc_no, curr_proc_outs, msg_thread, manager, print_callback)

        if proc_all_hyp is None:
            continue

        loop_no = 0
        while True:
            loop_no += 1

            ########## (1) Reflexion State ##########
            run_in_reflexion_state(proc_no, loop_no, proc_all_hyp, curr_proc_outs, msg_thread, manager, print_callback)

            ########## (2) Hypothesis Check State ##########
            continue_loop = run_in_hypothesis_check_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_outs, msg_thread, manager, print_callback)

            if not continue_loop:
                break

            ########## (3) Context Retrieval State ##########
            run_in_context_retrieval_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_outs, msg_thread, manager, print_callback)

            ########## (4) Hypothesis Verify State ##########
            continue_loop = run_in_hypothesis_verify_state(
                proc_no, loop_no, proc_all_hyp, curr_proc_outs, msg_thread, manager, print_callback)

            if not continue_loop:
                break

        ########## End State ##########
        run_in_end_state(proc_no, proc_all_hyp, curr_proc_outs, msg_thread, manager, print_callback)

        # ------------------------------------ 1.3 Update and save ------------------------------------ #
        # Update and save process status
        manager.proc_action_status.complete = True
        all_proc_status[curr_proc_name] = manager.proc_action_status

        # Record the whole conversation in current process
        logger.info(f"\n========== Complete Process {proc_no} ==========")
        logger.info(f"Current message thread:\n{msg_thread}")

    #####################################
    # STEP 2: Vote for the final result #
    #####################################

    valid_proc_dpaths = [os.path.join(output_dpath, proc_name) for proc_name, status in all_proc_status.items() if status]
    final_hyps: List[FinalHypothesis] = vote_on_result(valid_proc_dpaths)

    #########################################
    # STEP 3: Post process the final result #
    #########################################

    final_hyps = post_process(final_hyps, proc_all_hyp, curr_proc_outs, msg_thread, manager, print_callback)

    final_res_fpath = os.path.join(output_dpath, "result.json")
    with open(final_res_fpath, "w") as f:
        json.dump([hyp.to_dict() for hyp in final_hyps], f, indent=4)

    ######################
    # STEP 4: Evaluation #
    ######################

    eval_result = task_evaluation(manager.task.commit_type, manager.task.cwe_id, valid_proc_dpaths, final_res_fpath)

    eval_res_path = Path(output_dpath, "evaluation.json")
    eval_res_path.write_text(json.dumps(eval_result, indent=4))

    logger.info("Ending workflow.")

    return all_proc_status


def run_one_task(
        raw_commit_content: str,
        output_dpath: str,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None,
) -> Dict[str, ProcessActionStatus]:
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
