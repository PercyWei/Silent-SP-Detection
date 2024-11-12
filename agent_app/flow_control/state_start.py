import os
import json

from typing import *

from agent_app import globals, globals_opt
from agent_app.data_structures import CommitType, ProxyTask, MessageThread
from agent_app.api.manage import FlowManager
from agent_app.search.search_manage import PySearchResult, JavaSearchResult
from agent_app.flow_control.flow_recording import State, ProcOutPaths, ProcHypothesis
from agent_app.flow_control.flow_util import (
    _add_system_msg_and_print,
    _add_usr_msg_and_print,
    _ask_actor_agent_and_print,
    _ask_proxy_agent_and_print,
    _save_proxy_msg,
    get_system_prompt,
    get_hyp_def_prompt
)
from agent_app.flow_control.hypothesis import build_basic_hyp
from agent_app.util import LanguageNotSupportedError


"""ACTION: MAKE INIT HYPOTHESIS"""


def make_free_init_hypothesis(
        print_desc: str,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> ProcHypothesis | None:
    # ------------------ 1. Prepare the prompt ------------------ #
    # (1) System prompt
    system_prompt = get_system_prompt(globals.lang)
    _add_system_msg_and_print(system_prompt, msg_thread, print_desc, print_callback)

    # (2) Hypothesis proposal prompt
    commit_desc = manager.commit_manager.describe_commit_files()
    hyp_def_prompt = get_hyp_def_prompt()
    hyp_prop_prompt = ("The content of the commit is as follows:"
                       f"\n{commit_desc}"
                       "\n\nIn this step, based on the raw commit content, you need to make hypothesis about the functionality of the commit."
                       f"{hyp_def_prompt}"
                       f"\nNOTE: You can make multiple new hypothesis one time.")

    _add_usr_msg_and_print(hyp_prop_prompt, msg_thread, print_desc, print_callback)

    # ------------------ 2. Ask the LLM ------------------ #
    retry = 0
    while True:
        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_hyps, _, proxy_msg_threads = _ask_proxy_agent_and_print(
            ProxyTask.HYP_PROPOSAL, response, manager, f"{print_desc} | retry {retry}", print_callback
        )

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"init_hypothesis_proposal.json")
        _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

        if json_hyps is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = "The given hypothesis seems invalid. Please try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
        else:
            break

    if json_hyps is None:
        return None

    # ------------------ 3. Collect init hypothesis ------------------ #
    raw_hyps = json.loads(json_hyps)["hypothesis_list"]

    curr_proc_hyps: ProcHypothesis = ProcHypothesis()

    for hyp in raw_hyps:
        hyp = build_basic_hyp(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])
        if not curr_proc_hyps.in_unverified(hyp):
            curr_proc_hyps.unverified.append(hyp)

    assert len(curr_proc_hyps.unverified) > 0

    curr_proc_hyps.sort_unverified()
    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "init.json")
    curr_proc_hyps.save_hyp_to_file(hyp_fpath)

    return curr_proc_hyps


def make_constrained_init_hypothesis(
        print_desc: str,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> ProcHypothesis | None:
    # ------------------ 1. Prepare the prompt ------------------ #
    # (1) System prompt
    system_prompt = get_system_prompt(globals.lang)
    _add_system_msg_and_print(system_prompt, msg_thread, print_desc, print_callback)

    # (2) Hypothesis proposal prompt
    commit_desc = manager.commit_manager.describe_commit_files()
    hyp_prop_prompt = ("The content of the commit is as follows:"
                       f"\n{commit_desc}"
                       "\n\nIn this step, based on the raw commit content, you need to consider the following two possibilities."
                       "\nHypothesis 1: The given commit does not fix a vulnerability, and the confidence score is [mask_1]/10."
                       "\nHypothesis 2: The given commit fixes a vulnerability of type [mask_2], and the confidence score is [mask_3]/10."
                       "\nNow you need to give what is masked by the [mask_i] (i=1,2,3) in the two hypotheses above."
                       f"\n\nNOTE: [mask_1] and [mask_3] are integer between 1 and 10. [mask_2] is a CWE-ID which should be limited to the range of weaknesses included in View-{globals.view_id}.")

    _add_usr_msg_and_print(hyp_prop_prompt, msg_thread, print_desc, print_callback)

    # ------------------ 2. Ask the LLM ------------------ #
    retry = 0
    while True:
        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_masks, _, proxy_msg_threads = _ask_proxy_agent_and_print(
            ProxyTask.INIT_HYP_COMPLETION, response, manager, f"{print_desc} | retry {retry}", print_callback
        )

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"init_hypothesis_proposal.json")
        _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

        if json_masks is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = "The given content of masks seems invalid. Please try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
        else:
            break

    if json_masks is None:
        return None

    # ------------------ 3. Collect init hypothesis ------------------ #
    raw_masks = json.loads(json_masks)

    curr_proc_hyps: ProcHypothesis = ProcHypothesis()

    # Hypothesis 1: non_vulnerability_patch
    hyp = build_basic_hyp(
        commit_type="non_vulnerability_patch",
        vul_type="",
        conf_score=int(raw_masks["mask_1"])
    )
    curr_proc_hyps.unverified.append(hyp)

    # Hypothesis 2: vulnerability_patch
    hyp = build_basic_hyp(
        commit_type="vulnerability_patch",
        vul_type=raw_masks["mask_2"],
        conf_score=int(raw_masks["mask_3"])
    )
    curr_proc_hyps.unverified.append(hyp)

    curr_proc_hyps.sort_unverified()
    hyp_fpath = os.path.join(curr_proc_outs.hyp_dpath, "init.json")
    curr_proc_hyps.save_hyp_to_file(hyp_fpath)

    return curr_proc_hyps


"""ACTION: EXTRACT PATCH LOCATIONS"""


def extract_patch_locations(
        print_desc: str,
        curr_proc_outs: ProcOutPaths,
        curr_proc_hyps: ProcHypothesis,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
):
    # TODO: We believe that the extracted patch locations is not very closely related to the predicted
    #  vulnerability types in the hypothesis, so we only ask once.

    # ------------------ 1. Prepare the prompt ------------------ #
    patch_extraction_prompt = "Since your hypothesis include the case that the commit fixes a vulnerability, we need to extract the code snippets that might be the patch from the original commit."
    if globals.lang == 'Python':
        patch_extraction_prompt += ("\n\nNOTE: For each extracted code snippet, you should provide 'code'. "
                                    "\nBesides, there are four attributes that indicate its location in the code repo, namely 'file_name', 'func_name', ‘class_name’, and 'inclass_method_name', where 'file_name' is required.")
    elif globals.lang == 'Java':
        patch_extraction_prompt += ("\n\nNOTE: For each extracted code snippet, you should provide 'code'. "
                                    "\nBesides, there are six attributes that indicate its location in the code repo, namely 'file_name', 'iface_name', ‘class_name’, 'inclass_method_name', 'inclass_iface_name' and 'inclass_class_name', where 'file_name' is required.")
    else:
        raise LanguageNotSupportedError(globals.lang)

    _add_usr_msg_and_print(patch_extraction_prompt, msg_thread, print_desc, print_callback)

    # ------------------ 2. Ask the LLM ------------------ #
    retry = 0
    while True:
        response = _ask_actor_agent_and_print(msg_thread, print_desc, print_callback)

        json_patches, _, proxy_msg_threads = _ask_proxy_agent_and_print(
            ProxyTask.PATCH_EXTRACTION, response, manager, f"{print_desc} | retry {retry}", print_callback
        )

        proxy_conv_fpath = os.path.join(curr_proc_outs.proxy_dpath, f"patch_extraction.json")
        _save_proxy_msg(proxy_msg_threads, proxy_conv_fpath)

        if json_patches is None and retry < globals.state_retry_limit:
            retry += 1
            retry_msg = "The given patch code seems invalid. Please try again."
            _add_usr_msg_and_print(retry_msg, msg_thread, f"{print_desc} | retry {retry}", print_callback)
        else:
            break

    # ------------------ 3. Collect patch locations ------------------ #
    if json_patches is None:
        manager.action_status_records.update_patch_extraction_status(success_flag=False)
    else:
        manager.action_status_records.update_patch_extraction_status(success_flag=True)

        raw_patches = json.loads(json_patches)["patch_locations"]

        # TODO: Consider whether to activate search since the LLM response about locations may not be clear.
        for patch_loc in raw_patches:
            if globals.lang == 'Python':
                snip = PySearchResult(
                    file_path=patch_loc["file_name"],
                    code=patch_loc["code"],
                    func_name=patch_loc.get("func_name", None),
                    class_name=patch_loc.get("class_name", None),
                    inclass_method_name=patch_loc.get("inclass_method_name", None)
                )
            elif globals.lang == 'Java':
                snip = JavaSearchResult(
                    file_path=patch_loc["file_name"],
                    code=patch_loc["code"],
                    iface_name=patch_loc.get("iface_name", None),
                    class_name=patch_loc.get("class_name", None),
                    inclass_method_name=patch_loc.get("inclass_method_name", None),
                    inclass_iface_name=patch_loc.get("inclass_iface_name", None),
                    inclass_class_name=patch_loc.get("inclass_class_name", None)
                )
            else:
                raise LanguageNotSupportedError(globals.lang)

            curr_proc_hyps.patch.append(snip)


"""MAIN STATE"""


def run_in_start_state(
        process_no: int,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: FlowManager,
        print_callback: Callable[[dict], None] | None = None
) -> ProcHypothesis | None:
    print_desc = f"process {process_no} | state {State.START_STATE}"

    ## Step 1: Make init hypothesis
    if globals_opt.opt_to_start_state_path == 1:
        curr_proc_hyps = make_free_init_hypothesis(
            print_desc=print_desc,
            curr_proc_outs=curr_proc_outs,
            msg_thread=msg_thread,
            manager=manager,
            print_callback=print_callback
        )
    elif globals_opt.opt_to_start_state_path == 2:
        curr_proc_hyps = make_constrained_init_hypothesis(
            print_desc=print_desc,
            curr_proc_outs=curr_proc_outs,
            msg_thread=msg_thread,
            manager=manager,
            print_callback=print_callback
        )
    else:
        raise RuntimeError(f"Strategy {globals_opt.opt_to_start_state_path} for making init hypothesis is not supported yet.")

    ## Step 2: Extract patch locations
    # 2.1 Determine whether to extract the patch locations
    need_patch = False
    for hyp in curr_proc_hyps.unverified:
        if hyp.commit_type == CommitType.VulnerabilityPatch:
            need_patch = True
            break

    # 2.2 Extract the patch locations
    if need_patch:
        extract_patch_locations(
            print_desc=print_desc,
            curr_proc_outs=curr_proc_outs,
            curr_proc_hyps=curr_proc_hyps,
            msg_thread=msg_thread,
            manager=manager,
            print_callback=print_callback
        )

    return curr_proc_hyps
