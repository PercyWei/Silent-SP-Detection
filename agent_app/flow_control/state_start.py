import os
import json

from typing import *

from agent_app import globals
from agent_app.data_structures import CommitType, ProxyTask, MessageThread
from agent_app.api.manage import ProcessManager
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


def run_in_start_state(
        process_no: int,
        curr_proc_outs: ProcOutPaths,
        msg_thread: MessageThread,
        manager: ProcessManager,
        print_callback: Callable[[dict], None] | None = None
) -> ProcHypothesis | None:
    print_desc = f"process {process_no} | state {State.START_STATE}"

    ################################
    # STEP 1: Make init hypothesis #
    ################################

    # ------------------ 1.1 Prepare the prompt ------------------ #
    # (1) System prompt
    system_prompt = get_system_prompt()
    _add_system_msg_and_print(system_prompt, msg_thread, print_desc, print_callback)

    # (2) Hypothesis proposal prompt
    commit_desc = manager.commit_manager.describe_commit_files()
    hyp_def = get_hyp_def_prompt()
    hyp_prop_prompt = ("The content of the commit is as follows:"
                       f"\n{commit_desc}"
                       "\n\nIn this step, based on the raw commit content, you need to make hypothesis about the functionality of the commit."
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

    # ------------------ 1.3 Collect init hypothesis ------------------ #
    proc_all_hypothesis: ProcHypothesis = ProcHypothesis()

    raw_hyps = json.loads(json_hyps)["hypothesis_list"]
    for hyp in raw_hyps:
        hyp = build_basic_hyp(hyp["commit_type"], hyp["vulnerability_type"], hyp["confidence_score"])
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
        # TODO: We believe that the extracted patch locations is not very closely related to the predicted
        #  vulnerability types in the hypothesis, so we only ask once.

        # ------------------ 2.2 Prepare the prompt ------------------ #
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

        # ------------------ 2.3 Ask the LLM ------------------ #
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

        # ------------------ 2.4 Collect patch locations ------------------ #
        if json_patches is None:
            manager.action_status_count.update_patch_extraction_status(success_flag=False)
        else:
            manager.action_status_count.update_patch_extraction_status(success_flag=True)

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

                proc_all_hypothesis.patch.append(snip)

    return proc_all_hypothesis
