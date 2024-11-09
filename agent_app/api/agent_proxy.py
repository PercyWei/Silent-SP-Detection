# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/agent_proxy.py

"""A proxy agent. Process raw response into json format."""

import re
import json
import inspect

from typing import *
from enum import Enum

from loguru import logger

from agent_app.model import common
from agent_app.search.search_manage import PySearchManager
from agent_app.data_structures import MessageThread
from agent_app.util import LanguageNotSupportedError, parse_function_invocation


class ProxyTask(str, Enum):
    HYP_PROPOSAL = "HYP_PROPOSAL"
    HYP_CHECK = "HYP_CHECK"
    PATCH_EXTRACTION = "PATCH_EXTRACTION"
    CONTEXT_RETRIEVAL = "CONTEXT_RETRIEVAL"
    SCORE = "SCORE"
    RANK = "RANK"

    def task_target(self) -> str:
        if self == ProxyTask.HYP_PROPOSAL:
            return "hypothesis"
        elif self == ProxyTask.HYP_CHECK:
            return "CWE type"
        elif self == ProxyTask.PATCH_EXTRACTION:
            return "patch_code"
        elif self == ProxyTask.CONTEXT_RETRIEVAL:
            return "search APIs"
        elif self == ProxyTask.SCORE:
            return "confidence score"
        elif self == ProxyTask.RANK:
            return "ranking"


def _get_hyp_proposal_prompt() -> str:
    return """You are a helpful assistant to convert text containing the following information into json format.
1. Are new hypotheses being proposed?

Extract new hypothesis from question 1, leave an empty list if you do not find any valid hypothesis.

interface VulPatchHypothesis {
  commit_type: 'vulnerability_patch';
  vulnerability_type: `CWE-${number}`;
  confidence_score: number;
}

interface NonVulPatchHypothesis {
  commit_type: 'non_vulnerability_patch';
  vulnerability_type: '';
  confidence_score: number;
}

type Hypothesis = VulPatchHypothesis | NonVulPatchHypothesis;

interface HypothesisList {
    hypothesis_list: Hypothesis[];
};

Now based on the given context, write a hypothesis_list section that conforms to the HypothesisList schema.
"""


def _get_hyp_check_prompt() -> str:
    return """You are a helpful assistant to convert text containing the following information into json format.
1. What is the modified CWE type?

Extract the CWE type from question 1.

interface CWEType {
    cwe_type: `CWE-${number}`;
};

Now based on the given context, write a cwe_type section that conforms to the CWEType schema.
"""


def _get_patch_extraction_prompt(lang: Literal['Python', 'Java']) -> str:
    if lang == 'Python':
        return """You are a helpful assistant to convert text containing the following information into json format.
1. Where is the patch located?

Extract the locations of patch code snippet from question 1, and for each location, it at least contains a "file_name" and a "code".

interface PatchLocation {
  file_name: string;
  func_name?: string;
  class_name?: string;
  inclass_method_name?: string;
  code: string;
}

interface PatchLocations {
  patch_locations: PatchLocation[];
}

Now based on the given context, write a patch_locations section that conforms to the PatchLocations schema.
"""
    elif lang == 'Java':
        return """You are a helpful assistant to convert text containing the following information into json format.
1. Where is the patch located?

Extract the locations of patch code snippet from question 1, and for each location, it at least contains a "file_name" and a "code".

interface PatchLocation {
  file_name: string;
  iface_name?: string;
  class_name?: string;
  inclass_method_name?: string;
  inclass_iface_name?: string;
  inclass_class_name?: string;
  code: string;
}

interface PatchLocations {
  patch_locations: PatchLocation[];
}

Now based on the given context, write a patch_locations section that conforms to the PatchLocations schema.
"""
    else:
        raise LanguageNotSupportedError(lang)


def _get_context_retrieval_prompt(lang: Literal['Python', 'Java']) -> str:
    if lang == 'Python':
        return """You are a helpful assistant to convert text containing the following information into json format.
1. How to construct search API calls to get more context of the project?

Extract API calls from question 1, leave an empty list if you do not find any valid API calls or the text content indicates that no further context is needed.

The API calls include:
- search_class(class_name: str)
- search_class_in_file(class_name: str, file_name: str)
- search_method_in_file(method_name: str, file_name: str)
- search_method_in_class(method_name: str, class_name: str)
- search_method_in_class_in_file(method_name: str, class_name: str, file_name: str)

Provide your answer in JSON structure like this, you should ignore the argument placeholders in api calls.
For example, search_method(method_name="str") should be search_method("str"), search_method_in_file("method_name", "path.to.file") should be search_method_in_file("method_name", "path/to/file")
Make sure each API call is written as a valid python expression.
Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

type ApiCall = 
  | `search_class(${string})`
  | `search_class_in_file(${string}, ${string})`
  | `search_method_in_file(${string}, ${string})`
  | `search_method_in_class(${string}, ${string})`
  | `search_method_in_class_in_file(${string}, ${string}, ${string})`;

interface ApiCalls {
    api_calls: ApiCall[];
};

Now based on the given context, write a api_calls section that conforms to the ApiCalls schema.
"""
    elif lang == 'Java':
        return """You are a helpful assistant to convert text containing the following information into json format.
1. How to construct search API calls to get more context of the project?

Extract API calls from question 1, leave an empty list if you do not find any valid API calls or the text content indicates that no further context is needed.

The API calls include:
- search_interface(iface_name: str)
- search_class(class_name: str)
- search_interface_in_file(iface_name: str, file_name: str)
- search_class_in_file(class_name: str, file_name: str)
- search_type_in_class(ttype: ['interface', 'class', 'method'], type_name: str, class_name: str)
- search_type_in_class_in_file(ttype: ['interface', 'class', 'method'], type_name: str, class_name: str, file_name: str)

Provide your answer in JSON structure like this, you should ignore the argument placeholders in api calls.
For example, search_interface(iface_name="str") should be search_interface("str"), search_class_in_file("class_name", "path.to.file") should be search_class_in_file("class_name", "path/to/file")
Make sure each API call is written as a valid python expression.
Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

type SearchType = 'interface' | 'class' | 'method';

type ApiCall = 
  | `search_interface(${string})`
  | `search_class(${string})`
  | `search_interface_in_file(${string}, ${string})`
  | `search_class_in_file(${string}, ${string})`
  | `search_type_in_class(${SearchType}, ${string}, ${string})`
  | `search_type_in_class_in_file(${SearchType}, ${string}, ${string}, ${string})`;

interface ApiCalls {
    api_calls: ApiCall[];
};

Now based on the given context, write a api_calls section that conforms to the ApiCalls schema.
"""
    else:
        raise LanguageNotSupportedError(lang)


def _get_score_prompt() -> str:
    return """You are a helpful assistant to convert text containing the following information into json format.
1. What confidence score is set for the current hypothesis?

Extract the confidence score from question 1.

The confidence score should be an integer value between 1 and 10.

interface Score {
    confidence_score: number;
};

Now based on the given context, write a confidence_score section that conforms to the Score schema.
"""


def _get_rank_prompt() -> str:
    return """You are a helpful assistant to convert text containing the following information into json format.
1. What is the ranking of the hypothesis?

Extract the ranking from question 1.

The ranking should be a list consisting of integers, e.g. [2, 3, 1].

interface Ranking {
    ranking: number[];
};

Now based on the given context, write a ranking section that conforms to the Ranking schema.
"""


def get_task_prompt(task: ProxyTask, lang: Literal['Python', 'Java']) -> str:
    if task == ProxyTask.HYP_PROPOSAL:
        return _get_hyp_proposal_prompt()
    elif task == ProxyTask.HYP_CHECK:
        return _get_hyp_check_prompt()
    elif task == ProxyTask.PATCH_EXTRACTION:
        return _get_patch_extraction_prompt(lang)
    elif task == ProxyTask.CONTEXT_RETRIEVAL:
        return _get_context_retrieval_prompt(lang)
    elif task == ProxyTask.SCORE:
        return _get_score_prompt()
    elif task == ProxyTask.RANK:
        return _get_rank_prompt()


def run(
        task: ProxyTask,
        lang: Literal['Python', 'Java'],
        text: str,
        prev_summary: str | None = None
) -> Tuple[str, MessageThread]:
    """
    Run the agent to extract useful information in json format.

    Args:
        task (ProxyTask): Task of Proxy Agent.
        lang (str): Programming language. Only choose from 'Python' and 'Java'.
        text (str): Text to be extracted.
        prev_summary (str): The summary of the previous failed retries.
    Returns:
        respond_text (str): Response text in json format from Agent.
        msg_threads (MessageThread): MessageThread instance containing current conversation with Proxy Agent.
    """
    msg_thread = MessageThread()
    task_prompt = get_task_prompt(task, lang)
    msg_thread.add_system(task_prompt)
    msg_thread.add_user(text)
    if prev_summary is not None:
        msg_thread.add_user(prev_summary)
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg(), response_format="json_object")

    msg_thread.add_model(respond_text, [])

    return respond_text, msg_thread


def is_valid_json(json_str: str) -> Tuple[bool, Union[List, Dict, None]]:
    """
    Check whether a json string is valid.

    Args:
        json_str: A string to check if in json format
    Returns:
        bool: Whether is valid json.
        Union[List, Dict, None]: List or Dict if in json format, otherwise None
    """
    try:
        data = json.loads(json_str)
    except json.decoder.JSONDecodeError:
        return False, None
    return True, data


def is_valid_response(data: List | Dict, task: ProxyTask) -> Tuple[bool, str, str]:
    """
    Check if input data is a valid response

    Args:
        data (List | Dict | None): Json data.
        task (ProxyTask): Task of Proxy Agent.
    Returns:
        bool: True if input data is a valid response, otherwise False.
        str: Simplified statement of failure reason.
        str: Verbose statement of failure reason.
    """
    if not isinstance(data, dict):
        simp_reason = verb_reason = "JSON is not a Dict"
        return False, simp_reason, verb_reason

    if task == ProxyTask.HYP_PROPOSAL:
        """
        {
            "hypothesis_list" : [
                {
                    commit_type: 'vulnerability_patch' | 'non_vulnerability_patch',
                    vulnerability_type: str;
                    confidence_score: int;  
                },
                ...
            ]
        }
        """
        if "hypothesis_list" not in data:
            simp_reason = verb_reason = "Missing 'hypothesis_list' key"
            return False, simp_reason, verb_reason

        hypothesis_list = data["hypothesis_list"]
        for hypothesis in hypothesis_list:
            if not isinstance(hypothesis, Dict):
                simp_reason = verb_reason = "A hypothesis is not a Dict"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            if "commit_type" not in hypothesis:
                simp_reason = verb_reason = "A hypothesis missing 'commit_type' key"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            if "vulnerability_type" not in hypothesis:
                simp_reason = verb_reason = "A hypothesis missing 'vulnerability_type' key"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            if "confidence_score" not in hypothesis:
                simp_reason = verb_reason = "A hypothesis missing 'confidence_score' key"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            commit_type = hypothesis["commit_type"]
            vul_type = hypothesis["vulnerability_type"]
            conf_score = hypothesis["confidence_score"]

            if commit_type not in ["vulnerability_patch", "non_vulnerability_patch"]:
                simp_reason = verb_reason = "The 'commit_type' of a hypothesis is not 'vulnerability_patch' or 'non_vulnerability_patch'"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            if commit_type == "non_vulnerability_patch" and vul_type != "":
                simp_reason = verb_reason = "The 'vulnerability_type' of a hypothesis is not an empty string while the 'commit_type' is 'non_vulnerability_patch'"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            if commit_type == "vulnerability_patch" and not re.fullmatch(r"CWE-\d+", vul_type):
                simp_reason = verb_reason = "The 'vulnerability_type' of a hypothesis is not a valid CWE-ID string while the 'commit_type' is 'vulnerability_patch'"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

            if not isinstance(conf_score, int):
                simp_reason = verb_reason = "The 'confidence_score' of a hypothesis is not an integer"
                verb_reason += f" and the hypothesis is: {hypothesis}"
                return False, simp_reason, verb_reason

    elif task == ProxyTask.HYP_CHECK:
        """
       {
           "cwe_id": str
       }
       """
        if "cwe_id" not in data:
            simp_reason = verb_reason = "Missing 'cwe_id' key"
            return False, simp_reason, verb_reason

        cwe_id = data["cwe_id"]
        if not re.fullmatch(r"CWE-\d+", cwe_id):
            simp_reason = verb_reason = "The 'cwe_id' is not a valid CWE-ID string"
            return False, simp_reason, verb_reason

    elif task == ProxyTask.PATCH_EXTRACTION:
        """
        {
            "patch_locations": [
                [
                    "file_name": str, required
                    "code": str, required
                    "func_name": str, not required
                    "iface_name": str, not required
                    "class_name": str, not required
                    "inclass_method_name": str, not required
                    "inclass_iface_name": str, not required
                    "inclass_class_name": str, not required
                ],
                ...
            ]
        }
        """
        if "patch_locations" not in data:
            simp_reason = verb_reason = "Missing 'patch_locations' key"
            return False, simp_reason, verb_reason

        patch_locations = data["patch_locations"]
        for loc in patch_locations:
            if "file_name" in loc and "code" in loc:
                continue
            simp_reason = verb_reason = "A location missing the required 'file_name' and 'code'"
            verb_reason += f" and the location is: {loc}"
            return False, simp_reason, verb_reason

    elif task == ProxyTask.CONTEXT_RETRIEVAL:
        """
        {
            "api_calls" : [
                "api_call_1(arg)", 
                "api_call_2(arg1, arg2)", 
                ...
            ]
        }
        """
        if "api_calls" not in data:
            simp_reason = verb_reason = "Missing 'api_calls' key"
            return False, simp_reason, verb_reason

        api_calls = data["api_calls"]
        for api_call in api_calls:
            if not isinstance(api_call, str):
                simp_reason = verb_reason = "An API call is not a string"
                verb_reason += f" and the API call is: {api_call}"
                return False, simp_reason, verb_reason

            try:
                func_name, func_args = parse_function_invocation(api_call)
            except Exception:
                simp_reason = verb_reason = "An API call is not in the form api_call(arg1, ..., argn)"
                verb_reason += f" and the API call is: {api_call}"
                return False, simp_reason, verb_reason

            # NOTE: Generally speaking, the name of the api called by LLM is not wrong
            function = getattr(PySearchManager, func_name, None)
            if function is None:
                simp_reason = verb_reason = "An API call invokes a non-existent function"
                verb_reason += f" and the API call is: {api_call}"
                return False, simp_reason, verb_reason

            # NOTE: We found that in many cases, the LLM could not understand the search api correctly, resulting
            #       in mismatched parameters, while repeated queries to get the right format api tended to result
            #       in too many useless conversations, so we do not check the parameters here, but provide specific
            #       feedback later while calling the api.

    elif task == ProxyTask.SCORE:
        """
       {
           "confidence_score": int
       }
       """
        if "confidence_score" not in data:
            simp_reason = verb_reason = "Missing 'confidence_score' key"
            return False, simp_reason, verb_reason

        score = data["confidence_score"]
        if not isinstance(score, int):
            simp_reason = verb_reason = "The 'confidence_score' is not an integer"
            return False, simp_reason, verb_reason

    elif task == ProxyTask.RANK:
        """
       {
           "ranking": List[int]
       }
       """
        if "ranking" not in data:
            simp_reason = verb_reason = "Missing 'ranking' key"
            return False, simp_reason, verb_reason

        ranking = data["ranking"]
        if not isinstance(ranking, List):
            simp_reason = verb_reason = "The 'ranking' is not a List"
            return False, simp_reason, verb_reason

        for hyp_id in ranking:
            if not isinstance(hyp_id, int):
                simp_reason = verb_reason = "The 'ranking' is not a List consisting of integers"
                return False, simp_reason, verb_reason

    return True, "OK", "OK"


"""MAIN ENTRY"""


def run_with_retries(
        lang: Literal['Python', 'Java'],
        text: str,
        task: ProxyTask,
        retries: int = 3,
        with_summary: bool = False
) -> Tuple[str | None, str | None, List[MessageThread]]:
    """Main method to ask the LLM Agent to extract JSON answer from the given text with retries.

    Args:
        lang (str): Programming language. Only choose from 'Python' and 'Java'.
        text (str): Text to be extracted.
        task (ProxyTask): Task of Proxy Agent.
        retries (int): Number of retries for Proxy Agent.
        with_summary (bool): Use the summary of previous failed retries in the next attempt if True, otherwise not.
    Returns:
        str | None: Valid response in JSON format if the extraction succeed, otherwise None.
        str | None: Failure summary if the extraction failed, otherwise None.
        List[MessageThread]: List of all MessageThread instances.
    """
    msg_threads = []

    proxy_responses: List[str] = []
    failure_simp_reasons: List[str] = []
    failure_verb_reasons: List[str] = []

    ## Step 1: Ask the Proxy Agent with retries
    for idx in range(1, retries + 1):
        logger.debug(f"Trying to select {task.task_target()} in json. Try {idx} of {retries}.")

        # Summarize the previous failed retries
        prev_summary = None
        if with_summary and idx > 1:
            prev_summary = "Previous retries have failed, and their results and reasons for failure are as below:"
            for i, (res, simp_reason) in enumerate(zip(proxy_responses, failure_simp_reasons)):
                prev_summary += (f"\n\nRetry {i + 1}: "
                                 f"\n - Result: {res}"
                                 f"\n - Reason: {simp_reason}")
            prev_summary += "\n\nPlease avoid making the same mistake in your next answer."

        # Ask the LLM
        proxy_response, new_thread = run(task, lang, text, prev_summary)
        msg_threads.append(new_thread)

        # Check the format
        is_valid, data = is_valid_json(proxy_response)
        if not is_valid:
            logger.debug("Extracted a result in invalid json.")

            proxy_responses.append(proxy_response)
            failure_simp_reasons.append("Invalid json")
            failure_verb_reasons.append("Invalid json")
            continue

        # Check the content
        valid, simp_reason, verb_reason = is_valid_response(data, task)
        if not valid:
            logger.debug(f"Extracted a invalid result in json. Reason: {verb_reason}.")

            proxy_responses.append(proxy_response)
            failure_simp_reasons.append(simp_reason)
            failure_verb_reasons.append(verb_reason)
            continue

        logger.debug("Extracted a valid result in json.")
        return proxy_response, None, msg_threads

    ## Step 2: Extraction failed, summarize the failure reasons and return
    failure_summary = f"We failed to extract valid {task.task_target()} in JSON format with retries. "

    if len(set(failure_simp_reasons)) == 1:
        # Retires failed for the same reason
        failure_summary += f"The reason is: {failure_simp_reasons[0]}."
    else:
        # Retires failed for the different reasons
        # TODO: For multiple failure reasons, do we need to use LLM to summary?
        failure_summary += "The reasons include:"
        for i, reason in enumerate(failure_simp_reasons):
            failure_summary += f"\n - {i + 1}: {reason}"

    return None, failure_summary, msg_threads
