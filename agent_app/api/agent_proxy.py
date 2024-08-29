# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/agent_proxy.py

"""
A proxy agent. Process raw response into json format.
"""

import re
import inspect

from typing import *
from enum import Enum

from loguru import logger

from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import State, MessageThread
from agent_app.post_process import ExtractStatus, is_valid_json
from agent_app.util import parse_function_invocation


class ProxyTask(str, Enum):
    HYP_PROPOSAL = "HYP_PROPOSAL"
    PATCH_EXTRACTION = "PATCH_EXTRACTION"
    CONTEXT_RETRIEVAL = "CONTEXT_RETRIEVAL"
    SCORE = "SCORE"

    def task_target(self) -> str:
        if self == ProxyTask.HYP_PROPOSAL:
            return "hypothesis"
        elif self == ProxyTask.PATCH_EXTRACTION:
            return "patch_code"
        elif self == ProxyTask.CONTEXT_RETRIEVAL:
            return "search APIs"
        elif self == ProxyTask.SCORE:
            return "confidence score"


HYP_PROPOSAL_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
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
    hypothesis_list: Hypothesis[]
};

Now based on the given context, write a hypothesis_list section that conforms to the HypothesisList schema.
"""


PATCH_EXTRACTION_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
1. Where is the patch located?

Extract the locations of patch code snippet from question 1, and for each location, it at least contains a "file" and a "code".

interface PatchLocation {
  file: string;
  class?: string;
  func?: string;
  code: string;
}

interface PatchLocations {
  patch_locations: PatchLocation[];
}

Now based on the given context, write a patch_locations section that conforms to the PatchLocations schema.
"""


CONTEXT_RETRIEVAL_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
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
    api_calls: ApiCall[]
};

Now based on the given context, write a api_calls section that conforms to the ApiCalls schema.
"""


SCORE_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
1. What confidence score is set for the current hypothesis?

Extract the confidence score from question 1.

The confidence score should be an integer value between 1 and 10.

interface Score {
    confidence_score: number
};

Now based on the given context, write a confidence_score section that conforms to the Score schema.
"""


def get_task_prompt(task: ProxyTask) -> str:
    variable_name = f"{task}_PROMPT"
    system_prompt = globals().get(variable_name, '')
    assert system_prompt != '', KeyError(variable_name)
    return system_prompt


def run_with_retries(text: str, task: ProxyTask, retries: int = 3) -> Tuple[str | None, List[MessageThread]]:
    """
    Main method to ask the LLM Agent to extract JSON answer from the given text with retries.

    Args:
        text (str): Response from Actor Agent.
        task (ProxyTask): Task of Proxy Agent.
        retries (int): Number of retries for Proxy Agent.
    Returns:
        respond text: Valid response in json format from Poxy Agent, None if .
        msg_threads: List of all MessageThread instances.
    """
    msg_threads = []
    for idx in range(1, retries + 1):
        logger.debug(f"Trying to select {task.task_target()} in json. Try {idx} of {retries}.")

        respond_text, new_thread = run(text, task)
        msg_threads.append(new_thread)

        extract_status, data = is_valid_json(respond_text)

        if extract_status != ExtractStatus.IS_VALID_JSON:
            logger.debug("Invalid json. Will retry.")
            continue

        valid, diagnosis = is_valid_response(data, task)
        if not valid:
            logger.debug(f"{diagnosis}. Will retry.")
            continue

        logger.debug("Extracted a valid json")
        return respond_text, msg_threads
    return None, msg_threads


def run(text: str, task: ProxyTask) -> Tuple[str, MessageThread]:
    """
    Run the agent to extract useful information in json format.

    Args:
        text (str): Response from Actor Agent.
        task (ProxyTask): Task of Proxy Agent.
    Returns:
        respond_text (str): Response text in json format from Agent.
        msg_threads (MessageThread): MessageThread instance containing current conversation with Proxy Agent.
    """
    msg_thread = MessageThread()
    task_prompt = get_task_prompt(task)
    msg_thread.add_system(task_prompt)
    msg_thread.add_user(text)
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg(), response_format="json_object")

    msg_thread.add_model(respond_text, [])

    return respond_text, msg_thread


def is_valid_response(data: List | Dict, task: ProxyTask) -> Tuple[bool, str]:
    """
    Check if input data is a valid response

    Args:
        data (List | Dict | None): Json data.
        task (ProxyTask): Task of Proxy Agent.
    Returns:
        bool: True if input data is a valid response, False otherwise
        str: Statement of cause of failure
    """
    if not isinstance(data, dict):
        return False, "Json is not a dict"

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
            return False, "Missing 'hypothesis_list' key"

        hypothesis_list = data["hypothesis_list"]
        for hypothesis in hypothesis_list:
            if not isinstance(hypothesis, Dict):
                return False, "Every hypothesis must be a dict"

            if "commit_type" not in hypothesis:
                return False, "For hypothesis, missing 'commit_type' key"

            if "vulnerability_type" not in hypothesis:
                return False, "For hypothesis, missing 'vulnerability_type' key"

            if "confidence_score" not in hypothesis:
                return False, "For hypothesis, missing 'confidence_score' key"

            commit_type = hypothesis["commit_type"]
            vul_type = hypothesis["vulnerability_type"]
            conf_score = hypothesis["confidence_score"]

            if commit_type not in ["vulnerability_patch", "non_vulnerability_patch"]:
                return False, "For hypothesis, 'commit_type' is not 'vulnerability_patch' or 'non_vulnerability_patch'"

            if commit_type == "non_vulnerability_patch" and vul_type != "":
                return False, "For hypothesis, 'vulnerability_type' should be empty while 'commit_type' is 'non_vulnerability_patch'"

            if commit_type == "vulnerability_patch" and not re.fullmatch(r"CWE-\d+", vul_type):
                return False, "For hypothesis, 'vulnerability_type' should be a CWE-ID while 'commit_type' is 'vulnerability_patch'"

            if not isinstance(conf_score, int):
                return False, "For hypothesis, 'confidence_score' is not an integer"

    elif task == ProxyTask.PATCH_EXTRACTION:
        """
        {
            "patch_locations": [
                [
                    "file": str, required
                    "code": str, required
                    "class": str, not required
                    "func": str, not required
                ],
                ...
            ]
        }
        """
        if "patch_locations" not in data:
            return False, "Missing 'patch_locations' key"

        patch_locations = data["patch_locations"]
        for loc in patch_locations:
            if "file" in loc and "code" in loc:
                continue
            return False, "For each location in 'patch_locations', at least a 'file' and a 'code' are required"

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
            return False, "Missing 'api_calls' key"

        api_calls = data["api_calls"]
        for api_call in api_calls:
            if not isinstance(api_call, str):
                return False, "Every API call must be a string"

            try:
                func_name, func_args = parse_function_invocation(api_call)
            except Exception:
                return False, "Every API call must be of form api_call(arg1, ..., argn)"

            # NOTE: Generally speaking, the name of the api called by LLM is not wrong
            function = getattr(SearchManager, func_name, None)
            if function is None:
                return False, f"The API call '{api_call}' calls a non-existent function"

            # NOTE: We found that in many cases, the LLM could not understand the search api correctly, resulting
            #       in mismatched parameters, while repeated queries to get the right format api tended to result
            #       in too many useless conversations, so we do not check the parameters here, but provide specific
            #       feedback later while calling the api.

            # arg_spec = inspect.getfullargspec(function)
            # arg_names = arg_spec.args[1:]  # first parameter is self
            #
            # if len(func_args) != len(arg_names):
            #     return False, f"The API call '{api_call}' has wrong number of arguments"

    elif task == ProxyTask.SCORE:
        """
       {
           "confidence_score": int
       }
       """
        if "confidence_score" not in data:
            return False, "Missing 'confidence_score' key"

        score = data["confidence_score"]
        if not isinstance(score, int):
            return False, "'confidence_score' is not an integer"

    return True, "OK"
