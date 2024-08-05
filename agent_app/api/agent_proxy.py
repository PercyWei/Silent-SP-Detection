# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/agent_proxy.py

"""
A proxy agent. Process raw response into json format.
"""

import re
import inspect
from typing import *
from rich.text import Text

from loguru import logger

from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import State, MessageThread
from agent_app.post_process import ExtractStatus, is_valid_json
from agent_app.util import parse_function_invocation

START_PROXY_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
1. Whether the commit fixes the vulnerability?
2. Where is the patch located?
3. What types of vulnerabilities might it address?

Extract commit type from question 1 (it must exist).
Extract patch_locations and vulnerability_types from question 2 (leave empty if not exist).

For "commit_type", choose its value from "vulnerability_patch" and "non_vulnerability_type". If the value of "commit_type" is "non_vulnerability_type", "patch_locations" and "vulnerability_types" should be empty.
For "patch_locations", its value is a list in which each element is a list at least containing a "file" and a "code".
For "vulnerability_types", its value is a list in which each element is a list containing the type of vulnerability and the corresponding confidence score (1-10).
Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

interface PatchLocation {
  file: string;
  class?: string;
  func?: string;
  code: string;
}

type CWEId = `CWE-${number}`;

type VulnerabilityType = [CWEId, number];

interface VulPatchHypothesis {
  commit_type: 'vulnerability_patch';
  patch_locations: PatchLocation[];
  vulnerability_types: VulnerabilityType[];
}

interface NonVulPatchHypothesis {
  commit_type: 'non_vulnerability_patch';
  patch_locations: [];
  vulnerability_types: [];
}

type Hypothesis = VulPatchHypothesis | NonVulPatchHypothesis;

Now based on the given context, write a hypothesis section according to the Hypothesis schema.
"""

CONTEXT_RETRIEVAL_PROXY_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
1. How to construct search API calls to get more context of the project?

Extract API calls from question 1, leave an empty list if you do not find any valid API calls.

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

HYPOTHESIS_CHECK_PROXY_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
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

HYPOTHESIS_VERIFY_PROXY_PROMPT = """You are a helpful assistant to convert text containing the following information into json format.
1. What confidence score is set for the current hypothesis?

Extract the confidence score from question 1.

The confidence score should be an integer value between 1 and 10.

interface Score {
    confidence_score: number
};

Now based on the given context, write a confidence_score section that conforms to the Score schema.
"""


def run_with_retries(text: str, state: str, retries=3) -> Tuple[str | None, List[MessageThread]]:
    """


    Args:
        text (str): Response from Actor Agent.
        state (str): Actor Agent state.
        retries (int): Number of retries with Proxy Agent
    Returns:
        respond text: Valid response in json format from Poxy Agent, None if .
        msg_threads: List of all MessageThread instances.
    """
    msg_threads = []
    for idx in range(1, retries + 1):
        info = None
        if state == State.START_STATE:
            info = "hypothesis"
        elif State == State.HYPOTHESIS_CHECK_STATE:
            info = "hypothesis"
        elif state == State.CONTEXT_RETRIEVAL_STATE:
            info = "search APIs"
        elif State == State.HYPOTHESIS_VERIFY_STATE:
            info = "confidence score"

        logger.debug(f"Trying to select {info} in json. Try {idx} of {retries}.")

        respond_text, new_thread = run(text, state)
        msg_threads.append(new_thread)

        extract_status, data = is_valid_json(respond_text)

        if extract_status != ExtractStatus.IS_VALID_JSON:
            logger.debug("Invalid json. Will retry.")
            continue

        valid, diagnosis = is_valid_response(data, state)
        if not valid:
            logger.debug(f"{diagnosis}. Will retry.")
            continue

        logger.debug("Extracted a valid json")
        return respond_text, msg_threads
    return None, msg_threads


def get_system_prompt(state: str) -> str:
    variable_name = f"{state.upper()}_PROXY_PROMPT"
    system_prompt = globals().get(variable_name, '')
    assert system_prompt != '', KeyError(variable_name)
    return system_prompt


def run(text: str, state: str) -> Tuple[str, MessageThread]:
    """
    Run the agent to extract useful information in json format.

    Args:
        text (str): Response from Actor Agent.
        state (str): Actor Agent state.
    Returns:
        respond_text (str): Response text in json format from Agent.
        msg_threads (MessageThread): MessageThread instance containing current conversation with Proxy Agent.
    """
    msg_thread = MessageThread()
    system_prompt = get_system_prompt(state)
    msg_thread.add_system(system_prompt)
    msg_thread.add_user(text)
    respond_text, *_ = common.SELECTED_MODEL.call(msg_thread.to_msg(), response_format="json_object")

    msg_thread.add_model(respond_text, [])

    return respond_text, msg_thread


def is_valid_response(data: Any, state: str) -> Tuple[bool, str]:
    """
    Check if input data is a valid response

    Args:
        data:
        state (str):
    Returns:
        bool: True if input data is a valid response, False otherwise
        str: Statement of cause of failure
    """
    if not isinstance(data, dict):
        return False, "Json is not a dict"

    if state == State.START_STATE:
        """
        {
            "commit_type": "vulnerability_patch" | "non_vulnerability_patch", 
            "patch_locations": [
                [
                    "file": str, required
                    "code": str, required
                    "class": str, not required
                    "func": str, not required
                ],
                ...
            ]
            "vulnerability_types": [
                [CWE-ID, confidence_score], 
                ...
            ]
        }
        """
        if "commit_type" not in data:
            return False, "Missing 'commit_type' key"

        commit_type = data["commit_type"]
        if commit_type not in ["vulnerability_patch", "non_vulnerability_patch"]:
            return False, "'commit_type' is not 'vulnerability_patch' or 'non_vulnerability_patch'"

        if "patch_locations" not in data:
            return False, "Missing 'patch_locations' key"

        if "vulnerability_types" not in data:
            return False, "Missing 'vulnerability_types' key"

        patch_locations = data["patch_locations"]
        vul_types = data["vulnerability_types"]

        if commit_type == "non_vulnerability_patch":
            if len(patch_locations) != 0 or len(vul_types) != 0:
                return False, "'patch_locations' and 'vulnerability_types' should be empty while 'commit_type' is 'non_vulnerability_patch'"
        else:
            if len(patch_locations) == 0 or len(vul_types) == 0:
                return False, "'patch_locations' and 'vulnerability_types' should not be empty while 'commit_type' is 'vulnerability_patch'"

            for loc in patch_locations:
                if "file" in loc and "code" in loc:
                    continue
                return False, "For each location in 'patch_locations', at least a 'file' and a 'code' are required"

            for vul in vul_types:
                if len(vul) == 2 and re.fullmatch(r"CWE-\d+", vul[0]) and isinstance(vul[1], int):
                    continue
                return False, "For each vulnerability type in 'vulnerability_types', it should have a CWE-ID and an integer confidence score"

    elif state == State.HYPOTHESIS_CHECK_STATE:
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
        if len(hypothesis_list) != 0:
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

                if not re.fullmatch(r"CWE-\d+", vul_type):
                    return False, "For hypothesis, 'vulnerability_type' should be a CWE-ID"

                if not isinstance(conf_score, int):
                    return False, "For hypothesis, 'confidence_score' is not an integer"

    elif state == State.CONTEXT_RETRIEVAL_STATE:
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
        if len(api_calls) != 0:
            for api_call in api_calls:
                if not isinstance(api_call, str):
                    return False, "Every API call must be a string"

                try:
                    func_name, func_args = parse_function_invocation(api_call)
                except Exception:
                    return False, "Every API call must be of form api_call(arg1, ..., argn)"

                function = getattr(SearchManager, func_name, None)
                if function is None:
                    return False, f"The API call '{api_call}' calls a non-existent function"

                arg_spec = inspect.getfullargspec(function)
                arg_names = arg_spec.args[1:]  # first parameter is self

                if len(func_args) != len(arg_names):
                    return False, f"The API call '{api_call}' has wrong number of arguments"

    elif state == State.HYPOTHESIS_VERIFY_STATE:
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
