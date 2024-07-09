# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/agent_proxy.py

"""
A proxy agent. Process raw response into json format.
"""

import inspect
from typing import *

from loguru import logger

from agent_app.model import common
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import MessageThread
from agent_app.post_process import ExtractStatus, is_valid_json
from agent_app.utils import parse_function_invocation

# TODO: Need update
PROXY_PROMPT = """
You are a helpful assistant that retreive API calls and bug locations from a text into json format.
The text will consist of two parts:
1. do we need more context?
2. where are bug locations?
Extract API calls from question 1 (leave empty if not exist) and bug locations from question 2 (leave empty if not exist).

The API calls include:
search_method_in_class(method_name: str, class_name: str)
search_method_in_file(method_name: str, file_path: str)
search_method(method_name: str)
search_class_in_file(self, class_name, file_name: str)
search_class(class_name: str)
search_code_in_file(code_str: str, file_path: str)
search_code(code_str: str)

Provide your answer in JSON structure like this, you should ignore the argument placeholders in api calls.
For example, search_code(code_str="str") should be search_code("str")
search_method_in_file("method_name", "path.to.file") should be search_method_in_file("method_name", "path/to/file")
Make sure each API call is written as a valid python expression.

{
    "API_calls": ["api_call_1(args)", "api_call_2(args)", ...],
    "bug_locations":[{"file": "path/to/file", "class": "class_name", "method": "method_name"}, {"file": "path/to/file", "class": "class_name", "method": "method_name"} ... ]
}

NOTE: a bug location should at least has a "class" or "method".
"""


def run_with_retries(text: str, retries=5) -> Tuple[Optional[str], List[MessageThread]]:
    """


    Args:
        text (str): User question text for Proxy Agent
        retries (int): Number of retries with Proxy Agent
    Returns:
        respond text: Valid response in json format from Poxy Agent, None if .
        msg_threads: List of all MessageThread instances.
    """
    msg_threads = []
    for idx in range(1, retries + 1):
        logger.debug(
            "Trying to select search APIs in json. Try {} of {}.", idx, retries
        )

        respond_text, new_thread = run(text)
        msg_threads.append(new_thread)

        extract_status, data = is_valid_json(respond_text)

        if extract_status != ExtractStatus.IS_VALID_JSON:
            logger.debug("Invalid json. Will retry.")
            continue

        valid, diagnosis = is_valid_response(data)
        if not valid:
            logger.debug(f"{diagnosis}. Will retry.")
            continue

        logger.debug("Extracted a valid json")
        return respond_text, msg_threads
    return None, msg_threads


def run(text: str) -> Tuple[str, MessageThread]:
    """
    Run the agent to extract issue to json format.

    Args:
        text (str): User question text for Proxy Agent
    Returns:
        respond_text: Response text in json format from Agent
        msg_threads: MessageThread instance containing current conversation with Proxy Agent
    """
    msg_thread = MessageThread()
    msg_thread.add_system(PROXY_PROMPT)
    msg_thread.add_user(text)
    respond_text, *_ = common.SELECTED_MODEL.call(
        msg_thread.to_msg(), response_format="json_object"
    )

    msg_thread.add_model(respond_text, [])  # no tools

    return respond_text, msg_thread


def is_valid_response(data: Any) -> Tuple[bool, str]:
    """
    Check if input data is a valid response

    Args:
        data:
    Returns:
        bool: True if input data is a valid response, False otherwise
        str: Statement of cause of failure
    """
    if not isinstance(data, dict):
        return False, "Json is not a dict"

    # FIXME: Need update with PROXY_PROMPT
    if not data.get("API_calls"):
        bug_locations = data.get("bug_locations")
        if not isinstance(bug_locations, list) or not bug_locations:
            return False, "Both API_calls and bug_locations are empty"

        for loc in bug_locations:
            if loc.get("class") or loc.get("method"):
                continue
            return False, "Bug location not detailed enough"
    else:
        for api_call in data["API_calls"]:
            if not isinstance(api_call, str):
                return False, "Every API call must be a string"

            try:
                func_name, func_args = parse_function_invocation(api_call)
            except Exception:
                return False, "Every API call must be of form api_call(arg1, ..., argn)"

            function = getattr(SearchManager, func_name, None)
            if function is None:
                return False, f"the API call '{api_call}' calls a non-existent function"

            arg_spec = inspect.getfullargspec(function)
            arg_names = arg_spec.args[1:]  # first parameter is self

            if len(func_args) != len(arg_names):
                return False, f"the API call '{api_call}' has wrong number of arguments"

    return True, "OK"
