# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/manage.py

import os
import json

from typing import *
from copy import deepcopy
from docstring_parser import parse

from loguru import logger

from agent_app.api import agent_proxy
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import FunctionCallIntent, MessageThread
from agent_app.task import Task
from agent_app.log import log_exception


class Action:
    pass


class StateMachine:

    states = [
        "start",
        "hypothesis_making",
        "context_retrieval",
        "hypothesis_verification",
        "end"
    ]

    def __init__(self):
        self.curr_state: str = "start"

    def available_api_functions(self):
        pass

    def switch_state(self, next_state: str):
        if self.curr_state == "start":
            assert next_state == "hypothesis_making", \
                f"Next state of 'start' must be 'hypothesis_making', but got '{next_state}'"
        elif self.curr_state == "hypothesis_making":
            assert next_state == "information_collection", \
                f"Next state of 'hypothesis_making' must be 'information_collection', but got '{next_state}'"
        elif self.curr_state == "information_collection":
            assert next_state == "hypothesis_verification", \
                f"Next state of 'information_collection' must be 'hypothesis_verification', but got '{next_state}'"
        elif self.curr_state == "hypothesis_verification":
            assert next_state == "hypothesis_verification", \
                f"Next state of 'information_collection' must be 'hypothesis_verification', but got '{next_state}'"

        self.curr_state = next_state



class ProjectApiManager:
    ################# State machine specific ################
    # NOTE: this section is for state machine; APIs in stratified mode are specified
    # in agent_api_hypothesis verificationselector.py

    # Original settings in AutoCodeRover
    # api_functions = [
    #     "search_class",
    #     "search_class_in_file",
    #     "search_method",
    #     "search_method_in_class",
    #     "search_method_in_file",
    #     "search_code",
    #     "search_code_in_file",
    #     "write_patch",
    # ]
    # TODO: Need Improvement
    api_functions = [
        "search_class",
        "search_class_in_file",
        "search_method",
        "search_method_in_class",
        "search_method_in_file",
        "search_code",
        "search_code_in_file",
        "write_patch",
    ]


    def __init__(self, task: Task, output_dpath: str):
        # for logging of this task instance
        self.task = task

        # Where to write our output
        self.output_dpath = os.path.abspath(output_dpath)

        self.task.setup_project()

        # Build search manager
        self.search_manager = SearchManager(self.task.project_path)

        # Keeps track which tools is currently being used
        self.curr_tool: Optional[str] = None

        # Record the sequence of tools used, and their return status
        self.tool_call_sequence: List[Mapping] = []

        # Record layered API calls
        self.tool_call_layers: List[List[Mapping]] = []

        # Record cost and token information
        self.cost: float = 0.0
        self.input_tokens: int = 0
        self.output_tokens: int = 0

    def next_tools(self) -> List[str]:
        """
        Return the list of tools that should be used in the next round.
        """

        search_tools = [
            "search_class",
            "search_class_in_file",
            "search_method",
            "search_method_in_class",
            "search_method_in_file",
            "search_code",
            "search_code_in_file",
        ]
        all_tools = search_tools + ["write_patch"]
        if not self.curr_tool:
            # This means we are at the beginning of the conversation
            # you have to start from doing some search
            return search_tools

        state_machine = {
            "search_class": search_tools,
            "search_class_in_file": search_tools,
            "search_method": all_tools,
            "search_method_in_class": all_tools,
            "search_method_in_file": all_tools,
            "search_code": all_tools,
            "search_code_in_file": all_tools,
            "write_patch": [],
        }
        return state_machine[self.curr_tool]

    def start_new_tool_call_layer(self):
        self.tool_call_layers.append([])

    @classmethod
    def get_full_funcs_for_openai(cls, tool_list: List[str]) -> List[Dict]:
        """
        Return a list of function objects which can be sent to OpenAI for the function calling feature.

        Args:
            tool_list (List[str]): The available tools (self functions) which have detailed docstrings.

        Returns:
            List[Dict]: List of function objects (Dict) which can be sent to OpenAI.
        """
        tool_template = {
            "type": "function",
            "function": {
                "name": "",
                "description": "",
                "parameters": {
                    "type": "object",
                    "properties": {},  # mapping from para name to type+description
                    "required": [],  # name of required parameters
                },
            },
        }
        all_tool_objs = []

        for func_name in tool_list:
            if not hasattr(cls, func_name):
                continue
            tool_obj = deepcopy(tool_template)
            tool_obj["function"]["name"] = func_name
            func_obj = getattr(cls, func_name)
            # TODO: we only parse docstring now
            #   There are two sources of information:
            #   1. the docstring
            #   2. the function signature
            #   Docstring is where we get most of the textual descriptions; for accurate
            #   info about parameters (whether optional), we check signature.

            ## parse docstring
            doc = parse(func_obj.__doc__)
            short_desc = doc.short_description if doc.short_description is not None else ""
            long_desc = doc.long_description if doc.long_description is not None else ""
            description = short_desc + "\n" + long_desc
            tool_obj["function"]["description"] = description
            doc_params = doc.params
            for doc_param in doc_params:
                param_name = doc_param.arg_name
                if param_name == "self":
                    continue
                typ = doc_param.type_name
                desc = doc_param.description
                is_optional = doc_param.is_optional
                # now add this param to the tool object
                tool_obj["function"]["parameters"]["properties"][param_name] = {
                    "type": typ,
                    "description": desc,
                }
                if not is_optional:
                    tool_obj["function"]["parameters"]["required"].append(param_name)

            all_tool_objs.append(tool_obj)

        return all_tool_objs

    def dispatch_intent(
        self,
        intent: FunctionCallIntent,
        message_thread: MessageThread,
        print_callback: Optional[Callable[[Dict], None]] = None,
    ) -> Tuple[str, str, bool]:
        """Dispatch a function call intent to actually perform its action.

        Args:
            intent (FunctionCallIntent): The intent to dispatch.
            message_thread (MessageThread): The current message thread, since some tools require it.
            print_callback:
        Returns:
            tool_output (str): The result of the action
            summary (str): A summary that should be communicated to the model.
            new_threads (bool): True if the call gets the desired result, False otherwise.
        """
        # FIXME: Consider if we need 'get_class_full_snippet' function, which is not a api function.
        if (intent.func_name not in self.api_functions) and \
                (intent.func_name != "get_class_full_snippet"):
            error = f"Unknown function name {intent.func_name}."
            summary = "You called a tool that does not exist. Please only use the tools provided."
            return error, summary, False

        try:
            # Ready to call a function
            func_obj = getattr(self, intent.func_name)
            self.curr_tool = intent.func_name
            # FIXME: Delete function 'write_patch'
            if intent.func_name in ["write_patch"]:
                # these two functions require the message thread
                call_res = func_obj(message_thread, print_callback=print_callback)
            else:
                call_res = func_obj(**intent.arg_values)
        except Exception as e:
            # TypeError can happen when the function is called with wrong parameters
            # we just return the error message as the call result
            log_exception(e)
            error = str(e)
            summary = "The tool returned error message."
            call_res = (error, summary, False)

        logger.debug("Result of dispatch_intent: {}", call_res)

        # Record this call and its result separately
        _, _, call_is_ok = call_res
        self.tool_call_sequence.append(intent.to_dict_with_result(call_is_ok))

        if not self.tool_call_layers:
            self.tool_call_layers.append([])
        self.tool_call_layers[-1].append(intent.to_dict_with_result(call_is_ok))

        return call_res

    def dump_tool_call_sequence_to_file(self):
        """Dump the sequence of tool calls to a file."""
        tool_call_file = os.path.join(self.output_dpath, "tool_call_sequence.json")
        with open(tool_call_file, "w") as f:
            json.dump(self.tool_call_sequence, f, indent=4)

    def dump_tool_call_layers_to_file(self):
        """Dump the layers of tool calls to a file."""
        tool_call_file = os.path.join(self.output_dpath, "tool_call_layers.json")
        with open(tool_call_file, "w") as f:
            json.dump(self.tool_call_layers, f, indent=4)

    """Search APIs"""

    def search_class(self, class_name: str) -> Tuple[str, str, bool]:
        """Search for a class in the codebase.

        Only the signature of the class is returned. The class signature
        includes class name, base classes, and signatures for all of its methods/properties.

        Args:
            class_name (str): Name of the class to search for.

        Returns:
            str: The class signature if success, an error message otherwise.
            str: A message summarizing the method.
            bool:
        """
        return self.search_manager.search_class(class_name)

    def search_method(self, method_name: str) -> Tuple[str, str, bool]:
        """
        Search for a method in the entire codebase.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.

        Returns:
            str: The searched code if success, an error message otherwise.
            str: Summary of the tool call.
            bool:
        """
        return self.search_manager.search_method(method_name)

    def search_code(self, code_str: str) -> Tuple[str, str, bool]:
        """
        Search for a code snippet in the entire codebase.

        Returns the method that contains the code snippet, if it is found inside a file.
        Otherwise, returns the region of code surrounding it.

        Args:
            code_str (str): The code snippet to search for.

        Returns:
            str: The region of code containing the searched code string.
            str:
            bool:
        """
        return self.search_manager.search_code(code_str)

    """Ask agent proxy"""

    def proxy_apis(self, text: str) -> Tuple[Optional[str], str, List[MessageThread]]:
        """Proxy APIs to another agent."""
        tool_output, new_threads = agent_proxy.run_with_retries(text)  # FIXME: type of `text`

        if tool_output is None:
            summary = "The tool returned nothing. The main agent probably did not provide enough clues."
        else:
            summary = "The tool returned the selected search APIs in json format generated by another agent."
        return tool_output, summary, new_threads
