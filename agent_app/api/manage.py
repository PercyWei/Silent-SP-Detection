# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/manage.py

import os
import json

from typing import *
from copy import deepcopy
from docstring_parser import parse
from enum import Enum

from loguru import logger

from agent_app.api import agent_proxy
from agent_app.commit.commit_manage import CommitManager
from agent_app.CWE.cwe_manage import CWEManager
from agent_app.search.search_manage import SearchManager
from agent_app.data_structures import State, FunctionCallIntent, MessageThread
from agent_app.task import Task
from agent_app.log import log_exception


class ProjectStateManager:
    ################# State machine specific #################
    # NOTE: this section is for state machine

    states: List[State] = [
        State.START_STATE,
        State.HYPOTHESIS_CHECK_STATE,
        State.CONTEXT_RETRIEVAL_STATE,
        State.HYPOTHESIS_VERIFY_STATE,
        State.END_STATE
    ]

    next_states: Dict[State, List[State]] = {
        State.START_STATE: [State.HYPOTHESIS_CHECK_STATE],
        State.HYPOTHESIS_CHECK_STATE: [State.CONTEXT_RETRIEVAL_STATE, State.END_STATE],
        State.CONTEXT_RETRIEVAL_STATE: [State.HYPOTHESIS_VERIFY_STATE],
        State.HYPOTHESIS_VERIFY_STATE: [State.HYPOTHESIS_CHECK_STATE]
    }

    search_api_functions = [
        "search_class",
        "search_class_in_file",
        "search_method_in_file",
        "search_method_in_class",
        "search_method_in_class_in_file"
    ]

    def __init__(self, task: Task, output_dpath: str):
        # For logging of this task instance
        self.task = task

        # Where to write our output
        self.output_dpath = os.path.abspath(output_dpath)

        # Prepare the repo environment
        self.task.setup_project()

        # Keep track of the current state and the action currently being performed
        self.curr_state: State = State.START_STATE

        ## For state start
        self.commit_manager = CommitManager(self.task.project_path,
                                            self.task.commit_hash,
                                            self.task.commit_content)

        ## For providing CWE information
        # FIXME: Need update
        cwe_items_fpath = "/root/projects/VDTest/agent_app/CWE/CWE_1003_items.json"
        cwe_tree_fpath = "/root/projects/VDTest/agent_app/CWE/CWE_1003_tree.json"
        self.cwe_manager = CWEManager(cwe_items_fpath, cwe_tree_fpath)

        ## For state context_retrieval
        # Build search manager
        self.search_manager = SearchManager(self.task.project_path, self.commit_manager.mod_files)

        # Keep track which tools is currently being used
        self.curr_tool: Optional[str] = None

        # Record the sequence of tools used, and their return status
        self.tool_call_sequence: List[Mapping] = []

        # Record layered API calls (different rounds)
        self.tool_call_layers: List[List[Mapping]] = []

        # Record cost and token information
        self.cost: float = 0.0
        self.input_tokens: int = 0
        self.output_tokens: int = 0

    def next_tools(self) -> List[str]:
        """
        Return the list of tools that should be used in the next round.
        """
        return self.search_api_functions

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
        if intent.func_name not in self.search_api_functions and intent.func_name != "get_class_full_snippet":
            error = f"Unknown function name {intent.func_name}."
            summary = "You called a tool that does not exist. Please only use the tools provided."
            return error, summary, False

        try:
            if intent.func_name == "search_class_in_file":
                pass
            elif intent.func_name == "search_method_in_file":
                pass
            elif intent.func_name == "search_method_in_class_in_file":
                pass

            # Call a function
            func_obj = getattr(self, intent.func_name)
            self.curr_tool = intent.func_name
            call_res = func_obj(**intent.arg_values)
        except Exception as e:
            # TypeError can happen when the function is called with wrong parameters
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

    def dump_tool_call_sequence_to_file(self, tool_call_output_dpath: str):
        """Dump the sequence of tool calls to a file."""
        tool_call_file = os.path.join(tool_call_output_dpath, "tool_call_sequence.json")
        with open(tool_call_file, "w") as f:
            json.dump(self.tool_call_sequence, f, indent=4)

    def dump_tool_call_layers_to_file(self, tool_call_output_dpath: str):
        """Dump the layers of tool calls to a file."""
        tool_call_file = os.path.join(tool_call_output_dpath, "tool_call_layers.json")
        with open(tool_call_file, "w") as f:
            json.dump(self.tool_call_layers, f, indent=4)

    """State switch"""

    def into_state(self, next_state: State):
        """
        Change curr_state and curr_action
        """
        assert self.curr_state != State.END_STATE and next_state in self.next_states[self.curr_state]
        self.curr_state = next_state

    def switch_state(self, next_state: State):
        self.into_state(next_state)

    def reset_state(self):
        self.curr_state = State.START_STATE

    """Search APIs"""

    # Not a search API - just to get full class definition when only the class is specified
    def get_class_full_snippet(self, class_name: str):
        return self.search_manager.get_class_full_snippet(class_name)

    def search_class(self, class_name: str) -> Tuple[str, str, bool]:
        """Search for a class in the codebase.

        Only the signature of the class is returned. The class signature
        includes class name, base classes, and signatures for all of its methods/properties.

        Args:
            class_name (str): Name of the class to search for.

        Returns:
            str: The searched class signature if success, an error message otherwise.
            str: Summary of the tool call.
            bool: Any class was found.
        """
        return self.search_manager.search_class(class_name)

    def search_class_in_file(self, class_name: str, file_name: str) -> Tuple[str, str, bool]:
        """Search for a class in a given file.

        Returns the actual code of the entire class definition.

        Args:
            class_name (str): Name of the class to search for.
            file_name (str): The file to search in. Must be a valid python file name.

        Returns:
            str: The searched class signature if success, an error message otherwise.
            str: Summary of the tool call.
            bool: Any class was found.
        """
        return self.search_manager.search_class_in_file(class_name, file_name)

    def search_method_in_file(self, method_name: str, file_name: str) -> Tuple[str, str, bool]:
        """Search for a method in a given file.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.
            file_name (str): The file to search in. Must be a valid python file name.

        Returns:
            str: The searched method code if success, an error message otherwise.
            str: Summary of the tool call.
            bool: Any method was found.
        """
        return self.search_manager.search_method_in_file(method_name, file_name)

    def search_method_in_class(self, method_name: str, class_name: str) -> Tuple[str, str, bool]:
        """Search for a method in a given class.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.
            class_name (str): Consider only methods in this class.

        Returns:
            str: The searched method code if success, an error message otherwise.
            str: Summary of the tool call.
            bool: Any method was found.
        """
        return self.search_manager.search_method_in_class(method_name, class_name)

    def search_method_in_class_in_file(self, method_name: str, class_name: str, file_name: str) -> Tuple[str, str, bool]:
        """Search for a method in a given class which is in a given file.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.
            class_name (str): Consider only methods in this class.
            file_name (str): The file to search in. Must be a valid python file name.

        Returns:
            str: The searched method code if success, an error message otherwise.
            str: Summary of the tool call.
            bool: Any method was found.
        """
        return self.search_manager.search_method_in_class_in_file(method_name, class_name, file_name)

    """Ask agent proxy"""

    def call_proxy_apis(self, text: str) -> Tuple[str | None, str, List[MessageThread]]:
        """Proxy APIs to another agent."""
        tool_output, new_threads = agent_proxy.run_with_retries(text, self.curr_state)  # FIXME: type of `text`

        if tool_output is None:
            summary = "The tool returned nothing. The main agent probably did not provide enough clues."
        else:
            summary = "The tool returned the respond in standard json format generated by another agent."
        return tool_output, summary, new_threads
