# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/manage.py

import os
import json

from typing import *
from copy import deepcopy
from docstring_parser import parse

from loguru import logger

from agent_app.api.agent_proxy import ProxyTask, run_with_retries as run_proxy_with_retries
from agent_app.CWE.cwe_manage import CWEManager
from agent_app.commit.commit_manage_v2 import CommitManager
from agent_app.search.search_manage_v2 import SearchResult, SearchManager
from agent_app.data_structures import ProcessActionStatus, SearchStatus, FunctionCallIntent, MessageThread
from agent_app.task import Task
from agent_app.log import log_exception
from agent_app import globals


class ProcessManager:

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

        # Record special cases under processing
        self.proc_action_status: ProcessActionStatus = ProcessActionStatus()

        # Manage commit info
        self.commit_manager = CommitManager(self.task.project_path, self.task.commit_hash, self.task.commit_content)

        # Manage CWE info
        self.cwe_manager = CWEManager(globals.cwe_entry_file, globals.cwe_tree_file)

        # Manage context retrieval
        self.search_manager = self.init_search_manager()

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


    def init_search_manager(self) -> SearchManager:
        commit_files = {
            "del_files": self.commit_manager.del_files,
            "add_files": self.commit_manager.add_files,
            "mod_files": self.commit_manager.mod_files
        }

        return SearchManager(self.task.project_path, commit_files, self.commit_manager.file_comb_info)


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

    def dispatch_intent(self, intent: FunctionCallIntent) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Dispatch a function call intent to actually perform its action.

        Args:
            intent (FunctionCallIntent): The intent to dispatch.
        Returns:
            str: Detailed output of the current search API call.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        if intent.func_name not in self.search_api_functions and intent.func_name != "get_class_full_snippet":
            error = f"Unknown function name {intent.func_name}. You called a tool that does not exist."
            return error, SearchStatus.UNKNOWN_SEARCH_API, []

        try:
            # Call a function
            func_obj = getattr(self, intent.func_name)
            self.curr_tool = intent.func_name
            call_res = func_obj(**intent.arg_values)
        except Exception as e:
            # TypeError can happen when the function is called with wrong parameters
            log_exception(e)
            error = str(e)
            call_res = (error, SearchStatus.DISPATCH_ERROR, [])

        logger.debug(f"Result of {intent.call_stmt}: {call_res}")

        # Record this call and its result separately
        _, search_status, _ = call_res
        self.tool_call_sequence.append(intent.to_dict_with_result(search_status))

        if not self.tool_call_layers:
            self.tool_call_layers.append([])
        self.tool_call_layers[-1].append(intent.to_dict_with_result(search_status))

        return call_res

    """PROCESS ACTION STATUS"""

    def reset_proc_action_status(self):
        self.proc_action_status = ProcessActionStatus()

    """TOOL CALLs"""

    def start_new_tool_call_layer(self):
        self.tool_call_layers.append([])

    def reset_too_call_recordings(self):
        self.tool_call_sequence = []
        self.tool_call_layers = []

    def dump_tool_call_sequence_to_file(self, tool_call_output_dpath: str, prefix_fname: str = ""):
        """Dump the sequence of tool calls to a file."""
        fname = f"{prefix_fname}_tool_call_sequence.json" if prefix_fname != "" else "tool_call_sequence.json"
        tool_call_file = os.path.join(tool_call_output_dpath, fname)
        with open(tool_call_file, "w") as f:
            json.dump(self.tool_call_sequence, f, indent=4)

    def dump_tool_call_layers_to_file(self, tool_call_output_dpath: str, prefix_fname: str = ""):
        """Dump the layers of tool calls to a file."""
        fname = f"{prefix_fname}_tool_call_layers.json" if prefix_fname != "" else "tool_call_layers.json"
        tool_call_file = os.path.join(tool_call_output_dpath, fname)
        with open(tool_call_file, "w") as f:
            json.dump(self.tool_call_layers, f, indent=4)

    """SEARCH APIs"""

    # Not a search API - just to get full class definition when only the class is specified
    def get_class_full_snippet(self, class_name: str):
        return self.search_manager.get_class_full_snippet(class_name)

    def search_class(self, class_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search for a class in the codebase.

        Only the signature of the class is returned. The class signature
        includes class name, base classes, and signatures for all of its methods/properties.

        Args:
            class_name (str): Name of the class to search for.

        Returns:
            str: The searched class signature if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        return self.search_manager.search_class(class_name)

    def search_class_in_file(self, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search for a class in a given file.

        Returns the actual code of the entire class definition.

        Args:
            class_name (str): Name of the class to search for.
            file_name (str): The file to search in. Must be a valid python file name.

        Returns:
            str: The searched class signature if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        return self.search_manager.search_class_in_file(class_name, file_name)

    def search_method_in_file(self, method_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search for a method in a given file.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.
            file_name (str): The file to search in. Must be a valid python file name.

        Returns:
            str: The searched method code if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        return self.search_manager.search_method_in_file(method_name, file_name)

    def search_method_in_class(self, method_name: str, class_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search for a method in a given class.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.
            class_name (str): Consider only methods in this class.

        Returns:
            str: The searched method code if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        return self.search_manager.search_method_in_class(method_name, class_name)

    def search_method_in_class_in_file(self, method_name: str, class_name: str, file_name: str) -> Tuple[str, SearchStatus, List[SearchResult]]:
        """Search for a method in a given class which is in a given file.

        Returns the actual code of the method.

        Args:
            method_name (str): Name of the method to search for.
            class_name (str): Consider only methods in this class.
            file_name (str): The file to search in. Must be a valid python file name.

        Returns:
            str: The searched method code if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[SearchResult]: All search results.
        """
        return self.search_manager.search_method_in_class_in_file(method_name, class_name, file_name)

    """PROXY AGENT"""

    def call_proxy_apis(self, text: str, task: ProxyTask) -> Tuple[str | None, str | None, List[MessageThread]]:
        """Call the Proxy Agent to do some tasks.

        Args:
            text (str): Text to be extracted.
            task (ProxyTask): Task of Proxy Agent.
        Returns:
            str | None: Valid response in JSON format if the extraction succeed, otherwise None.
            str | None: Failure summary if the extraction failed, otherwise None.
            List[MessageThread]: List of all MessageThread instances.
        """
        return run_proxy_with_retries(text, task)
