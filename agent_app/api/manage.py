# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/manage.py

import os
import json
import inspect

from typing import *
from copy import deepcopy
from docstring_parser import parse
from abc import abstractmethod

from agent_app import globals, log
from agent_app.api.agent_proxy import ProxyTask, run_with_retries as run_proxy_with_retries
from agent_app.CWE.cwe_manage import CWEManager
from agent_app.commit.commit_manage import PyCommitManager, JavaCommitManager
from agent_app.search.search_manage import (
    PySearchManager, JavaSearchManager,
    PySearchResult, JavaSearchResult
)
from agent_app.flow_control.flow_recording import (
    ProcOutPaths,
    ProcHypothesis,
    ProcActionStatus, ProcSearchStatus,
    ProcPyCodeContext, ProcJavaCodeContext
)
from agent_app.data_structures import SearchStatus, ToolCallIntent, MessageThread
from agent_app.task import Task
from agent_app.util import LanguageNotSupportedError
from utils import make_hie_dirs

"""BASE MANAGER"""


class FlowManager:

    def __init__(self, task: Task, output_dpath: str):
        # All valid search APIs
        self.search_api_functions: List[str] = []

        # Current task instance
        self.task = task

        # Where to write our output
        self.output_dpath = os.path.abspath(output_dpath)

        # Prepare the repo environment
        self.task.setup_project()

        ## Tool call records (search API)
        # NOTE: 1 process = m * loop
        # 1. Record the tool currently being used
        self.curr_tool_call: str | None = None
        # 2. Record the sequence of tool calls used in current loop
        self.loop_tool_call_sequence: List[Dict] = []
        # 3. Record the layers of tool calls used in current loop
        self.loop_tool_call_layers: List[List[Dict]] = []
        # 4. Record the executable tool calls used in current process
        self.process_executable_tool_calls: Dict[str, List[Dict]] = {}

        ## Record cost and token information
        self.cost: float = 0.0
        self.input_tokens: int = 0
        self.output_tokens: int = 0

        ## Status records of the entire flow
        # process name -> {status name -> status data}
        self.flow_all_status: Dict[str, Dict[str, Dict]] = {}
        ## Status records of current process
        self.cur_proc_action_status: ProcActionStatus = ProcActionStatus()
        self.cur_proc_search_status: ProcSearchStatus = ProcSearchStatus()

        ## Sub-manager (need initialization)
        self.commit_manager = None
        self.search_manager = None
        self.cwe_manager = None

        ## Output paths of current process (need set)
        self.cur_proc_outs: ProcOutPaths | None = None

        ## All hypothesis (verified & unverified) of the entire flow
        self.flow_all_hyps: Dict[str, ProcHypothesis] = {}
        ## All hypothesis (verified & unverified) of current process
        self.cur_proc_all_hyps: ProcHypothesis = ProcHypothesis()

        ## Collected code context of current process (need set according to language)
        self.cur_proc_code_context: ProcPyCodeContext | ProcJavaCodeContext | None = None

    """INITIALIZATION"""

    @abstractmethod
    def init_search_api_functions(self, *args, **kwargs):
        method_name = inspect.currentframe().f_code.co_name
        raise NotImplementedError(f"Method '{method_name}' not implemented yet")

    @abstractmethod
    def init_commit_manager(self , *args, **kwargs):
        method_name = inspect.currentframe().f_code.co_name
        raise NotImplementedError(f"Method '{method_name}' not implemented yet")

    @abstractmethod
    def init_search_manager(self, *args, **kwargs):
        method_name = inspect.currentframe().f_code.co_name
        raise NotImplementedError(f"Method '{method_name}' not implemented yet")

    @abstractmethod
    def init_cwe_manager(self, *args, **kwargs):
        method_name = inspect.currentframe().f_code.co_name
        raise NotImplementedError(f"Method '{method_name}' not implemented yet")

    """UTILS"""

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

    def is_duplicate_tool_call(self, intent: ToolCallIntent) -> Dict | None:
        if intent.tool_name in self.process_executable_tool_calls:
            for tool_call in self.process_executable_tool_calls[intent.tool_name]:
                if intent.call_arg2values == tool_call["call_arg2values"]:
                    return tool_call
        return None

    @abstractmethod
    def response_to_duplicate_tool_call(self, intent: ToolCallIntent, old_tool_call: Dict) -> str:
        method_name = inspect.currentframe().f_code.co_name
        raise NotImplementedError(f"Method '{method_name}' not implemented yet")

    def dispatch_intent(
            self,
            intent: ToolCallIntent
    ) -> Tuple[str, SearchStatus, List[PySearchResult | JavaSearchResult]]:
        """Dispatch a tool call intent to actually perform its action.

        Args:
            intent (ToolCallIntent): The intent to dispatch.
        Returns:
            str: Detailed output of the current tool call.
            SearchStatus: Status of the search.
            List[PySearchResult | JavaSearchResult]: All search results.
        """
        ## Condition 1: Unknown search API
        if intent.tool_name not in self.search_api_functions:
            error_msg = f"You called a search API that does not exist: search API name '{intent.tool_name}' is unknown."
            call_res = (error_msg, SearchStatus.UNKNOWN_SEARCH_API, [])

        ## Condition 2: Wrong parameters
        elif len(intent.tool_args) != len(intent.call_arg2values):
            tool_args_str = ', '.join([f'{arg_name}' for arg_name in intent.tool_args])
            error_msg = ("You called a search API with wrong parameters: "
                         f"search API '{intent.tool_name}' has {len(intent.tool_args)} parameters ({tool_args_str}), "
                         f"while you provided {len(intent.call_arg2values)} values.")
            call_res = (error_msg, SearchStatus.WRONG_ARGUMENT, [])

        ## Condition 3: Duplicate call
        elif (old_tool_call := self.is_duplicate_tool_call(intent)) is not None:
            error_msg = self.response_to_duplicate_tool_call(intent, old_tool_call)
            call_res = (error_msg, SearchStatus.DUPLICATE_CALL, [])

        else:
            try:
                func_obj = getattr(self, intent.tool_name)
                self.curr_tool_call = intent.tool_name
                call_res = func_obj(**intent.call_arg2values)
            except Exception as e:
                ## BAD CONDITION!
                log.log_exception(e)
                error_msg = "An error occurred while executing the search api."
                call_res = (error_msg, SearchStatus.DISPATCH_ERROR, [])

        log.log_debug(f"Result of {intent.call_stmt}: {call_res}")

        # Update with search status
        _, search_status, _ = call_res

        # 1. Tool call intent
        intent.update_with_search_status(search_status)
        # 2. Search status records
        self.cur_proc_search_status.update_with_search_status(search_status)

        return call_res

    """PROCESS OUTPUT PATHS"""

    def reset_process_output_paths(
            self,
            cur_proc_root: str,
            cur_proc_hyp_dpath: str,
            cur_proc_proxy_dpath: str,
            cur_proc_tool_call_dpath: str
    ):
        self.cur_proc_outs = ProcOutPaths(
            root=cur_proc_root,
            hyp_dpath=cur_proc_hyp_dpath,
            proxy_dpath=cur_proc_proxy_dpath,
            tool_call_dpath=cur_proc_tool_call_dpath
        )

    """PROCESS HYPOTHESIS"""

    def reset_process_all_hypothesis(self):
        self.cur_proc_all_hyps = ProcHypothesis()

    """PROCESS CODE CONTEXT"""

    def reset_process_code_context(self, lang: str):
        if lang == "Python":
            self.cur_proc_code_context = ProcPyCodeContext
        elif lang == "Java":
            self.cur_proc_code_context = ProcJavaCodeContext
        else:
            raise LanguageNotSupportedError(lang)

    """PROCESS STATUS RECORDS"""

    def reset_process_status_records(self):
        self.cur_proc_action_status = ProcActionStatus()
        self.cur_proc_search_status = ProcSearchStatus()

    def save_current_process_all_status(self, cur_proc_name: str):
        self.flow_all_status[cur_proc_name] = {
            "action_status_records": self.cur_proc_action_status.to_dict(),
            "search_status_records": self.cur_proc_search_status.to_dict()
        }

    """PROCESS PREPARATION"""

    def prepare_for_new_process(self, output_dpath: str, cur_proc_name: str):
        ## 1. Output paths of current process
        # Root
        cur_proc_dpath = make_hie_dirs(output_dpath, cur_proc_name)
        # Dirs
        cur_proc_hyp_dpath = make_hie_dirs(cur_proc_dpath, f"hypothesis")
        cur_proc_proxy_dpath = make_hie_dirs(cur_proc_dpath, f"proxy_agent")
        cur_proc_tool_call_dpath = make_hie_dirs(cur_proc_dpath, "tool_calls")

        self.reset_process_output_paths(
            cur_proc_root=cur_proc_dpath,
            cur_proc_hyp_dpath=cur_proc_hyp_dpath,
            cur_proc_proxy_dpath=cur_proc_proxy_dpath,
            cur_proc_tool_call_dpath=cur_proc_tool_call_dpath
        )

        ## 2. All hypothesis of current process
        self.reset_process_all_hypothesis()

        ## 3. Collected code context of current process
        self.reset_process_code_context(globals.lang)

        ## 4. Status of current process
        self.reset_process_status_records()

    """TOOL CALL RECORDS"""

    def start_new_tool_call_layer(self):
        self.loop_tool_call_layers.append([])

    def reset_loop_tool_call_records(self):
        self.loop_tool_call_sequence = []
        self.loop_tool_call_layers = []

    def reset_process_exec_tool_calls(self):
        self.process_executable_tool_calls = {}

    def update_loop_tool_call_records(self, intent: ToolCallIntent):
        self.loop_tool_call_sequence.append(intent.to_dict_with_result())
        if not self.loop_tool_call_layers:
            self.loop_tool_call_layers.append([])
        self.loop_tool_call_layers[-1].append(intent.to_dict_with_result())

    def update_process_exec_tool_calls(self, intent: ToolCallIntent):
        if intent.tool_name not in self.process_executable_tool_calls:
            self.process_executable_tool_calls[intent.tool_name] = []
        self.process_executable_tool_calls[intent.tool_name].append(intent.to_dict_with_result())

    def dump_loop_tool_call_sequence_to_file(self, output_dpath: str, loop_no: str):
        """Dump the sequence of tool calls used in current loop to a file."""
        save_file = os.path.join(output_dpath, f"loop_{loop_no}_tool_call_sequence.json")
        with open(save_file, "w") as f:
            json.dump(self.loop_tool_call_sequence, f, indent=4)

    def dump_loop_tool_call_layers_to_file(self, output_dpath: str, loop_no: str):
        """Dump the layers of tool calls used in current loop to a file."""
        save_file = os.path.join(output_dpath, f"loop_{loop_no}_tool_call_layers.json")
        with open(save_file, "w") as f:
            json.dump(self.loop_tool_call_layers, f, indent=4)

    """PROXY AGENT"""

    @staticmethod
    def call_proxy_llm(
            lang: Literal['Python', 'Java'],
            text: str,
            task: ProxyTask
    ) -> Tuple[str | None, str | None, List[MessageThread]]:
        """Call the Proxy Agent to do some tasks.

        Args:
            lang (str): Programming language. Only choose from 'Python' and 'Java'.
            text (str): Text to be extracted.
            task (ProxyTask): Task of Proxy Agent.
        Returns:
            str | None: Valid response in JSON format if the extraction succeed, otherwise None.
            str | None: Failure summary if the extraction failed, otherwise None.
            List[MessageThread]: List of all MessageThread instances.
        """
        return run_proxy_with_retries(lang, text, task)


"""PYTHON MANAGER"""


class PyFlowManager(FlowManager):

    def __init__(self, task: Task, output_dpath: str):
        super().__init__(task, output_dpath)

        # Initialize search API functions
        self.init_search_api_functions()

        # Initialize commit manager
        self.init_commit_manager()

        # Initialize search manager
        self.init_search_manager()

        # Initialize cwe manager
        self.init_cwe_manager()

    def init_search_api_functions(self):
        self.search_api_functions = [
            "search_top_level_function",
            "search_class",
            "search_method_in_file",
            "search_class_in_file",
            "search_method_in_class",
            "search_method_in_class_in_file"
        ]

    def init_commit_manager(self):
        self.commit_manager: PyCommitManager = PyCommitManager(
            local_repo_dpath=self.task.project_path,
            commit_hash=self.task.commit_hash,
            raw_commit_content=self.task.commit_content
        )

    def init_search_manager(self):
        assert isinstance(self.commit_manager, PyCommitManager)
        self.search_manager: PySearchManager = PySearchManager(
            local_repo_dpath=self.task.project_path,
            del_files=self.commit_manager.del_files,
            add_files=self.commit_manager.add_files,
            mod_files=self.commit_manager.mod_files,
            file_diff_info=self.commit_manager.file_diff_info
        )

    def init_cwe_manager(self):
        self.cwe_manager: CWEManager = CWEManager(
            full_view_id=globals.view_id,
            cwe_entry_fpath=globals.cwe_entry_file,
            cwe_tree_fpath=globals.cwe_tree_file,
            all_weakness_entries_fpath=globals.all_weakness_entries_file,
            weakness_attributes_fpath=globals.weakness_attributes_file,
            view_cwe_entries_fpaths=globals.view_cwe_entries_files,
            view_cwe_tree_fpaths=globals.view_cwe_tree_files
        )

    """TOOL CALL"""

    @staticmethod
    def tool_call_pre_check(tool_name: str, **kwargs) -> str:
        # (1) Check parameters
        # Check if the parameter value is an empty string
        empty_args = [arg_name for arg_name, value in kwargs.items() if not isinstance(value, str) or value == ""]

        # (2) Prepare the error msg
        error_msg = ""
        if empty_args:
            if len(empty_args) == 1:
                error_msg += f"All parameters of search API {tool_name} must be specified, however, '{empty_args[0]}' is an empty string."
            else:
                empty_args_str = ", ".join([f'{arg_name}' for arg_name in empty_args])
                error_msg += f"All parameters of search API {tool_name} must be specified, however, {empty_args_str} are empty strings."
        return error_msg

    def response_to_duplicate_tool_call(self, intent: ToolCallIntent, old_tool_call: Dict) -> str:

        # (1) tool name + arguments + values
        arg2values_str_list: List[str] = []
        for arg_name, value in intent.call_arg2values.items():
            arg2values_str_list.append(f"{arg_name}={value}")
        arg2values_str = ", ".join(arg2values_str_list)

        response = f"You have called tool {intent.tool_name} with arguments {arg2values_str}. Please review our previous conversation to look carefully."

        # (2) search status of old tool call
        # TODO: HOW TO CONSTRUCT RESPONSE?

        # (3) advice according to tool name
        # TODO: HOW TO CONSTRUCT RESPONSE?

        return response

    """SEARCH API FUNCTIONS"""

    def search_top_level_function(
            self,
            func_name: str
    ) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a top-level function in the codebase.

        Definition of top-level function: a function defined directly in the module, not as an internal definition
        of another function or method.
        Args:
            func_name (str): Name of the top level function to search for.
        Returns:
            str: The searched function snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[PySearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(tool_name="search_top_level_function", func_name=func_name)
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_top_level_function(func_name)

    def search_class(
            self,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a class in the codebase.

        Args:
            class_name (str): Name of the class to search for.
        Returns:
            str: The searched class signature if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[PySearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(tool_name="search_class", class_name=class_name)
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_class(class_name)

    def search_method_in_file(
            self,
            method_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a method in a given file, including top-level function and inclass method.

        Args:
            method_name (str): Name of the method to search for.
            file_name (str): Name of the file to search in. Must be a valid Python file name.
        Returns:
            str: The searched method snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[PySearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_method_in_file",
            method_name=method_name,
            file_name=file_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_method_in_file(method_name, file_name)

    def search_class_in_file(
            self,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a class in a given file.

        Args:
            class_name (str): Name of the class to search for.
            file_name (str): Name of the file to search in. Must be a valid Python file name.
        Returns:
            str: The searched class signature if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[PySearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_class_in_file",
            class_name=class_name,
            file_name=file_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_class_in_file(class_name, file_name)

    def search_method_in_class(
            self,
            method_name: str,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a method in a given class.

        Args:
            method_name (str): Name of the method to search for.
            class_name (str): Name of the class to search in.
        Returns:
            str: The searched method snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[PySearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_method_in_class",
            method_name=method_name,
            class_name=class_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_method_in_class(method_name, class_name)

    def search_method_in_class_in_file(
            self,
            method_name: str,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[PySearchResult]]:
        """Search for a method in a given class which is in a given file.

        Args:
            method_name (str): Name of the method to search for.
            class_name (str): Name of the class to search in.
            file_name (str): Name of the file to search in. Must be a valid Python file name.
        Returns:
            str: The searched method snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[PySearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_method_in_class_in_file",
            method_name=method_name,
            class_name=class_name,
            file_name=file_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_method_in_class_in_file(method_name, class_name, file_name)


"""JAVA MANAGER"""


class JavaFlowManager(FlowManager):

    def __init__(self, task: Task, output_dpath: str):
        super().__init__(task, output_dpath)

        # Initialize search API functions
        self.init_search_api_functions()

        # Initialize commit manager
        self.init_commit_manager()

        # Initialize search manager
        self.init_search_manager()

        # Initialize cwe manager
        self.init_cwe_manager()

    def init_search_api_functions(self):
        self.search_api_functions = [
            "search_interface",
            "search_class",
            "search_interface_in_file",
            "search_class_in_file",
            "search_type_in_class",
            "search_type_in_class_in_file"
        ]

    def init_commit_manager(self):
        self.commit_manager: JavaCommitManager = JavaCommitManager(
            local_repo_dpath=self.task.project_path,
            commit_hash=self.task.commit_hash,
            raw_commit_content=self.task.commit_content
        )

    def init_search_manager(self):
        assert isinstance(self.commit_manager, JavaCommitManager)
        self.search_manager: JavaSearchManager = JavaSearchManager(
            local_repo_dpath=self.task.project_path,
            del_files=self.commit_manager.del_files,
            add_files=self.commit_manager.add_files,
            mod_files=self.commit_manager.mod_files,
            file_diff_info=self.commit_manager.file_diff_info
        )

    def init_cwe_manager(self):
        self.cwe_manager: CWEManager = CWEManager(
            full_view_id=globals.view_id,
            cwe_entry_fpath=globals.cwe_entry_file,
            cwe_tree_fpath=globals.cwe_tree_file,
            all_weakness_entries_fpath=globals.all_weakness_entries_file,
            weakness_attributes_fpath=globals.weakness_attributes_file,
            view_cwe_entries_fpaths=globals.view_cwe_entries_files,
            view_cwe_tree_fpaths=globals.view_cwe_tree_files
        )

    """TOOL CALL"""

    @staticmethod
    def tool_call_pre_check(tool_name: str, **kwargs) -> str:
        # (1) Check parameters
        empty_args = []
        wrong_ttype_value = None

        for arg_name, value in kwargs.items():
            # 1. Check if the parameter value is an empty string
            if not isinstance(value, str) or value == "":
                empty_args.append(arg_name)

            # 2. Check parameter 'ttype' for tool 'search_type_in_class' and 'search_type_in_class_in_file'
            if (tool_name == 'search_type_in_class' or tool_name == 'search_type_in_class_in_file') and \
                    arg_name == 'ttype' and value not in ['interface', 'class', 'method']:
                # Permitted special cases
                if value.lower() in ['annotation', 'enum', 'record']:
                    continue
                wrong_ttype_value = value

        # (2) Prepare the error msg
        error_msg = ""
        if empty_args:
            if len(empty_args) == 1:
                error_msg += f"For search API '{tool_name}', all parameters must be specified, while the value of '{empty_args[0]}' is an empty string."
            else:
                empty_args_str = ", ".join([f'{arg_name}' for arg_name in empty_args])
                error_msg += f"For search API '{tool_name}', all parameters must be specified, while the values of {empty_args_str} are empty strings."
        if wrong_ttype_value:
            if error_msg:
                error_msg += "\nBesides, the value of 'ttype' can only be 'interface' or 'class' or 'method'."
            else:
                error_msg += f"For search API '{tool_name}', the value of 'ttype' can only be 'interface' or 'class' or 'method'."

        return error_msg

    def response_to_duplicate_tool_call(self, intent: ToolCallIntent, old_tool_call: Dict) -> str:

        # (1) tool name + arguments + values
        arg2values_str_list: List[str] = []
        for arg_name, value in intent.call_arg2values.items():
            arg2values_str_list.append(f"{arg_name}={value}")
        arg2values_str = ", ".join(arg2values_str_list)

        response = f"You have called tool {intent.tool_name} with arguments {arg2values_str}. Please review our previous conversation to look carefully."

        # (2) search status of old tool call
        # TODO: HOW TO CONSTRUCT RESPONSE?

        # (3) advice according to tool name
        # TODO: HOW TO CONSTRUCT RESPONSE?

        return response

    """SEARCH API FUNCTIONS"""

    def search_interface(
            self,
            iface_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for an interface in the codebase.

        Return the entire snippet of the interface.
        Args:
            iface_name (str): Name of the interface to search for.
        Returns:
            str: The searched interface snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[JavaSearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(tool_name="search_interface", iface_name=iface_name)
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_interface(iface_name)

    def search_class(
            self,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a class in the codebase.

        Return only the signature of the class. The class signature
        includes class name, attributes, and signatures for all of its fields and inner types.
        Args:
            class_name (str): Name of the class to search for.
        Returns:
            str: The searched class signature if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[JavaSearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(tool_name="search_class", class_name=class_name)
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_class(class_name)

    def search_interface_in_file(
            self,
            iface_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for an interface in a given file.

        Return the entire snippet of the interface.
        Args:
            iface_name (str): Name of the interface to search for.
            file_name (str): Name of the file to search in. Must be a valid Java file name.
        Returns:
            str: The searched interface snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[JavaSearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_interface_in_file",
            iface_name=iface_name,
            file_name=file_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_interface_in_file(iface_name, file_name)

    def search_class_in_file(
            self,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a class in a given file.

        Return only the signature of the class. The class signature
        includes class name, attributes, and signatures for all of its fields and inner types.
        Args:
            class_name (str): Name of the class to search for.
            file_name (str): Name of the file to search in. Must be a valid Java file name.
        Returns:
            str: The searched class signature if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[JavaSearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_class_in_file",
            class_name=class_name,
            file_name=file_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_class_in_file(class_name, file_name)

    def search_type_in_class(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a type in a given class. 'Type' indicates interface or class or method.

        Return the entire snippet of the inclass interface / class / method.
        Args:
            ttype (str): Type of the type to search for. Can only choose from 'interface', 'class', 'method'.
            type_name (str): Name of the type to search for.
            class_name (str): Name of the class to search in.
        Returns:
            str: The searched type snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[JavaSearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_type_in_class",
            ttype=ttype,
            type_name=type_name,
            class_name=class_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_type_in_class(ttype, type_name, class_name)

    def search_type_in_class_in_file(
            self,
            ttype: Literal['interface', 'class', 'method'],
            type_name: str,
            class_name: str,
            file_name: str
    ) -> Tuple[str, SearchStatus, List[JavaSearchResult]]:
        """Search for a type in a given class which is in a given file. 'Type' indicate interface or class or method.

        Return the entire snippet of the inclass interface / class / method.
        Args:
            ttype (str): Type of the type to search for. Can only choose from 'interface', 'class', 'method'.
            type_name (str): Name of the type to search for.
            class_name (str): Name of the class to search in.
            file_name (str): Name of the file to search in. Must be a valid Java file name.
        Returns:
            str: The searched type snippet if success, an error message otherwise.
            SearchStatus: Status of the search.
            List[JavaSearchResult]: All search results.
        """
        error_msg = self.tool_call_pre_check(
            tool_name="search_type_in_class_in_file",
            ttype=ttype,
            type_name=type_name,
            class_name=class_name,
            file_name=file_name
        )
        if error_msg:
            return error_msg, SearchStatus.INVALID_ARGUMENT, []

        return self.search_manager.search_type_in_class_in_file(ttype, type_name, class_name, file_name)
