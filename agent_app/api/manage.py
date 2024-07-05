# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/api/manage.py

import os


from typing import *


from agent_app.task import Task
from agent_app.search.search_manage import SearchManager


class ProjectApiManager:
    ################# State machine specific ################
    # NOTE: this section is for state machine; APIs in stratified mode are specified
    # in agent_api_selector.py

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
        self.output_dir = os.path.abspath(output_dpath)

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



