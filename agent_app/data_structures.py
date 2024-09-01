# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/data_structures.py

import json

from typing import *
from pprint import pformat
from enum import Enum
from dataclasses import dataclass

from openai.types.chat import ChatCompletionMessageToolCall
from openai.types.chat.chat_completion_message_tool_call import Function as OpenaiFunction

"""MANAGER"""


class State(str, Enum):
    START_STATE = "start"
    REFLEXION_STATE = "reflexion"
    HYPOTHESIS_CHECK_STATE = "hypothesis_check"
    CONTEXT_RETRIEVAL_STATE = "context_retrieval"
    HYPOTHESIS_VERIFY_STATE = "hypothesis_verify"
    END_STATE = "end"
    POST_PROCESS_STATE = "post_process"

    @staticmethod
    def attributes():
        return [k.value for k in State]


"""COMMIT"""


class CommitType(str, Enum):
    VulnerabilityPatch = "vulnerability_patch"
    NonVulnerabilityPatch = "non_vulnerability_patch"

    @staticmethod
    def attributes():
        return [e.value for e in CommitType]


"""CODE"""


@dataclass
class CodeSnippetLocation:
    """Dataclass to hold the location of code snippet."""
    file_path: str  # This is RELATIVE path
    class_name: str | None
    func_name: str | None
    code: str

    def to_tagged_upto_file(self) -> str:
        """Convert the code snippet location to a tagged string, upto file path."""
        file_part = f"<file>{self.file_path}</file>"
        return file_part

    def to_tagged_upto_class(self) -> str:
        """Convert the code snippet location to a tagged string, upto class."""
        prefix = self.to_tagged_upto_file()
        class_part = f"<class>{self.class_name}</class> " if self.class_name is not None else ""
        return f"{prefix}\n{class_part}"

    def to_tagged_upto_func(self) -> str:
        """Convert the code snippet location to a tagged string, upto function."""
        prefix = self.to_tagged_upto_class()
        func_part = f"<func>{self.func_name}</func>" if self.func_name is not None else ""
        return f"{prefix}{func_part}"

    def to_tagged_str(self) -> str:
        """Convert the code snippet location to a tagged string."""
        prefix = self.to_tagged_upto_func()
        code_part = f"<code>\n{self.code}\n</code>"
        return f"{prefix}\n{code_part}"

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "class_name": self.class_name,
            "func_name": self.func_name,
            "code": self.code
        }


"""SEARCH MANAGE"""


class SearchStatus(str, Enum):
    UNKNOWN_SEARCH_API = "UNKNOWN_SEARCH_API"
    DISPATCH_ERROR = "DISPATCH_ERROR"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NON_UNIQUE_FILE = "NON_UNIQUE_FILE"
    FIND_NONE = "FIND_NONE"
    FIND_IMPORT = "FIND_IMPORT"
    FIND_CODE = "FIND_CODE"


class FunctionCallIntent:
    """An intent to call a tool function.

    This object created from OpenAI API response.
    """

    def __init__(
            self,
            call_stmt: str,
            func_name: str,
            arguments: Mapping[str, str],
            openai_func: Optional[OpenaiFunction]
    ):
        self.call_stmt = call_stmt
        self.func_name = func_name
        self.arg_values: Dict = {}
        self.arg_values.update(arguments)
        # Record the original openai function object,
        # which is used when we want to tell the model that it has previously called this function/tool
        self.openai_func = openai_func or OpenaiFunction(arguments=json.dumps(arguments), name=func_name)

    def __str__(self):
        return f"Call function `{self.func_name}` with arguments {self.arg_values}."

    def to_dict(self):
        return {"func_name": self.func_name, "arguments": self.arg_values}

    def to_dict_with_result(self, search_status: SearchStatus):
        return {
            "func_name": self.func_name,
            "arguments": self.arg_values,
            "search_status": search_status,
        }


"""CONVERSATION"""


class MessageThread:
    """
    Represents a thread of conversation with the model.
    Abstracted into a class so that we can dump this to a file at any point.
    """

    def __init__(self, messages=None):
        self.messages: List[Dict] = messages or []

    def reset(self):
        self.messages: List[Dict] = []

    def add(self, role: str, message: str):
        """
        Add a new message to the thread.
        Args:
            message (str): The content of the new message.
            role (str): The role of the new message.
        """
        self.messages.append({"role": role, "content": message})

    def add_system(self, message: str):
        self.messages.append({"role": "system", "content": message})

    def add_user(self, message: str):
        self.messages.append({"role": "user", "content": message})

    def add_tool(self, message: str, tool_call_id: str):
        m = {"role": "tool", "content": message, "tool_call_id": tool_call_id}
        self.messages.append(m)

    def add_model(
            self, message: Optional[str], tools: List[ChatCompletionMessageToolCall]
    ):
        # let's serialize tools into json first
        json_tools = []
        for tool in tools:
            this_tool_dict = {
                "id": tool.id,
                "type": tool.type
            }
            # Now serialize function as well
            func_obj: OpenaiFunction = tool.function
            func_args: str = func_obj.arguments
            func_name: str = func_obj.name
            this_tool_dict["function"] = {"name": func_name, "arguments": func_args}
            json_tools.append(this_tool_dict)

        if not json_tools:
            # There is no tool calls from the model last time,
            # the best we could do is to return the generated text
            self.messages.append({"role": "assistant", "content": message})
        else:
            self.messages.append(
                {"role": "assistant", "content": None, "tool_calls": json_tools}
            )

    def to_msg(self) -> List[Dict]:
        """
        Convert to the format to be consumed by the model.
        Returns:
            List[Dict]: The message thread.
        """
        return self.messages

    def __str__(self):
        return pformat(self.messages, width=160, sort_dicts=False)

    def save_to_file(self, file_path: str):
        """
        Save the current state of the message thread to a file.
        Args:
            file_path (str): The path to the file.
        """
        with open(file_path, "w") as f:
            json.dump(self.messages, f, indent=4)

    def get_round_number(self) -> int:
        """
        From the current message history, decide how many rounds have been completed.
        """
        completed_rounds = 0
        for message in self.messages:
            if message["role"] == "assistant":
                completed_rounds += 1
        return completed_rounds

    @classmethod
    def load_from_file(cls, file_path: str):
        """
        Load the message thread from a file.
        Args:
            file_path (str): The path to the file.
        Returns:
            MessageThread: The message thread.
        """
        with open(file_path) as f:
            messages = json.load(f)
        return cls(messages)
