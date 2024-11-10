# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/data_structures.py

import json

from typing import *
from pprint import pformat
from enum import Enum
from dataclasses import dataclass, field

from openai.types.chat import ChatCompletionMessageToolCall
from openai.types.chat.chat_completion_message_tool_call import Function as OpenaiFunction


LineRange = NamedTuple("LineRange", [("start", int), ("end", int)])


CodeRange = NamedTuple('CodeRange', [('file_path', str), ('range', LineRange)])


"""STATIC ANALYSIS"""


class SimNodeType(str, Enum):
    # Root
    MODULE = "module"


class PySimNodeType(str, Enum):
    """Types of SimNode for Python code."""
    # Root
    ROOT = "root"
    # Top level structs
    UNIT = "unit"
    FUNCTION = "function"
    CLASS = "class"
    MAIN = "main"
    # Class children
    CLASS_UNIT = "class_unit"
    CLASS_METHOD = "class_method"
    # Main children
    MAIN_UNIT = "main_unit"

    @staticmethod
    def top_level_node_types():
        return [PySimNodeType.UNIT, PySimNodeType.FUNCTION, PySimNodeType.CLASS, PySimNodeType.MAIN]

    @staticmethod
    def class_child_node_types():
        return [PySimNodeType.CLASS_UNIT, PySimNodeType.CLASS_METHOD]

    @staticmethod
    def main_child_node_types():
        return [PySimNodeType.MAIN_UNIT]

    @staticmethod
    def line_node_types():
        return [PySimNodeType.UNIT, PySimNodeType.FUNCTION,
                PySimNodeType.CLASS_UNIT, PySimNodeType.CLASS_METHOD,
                PySimNodeType.MAIN_UNIT]


class JavaSimNodeType(str, Enum):
    """Types of SimNode for Java code."""
    # Root
    ROOT = "root"
    # Top level structs
    UNIT = "unit"
    INTERFACE = "interface"
    CLASS = "class"
    # Class children
    CLASS_UNIT = "class_unit"
    CLASS_INTERFACE = "class_interface"
    CLASS_CLASS = "class_class"
    CLASS_METHOD = "class_method"

    @staticmethod
    def top_level_node_types():
        return [JavaSimNodeType.UNIT, JavaSimNodeType.INTERFACE, PySimNodeType.CLASS]

    @staticmethod
    def class_child_node_types():
        return [JavaSimNodeType.CLASS_UNIT, JavaSimNodeType.CLASS_INTERFACE,
                JavaSimNodeType.CLASS_CLASS, JavaSimNodeType.CLASS_METHOD]

    @staticmethod
    def line_node_types():
        return [JavaSimNodeType.UNIT, JavaSimNodeType.INTERFACE,
                JavaSimNodeType.CLASS_UNIT, JavaSimNodeType.CLASS_INTERFACE,
                JavaSimNodeType.CLASS_CLASS, JavaSimNodeType.CLASS_METHOD]


@dataclass
class SimNode:
    """Simple AST node."""
    id: int
    father: int | None
    type: SimNodeType
    ast: str
    name: str
    range: LineRange

    def get_full_range(self) -> List[int]:
        return list(range(self.range.start, self.range.end + 1))


@dataclass
class PySimNode(SimNode):
    """Simple AST node for Python code."""
    type: PySimNodeType


@dataclass
class JavaSimNode(SimNode):
    """Simple AST node for Java code."""
    type: JavaSimNodeType


"""CODE"""


@dataclass
class BaseCodeSnippetLocation:
    """Dataclass to hold the location of code snippet."""
    file_path: str  # This is RELATIVE path
    code: str

    def to_tagged_upto_file(self) -> str:
        """Convert the code snippet location to a tagged string, upto file path."""
        file_part = f"<file>{self.file_path}</file>"
        return file_part

    def to_tagged_str(self) -> str:
        """Convert the code snippet location to a tagged string."""
        prefix = self.to_tagged_upto_file()
        code_part = f"<code>\n{self.code}\n</code>"
        return f"{prefix}\n{code_part}"

    @staticmethod
    def collapse_to_file_level(lst) -> str:
        """Collapse search results to file level."""
        res = dict()  # file -> count
        for r in lst:
            if r.file_path not in res:
                res[r.file_path] = 1
            else:
                res[r.file_path] += 1
        res_str = ""
        for file_path, count in res.items():
            file_part = f"<file>{file_path}</file>"
            res_str += f"- {file_part} ({count} matches)\n"
        res_str.rstrip()
        return res_str

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "code": self.code
        }


"""COMMIT MANAGE"""


class CommitType(str, Enum):
    VulnerabilityPatch = "vulnerability_patch"
    NonVulnerabilityPatch = "non_vulnerability_patch"

    @staticmethod
    def attributes():
        return [e.value for e in CommitType]


@dataclass
class DiffFileInfo:
    """Dataclass to hold info of diff file in the commit.
    Here 'diff' indicates deleted, added and modified.
    """
    _lang: str = field(init=False, repr=False)
    # -------------------- Code -------------------- #
    old_code: str | None  # Need setup while initializing
    new_code: str | None  # Need setup while initializing
    merge_code: str | None = None
    # -------------------- Simple Node -------------------- #
    old_nodes: Dict[int, SimNode] | None = None  # Simple Node id -> Simple Node
    new_nodes: Dict[int, SimNode] | None = None  # Simple Node id -> Simple Node
    # -------------------- Mapping -------------------- #
    # (1) Mapping of line id to Simple Node id
    old_li2node: Dict[int, int] | None = None
    new_li2node: Dict[int, int] | None = None
    # (2) Line id mapping
    line_id_old2new: Dict[int, int] | None = None
    line_id_old2merge: Dict[int, int] | None = None
    line_id_new2merge: Dict[int, int] | None = None

    def __post_init__(self):
        self._lang = self._get_lang()

    @property
    def lang(self) -> str:
        return self._lang

    def _get_lang(self) -> str:
        raise NotImplementedError("Subclasses must implement this method.")


@dataclass
class PyDiffFileInfo(DiffFileInfo):
    """Dataclass to hold info of diff Python file in the commit."""
    # -------------------- Simple Node -------------------- #
    old_nodes: Dict[int, PySimNode] | None = None  # Simple Node id -> Simple Node
    new_nodes: Dict[int, PySimNode] | None = None  # Simple Node id -> Simple Node
    # ----------------------- Old Struct Index ----------------------- #
    # 1.1 Top-level class / function:   [name, line range]
    old_func_index: List[Tuple[str, LineRange]] | None = None
    old_class_index: List[Tuple[str, LineRange]] | None = None
    # 1.2 Inclass method:               [{class name -> [(name, line range)]}
    old_inclass_method_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    # 1.3 Import:                       [(pkg path, attr name, alias name)]
    old_imports: List[Tuple[str, str, str]] | None = None
    # ----------------------- New Struct Index ----------------------- #
    # 2.1 Top-level class / function:   [name, line range]
    new_func_index: List[Tuple[str, LineRange]] | None = None
    new_class_index: List[Tuple[str, LineRange]] | None = None
    # 2.2 Inclass method:               {class name -> [(name, line range)]}
    new_inclass_method_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    # 2.3 Import:                       [(pkg path, attr name, alias name)]
    new_imports: List[Tuple[str, str, str]] | None = None

    def _get_lang(self) -> str:
        return "Python"


@dataclass
class JavaDiffFileInfo(DiffFileInfo):
    """Dataclass to hold info of diff Java file in the commit."""
    # -------------------- Package -------------------- #
    package_name: str | None = None
    # -------------------- Simple Node -------------------- #
    old_nodes: Dict[int, JavaSimNode] | None = None  # Simple Node id -> Simple Node
    new_nodes: Dict[int, JavaSimNode] | None = None  # Simple Node id -> Simple Node
    # ----------------------- Old Struct Index ----------------------- #
    # 1.1 Top-level interface / class:        [name, line range]
    old_iface_index: List[Tuple[str, LineRange]] | None = None
    old_class_index: List[Tuple[str, LineRange]] | None = None
    # 1.2 Inclass interface / class / method: {class name -> [(name, line range)]}
    old_inclass_iface_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    old_inclass_class_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    old_inclass_method_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    # 1.3 Import:                             [full import statement]
    old_imports: List[str] | None = None
    # ----------------------- New Struct Index ----------------------- #
    # 2.1 Top-level interface / class:        [name, line range]
    new_iface_index: List[Tuple[str, LineRange]] | None = None
    new_class_index: List[Tuple[str, LineRange]] | None = None
    # 2.2 Inclass interface / class / method: {class name -> [(name, line range)]}
    new_inclass_iface_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    new_inclass_class_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    new_inclass_method_index: Dict[str, List[Tuple[str, LineRange]]] | None = None
    # 2.3 Import:                             [full import statement]
    new_imports: List[str] | None = None

    def _get_lang(self) -> str:
        return "Java"


"""SEARCH MANAGE"""


class SearchStatus(str, Enum):
    UNKNOWN_SEARCH_API = "unknown_search_api"
    DISPATCH_ERROR = "dispatch_error"
    INVALID_ARGUMENT = "invalid_argument"
    NON_UNIQUE_FILE = "non_unique_file"
    FIND_NONE = "find_none"
    FIND_IMPORT = "find_import"
    FIND_CODE = "find_code"


class FunctionCallIntent:
    """An intent to call a tool function.

    This object created from OpenAI API response.
    """

    def __init__(
            self,
            func_name: str,
            func_args: List[str],
            call_stmt: str,
            call_arg_values: Mapping[str, str],
            openai_func: Optional[OpenaiFunction]
    ):
        self.func_name = func_name
        self.func_args = func_args
        self.call_stmt = call_stmt
        self.call_arg_values: Dict = {}
        self.call_arg_values.update(call_arg_values)
        # Record the original openai function object,
        # which is used when we want to tell the model that it has previously called this function/tool
        self.openai_func = openai_func or OpenaiFunction(arguments=json.dumps(call_arg_values), name=func_name)


    def __str__(self):
        return f"Call function `{self.func_name}` with arguments {self.call_arg_values}."


    def to_dict(self):
        return {"func_name": self.func_name, "call_arg_values": self.call_arg_values}


    def to_dict_with_result(self, search_status: SearchStatus):
        return {
            "func_name": self.func_name,
            "func_args": self.func_args,
            "call_arg_values": self.call_arg_values,
            "search_status": search_status,
        }


"""LLM MANAGE"""


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
        """Load the message thread from a file.
        Args:
            file_path (str): The path to the file.
        Returns:
            MessageThread: The message thread.
        """
        with open(file_path) as f:
            messages = json.load(f)
        return cls(messages)


"""PROCESS MANAGE"""


@dataclass
class ProcessStatus:

    def to_dict(self):
        return {attr.lstrip('_'): value for attr, value in vars(self).items()}


@dataclass
class ProcessActionStatus(ProcessStatus):
    """Dataclass to hold status of some actions during the identification processes."""
    _patch_extraction: List[int] = field(default_factory=lambda: [0, 0])
    _unsupported_hyp_modification: List[int] = field(default_factory=lambda: [0, 0, 0, 0])
    _too_detailed_hyp_modification: int = 0
    _post_process_rank: List[int] = field(default_factory=lambda: [0, 0])
    _finish: bool = False


    def update_patch_extraction_status(self, success_flag: bool):
        if success_flag:
            self._patch_extraction[0] += 1
        else:
            self._patch_extraction[1] += 1


    def add_unsupported_hyp_modification_case(self, none_result: bool, same_result: bool, uns_result: bool, good_result: bool):
        assert none_result + same_result + uns_result + good_result == 1
        if none_result:
            self._unsupported_hyp_modification[0] += 1
        elif same_result:
            self._unsupported_hyp_modification[1] += 1
        elif uns_result:
            self._unsupported_hyp_modification[2] += 1
        else:
            self._unsupported_hyp_modification[3] += 1


    def update_too_detailed_hyp_modification_case(self):
        self._too_detailed_hyp_modification += 1


    def update_post_process_rank_status(self, success_flag: bool):
        if success_flag:
            self._post_process_rank[0] += 1
        else:
            self._post_process_rank[1] += 1


    def update_finish_status(self, success_flag: bool):
        if success_flag:
            self._finish = True
        else:
            self._finish = False


@dataclass
class ProcessSearchStatus(ProcessStatus):
    """Dataclass to hold search status of called search APIs during the identification processes."""
    _unknown_search_api_count: int = 0
    _dispatch_error_count: int = 0
    _invalid_argument_count: int = 0
    _non_unique_file_count: int = 0
    _find_none_count: int = 0
    _find_import_count: int = 0
    _find_code_count: int = 0


    def update_by_search_status(self, search_status: SearchStatus):
        attr_name = f"_{search_status}_count"
        count = getattr(self, attr_name, None)
        if count is not None:
            setattr(self, attr_name, count + 1)
        else:
            raise ValueError(f"Unknown attr {attr_name}")
