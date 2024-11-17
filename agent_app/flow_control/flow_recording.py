import json

from typing import *
from enum import Enum
from dataclasses import dataclass, field
from abc import abstractmethod
from collections import defaultdict

from agent_app.data_structures import SearchStatus
from agent_app.flow_control.hypothesis import Hypothesis, VerifiedHypothesis
from agent_app.search.search_util import PySearchResult, JavaSearchResult


"""FLOW STATE"""


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


"""PROCESS DATACLASS"""


@dataclass
class ProcOutPaths:
    """For recording all relevant output paths in current process."""
    root: str
    hyp_dpath: str
    proxy_dpath: str
    tool_call_dpath: str


@dataclass
class ProcHypothesis:
    """For recording all relevant info about hypothesis in current process."""
    cur_hyp: Hypothesis | None = None
    unverified: List[Hypothesis] = field(default_factory=list)
    verified: List[VerifiedHypothesis] = field(default_factory=list)
    patch: List[PySearchResult | JavaSearchResult] = field(default_factory=list)
    code_context: List[PySearchResult | JavaSearchResult] = field(default_factory=list)

    """UPDATE"""

    def update_cur_hyp(self) -> None:
        self.sort_unverified()
        self.cur_hyp = self.unverified[0]
        self.unverified.pop(0)

    def add_new_unverified(self, hyp: Hypothesis) -> None:
        if not self.in_verified(hyp):
            self.unverified.append(hyp)

    """SORT"""

    def sort_unverified(self) -> None:
        sorted_hyps = sorted(self.unverified, key=lambda x: x.confidence_score, reverse=True)
        self.unverified = sorted_hyps

    def sort_verified(self) -> None:
        sorted_hyps = sorted(self.verified, key=lambda x: x.confidence_score, reverse=True)
        self.verified = sorted_hyps

    """IDENTIFICATION"""

    def in_unverified(self, hyp: Hypothesis) -> bool:
        for u_hyp in self.unverified:
            if u_hyp.commit_type == hyp.commit_type and u_hyp.vulnerability_type == hyp.vulnerability_type:
                return True
        return False

    def in_verified(self, hyp: Hypothesis) -> bool:
        for v_hyp in self.verified:
            if v_hyp.commit_type == hyp.commit_type and v_hyp.vulnerability_type == hyp.vulnerability_type:
                return True
        return False

    """TO DICT"""

    def hyp_to_dict(self) -> Dict:
        return {
            "unverified": [hyp.to_dict() for hyp in self.unverified],
            "verified": [hyp.to_dict() for hyp in self.verified]
        }

    """TO STRING"""

    def context_to_str(self) -> str:
        code_seq_list = []
        for c in self.code_context:
            code_seq_list.append(c.to_tagged_str())
        return "\n\n".join(code_seq_list)

    def patch_to_str(self) -> str:
        code_seq_list = []
        for c in self.patch:
            code_seq_list.append(c.to_tagged_str())
        return "\n\n".join(code_seq_list)

    """SAVE"""

    def save_hyp_to_file(self, fpath: str) -> None:
        with open(fpath, "w") as f:
            json.dump(self.hyp_to_dict(), f, indent=4)


@dataclass
class CodeContext:
    line_ids: List[int]
    context: str


def have_duplicate_lines(line_ids_1: List[int], line_ids_2: List[int]) -> bool:
    assert -1 not in line_ids_1 and -1 not in line_ids_2
    return len(set(line_ids_1).intersection(set(line_ids_2))) > 0


@dataclass
class ProcessCodeContext:
    """For recording all collected code context in current process."""
    files: List[str] = field(default_factory=list)
    file_line_ids: Dict[str, List[int]] = field(default_factory=dict)

    @abstractmethod
    def update_with_search_result(self, search_result):
        raise NotImplementedError

    @abstractmethod
    def update_with_search_results(self, search_results):
        raise NotImplementedError

    def update_with_file(self, file_name: str):
        if file_name not in self.files:
            self.files.append(file_name)

    def update_with_file_line_ids(self, file_name: str, line_ids: List[int]):
        if file_name not in self.file_line_ids:
            self.file_line_ids[file_name] = []
        self.file_line_ids[file_name].extend(line_ids)
        self.file_line_ids[file_name] = list(set(self.file_line_ids[file_name]))
        self.file_line_ids[file_name].sort()

    @abstractmethod
    def get_all_struct_description(self):
        raise NotImplementedError

    @abstractmethod
    def get_all_context(self, all_file_content):
        raise NotImplementedError


@dataclass
class ProcPyCodeContext(ProcessCodeContext):
    # file name -> [import statement]
    file_imports: Dict[str, List[str]] = field(default_factory=dict)

    # file name -> {name -> code}
    file_functions: Dict[str, Dict[str, CodeContext]] = field(default_factory=dict)
    # file name -> {name -> code}
    file_classes: Dict[str, Dict[str, CodeContext]] = field(default_factory=dict)
    # file name -> {class name -> {name -> [code]} (just in case)
    file_inclass_methods: Dict[str, Dict[str, Dict[str, List[CodeContext]]]] = field(default_factory=dict)
    # file name -> [code]
    file_other_snippets: Dict[str, List[CodeContext]] = field(default_factory=dict)

    """DUPLICATE STRUCT"""

    def is_duplicate_function(self, file_name: str, func_name: str) -> Tuple[bool, str]:
        old_func = self.file_functions.get(file_name, {}).get(func_name, None)
        if old_func:
            return True, f"Have collected function '{func_name}' in file '{file_name}'."
        else:
            return False, "ok"

    def is_duplicate_class(self, file_name: str, class_name: str) -> Tuple[bool, str]:
        old_class = self.file_classes.get(file_name, {}).get(class_name, None)
        if old_class:
            return True, f"Have collected class '{class_name}' in file '{file_name}'."
        else:
            return False, "ok"

    def is_duplicate_inclass_method(self, file_name: str, class_name: str, inclass_method_name: str, line_ids: List[int]) -> Tuple[bool, str]:
        old_inclass_methods = self.file_inclass_methods.get(file_name, {}).get(class_name, {}).get(inclass_method_name, [])
        for old_inclass_method in old_inclass_methods:
            if have_duplicate_lines(old_inclass_method.line_ids, line_ids):
                return True, f"Have collected method '{inclass_method_name}' in class '{class_name}' of file '{file_name}'."
        return False, "ok"

    """CLASSIFICATION"""

    @staticmethod
    def is_import_search_result(res: PySearchResult):
        if -1 in res.line_ids and res.func_name is None and res.class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_function_search_result(res: PySearchResult):
        if -1 not in res.line_ids and res.func_name is not None and res.class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_class_search_result(res: PySearchResult):
        if -1 not in res.line_ids and res.class_name is not None and res.func_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_inclass_method_search_result(res: PySearchResult):
        if -1 not in res.line_ids and res.class_name is not None and res.inclass_method_name is not None and res.func_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_other_search_result(res: PySearchResult):
        if -1 not in res.line_ids and res.func_name is None and res.class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    """UPDATE"""

    def update_with_import_search_result(self, res: PySearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_imports:
            self.file_imports[res.file_path] = []
        if res.code not in self.file_imports[res.file_path]:
            self.file_imports[res.file_path].append(res.code)
        return True, "ok"

    def update_with_function_search_result(self, res: PySearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_functions:
            self.file_functions[res.file_path] = {}

        flag, msg = self.is_duplicate_function(res.file_path, res.func_name)
        if flag:
            return False, msg

        self.file_functions[res.file_path][res.func_name] = CodeContext(res.line_ids, res.code)

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_class_search_result(self, res: PySearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_classes:
            self.file_classes[res.file_path] = {}

        flag, msg = self.is_duplicate_class(res.file_path, res.class_name)
        if flag:
            return False, msg

        self.file_classes[res.file_path][res.class_name] = CodeContext(res.line_ids, res.code)

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_inclass_method_search_result(self, res: PySearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_inclass_methods:
            self.file_inclass_methods[res.file_path] = defaultdict(lambda: defaultdict(list))

        flag, msg = self.is_duplicate_inclass_method(res.file_path, res.class_name, res.inclass_method_name, res.line_ids)
        if flag:
            return False, msg

        self.file_inclass_methods[res.file_path][res.class_name][res.inclass_method_name].append(CodeContext(res.line_ids, res.code))

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_other_search_result(self, res: PySearchResult) -> Tuple[bool, str]:
        if not res.line_ids:
            return False, "Empty line ids"

        # TODO: For now, we do not check if other code added is duplicated.
        if res.file_path not in self.file_other_snippets:
            self.file_other_snippets[res.file_path] = []
        self.file_other_snippets[res.file_path].append(CodeContext(res.line_ids, res.code))

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_search_result(self, res: PySearchResult) -> Tuple[bool, str]:
        ## Code context
        # 1. Import statement
        if self.is_import_search_result(res):
            return self.update_with_import_search_result(res)

        # 2. Function
        if self.is_function_search_result(res):
            return self.update_with_function_search_result(res)

        # 3. Class
        if self.is_class_search_result(res):
            return self.update_with_class_search_result(res)

        # 4. Inclass method
        if self.is_inclass_method_search_result(res):
            return self.update_with_inclass_method_search_result(res)

        # 5. Other code snippet
        assert self.is_other_search_result(res)
        return self.update_with_other_search_result(res)

    def update_with_search_results(self, search_results: List[PySearchResult]) -> str:
        msg = ""
        for res in search_results:
            flag, msg = self.update_with_search_result(res)
            if not flag:
                msg += "\n" + msg
        msg.strip()
        return msg

    """DESCRIPTION"""

    def get_file_function_name_seq(self, file_name: str) -> str:
        if file_name not in self.file_functions:
            return ""
        func_names: List[str] = [name for name, _ in self.file_functions[file_name].items()]
        return ", ".join(func_names)

    def get_file_class_name_seq(self, file_name: str) -> str:
        if file_name not in self.file_classes:
            return ""
        class_names: List[str] = [name for name, _ in self.file_classes[file_name].items()]
        return ", ".join(class_names)

    def get_file_inclass_method_name_seq(self, file_name: str) -> str:
        file_inclass_methods = {}
        if file_name in self.file_inclass_methods:
            file_inclass_methods = self.file_inclass_methods[file_name]

        if file_inclass_methods:
            return ""

        class_names = list(file_inclass_methods.keys())

        desc = ""
        for class_name in class_names:
            inclass_method_names = list(file_inclass_methods[class_name].keys())
            cur_desc = f"For class {class_name}:\n- method: " + ", ".join(inclass_method_names)
            desc += "\n\n" + cur_desc

        desc.strip()

        return desc

    def get_file_struct_description(self, file_name: str) -> str:
        file_desc = f"In file {file_name}:"

        # 1. Function
        func_name_seq = self.get_file_function_name_seq(file_name)
        if func_name_seq:
            file_desc += "\n- Interface: " + func_name_seq
        # 2. Class
        class_name_seq = self.get_file_class_name_seq(file_name)
        if class_name_seq:
            file_desc += "\n- Class: " + class_name_seq
        # 3. Inclass method
        inclass_method_seq = self.get_file_inclass_method_name_seq(file_name)
        if inclass_method_seq:
            file_desc += "\n- Inclass Method: "
            for line in inclass_method_seq.split('\n'):
                file_desc += "\n    " + line

        return file_desc

    def get_all_struct_description(self):
        desc = ""
        for file_name in self.files:
            cur_file_desc = self.get_file_struct_description(file_name)
            desc += "\n\n" + cur_file_desc
        desc.strip()
        return desc

    """CONTEXT"""

    def get_file_context(self, file_name: str, file_content: str) -> str:
        file_lines = file_content.split("\n")

        cur_context = ""
        # 1. Import statements
        cur_imports = self.file_imports.get(file_name, [])
        if cur_imports:
            cur_context += "\n".join(cur_imports)
            cur_context += "\n..."
        # 2. Other context
        cur_line_ids = self.file_line_ids.get(file_name, [])
        cur_line_ids.sort()
        for i in range(len(cur_line_ids)):
            if i > 0 and cur_line_ids[i] != cur_line_ids[i - 1] + 1:
                cur_context += "\n..."
            cur_context += "\n" + file_lines[cur_line_ids[i]]

        cur_context.strip()

        return cur_context

    def get_all_context(self, all_file_content: Dict[str, str]) -> str:
        total_context = ""
        for i, file_name in enumerate(self.files):
            file_context = self.get_file_context(file_name, all_file_content[file_name])
            total_context += (f"\n\n## File {i + 1}: {file_name}"
                              f"\n{file_context}")
        total_context.strip()
        return total_context


@dataclass
class ProcJavaCodeContext(ProcessCodeContext):
    # package name -> [file name]
    package_files: Dict[str, List[str]] = field(default_factory=Dict)

    # file name -> package name
    file_package: Dict[str, str] = field(default_factory=Dict)

    # file name -> [import statement]
    file_imports: Dict[str, List[str]] = field(default_factory=dict)

    # file name -> {name -> code}
    file_interfaces: Dict[str, Dict[str, CodeContext]] = field(default_factory=dict)
    # file name -> {name -> code}
    file_classes: Dict[str, Dict[str, CodeContext]] = field(default_factory=dict)
    # file name -> {class name -> {name -> code}
    file_inclass_interfaces: Dict[str, Dict[str, Dict[str, CodeContext]]] = field(default_factory=dict)
    # file name -> {class name -> {name -> code}
    file_inclass_classes: Dict[str, Dict[str, Dict[str, CodeContext]]] = field(default_factory=dict)
    # file name -> {class name -> {name -> [code]} (method overloading)
    file_inclass_methods: Dict[str, Dict[str, Dict[str, List[CodeContext]]]] = field(default_factory=dict)
    # file name -> [code]
    file_other_snippets: Dict[str, List[CodeContext]] = field(default_factory=dict)

    """DUPLICATE STRUCT"""

    def is_duplicate_interface(self, file_name: str, iface_name: str) -> Tuple[bool, str]:
        old_iface = self.file_interfaces.get(file_name, {}).get(iface_name, None)
        if old_iface:
            return True, f"Have collected interface '{iface_name}' in file '{file_name}'."
        else:
            return False, "ok"

    def is_duplicate_class(self, file_name: str, class_name: str) -> Tuple[bool, str]:
        old_class = self.file_classes.get(file_name, {}).get(class_name, None)
        if old_class:
            return True, f"Have collected class '{class_name}' in file '{file_name}'."
        else:
            return False, "ok"

    def is_duplicate_inclass_interface(self, file_name: str, class_name: str, inclass_iface_name: str) -> Tuple[bool, str]:
        old_inclass_iface = self.file_inclass_interfaces.get(file_name, {}).get(class_name, {}).get(inclass_iface_name, None)
        if old_inclass_iface:
            return True, f"Have collected interface '{inclass_iface_name}' in class '{class_name}' of file '{file_name}'."
        else:
            return False, "ok"

    def is_duplicate_inclass_class(self, file_name: str, class_name: str, inclass_class_name: str) -> Tuple[bool, str]:
        old_inclass_class = self.file_inclass_classes.get(file_name, {}).get(class_name, {}).get(inclass_class_name, None)
        if old_inclass_class:
            return True, f"Have collected class '{inclass_class_name}' in class '{class_name}' of file '{file_name}'."
        else:
            return False, "ok"

    def is_duplicate_inclass_method(self, file_name: str, class_name: str, inclass_method_name: str, line_ids: List[int]) -> Tuple[bool, str]:
        old_inclass_methods = self.file_inclass_methods.get(file_name, {}).get(class_name, {}).get(inclass_method_name, [])
        for old_inclass_method in old_inclass_methods:
            if have_duplicate_lines(old_inclass_method.line_ids, line_ids):
                return True, f"Have collected method '{inclass_method_name}' in class '{class_name}' of file '{file_name}'."
        return False, "ok"

    """CLASSIFICATION"""

    @staticmethod
    def is_import_search_result(res: JavaSearchResult):
        if -1 in res.line_ids and res.iface_name is None and res.class_name is None and \
                res.inclass_iface_name is None and res.inclass_class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_interface_search_result(res: JavaSearchResult):
        if -1 not in res.line_ids and res.iface_name is not None and res.class_name is None and \
                res.inclass_iface_name is None and res.inclass_class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_class_search_result(res: JavaSearchResult):
        if -1 not in res.line_ids and res.class_name is not None and res.iface_name is None and \
                res.inclass_iface_name is None and res.inclass_class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    @staticmethod
    def is_inclass_type_search_result(res: JavaSearchResult):
        if -1 not in res.line_ids and res.iface_name is None and res.class_name is not None and \
                (res.inclass_iface_name is not None or res.inclass_class_name is not None or res.inclass_method_name is not None):
            return True
        else:
            return False

    @staticmethod
    def is_other_search_result(res: JavaSearchResult):
        if -1 not in res.line_ids and res.iface_name is None and res.class_name is None and \
                res.inclass_iface_name is None and res.inclass_class_name is None and res.inclass_method_name is None:
            return True
        else:
            return False

    """UPDATE"""

    def update_with_import_search_result(self, res: JavaSearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_imports:
            self.file_imports[res.file_path] = []
        if res.code not in self.file_imports[res.file_path]:
            self.file_imports[res.file_path].append(res.code)
        return True, "ok"

    def update_with_interface_search_result(self, res: JavaSearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_interfaces:
            self.file_interfaces[res.file_path] = {}

        flag, msg = self.is_duplicate_interface(res.file_path, res.iface_name)
        if flag:
            return False, msg

        self.file_interfaces[res.file_path][res.iface_name] = CodeContext(res.line_ids, res.code)

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_class_search_result(self, res: JavaSearchResult) -> Tuple[bool, str]:
        if res.file_path not in self.file_classes:
            self.file_classes[res.file_path] = {}

        flag, msg = self.is_duplicate_class(res.file_path, res.class_name)
        if flag:
            return False, msg

        self.file_classes[res.file_path][res.class_name] = CodeContext(res.line_ids, res.code)

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_inclass_type_search_result(self, res: JavaSearchResult) -> Tuple[bool, str]:
        if res.inclass_iface_name:
            if res.file_path not in self.file_inclass_interfaces:
                self.file_inclass_interfaces[res.file_path] = defaultdict(dict)

            flag, msg = self.is_duplicate_inclass_interface(res.file_path, res.class_name, res.inclass_iface_name)
            if flag:
                return False, msg

            self.file_inclass_interfaces[res.file_path][res.class_name][res.inclass_iface_name] = CodeContext(res.line_ids, res.code)
        elif res.inclass_class_name:
            if res.file_path not in self.file_inclass_classes:
                self.file_inclass_classes[res.file_path] = defaultdict(dict)

            flag, msg = self.is_duplicate_inclass_class(res.file_path, res.class_name, res.inclass_class_name)
            if flag:
                return False, msg

            self.file_inclass_classes[res.file_path][res.class_name][res.inclass_class_name] = CodeContext(res.line_ids, res.code)
        else:
            if res.file_path not in self.file_inclass_methods:
                self.file_inclass_methods[res.file_path] = defaultdict(lambda: defaultdict(list))

            flag, msg = self.is_duplicate_inclass_method(res.file_path, res.class_name, res.inclass_method_name, res.line_ids)
            if flag:
                return False, msg

            self.file_inclass_methods[res.file_path][res.class_name][res.inclass_method_name].append(CodeContext(res.line_ids, res.code))

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_other_search_result(self, res: JavaSearchResult) -> Tuple[bool, str]:
        if not res.line_ids:
            return False, "Empty line ids"

        # TODO: For now, we do not check if other code added is duplicated.
        if res.file_path not in self.file_other_snippets:
            self.file_other_snippets[res.file_path] = []
        self.file_other_snippets[res.file_path].append(CodeContext(res.line_ids, res.code))

        self.update_with_file(res.file_path)
        self.update_with_file_line_ids(res.file_path, res.line_ids)

        return True, "ok"

    def update_with_search_result(self, res: JavaSearchResult) -> Tuple[bool, str]:
        ## Package
        if res.package_name:
            if res.package_name in self.package_files:
                self.package_files[res.package_name].append(res.file_path)
                self.package_files[res.package_name] = list(set(self.package_files[res.package_name]))
            else:
                self.package_files[res.package_name] = [res.file_path]

            self.file_package[res.file_path] = res.package_name

        ## Code context
        # 1. Package declaration
        # TODO: For package declarations, we do not actively add them (there are no search results that simply
        #       contain a package declaration statement), but we will add package declaration like 'package xxx'
        #       to the beginning of each collected file when showing

        # 2. Import statement
        if self.is_import_search_result(res):
            return self.update_with_import_search_result(res)

        # 3. Interface
        if self.is_interface_search_result(res):
            return self.update_with_interface_search_result(res)

        # 4. Class
        if self.is_class_search_result(res):
            return self.update_with_class_search_result(res)

        # 5. Inclass type
        if self.is_inclass_type_search_result(res):
            return self.update_with_inclass_type_search_result(res)

        # 6. Other code snippet
        assert self.is_other_search_result(res)
        return self.update_with_other_search_result(res)

    def update_with_search_results(self, search_results: List[JavaSearchResult]) -> str:
        msg = ""
        for res in search_results:
            flag, msg = self.update_with_search_result(res)
            if not flag:
                msg += "\n" + msg
        msg.strip()
        return msg

    """DESCRIPTION"""

    def get_file_interface_name_seq(self, file_name: str) -> str:
        if file_name not in self.file_interfaces:
            return ""
        iface_names: List[str] = [name for name, _ in self.file_interfaces[file_name].items()]
        return ", ".join(iface_names)

    def get_file_class_name_seq(self, file_name: str) -> str:
        if file_name not in self.file_classes:
            return ""
        class_names: List[str] = [name for name, _ in self.file_classes[file_name].items()]
        return ", ".join(class_names)

    def get_file_inclass_type_name_seq(self, file_name: str) -> str:
        file_inclass_interfaces = {}
        if file_name in self.file_inclass_interfaces:
            file_inclass_interfaces = self.file_inclass_interfaces[file_name]

        file_inclass_classes = {}
        if file_name in self.file_inclass_classes:
            file_inclass_classes = self.file_inclass_classes[file_name]

        file_inclass_methods = {}
        if file_name in self.file_inclass_methods:
            file_inclass_methods = self.file_inclass_methods[file_name]

        if not file_inclass_interfaces and not file_inclass_classes and not file_inclass_methods:
            return ""

        class_names = list(set(list(file_inclass_interfaces.keys()) +
                               list(file_inclass_classes.keys()) +
                               list(file_inclass_methods.keys())))

        desc = ""
        for class_name in class_names:
            cur_desc = f"For class {class_name}: "

            # 1. Inclass interface
            if class_name in file_inclass_interfaces:
                inclass_iface_names = list(file_inclass_interfaces[class_name].keys())
                cur_desc += "\n- interface: " + ", ".join(inclass_iface_names)

            # 2. Inclass class
            if class_name in file_inclass_classes:
                inclass_class_names = list(file_inclass_classes[class_name].keys())
                cur_desc += "\n- class: " + ", ".join(inclass_class_names)

            # 3. Inclass method
            if class_name in file_inclass_methods:
                inclass_method_names = list(file_inclass_methods[class_name].keys())
                cur_desc += "\n- method: " + ", ".join(inclass_method_names)

            desc += "\n\n" + cur_desc

        desc.strip()

        return desc

    def get_file_struct_description(self, file_name: str) -> str:
        file_desc = f"In file {file_name}:"

        # 1. Interface
        iface_name_seq = self.get_file_interface_name_seq(file_name)
        if iface_name_seq:
            file_desc += "\n- Interface: " + iface_name_seq
        # 2. Class
        class_name_seq = self.get_file_class_name_seq(file_name)
        if class_name_seq:
            file_desc += "\n- Class: " + class_name_seq
        # 3. Inclass type
        inclass_type_seq = self.get_file_inclass_type_name_seq(file_name)
        if inclass_type_seq:
            file_desc += "\n- Inclass Interface / Class / Method: "
            for line in inclass_type_seq.split('\n'):
                file_desc += "\n    " + line

        return file_desc

    def get_all_struct_description(self):
        desc = ""
        for file_name in self.files:
            cur_file_desc = self.get_file_struct_description(file_name)
            desc += "\n\n" + cur_file_desc
        desc.strip()
        return desc

    """CONTEXT"""

    def get_file_context(self, file_name: str, file_content: str) -> str:
        file_lines = file_content.split("\n")

        cur_context = ""
        # 1. Package declaration
        cur_package = self.file_package.get(file_name, None)
        if cur_package:
            cur_context += f"package {cur_package}"
        # 2. Import statements
        cur_imports = self.file_imports.get(file_name, [])
        if cur_imports:
            cur_context += "\n".join(cur_imports)
            cur_context += "\n..."
        # 3. Other context
        cur_line_ids = self.file_line_ids.get(file_name, [])
        cur_line_ids.sort()
        for i in range(len(cur_line_ids)):
            if i > 0 and cur_line_ids[i] != cur_line_ids[i - 1] + 1:
                cur_context += "\n..."
            cur_context += "\n" + file_lines[cur_line_ids[i]]

        cur_context.strip()

        return cur_context

    def get_all_context(self, all_file_content: Dict[str, str]) -> str:
        total_context = ""
        for i, file_name in enumerate(self.files):
            file_context = self.get_file_context(file_name, all_file_content[file_name])
            total_context += (f"\n\n## File {i + 1}: {file_name}"
                              f"\n{file_context}")
        total_context.strip()
        return total_context


@dataclass
class ProcessStatus:

    def to_dict(self):
        return {attr.lstrip('_'): value for attr, value in vars(self).items()}


@dataclass
class ProcActionStatus(ProcessStatus):
    """Dataclass to hold status of some actions during the process."""
    ## STATE: start
    # [success number, failure number]
    _patch_extraction: List[int] = field(default_factory=lambda: [0, 0])

    ## STATE: hypothesis checking
    # [none result number, same result number, unsupported result number, good result number]
    _unsupported_hyp_modification: List[int] = field(default_factory=lambda: [0, 0, 0, 0])
    # modification number
    _too_detailed_hyp_modification: int = 0

    ## STATE: context retrieval
    _tool_call_extraction: List[int] = field(default_factory=lambda: [0, 0])

    ## STATE: post process
    # [success number, failure number]
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


    def update_tool_call_extraction_status(self, success_flag: bool):
        if success_flag:
            self._tool_call_extraction[0] += 1
        else:
            self._tool_call_extraction[1] += 1


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
class ProcSearchStatus(ProcessStatus):
    """Dataclass to hold search status of called search APIs during the identification processes."""
    _dispatch_error_count: int = 0
    _unknown_search_api_count: int = 0
    _wrong_argument_count: int = 0
    _invalid_argument_count: int = 0
    _duplicate_call_count: int = 0
    _wide_search_range_count: int = 0
    _find_none_count: int = 0
    _find_import_count: int = 0
    _find_code_count: int = 0

    def update_with_search_status(self, search_status: SearchStatus):
        attr_name = f"_{search_status}_count"
        count = getattr(self, attr_name, None)
        if count is not None:
            setattr(self, attr_name, count + 1)
        else:
            raise ValueError(f"Unknown attr {attr_name}")
