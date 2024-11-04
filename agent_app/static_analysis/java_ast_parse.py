import os
import json
import subprocess

from typing import *
from collections import defaultdict
from loguru import logger

from agent_app.data_structures import LineRange, JavaSimNodeType, JavaSimNode
from agent_app.util import make_tmp_file, remove_tmp_file
from utils import run_command


"""JAVA SCRIPT PROCESSING"""


def process_java_script(
        java_class_path: str,
        java_class_full_name: str,
        cwd: str | None = "./agent_app/static_analysis/java-static-analysis",
        java_path: str | None = "/usr/local/jdk19/bin",
        *args
) -> str | None:
    # Env
    env = os.environ.copy()
    if "jdk" not in env["PATH"] and java_path is not None:
        env["PATH"] = f"{java_path}:" + env["PATH"]

    # Command
    java_process_cmd = ['java', '-cp', java_class_path, java_class_full_name] + list(args)

    # Run
    result, _ = run_command(java_process_cmd, raise_error=False, cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result is not None:
        return result.stdout
    else:
        return None


"""CODE FILTER"""


def filter_code_content_by_processing_java_script(
        code_fpath: str,
        output_fpath: str,
        filter_comment: bool = True,
        filter_javadoc: bool = False,
        filter_blank: bool = True,
        java_class_path: str = "target/MyASTParser-1.0.jar",
        java_class_full_name: str = "com.percy.MyASTParser.CodeFilter",
        cwd: str | None = "./agent_app/static_analysis/java-static-analysis",
        java_path: str | None = "/usr/local/jdk19/bin"
) -> bool:
    args = []
    args.extend(['-s', os.path.abspath(code_fpath)])
    args.extend(['-o', os.path.abspath(output_fpath)])
    if filter_comment:
        args.append('-fc')
    if filter_javadoc:
        args.append('-fd')
    if filter_blank:
        args.append('-fb')

    res = process_java_script(java_class_path, java_class_full_name, cwd, java_path, *args)

    return res is not None


"""CODE SNIPPET EXTRACTION"""


def extract_struct_sig_lines_from_snippet_by_processing_java_script(
        code_fpath: str,
        output_fpath: str,
        struct_type: Literal['interface', 'class', 'method'],
        base: bool,
        detailed: bool,
        java_class_path: str = "target/MyASTParser-1.0.jar",
        java_class_full_name: str = "com.percy.MyASTParser.SnippetStructSigExtractor",
        cwd: str | None = "./agent_app/static_analysis/java-static-analysis",
        java_path: str | None = "/usr/local/jdk19/bin"
) -> bool:
    """Extract structure signature line ids from structure code snippet.
    NOTE: Input file only contains the structure code snippet but not the entire code.
    """
    args = []
    args.extend(['-s', os.path.abspath(code_fpath)])
    args.extend(['-o', os.path.abspath(output_fpath)])
    assert struct_type in ['interface', 'class', 'method']
    args.extend(['-t', struct_type])
    if base:
        args.append('-b')
    if detailed:
        args.append('-d')

    res = process_java_script(java_class_path, java_class_full_name, cwd, java_path, *args)

    return res is not None


def extract_iface_sig_lines_from_snippet(iface_code: str, iface_start: int = 1) -> List[int] | None:
    """Extract the interface signature from the interface code snippet."""
    sig_line_ids = None

    # (1) Extract line ids of signature
    tmp_code_fpath = None
    output_fpath = None
    try:
        tmp_code_fpath = make_tmp_file(iface_code)
        output_fpath = tmp_code_fpath.replace(".java", ".json")

        res = extract_struct_sig_lines_from_snippet_by_processing_java_script(
            tmp_code_fpath, output_fpath, struct_type='interface', base=True, detailed=False
        )

        if res:
            with open(output_fpath, "r") as f:
                sig_line_ids = json.load(f)
            sig_line_ids = [int(line_id) for line_id in sig_line_ids]
    finally:
        if tmp_code_fpath is not None:
            remove_tmp_file(tmp_code_fpath)
        if output_fpath is not None:
            remove_tmp_file(output_fpath)

    # (2) Normalize
    if sig_line_ids is not None:
        sig_line_ids = [iface_start + line_id - 1 for line_id in sig_line_ids]

    return sig_line_ids


def extract_method_sig_lines_from_snippet(method_code: str, method_start: int = 1) -> List[int] | None:
    """Extract the method signature from the method code snippet."""
    sig_line_ids = None

    # (1) Extract line ids of signature
    tmp_code_fpath = None
    output_fpath = None
    try:
        tmp_code_fpath = make_tmp_file(method_code)
        output_fpath = tmp_code_fpath.replace(".java", ".json")

        res = extract_struct_sig_lines_from_snippet_by_processing_java_script(
            tmp_code_fpath, output_fpath, struct_type='method', base=True, detailed=False
        )

        if res:
            with open(output_fpath, "r") as f:
                sig_line_ids = json.load(f)
            sig_line_ids = [int(line_id) for line_id in sig_line_ids]
    finally:
        if tmp_code_fpath is not None:
            remove_tmp_file(tmp_code_fpath)
        if output_fpath is not None:
            remove_tmp_file(output_fpath)

    # (2) Normalize
    if sig_line_ids is not None:
        sig_line_ids = [method_start + line_id - 1 for line_id in sig_line_ids]

    return sig_line_ids


def extract_class_sig_lines_from_snippet(class_code: str, class_start: int = 1, base: bool = False, detailed: bool = True) -> List[int] | None:
    """Extract the class signature from the class code snippet."""
    sig_line_ids = None

    # (1) Extract line ids of signature
    tmp_code_fpath = None
    output_fpath = None
    try:
        tmp_code_fpath = make_tmp_file(class_code)
        output_fpath = tmp_code_fpath.replace(".java", ".json")

        res = extract_struct_sig_lines_from_snippet_by_processing_java_script(
            tmp_code_fpath, output_fpath, struct_type='class', base=base, detailed=detailed
        )

        if res:
            with open(output_fpath, "r") as f:
                sig_line_ids = json.load(f)
            sig_line_ids = [int(line_id) for line_id in sig_line_ids]
    finally:
        if tmp_code_fpath is not None:
            remove_tmp_file(tmp_code_fpath)
        if output_fpath is not None:
            remove_tmp_file(output_fpath)

    # (2) Normalize
    if sig_line_ids is not None:
        sig_line_ids = [class_start + line_id - 1 for line_id in sig_line_ids]

    return sig_line_ids


def extract_class_sig_lines_from_file_by_processing_java_script(
        code_fpath: str,
        output_fpath: str,
        class_name: str,
        class_start: int,
        class_end: int,
        base: bool,
        detailed: bool,
        java_class_path: str = "target/MyASTParser-1.0.jar",
        java_class_full_name: str = "com.percy.MyASTParser.FileClassSigExtractor",
        cwd: str | None = "./agent_app/static_analysis/java-static-analysis",
        java_path: str | None = "/usr/local/jdk19/bin"
) -> bool:
    """Extract class signature line ids from the file code.
    NOTE: Input file contains the entire code but not only the class code snippet.
    """
    args = []
    args.extend(['-s', os.path.abspath(code_fpath)])
    args.extend(['-o', os.path.abspath(output_fpath)])
    args.extend(['-cn', class_name])
    args.extend(['-cs', class_start])
    args.extend(['-ce', class_end])
    if base:
        args.append('-b')
    if detailed:
        args.append('-d')

    res = process_java_script(java_class_path, java_class_full_name, cwd, java_path, *args)

    return res is not None


def extract_class_sig_lines_from_file(
        code: str | None,
        code_fpath: str | None,
        class_name: str,
        class_range: LineRange,
        base: bool = False,
        detailed: bool = False
) -> List[int]:
    """Extract class signature line ids from the file code.
    NOTE 1: One and only one of 'code' and 'code_fpath' must be None.
    NOTE 2: When 'base' and 'detailed' are both False, use the default class signature extraction strategy.
    """
    sig_line_ids: List[int] = []

    # Check arguments
    if not ((code is None) ^ (code_fpath is None)):
        raise RuntimeError("One and only one of 'code' and 'code_fpath' must be None.")

    # Main
    tmp_code_flag = False
    output_fpath = None
    try:
        if code_fpath is None:
            # Make tmp file to store input code
            assert code is not None
            tmp_code_flag = True
            code_fpath = make_tmp_file(code)

        output_fpath = make_tmp_file(content="", suffix=".json")

        res = extract_class_sig_lines_from_file_by_processing_java_script(
            code_fpath, output_fpath, class_name, class_range.start, class_range.end, base=base, detailed=detailed
        )

        if res:
            with open(output_fpath, "r") as f:
                sig_line_ids = json.load(f)
            sig_line_ids = [int(line_id) for line_id in sig_line_ids]
    finally:
        if tmp_code_flag:
            remove_tmp_file(code_fpath)
        if output_fpath is not None:
            remove_tmp_file(output_fpath)

    return sig_line_ids


"""MAIN ENTRY"""


def parse_java_code_by_processing_java_script(
        code_fpath: str,
        output_fpath: str,
        java_class_path: str = "target/MyASTParser-1.0.jar",
        java_class_full_name: str = "com.percy.MyASTParser.SimNodeParser",
        cwd: str | None = "./agent_app/static_analysis/java-static-analysis",
        java_path: str | None = "/usr/local/jdk19/bin"
) -> bool:
    args = []
    args.extend(['-s', os.path.abspath(code_fpath)])
    args.extend(['-o', os.path.abspath(output_fpath)])

    res = process_java_script(java_class_path, java_class_full_name, cwd, java_path, *args)

    return res is not None


class ASTParser:
    def __init__(self):
        # Parse the code entered or read from a file
        self.code: str | None = None
        self.code_fpath: str | None = None

        # (1) Package name
        self.package_name: str | None = None
        # (2) Simple Node data
        self.cur_node_id: int | None = None
        self.all_nodes: Dict[int, JavaSimNode] = {}  # {node id -> Simple Node}
        self.li2node_map: Dict[int, int] = {}        # {line id -> node id}
        # (3) Struct indexes (interface, class, inclass interface, inclass class, inclass method)
        self.all_interfaces: List[Tuple[str, LineRange]] = []                     # [(name, line range)]
        self.all_classes: List[Tuple[str, LineRange]] = []                        # [(name, line range)]
        self.all_inclass_interfaces: Dict[str, List[Tuple[str, LineRange]]] = {}  # {class name -> [(name, line range)]}
        self.all_inclass_classes: Dict[str, List[Tuple[str, LineRange]]] = {}     # {class name -> [(name, line range)]}
        self.all_inclass_methods: Dict[str, List[Tuple[str, LineRange]]] = {}     # {class name -> [(name, line range)]}
        # (4) Imports
        self.all_imports: List[str] = []  # [full import statement]


    def set(self, code: str | None, code_fpath: str | None) -> bool:
        # Reset before setting
        self.reset()

        # Check arguments
        if not ((code is None) ^ (code_fpath is None)):
            raise RuntimeError("One and only one of 'code' and 'code_fpath' must be None.")

        # Main
        if code is not None:
            self.code = code
        else:
            assert code_fpath is not None
            self.code_fpath = code_fpath

        return True


    def reset(self):
        self.code = None
        self.code_fpath = None
        self.code_len = 0

        self.cur_node_id = None
        self.all_nodes = {}
        self.li2node_map = {}
        self.all_interfaces = []
        self.all_classes = []
        self.all_inclass_interfaces = {}
        self.all_inclass_classes = {}
        self.all_inclass_methods = {}
        self.all_imports = []


    def _update_all_nodes(
            self,
            father_node_id: int | None,
            node_type: JavaSimNodeType,
            ast_type: str,
            node_name: str,
            node_range: LineRange
    ) -> JavaSimNode:
        assert isinstance(self.cur_node_id, int)

        cur_node = JavaSimNode(
            id=self.cur_node_id,
            father=father_node_id,
            type=node_type,
            ast=ast_type,
            name=node_name,
            range=node_range
        )
        self.all_nodes[self.cur_node_id] = cur_node
        self.cur_node_id += 1

        return cur_node


    def _update_line_to_node_map(self, line_node: JavaSimNode) -> None:
        for line_id in line_node.get_full_range():
            assert line_id not in self.li2node_map
            self.li2node_map[line_id] = line_node.id


    def parse_java_code(self) -> bool:
        """Parse the Java code.
        (1) Extract the following Simple Nodes:
        - Top level structs:
            - Unit
            - Interface
            - Class
        - Class child structs
            - Class Unit
            - Class Interface
            - Class Class
            - Class Method
        (2) Build important struct indexes
        - Interface
        - Class
        - Inclass interface
        - Inclass class
        - Inclass method
        """
        tmp_code_flag = False
        output_fpath = None
        parse_flag = False

        # NOTE: Need a valid 'code_fpath' to call the jar package for AST parsing.
        try:
            # Make tmp code file
            if self.code_fpath is None:
                assert self.code is not None
                tmp_code_flag = True
                self.code_fpath = make_tmp_file(self.code)
            # Make tmp output file
            output_fpath = make_tmp_file("", ".json")

            # Parse
            parse_flag = parse_java_code_by_processing_java_script(self.code_fpath, output_fpath)

            # Update
            if parse_flag:
                with open(output_fpath, "r") as f:
                    json_parse_result = json.load(f)

                # (1) Package name
                self.package_name = json_parse_result["packageName"]

                # (2) Simple Node data
                all_nodes = json_parse_result['fileSimNodeData']['allNodes']
                for node_id, node in all_nodes.items():
                    self.all_nodes[int(node_id)] = JavaSimNode(
                        id=node["id"],
                        father=node["father"],
                        type=node["type"],
                        ast=node["ast"],
                        name=node["name"],
                        range=LineRange(start=node["range"]["start"], end=node["range"]["end"])
                    )

                li2node_map = json_parse_result['fileSimNodeData']['li2NodeMap']
                for line_id, node_id in li2node_map.items():
                    self.li2node_map[int(line_id)] = int(node_id)

                # (3) Struct indexes
                all_interfaces = json_parse_result['fileSearchIndexData']['allInterfaces']
                for name, line_ranges in all_interfaces.items():
                    for lrange in line_ranges:
                        self.all_interfaces.append((name, LineRange(lrange['start'], lrange['end'])))

                all_classes = json_parse_result['fileSearchIndexData']['allClasses']
                for class_name, line_ranges in all_classes.items():
                    for lrange in line_ranges:
                        self.all_classes.append((class_name, LineRange(lrange['start'], lrange['end'])))

                self.all_inclass_interfaces = defaultdict(list)
                all_inclass_interfaces = json_parse_result['fileSearchIndexData']['allInclassInterfaces']
                for class_name, inclass_interfaces in all_inclass_interfaces.items():
                    for name, line_ranges in inclass_interfaces.items():
                        for lrange in line_ranges:
                            self.all_inclass_methods[class_name].append((name, LineRange(lrange['start'], lrange['end'])))

                self.all_inclass_classes = defaultdict(list)
                all_inclass_classes = json_parse_result['fileSearchIndexData']['allInclassClasses']
                for class_name, inclass_classes in all_inclass_classes.items():
                    for name, line_ranges in inclass_classes.items():
                        for lrange in line_ranges:
                            self.all_inclass_classes[class_name].append((name, LineRange(lrange['start'], lrange['end'])))

                self.all_inclass_methods = defaultdict(list)
                all_inclass_methods = json_parse_result['fileSearchIndexData']['allInclassMethods']
                for class_name, inclass_methods in all_inclass_methods.items():
                    for name, line_ranges in inclass_methods.items():
                        for lrange in line_ranges:
                            self.all_inclass_methods[class_name].append((name, LineRange(lrange['start'], lrange['end'])))

                # (4) Imports
                self.all_imports = json_parse_result['fileSearchIndexData']['allImports']

        finally:
            if tmp_code_flag:
                remove_tmp_file(self.code_fpath)
            if output_fpath is not None:
                remove_tmp_file(output_fpath)

        return parse_flag
