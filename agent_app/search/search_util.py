# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_utils.py

import os
import ast
import glob

from typing import *
from dataclasses import dataclass

from agent_app.data_structures import LineRange, BaseCodeSnippetLocation
from agent_app.static_analysis.py_ast_parse import (
    extract_class_sig_lines_from_file as extract_class_sig_lines_from_py_file
)
from agent_app.static_analysis.java_ast_parse import (
    extract_class_sig_lines_from_file as extract_class_sig_lines_from_java_file
)


"""SEARCH RESULT DATACLASS"""


@dataclass
class PySearchResult(BaseCodeSnippetLocation):
    """Dataclass to hold the search result containing the location of Python code snippet."""
    func_name: str | None
    class_name: str | None
    inclass_method_name: str | None

    def to_tagged_upto_func(self) -> str:
        """Convert the code snippet location to a tagged string, upto function."""
        prefix = self.to_tagged_upto_file()
        func_part = f"<func>{self.func_name}</func>" if self.func_name is not None else ""
        return f"{prefix}{func_part}"

    def to_tagged_upto_class(self) -> str:
        """Convert the code snippet location to a tagged string, upto class."""
        prefix = self.to_tagged_upto_file()
        class_part = f"<class>{self.class_name}</class> " if self.class_name is not None else ""
        return f"{prefix}\n{class_part}"

    def to_tagged_upto_inclass_func(self) -> str:
        """Convert the code snippet location to a tagged string, upto inclass method."""
        prefix = self.to_tagged_upto_class()
        inclass_func_part = f"<func>{self.inclass_method_name}</func>" if self.inclass_method_name is not None else ""
        return f"{prefix}{inclass_func_part}"

    def to_tagged_str(self) -> str:
        """Convert the code snippet location to a tagged string."""
        # Cannot in top-level function / class at the same time.
        assert (self.func_name is not None) + (self.class_name is not None) <= 1

        if self.func_name is not None:
            prefix = self.to_tagged_upto_func()
        elif self.class_name is not None:
            prefix = self.to_tagged_upto_inclass_func()
        else:
            prefix = self.to_tagged_upto_file()
        code_part = f"<code>\n{self.code}\n</code>"
        return f"{prefix}\n{code_part}"

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "func_name": self.func_name,
            "class_name": self.class_name,
            "inclass_func_name": self.inclass_method_name,
            "code": self.code
        }


@dataclass
class JavaSearchResult(BaseCodeSnippetLocation):
    """Dataclass to hold the search result containing the location of Java code snippet."""
    package_name: str | None = None
    iface_name: str | None = None
    class_name: str | None = None
    inclass_iface_name: str | None = None
    inclass_class_name: str | None = None
    inclass_method_name: str | None = None

    def to_tagged_upto_iface(self) -> str:
        """Convert the code snippet location to a tagged string, upto interface."""
        prefix = self.to_tagged_upto_file()
        iface_part = f"<iface>{self.iface_name}</iface>" if self.iface_name is not None else ""
        return f"{prefix}{iface_part}"

    def to_tagged_upto_class(self) -> str:
        """Convert the code snippet location to a tagged string, upto class."""
        prefix = self.to_tagged_upto_file()
        class_part = f"<class>{self.class_name}</class> " if self.class_name is not None else ""
        return f"{prefix}\n{class_part}"

    def to_tagged_upto_inclass_type(self) -> str:
        """Convert the code snippet location to a tagged string, upto inclass method / interface / class."""
        # Cannot in inclass method / interface / class at the same time.
        assert (self.inclass_method_name is not None) + \
               (self.inclass_iface_name is not None) + \
               (self.inclass_class_name is not None) <= 1

        prefix = self.to_tagged_upto_class()
        if self.inclass_method_name is not None:
            inclass_type_part = f"<func>{self.inclass_method_name}</func>"
        elif self.inclass_iface_name is not None:
            inclass_type_part = f"<iface>{self.inclass_iface_name}</iface>"
        elif self.inclass_class_name is not None:
            inclass_type_part = f"<class>{self.inclass_class_name}</class>"
        else:
            inclass_type_part = ""
        return f"{prefix}{inclass_type_part}"

    def to_tagged_str(self) -> str:
        """Convert the code snippet location to a tagged string."""
        # Cannot in interface / class at the same time.
        assert (self.iface_name is not None) + (self.class_name is not None) <= 1

        if self.iface_name is not None:
            prefix = self.to_tagged_upto_iface()
        elif self.class_name is not None:
            prefix = self.to_tagged_upto_inclass_type()
        else:
            prefix = self.to_tagged_upto_file()
        code_part = f"<code>\n{self.code}\n</code>"
        return f"{prefix}\n{code_part}"

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "package_name": self.package_name,
            "interface_name": self.iface_name,
            "class_name": self.class_name,
            "inclass_func_name": self.inclass_method_name,
            "inclass_iface_name": self.inclass_iface_name,
            "inclass_class_name": self.inclass_class_name,
            "code": self.code
        }


"""REPO FILES"""


def find_python_files(dir_path: str) -> List[str]:
    """Get all .py files recursively from a directory.

    Skips files that are obviously not from the source code, such third-party library code.
    Args:
        dir_path (str): Path to the directory.
    Returns:
        List[str]: List of .py file paths. These paths are ABSOLUTE path!
    """
    abs_py_fpaths = glob.glob(os.path.join(dir_path, "**/*.py"), recursive=True)
    res = []
    for abs_fpath in abs_py_fpaths:
        rel_path = abs_fpath[len(dir_path) + 1:]
        if rel_path.startswith("build"):
            continue
        res.append(abs_fpath)
    return res


def find_java_files(dir_path: str) -> List[str]:
    """Get all .java files recursively from a directory.

    Args:
        dir_path (str): Path to the directory.
    Returns:
        List[str]: List of .java file paths. These paths are ABSOLUTE path!
    """
    abs_java_fpaths = glob.glob(os.path.join(dir_path, "**/*.java"), recursive=True)
    return abs_java_fpaths


"""MERGED LINES"""


def is_overlap_in_merged_file(
        old_range: LineRange,
        new_range: LineRange,
        line_id_old2merge: Dict[int, int],
        line_id_new2merge: Dict[int, int]
) -> bool:
    old_merge_range = (line_id_old2merge[old_range.start], line_id_old2merge[old_range.end])
    new_merge_range = (line_id_new2merge[new_range.start], line_id_new2merge[new_range.end])
    return old_merge_range[0] <= new_merge_range[1] and new_merge_range[0] <= old_merge_range[1]


def group_overlap_struct_line_range(
        old_lranges: List[LineRange],
        new_lranges: List[LineRange],
        line_id_old2merge: Dict[int, int],
        line_id_new2merge: Dict[int, int]
) -> List[Tuple[List[LineRange], List[LineRange]]]:
    """Group line ranges that belongs to the same structure before and after the modification.

    NOTE 1: All input line ranges are from the same file, including before and after modification.
    NOTE 2: All input line ranges are line ranges of structures.
    NOTE 3: Here structure indicates function, interface, class, methods and so on.
    NOTE 4: We only check if there is any overlap between the old and new line ranges after they are mapped into the merged file.
    TODO: If a code snippet A is copied, deleted, and pasted to a new location B, although their functions are
          exactly the same, since they have no overlapping code lines in the merged code, they are considered
          as two independent code snippets, i.e. A is a deleted snippet and B is an added code snippet.
    NOTE 5: It may happen that OLD_i and NEW_j overlap, OLD_k and NEW_j overlap, but OLD_i and OLD_k do not overlap,
            but we still put OLD_i, OLD_k and NEW_j into the same group.
    """
    overlap_lrange_groups: List[Tuple[List[LineRange], List[LineRange]]] = []  # [([old line range], [new line range])]

    old_lrange_group_id_map: Dict[int, int] = {}  # old line range id -> group id
    new_lrange_group_id_map: Dict[int, int] = {}  # new line range id -> group id

    # (1) Find overlapping new line ranges for each old line range
    for i, old_lrange in enumerate(old_lranges):
        cur_group_id = len(overlap_lrange_groups)
        cur_group: Tuple[List[LineRange], List[LineRange]] = ([], [])

        cur_old_lrange_ids: List[int] = []
        cur_new_lrange_ids: List[int] = []

        # 1. Update current group
        cur_group[0].append(old_lrange)
        cur_old_lrange_ids.append(i)

        for j, new_lrange in enumerate(new_lranges):
            if is_overlap_in_merged_file(old_lrange, new_lrange, line_id_old2merge, line_id_new2merge):
                # Determine if the current group can be merged into the collected group
                if j in new_lrange_group_id_map:
                    cur_group_id = new_lrange_group_id_map[j]
                    cur_group = overlap_lrange_groups[cur_group_id]

                cur_group[1].append(new_lrange)
                cur_new_lrange_ids.append(j)

        if cur_group_id < len(overlap_lrange_groups):
            overlap_lrange_groups[cur_group_id] = cur_group
        else:
            overlap_lrange_groups.append(cur_group)

        # 2. Update mapping from lrange id to group id
        for lrange_id in cur_old_lrange_ids:
            old_lrange_group_id_map[lrange_id] = cur_group_id

        for lrange_id in cur_new_lrange_ids:
            new_lrange_group_id_map[lrange_id] = cur_group_id

    # (2) Add new line ranges with no overlapping old line range
    left_new_lrange_ids = list(set(list(range(len(new_lranges)))) - set(list(new_lrange_group_id_map.keys())))

    for lrange_id in left_new_lrange_ids:
        new_lrange = new_lranges[lrange_id]
        overlap_lrange_groups.append(([], [new_lrange]))

    return overlap_lrange_groups


"""EXTRACT CODE SNIPPET"""


def get_code_snippet_from_file_content(file_content: str, line_ids: List[int]) -> str:
    """Get the code snippet from the file content according to the line ids.

    Args:
        file_content (str): File content.
        line_ids (List[int]): Code snippet line ids. (1-based)
    """
    file_lines = file_content.splitlines(keepends=True)
    snippet = ""
    for line_id in line_ids:
        snippet += file_lines[line_id - 1]
    return snippet


def get_code_snippet_from_diff_file(
        merged_file_content: str,
        old_line_ranges: List[LineRange],
        new_line_ranges: List[LineRange],
        line_id_old2merge: Dict[int, int],
        line_id_new2merge: Dict[int, int]
) -> str:
    """Get code snippet in the range from the file content.

    NOTE 1: Valid for Python file and Java file.
    NOTE 2: For diff files, since we have stored their merged version in the SearchManager,
            so we get their contents from the storage instead of the local repo.
    """
    # (1) Map line ranges in the old file and new file to the merged file
    merge_lranges_for_old: List[LineRange] = [LineRange(line_id_old2merge[lrange.start], line_id_old2merge[lrange.end])
                                              for lrange in old_line_ranges]
    merge_lranges_for_new: List[LineRange] = [LineRange(line_id_new2merge[lrange.start], line_id_new2merge[lrange.end])
                                              for lrange in new_line_ranges]

    # (2) Find the smallest line range that contains these line ranges
    try:
        range_start = min(
            [lrange.start for lrange in merge_lranges_for_old] +
            [lrange.start for lrange in merge_lranges_for_new]
        )
    except ValueError:
        range_start = None
    try:
        range_end = max(
            [lrange.end for lrange in merge_lranges_for_old] +
            [lrange.end for lrange in merge_lranges_for_new]
        )
    except ValueError:
        range_end = None

    assert range_start is not None and range_end is not None

    # (3) Extract the code snippet within this line range
    snippet_line_ids = list(range(range_start, range_end + 1))
    snippet = get_code_snippet_from_file_content(merged_file_content, snippet_line_ids)

    return snippet


def get_code_snippet_from_nodiff_file(abs_fpath: str, line_start: int, line_end: int) -> str:
    """Get the code snippet in the range from the file content.

    NOTE 1: Valid for Python file and Java file.
    NOTE 2: For nodiff files, we get their contents from the local repo.
    Args:
        abs_fpath (str): Absolute path to the file.
        line_start (int): Start line id. (1-based)
        line_end (int): End line id. (1-based)
    """
    with open(abs_fpath, 'r') as f:
        file_content = f.read()

    snippet_line_ids = list(range(line_start, line_end + 1))
    snippet = get_code_snippet_from_file_content(file_content, snippet_line_ids)

    return snippet


def get_class_signature_from_nodiff_file(
        abs_fpath: str,
        class_name: str,
        class_range: LineRange,
        lang: Literal['Python', 'Java']
) -> str:
    """Get the signature of the specified class from the file.

    NOTE 1: Valid for Python or Java file.
    NOTE 2: Only for nodiff file.
    NOTE 3: Input is file path. We get the file content by reading it from the local repo.
    Args:
        abs_fpath (str): Absolute path to the code file.
        class_name (str): Class name.
        class_range (LineRange): Class line range.
        lang (str): Programming language. ['Python', 'Java']
    """
    with open(abs_fpath, "r") as f:
        file_content = f.read()

    if lang == 'Python':
        sig_line_ids = extract_class_sig_lines_from_py_file(file_content, class_name, class_range)
    elif lang == 'Java':
        sig_line_ids = extract_class_sig_lines_from_java_file(
            code=None, code_fpath=abs_fpath, class_name=class_name, class_range=class_range
        )
    else:
        raise RuntimeError(f"Language '{lang}' is not supported yet.")

    assert len(sig_line_ids) > 0

    sig_snippet = get_code_snippet_from_file_content(file_content, sig_line_ids)

    return sig_snippet


def get_class_signature_from_diff_file(
        merge_file_content: str,
        old_file_content: str | None,
        new_file_content: str | None,
        line_id_old2merge: Dict[int, int] | None,
        line_id_new2merge: Dict[int, int] | None,
        class_name: str,
        old_class_range: LineRange | None,
        new_class_range: LineRange | None,
        lang: Literal['Python', 'Java']
) -> str:
    """Get the signature of the specified class from the file.

    NOTE 1: Valid for Python or Java file.
    NOTE 2: Only for diff file.
    NOTE 3: Input is file content. Since we have stored the merged version of diff files in the SearchManager,
            so we get their contents from the storage instead of the local repo.
    Args:
        merge_file_content (str): Content of merged file.
        old_file_content (str | None): Content of the old file.
        new_file_content (str | None): Content of the new file.
        line_id_old2merge (Dict[int, int] | None): Line id mapping from old code to merged code.
        line_id_new2merge (Dict[int, int] | None): Line id mapping from new code to merged code.
        class_name (str): Name of the class.
        old_class_range (LineRange | None): Line range of the class in the old file.
        new_class_range (LineRange | None): Line range of the class in the new file.
        lang (str): Programming language. ['Python', 'Java']
    """
    if old_file_content is None or new_file_content is None:
        # Deleted / added file
        if old_file_content is not None:
            assert line_id_old2merge is not None and old_class_range is not None
            ori_content = old_file_content
            class_range = old_class_range
            line_id_ori2merge = line_id_old2merge
        else:
            assert line_id_new2merge is not None and new_class_range is not None
            ori_content = new_file_content
            class_range = new_class_range
            line_id_ori2merge = line_id_new2merge

        if lang == 'Python':
            sig_line_ids = extract_class_sig_lines_from_py_file(ori_content, class_name, class_range)
        elif lang == 'Java':
            sig_line_ids = extract_class_sig_lines_from_java_file(
                code=ori_content, code_fpath=None, class_name=class_name, class_range=class_range
            )
        else:
            raise RuntimeError(f"Language '{lang}' is not supported yet.")

        merge_sig_line_ids = [line_id_ori2merge[li] for li in sig_line_ids]

        sig_snippet = get_code_snippet_from_file_content(merge_file_content, merge_sig_line_ids)

    else:
        # Modified file
        assert line_id_old2merge is not None and line_id_new2merge is not None

        if old_class_range is not None and line_id_old2merge is not None:
            assert is_overlap_in_merged_file(old_class_range, line_id_old2merge, new_class_range, line_id_new2merge)
        else:
            assert old_class_range is not None or line_id_old2merge is not None

        old_sig_line_ids: List[int] = []
        new_sig_line_ids: List[int] = []
        if lang == 'Python':
            if old_class_range is not None:
                old_sig_line_ids = extract_class_sig_lines_from_py_file(old_file_content, class_name, old_class_range)
            if new_class_range is not None:
                new_sig_line_ids = extract_class_sig_lines_from_py_file(new_file_content, class_name, new_class_range)
        elif lang == 'Java':
            if old_class_range is not None:
                old_sig_line_ids = extract_class_sig_lines_from_java_file(
                    code=old_file_content, code_fpath=None, class_name=class_name, class_range=old_class_range
                )
            if new_class_range is not None:
                new_sig_line_ids = extract_class_sig_lines_from_java_file(
                    code=new_file_content, code_fpath=None, class_name=class_name, class_range=new_class_range
                )
        else:
            raise RuntimeError(f"Language '{lang}' is not supported yet.")

        merge_sig_line_ids = []
        for old_line_id in old_sig_line_ids:
            merge_sig_line_ids.append(line_id_old2merge[old_line_id])

        for new_line_id in new_sig_line_ids:
            merge_sig_line_ids.append(line_id_new2merge[new_line_id])

        merge_sig_line_ids = sorted(list(set(merge_sig_line_ids)))

        sig_snippet = get_code_snippet_from_file_content(merge_file_content, merge_sig_line_ids)

    return sig_snippet
