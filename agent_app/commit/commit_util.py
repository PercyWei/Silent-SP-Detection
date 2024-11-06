from __future__ import annotations

import json
import re
import tokenize
import subprocess
from collections import defaultdict

from typing import *
from io import StringIO
from dataclasses import dataclass
from enum import Enum

from agent_app import globals_opt
from agent_app.static_analysis.py_ast_parse import (
    ASTParser as PyASTParser,
    extract_func_sig_lines_from_snippet as extract_func_sig_lines_from_py_code,
    extract_class_sig_lines_from_snippet as extract_class_sig_lines_from_py_code
)
from agent_app.static_analysis.java_ast_parse import (
    ASTParser as JavaASTParser,
    filter_code_content_by_processing_java_script,
    extract_iface_sig_lines_from_snippet as extract_iface_sig_lines_from_java_code,
    extract_class_sig_lines_from_snippet as extract_class_sig_lines_from_java_code,
    extract_method_sig_lines_from_snippet as extract_method_sig_lines_from_java_code
)
from agent_app.data_structures import (
    DiffFileInfo, PyDiffFileInfo, JavaDiffFileInfo,
    PySimNodeType, JavaSimNodeType,
    PySimNode, JavaSimNode
)
from agent_app.util import make_tmp_file, remove_tmp_file
from utils import run_command


class SourceFileType(str, Enum):
    OLD = "before_commit"
    NEW = "after_commit"

    @staticmethod
    def attributes():
        return [k.value for k in SourceFileType]


"""GET FILE CONTENT"""


def get_code_before_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str, parent_id: int = 1) -> str | None:
    """
    Get file content before applying the given commit.

    Args:
        local_repo_dpath (str): Path to the local repository dir.
        commit_hash (str): Commit hash.
        rel_fpath (str): Relative (to the local repo root) file path.
        parent_id (int): ID of the parent comment.
    Returns:
        str | None: Content of file before applying the given commit. None if failed to get the content.
    """
    git_show_cmd = ['git', 'show', f'{commit_hash}^{parent_id}:{rel_fpath}']

    result, _ = run_command(git_show_cmd, raise_error=False,
                            cwd=local_repo_dpath, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result is not None:
        return result.stdout
    else:
        return None


def get_code_after_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str) -> str | None:
    """Get file content after applying the given commit.

    Args:
        local_repo_dpath (str): Path to the local repository dir.
        commit_hash (str): Commit hash.
        rel_fpath (str): Relative (to the local repo root) file path.
    Returns:
        str | None: Content of file after applying the given commit. None if failed to get the content.
    """
    git_show_cmd = ['git', 'show', f'{commit_hash}:{rel_fpath}']

    result, _ = run_command(git_show_cmd, raise_error=False,
                            cwd=local_repo_dpath, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result is not None:
        return result.stdout
    else:
        return None


"""EXTRACT RAW COMMIT CONTENT INFO"""


# FIXME: Use 'pydriller' and 'unidiff'
def parse_commit_content(commit_content: str, file_suffix: List[str] | None = None) -> List[Dict]:
    # TODO: For now, we only focus on Python code.
    if file_suffix is None:
        # file_suffix = [".c", ".cc", ".java", ".py", ".js", ".php", ".h", ".rb", ".go", ".ts", ".tsx"]
        file_suffix = [".py"]

    commit_with_parent_line_pattern = r"^commit (\b[a-f0-9]{40}\b) \(from (\b[a-f0-9]{40}\b)\)$"
    commit_line_pattern = r"^commit (\b[a-f0-9]{40}\b)$"
    merge_line_pattern = r'Merge:\s((?:[a-f0-9]+\s?)+)'

    commit_content_lines = commit_content.splitlines(keepends=False)

    # Match the merge lines (Merge: xxx xxx xxx)
    parent_commits: List[str] = []
    merge_lines: List[int] = []
    for idx, line in enumerate(commit_content_lines):
        match = re.match(merge_line_pattern, line)
        if match:
            hashes = match.group(1).split()
            # Check
            if not parent_commits:
                parent_commits = hashes
            else:
                assert parent_commits == hashes
            # Record
            merge_lines.append(idx)

    if parent_commits:
        # This commit has more than one parent commits
        assert len(parent_commits) == len(merge_lines)

        # (1) Get ranges in commit recording info from different parent commits
        line_ranges: List[Tuple[int, int]] = []
        for i in range(len(merge_lines) - 1):
            # Get range
            start = merge_lines[i] - 1
            end = merge_lines[i + 1] - 2
            # Check
            assert re.match(commit_with_parent_line_pattern, commit_content_lines[start])
            # Record
            line_ranges.append((start, end))
        # The last range
        start = merge_lines[-1] - 1
        end = len(commit_content_lines) - 1
        # Check
        assert re.match(commit_with_parent_line_pattern, commit_content_lines[start])
        # Record
        line_ranges.append((start, end))

        # (2) Extract info range by range
        total_diff_file_info: List[Dict] = []
        for i, (start, end) in enumerate(line_ranges):
            range_lines = commit_content_lines[start: end + 1]
            diff_file_info = extract_diff_files_info(range_lines, file_suffix, i + 1)

            total_diff_file_info.extend(diff_file_info)

    else:
        # This commit has only one parent commit
        assert re.match(commit_line_pattern, commit_content_lines[0])

        total_diff_file_info = extract_diff_files_info(commit_content_lines, file_suffix)

    return total_diff_file_info


# A commit is generally organized in the following format:
# +++++++++++++++++++++++ <commit> +++++++++++++++++++++++
# commit <commit_id>
# Author: <author>
# Date: <timestamp>
#
#   <description>
#
#     <changed_file_info / section-1>
#     <changed_file_info / section-2>
#     ...
#     ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#
#     Each <changed_file_info / section-i> corresponds to info of one changed file,
#     while <changed_file_info / section-1> is generally organized in the following format:
#
#     =========== <changed_file_info / section-i> ===========
#     diff --git <old_file_path> <new_file_path>
#     ((new / deleted) file mode <id1>)
#     index <old_id>..<new_id> (id2)
#     --- <old_file_path>
#     +++ <new_file_path>
#     <changed_code_snippet_info / hunk-1>
#     <changed_code_snippet_info / hunk-2>
#     ...
#     =======================================================
#
#     Each <changed_code_snippet_info / hunk-j> corresponds to info of one changed code snippet,
#     while <changed_code_snippet_info / hunk-j> is generally organized in the following format:
#
#     -------- <changed_code_snippet_info / hunk-j> --------
#     @@ -<old_file_line_start_idx>,<old_file_line_scope> +<new_file_line_start_idx>,<new_file_line_scope> @@ (<function name>)
#     <changed_code_snippet>
#     ------------------------------------------------------


def extract_diff_files_info(
        commit_content_lines: List[str],
        file_suffix: List[str] | None = None,
        parent_commit: int = 1
) -> List[Dict]:
    """Extract and collate info of diff files which have the same parent commit from the raw commit.

    Args:
        commit_content_lines (List[str]): The raw commit content lines.
        file_suffix (List[str] | None): Selection of the suffix of files involved in the commit.
        parent_commit (int): The ID of the parent commit of this commit.
    Returns:
        List: The info of commit content.
            Format:
            [
                {
                    "parent_commit": The ID of the parent commit of this commit.
                    "old_fpath": relative path of the file before commit, "/dev/null" for added file.
                    "new_fpath": relative path of the file after commit, "/dev/null" for removed file.
                    "file_type": "added" / "removed" / "modified
                    "code_diff":
                    [
                        {
                            "diff_code_snippet": List[str]
                            "diff_line_indexes": List (0-based)
                            "old_start_line_id": int (1-based)
                            "old_line_scope":    int
                            "old_line_index2id": Dict (0-based -> 1-based)
                            "new_start_line_id": int (1-based)
                            "new_line_scope":    int
                            "new_line_index2id": Dict (0-based -> 1-based)
                        }
                        {...}
                        ...
                    ]
                }
                {...}
                ...
            ]
    """
    if file_suffix is None:
        # file_suffix = [".c", ".cc", ".java", ".py", ".js", ".php", ".h", ".rb", ".go", ".ts", ".tsx"]
        file_suffix = [".py"]

    diff_line_pattern = r"diff --git (.+) (.+)"               # must exist
    add_file_line_pattern = r"new file mode (\d+)"            # may exist
    remove_file_line_pattern = r"deleted file mode (\d+)"     # may exist
    index_line_pattern = r"index (\w+)\.\.(\w+)(?: .*)?$"     # must exist
    old_fpath_pattern = r"--- (.+)"                           # may exist
    new_fpath_pattern = r"\+\+\+ (.+)"                        # may exist
    line_id_pattern = r"@@ -(\d+),(\d+) \+(\d+),(\d+) (.*)$"  # may exist

    # Match the section start line (diff --git xxx xxx)
    # diff line id -> (old fpath, new fpath)
    changed_fpath_lines: Dict[int, Tuple[str, str]] = {}
    for idx, line in enumerate(commit_content_lines):
        line = line.rstrip('\n')
        diff_line_match = re.match(diff_line_pattern, line)
        if diff_line_match:
            changed_fpath_lines[idx] = (diff_line_match.group(1), diff_line_match.group(2))

    # Extract code change info section-by-section
    commit_content_info: List[Dict] = []
    for i, section_start_line_idx in enumerate(changed_fpath_lines.keys()):
        # Select only code changes in the specified files
        # TODO: Only extract commit content related to Python code.
        old_fpath, new_fpath = changed_fpath_lines[section_start_line_idx]
        if not (any(old_fpath.endswith(suf) for suf in file_suffix) and
                any(new_fpath.endswith(suf) for suf in file_suffix)):
            continue

        # Current section start and end line idx
        section_end_line_idx = list(changed_fpath_lines.keys())[i + 1] - 1 \
            if i < len(changed_fpath_lines) - 1 else len(commit_content_lines) - 1

        current_line_idx = section_start_line_idx

        # ----------------- format: new file mode <index> / deleted file mode <index> ------------------ #
        # File type: added, removed, modified
        file_type = "modified"
        add_file_flag = False
        remove_file_flag = False
        if re.match(add_file_line_pattern, commit_content_lines[section_start_line_idx + 1]):
            add_file_flag = True
            file_type = "added"
            current_line_idx += 1
        if re.match(remove_file_line_pattern, commit_content_lines[section_start_line_idx + 1]):
            remove_file_flag = True
            file_type = "removed"
            current_line_idx += 1

        assert not (add_file_flag and remove_file_flag)

        # TODO: When only the path of a file is changed without modifying, the commit will contain the following content
        #       """
        #       diff --git <old_file_path> <new_file_path>
        #       similarity index 100%
        #       rename from <old_file_path>
        #       rename to <new_file_path>
        #       """
        #       For this, we do not need to record its changes.
        # ex: https://github.com/E2OpenPlugins/e2openplugin-OpenWebif/commit/a846b7664eda3a4c51a452e00638cf7337dc2013
        #     plugin/utilities.py -> plugin/controllers/utilities.py
        if commit_content_lines[current_line_idx + 1] == "similarity index 100%":
            assert re.match(r"^rename\s+from\s+(.+)$", commit_content_lines[current_line_idx + 2])
            assert re.match(r"^rename\s+to\s+(.+)$", commit_content_lines[current_line_idx + 3])
            continue

        # ----------------- format: index <index1>..<index2> ----------------- #
        assert re.match(index_line_pattern, commit_content_lines[current_line_idx + 1])
        current_line_idx += 1

        if current_line_idx > section_end_line_idx:
            # TODO: When adding or removing an empty file, there is no subsequent content.
            # ex: https://github.com/cobbler/cobbler/commit/d8f60bbf14a838c8c8a1dba98086b223e35fe70a
            #     tests/actions/__init__.py
            continue

        # ----------------- format: diff --git <file_path_1> <file_path_2> ----------------- #
        assert re.match(old_fpath_pattern, commit_content_lines[current_line_idx + 1])
        assert re.match(new_fpath_pattern, commit_content_lines[current_line_idx + 2])

        old_fpath = re.match(old_fpath_pattern, commit_content_lines[current_line_idx + 1]).group(1)
        new_fpath = re.match(new_fpath_pattern, commit_content_lines[current_line_idx + 2]).group(1)
        current_line_idx += 2

        if add_file_flag:
            assert old_fpath == '/dev/null'
            old_fpath = None
        if remove_file_flag:
            assert new_fpath == '/dev/null'
            new_fpath = None

        if old_fpath is not None:
            old_fpath = '/'.join(old_fpath.split('/')[1:])
        if new_fpath is not None:
            new_fpath = '/'.join(new_fpath.split('/')[1:])

        curr_diff_file_info = {
            "parent_commit": parent_commit,  # (int)
            "old_fpath": old_fpath,  # (str | None) old file path / None
            "new_fpath": new_fpath,  # (str | None) new file path / None
            "file_type": file_type,  # (str) modified / added / removed
            "code_diff": []
        }

        assert re.match(line_id_pattern, commit_content_lines[current_line_idx + 1])
        current_line_idx += 1

        # ----------------- format: @@ -<idx_1>,<scope_1> +<idx_2>,<scope_2> @@ xxx ----------------- #
        diff_code_info_start_list = []
        for idx in range(current_line_idx, section_end_line_idx + 1):
            if re.match(line_id_pattern, commit_content_lines[idx]):
                diff_code_info_start_list.append(idx)

        # ----------------- Extract changed code snippet of each hunk ----------------- #
        for j, hunk_start_line_idx in enumerate(diff_code_info_start_list):
            ## Current section start and end line idx
            hunk_end_line_idx = diff_code_info_start_list[j + 1] - 1 \
                if j < len(diff_code_info_start_list) - 1 else section_end_line_idx

            ## Code snippet loc info before and after commit
            old_line_start, old_line_scope, new_line_start, new_line_scope, rest = \
                re.match(line_id_pattern, commit_content_lines[hunk_start_line_idx]).groups()

            ## Changed code snippet
            diff_code_snippet = commit_content_lines[hunk_start_line_idx + 1: hunk_end_line_idx + 1]
            # NOTE: This flag appears when the python code does not end in a blank line and happens to be commited,
            #       but this line is not actually shown in the code
            # exp: https://github.com/sergeKashkin/Simple-RAT/commit/ef93261b05f1bbbefb47c7c6115cfa0a85cec22b
            #      line between 288 (old code) and 300 (new code)
            diff_code_snippet = [line for line in diff_code_snippet if line != "\ No newline at end of file"]

            ## Delete line (in old file) and add line (in new line) ids
            # (1) changed_code_snippet index
            diff_line_indexes: List[int] = []
            # (2) changed_code_snippet index -> (old / new) file line id
            old_line_index2id: Dict[int, int] = {}
            new_line_index2id: Dict[int, int] = {}

            cur_old_line_id = int(old_line_start) - 1
            cur_new_line_id = int(new_line_start) - 1
            for k, line in enumerate(diff_code_snippet):
                if line.startswith("+"):
                    cur_new_line_id += 1
                    diff_line_indexes.append(k)
                    new_line_index2id[k] = cur_new_line_id
                elif line.startswith("-"):
                    cur_old_line_id += 1
                    diff_line_indexes.append(k)
                    old_line_index2id[k] = cur_old_line_id
                else:
                    cur_new_line_id += 1
                    cur_old_line_id += 1

            curr_code_diff = {
                # For all diff lines
                "diff_code_snippet": diff_code_snippet,  # List[str]
                "diff_line_indexes": diff_line_indexes,  # List, 0-based
                # For diff lines in old file
                "old_start_line_id": int(old_line_start),  # int, 1-based
                "old_line_scope": int(old_line_scope),     # int
                "old_line_index2id": old_line_index2id,    # Dict, 0-based -> 1-based
                # For diff lines in new file
                "new_start_line_id": int(new_line_start),  # int, 1-based
                "new_line_scope": int(new_line_scope),     # int
                "new_line_index2id": new_line_index2id     # Dict, 0-based -> 1-based
            }

            curr_diff_file_info["code_diff"].append(curr_code_diff)

        commit_content_info.append(curr_diff_file_info)

    return commit_content_info


"""EXTRACT DIFF LINES"""


@dataclass
class DiffLine:
    """For recording a line deleted / added."""
    id: int  # 0-based
    source: SourceFileType | None
    lineno: int | None
    code: str | None
    sep: bool


def _build_sep_for_diff_lines(cur_id: int) -> DiffLine:
    return DiffLine(id=cur_id, source=None, lineno=None, code=None, sep=True)


def _get_diff_line_source_file(diff_line: str) -> SourceFileType:
    if diff_line.startswith("-"):
        return SourceFileType.OLD
    elif diff_line.startswith("+"):
        return SourceFileType.NEW
    else:
        raise Exception("Unexpected diff line")


def extract_all_diff_lines_within_file(diff_file_info: Dict) -> List[DiffLine]:
    """Extract all diff code within a file of the commit, using sep to separate discontinuous diff lines.

    NOTE: Only for modified files.
    Args:
        diff_file_info (Dict): For detailed format, see the method 'extract_diff_files_info'.
    Returns:
        List[DiffLine]: All diff lines within a file.
    """
    diff_lines: List[DiffLine] = []

    for diff_code_info in diff_file_info["code_diff"]:
        last_line_is_diff = False

        cur_diff_code = diff_code_info["diff_code_snippet"]
        cur_old_line_index2id = diff_code_info["old_line_index2id"]
        cur_new_line_index2id = diff_code_info["new_line_index2id"]

        for ind, line in enumerate(cur_diff_code):
            if line.startswith("-") or line.startswith("+"):
                source = _get_diff_line_source_file(line)
                line_id = cur_old_line_index2id[ind] if ind in cur_old_line_index2id else cur_new_line_index2id[ind]

                if len(diff_lines) == 0:
                    # Do not add "..." in the beginning anyway
                    diff_line = DiffLine(id=len(diff_lines), source=source, lineno=line_id, code=line, sep=False)
                    diff_lines.append(diff_line)
                elif last_line_is_diff:
                    diff_line = DiffLine(id=len(diff_lines), source=source, lineno=line_id, code=line, sep=False)
                    diff_lines.append(diff_line)
                else:
                    sep = _build_sep_for_diff_lines(len(diff_lines))
                    diff_lines.append(sep)

                    diff_line = DiffLine(id=len(diff_lines), source=source, lineno=line_id, code=line, sep=False)
                    diff_lines.append(diff_line)

                last_line_is_diff = True
            else:
                last_line_is_diff = False

    return diff_lines


"""CODE FILTER"""


def _is_only_comment(line: str) -> bool:
    """Check if the given line contains only a comment.

    Args:
        line (str): Python code line, which does not contain line breaks.
    Returns:
        bool: True if the line contains only a comment, False otherwise.
    """
    assert re.search(r'#(.*)$', line)
    return line.strip().startswith('#')


def _update_line_id_map_for_filtering(line_id_map: Dict[int, int], retained_line_ids: List[int]) -> Dict[int, int]:
    """Update line id mapping for code filtering.

    Args:
        line_id_map (Dict[int, int]): Line id mapping from original code to filtered code.
        retained_line_ids (List[int]): Retained line ids.
    Returns:
        Dict[int, int]: Line id mapping (1-based) from original code to new filtered code.
    """
    ## Check
    assert set(retained_line_ids).issubset(set(line_id_map.values()))

    ## Update
    new_line_id_map: Dict[int, int] = {}

    line_id_map = dict(sorted(line_id_map.items()))
    retained_line_ids = sorted(retained_line_ids)

    for ori_line_id, map_line_id in line_id_map.items():
        if map_line_id in retained_line_ids:
            new_map_line_id = retained_line_ids.index(map_line_id) + 1
            new_line_id_map[ori_line_id] = new_map_line_id

    return new_line_id_map


def filter_comments_in_py_code(code: str, line_id_map: Dict[int, int]) -> Tuple[str, Dict[int, int]]:
    """Filter out comments in Python code.
    TODO: Since multi-line comments marked with three single quotes or three double quotes are parsed as ast.Expr in
          python ast, for now, we only consider single-line commits that won't be parsed by ast and also take up a
          single line.
    """
    ## Step 1: Check
    code_lines = code.splitlines(keepends=False)
    if line_id_map:
        assert len(code_lines) == len(line_id_map)
    else:
        line_id_map = {i: i for i in range(1, len(code_lines) + 1)}

    ## Step 2: Find all comment lines
    cand_comment_line_ids: List[int] = []

    code_io = StringIO(code)
    tokens = tokenize.generate_tokens(code_io.readline)
    for token in tokens:
        if token.type == tokenize.COMMENT:
            cand_comment_line_ids.append(token.start[0])

    ## Step 3: Find all comment lines containing only comment
    for i in range(len(cand_comment_line_ids) - 1, -1, -1):
        line_id = cand_comment_line_ids[i]
        if not _is_only_comment(code_lines[line_id - 1]):
            del cand_comment_line_ids[i]

    ## Step 4: Remove all candidate comment lines
    retained_line_ids = sorted(list(set(line_id_map.values()) - set(cand_comment_line_ids)))

    # (1) Filtered code
    filtered_code_lines: List[str] = []
    for i, line in enumerate(code_lines):
        if (i + 1) in retained_line_ids:
            filtered_code_lines.append(line)
    # (2) New line id mapping
    new_line_id_map = _update_line_id_map_for_filtering(line_id_map, retained_line_ids)

    return '\n'.join(filtered_code_lines), new_line_id_map


def filter_blank_lines_in_py_code(code: str, line_id_map: Dict[int, int]) -> Tuple[str, Dict[int, int]]:
    """Filter out blank lines in Python code."""
    ## Check
    code_lines = code.splitlines(keepends=False)
    if line_id_map:
        assert len(code_lines) == len(line_id_map), (f"\n{len(code_lines)}\n"
                                                     f"{json.dumps(code_lines, indent=4)}\n\n"
                                                     f"{len(line_id_map)}\n"
                                                     f"{json.dumps(line_id_map, indent=4)}")
    else:
        line_id_map = {i: i for i in range(1, len(code_lines) + 1)}

    ## Filter
    retained_line_ids: List[int] = []

    # (1) Filtered code
    filtered_code_lines: List[str] = []
    for i, line in enumerate(code_lines):
        if line.strip() != "":
            filtered_code_lines.append(line)
            retained_line_ids.append(i + 1)

    # (2) New line id mapping
    new_line_id_map = _update_line_id_map_for_filtering(line_id_map, retained_line_ids)

    return '\n'.join(filtered_code_lines), new_line_id_map


def filter_py_code_content(
        code: str,
        filter_comment: bool = True,
        filter_blank: bool = True
) -> Tuple[str, Dict[int, int]]:
    """Filter the content of Python code.

    Args:
        code (str): Python code.
        filter_comment (bool): Whether to filter out comments.
        filter_blank (bool): Whether to filter out blank lines.
    Returns:
        str: Filtered python code.
        Dict[int, int]: Line id mapping (1-based) from original code to filtered code.
    """
    code_lines = code.splitlines(keepends=False)
    filtered_code: str = code
    line_id_map: Dict[int, int] = {i: i for i in range(1, len(code_lines) + 1)}

    # Step 1: Filter out comments
    if filter_comment:
        filtered_code, line_id_map = filter_comments_in_py_code(filtered_code, line_id_map)

    # Step 2: Filter out blank lines
    if filter_blank:
        filtered_code, line_id_map = filter_blank_lines_in_py_code(filtered_code, line_id_map)

    return filtered_code, line_id_map


def filter_java_code_content(
        code: str,
        filter_comment: bool = True,
        filter_javadoc: bool = False,
        filter_blank: bool = True
) -> Tuple[str, Dict[int, int]] | None:
    """Filter the content of Java code.

    Args:
       code (str): Java code.
       filter_comment (bool): Whether to filter out comments.
       filter_javadoc (bool): Whether to filter out javadocs.
       filter_blank (bool): Whether to filter out blank lines.
    Returns:
       str: Filtered Java code.
       Dict[int, int]: Line id mapping (1-based) from original code to filtered code.
    """
    code_fpath = None
    output_fpath = None

    filtered_code: str | None = None
    line_id_map: Dict[int, int] | None = None

    try:
        code_fpath = make_tmp_file(code)
        output_fpath = make_tmp_file("", ".json")

        filter_flag = filter_code_content_by_processing_java_script(
            code_fpath, output_fpath, filter_comment, filter_javadoc, filter_blank
        )

        if filter_flag:
            with open(output_fpath, "r") as f:
                filtered_res = json.load(f)

            filtered_code = filtered_res["code"]
            line_id_map = filtered_res["lineIdMap"]

            line_id_map = {int(ori_li): int(new_li) for ori_li, new_li in line_id_map.items()}
            line_id_map = dict(sorted(line_id_map.items()))
    finally:
        if code_fpath is not None:
            remove_tmp_file(code_fpath)
        if output_fpath is not None:
            remove_tmp_file(output_fpath)

    if filtered_code is None or line_id_map is None:
        return None
    else:
        return filtered_code, line_id_map


def filter_file_diff_content(
        file_diff_lines: List[DiffLine],
        old_line_id_map: Dict[int, int],
        new_line_id_map: Dict[int, int]
) -> List[DiffLine]:
    """Filter the changed content of file in the commit according to the (old / new) line id mapping.

    NOTE 1: Only for modified file.
    NOTE 2: Useful for Python file and Java file.
    NOTE 3: 'file_diff_lines' is obtained from function 'combine_diff_code_info_within_file'.
    Args:
        file_diff_lines (List[DiffLine]): List of original diff lines within file.
        old_line_id_map (Dict[int, int]): Line id mapping (1-based) from original old code to filtered old code.
        new_line_id_map (Dict[int, int]): Line id mapping (1-based) from original new code to filtered new code.
    Returns:
        List[DiffLine]: List of filtered diff lines within file.
    """
    filtered_file_diff_lines: List[DiffLine] = []
    last_is_sep = False

    for diff_line in file_diff_lines:
        # (1) Separation
        if diff_line.sep:
            if len(filtered_file_diff_lines) == 0 or last_is_sep:
                # Do not add sep in the beginning or after sep
                pass
            else:
                # Update sep info
                diff_line.id = len(filtered_file_diff_lines)

                filtered_file_diff_lines.append(diff_line)
                last_is_sep = True
            continue

        # (2) Code
        if diff_line.source == SourceFileType.OLD and diff_line.lineno in old_line_id_map:
            # Update diff line info
            diff_line.id = len(filtered_file_diff_lines)
            diff_line.lineno = old_line_id_map[diff_line.lineno]
            # Add diff line
            filtered_file_diff_lines.append(diff_line)
            last_is_sep = False
        elif diff_line.source == SourceFileType.NEW and diff_line.lineno in new_line_id_map:
            # Update diff line info
            diff_line.id = len(filtered_file_diff_lines)
            diff_line.lineno = new_line_id_map[diff_line.lineno]
            # Add diff line
            filtered_file_diff_lines.append(diff_line)
            last_is_sep = False

    if filtered_file_diff_lines and filtered_file_diff_lines[-1].sep:
        filtered_file_diff_lines.pop(-1)

    return filtered_file_diff_lines


"""COMBINE"""


def combine_code_old_and_new(
        old_code: str,
        new_code: str,
        file_diff_lines: List[DiffLine]
) -> Tuple[str, Dict[int, int], Dict[int, int], Dict[int, int]]:
    """Combine old code and new code.

    NOTE 1: Only for modified file.
    NOTE 2: The '+' / '-' at the beginning of the diff line will be retained in the combined code.
    NOTE 3: Old code, new code and diff lines need to be in the same state.
            By default, blank lines and comment lines are filtered out.
    Args:
        old_code (str): Old code.
        new_code (str): New code.
        file_diff_lines (List[DiffLine]): List of diff lines.
    Returns:
        str: Combined code.
        Dict[int, int]: Line id mapping from old code to new code.
        Dict[int, int]: Line id mapping from old code to combined code.
        Dict[int, int]: Line id mapping from new code to combined code.
    """
    #######################################
    # Step I: Group continuous diff lines #
    #######################################

    diff_li_groups: List[List[DiffLine]] = []
    diff_li_group: List[DiffLine] = []

    for diff_li in file_diff_lines:
        if diff_li.sep:
            continue

        if len(diff_li_group) == 0:
            diff_li_group.append(diff_li)
        elif diff_li.id == diff_li_group[-1].id + 1:
            diff_li_group.append(diff_li)
        else:
            assert diff_li.id == diff_li_group[-1].id + 2
            diff_li_groups.append(diff_li_group)
            diff_li_group = [diff_li]

    if len(diff_li_group) > 0:
        diff_li_groups.append(diff_li_group)

    #################################################################
    # Step II: Add unchanged lines to combine old code and new code #
    #################################################################

    old_code_lines = old_code.splitlines(keepends=False)
    new_code_lines = new_code.splitlines(keepends=False)

    line_id_old2new: Dict[int, int] = {}   # 1-based, 1-based
    line_id_old2comb: Dict[int, int] = {}  # 1-based, 1-based
    line_id_new2comb: Dict[int, int] = {}  # 1-based, 1-based

    cur_old_li = cur_new_li = 0

    ####### (1) Add unchanged lines in the beginning #######
    start_diff_li = diff_li_groups[0][0]
    assert old_code_lines[:start_diff_li.lineno - 1] == new_code_lines[:start_diff_li.lineno - 1]

    lines_before: List[str] = old_code_lines[:start_diff_li.lineno - 1]

    for cur_comb_li in range(1, len(lines_before) + 1):
        cur_old_li = cur_new_li = cur_comb_li
        # Update mapping
        line_id_old2new[cur_old_li] = cur_new_li
        line_id_old2comb[cur_old_li] = cur_comb_li
        line_id_new2comb[cur_new_li] = cur_comb_li

    ####### (2) Add unchanged lines between diff line groups #######
    lines_between: List[str] = []

    for i, diff_line_group in enumerate(diff_li_groups):
        # 1. Add unchanged lines, until reaching the first diff line of the current diff_line_group
        group_start_dl = diff_line_group[0]
        while (group_start_dl.source == SourceFileType.OLD and cur_old_li < group_start_dl.lineno - 1) or \
                (group_start_dl.source == SourceFileType.NEW and cur_new_li < group_start_dl.lineno - 1):
            # Update current line (old / new)
            cur_old_li += 1
            cur_new_li += 1
            assert old_code_lines[cur_old_li - 1] == new_code_lines[cur_new_li - 1]
            # Add comb line and update current line (comb)
            lines_between.append(old_code_lines[cur_old_li - 1])
            cur_comb_li = len(lines_before) + len(lines_between)

            # Update mapping
            line_id_old2new[cur_old_li] = cur_new_li
            line_id_old2comb[cur_old_li] = cur_comb_li
            line_id_new2comb[cur_new_li] = cur_comb_li

        # 2. Add diff lines
        for diff_li in diff_line_group:
            # Add comb line and update current line (comb)
            lines_between.append(diff_li.code)
            cur_comb_li = len(lines_before) + len(lines_between)

            # Update current line (old / new) and mapping
            if diff_li.source == SourceFileType.OLD:
                cur_old_li += 1
                line_id_old2comb[cur_old_li] = cur_comb_li
            else:
                cur_new_li += 1
                line_id_new2comb[cur_new_li] = cur_comb_li

    ####### (3) Add unchanged lines in the end #######
    assert old_code_lines[cur_old_li:] == new_code_lines[cur_new_li:]

    lines_after: List[str] = old_code_lines[cur_old_li:]

    for i in range(len(lines_after)):
        # Update current line (old / new / comb)
        cur_old_li += 1
        cur_new_li += 1
        cur_comb_li = len(lines_before) + len(lines_between) + i + 1
        # Update mapping
        line_id_old2new[cur_old_li] = cur_new_li
        line_id_old2comb[cur_old_li] = cur_comb_li
        line_id_new2comb[cur_new_li] = cur_comb_li

    ####### (4) End #######
    code_comb = "\n".join(lines_before + lines_between + lines_after)

    return code_comb, line_id_old2new, line_id_old2comb, line_id_new2comb


"""BUILD FILE DIFF CONTENT"""


def diff_lines_to_str(diff_lines: List[DiffLine]) -> str:
    diff_lines = sorted(diff_lines, key=lambda x: x.id)

    desc = "..."
    last_sep = True

    for diff_line in diff_lines:
        if diff_line.sep and not last_sep:
            desc += "\n..."
            last_sep = True
        elif not diff_line.sep:
            desc += f"\n{diff_line.code}"
            last_sep = False

    if not last_sep:
        desc += "\n..."

    return desc


class DiffContextBuilder:
    """Base tool class for building diff content of file."""
    @staticmethod
    def _adjust_code_snippet_indent(code_lines: List[str]) -> str:
        """Remove spare indent based on the first code line."""
        first_line = code_lines[0]

        indent_len = len(first_line) - len(first_line.lstrip())
        stripped_code_lines = [line[indent_len:] for line in code_lines]

        return '\n'.join(stripped_code_lines)


    @staticmethod
    def _extract_diff_lines_context(
            source: SourceFileType,
            diff_lines: List[DiffLine],
            start_line_id: int,
            end_line_id: int,
            offset: int = 3
    ) -> List[int]:
        """Extract the context of diff lines from a code snippet.
        Strategy: Extract code lines within x (default = 3) lines of the diff line (forward, backward).
        """
        context_line_ids: List[int] = []

        for diff_line in diff_lines:
            if diff_line.source == source and start_line_id <= diff_line.lineno <= end_line_id:
                li_context_start = max(start_line_id, diff_line.lineno - offset)
                li_context_end = min(end_line_id, diff_line.lineno + offset)
                li_context = list(range(li_context_start, li_context_end + 1))
                context_line_ids.extend(li_context)

        context_line_ids = list(set(context_line_ids))

        return context_line_ids


class PyDiffContextBuilder(DiffContextBuilder):
    """Tool class for building diff content of Python file."""
    @staticmethod
    def _extract_relevant_lines_in_func(
            source: SourceFileType,
            func_node: PySimNode,
            code_lines: List[str],
            diff_lines: List[DiffLine]
    ) -> List[int]:
        """Extract relevant lines in function, including top-level functions and class methods."""
        rel_line_ids: List[int] = []

        if globals_opt.opt_to_func_diff_context == 1:
            rel_line_ids = func_node.get_full_range()
        elif globals_opt.opt_to_func_diff_context == 2:
            func_start, func_end = func_node.range
            func_code = PyDiffContextBuilder._adjust_code_snippet_indent(code_lines[func_start - 1: func_end])

            # (1) Add function signature lines
            sig_line_ids = extract_func_sig_lines_from_py_code(func_code, func_start)
            rel_line_ids.extend(sig_line_ids)

            # (2) Add context of diff lines in the function
            dlc_line_ids = PyDiffContextBuilder._extract_diff_lines_context(source, diff_lines, func_start, func_end)
            rel_line_ids.extend(dlc_line_ids)

            # (3) Normalize
            rel_line_ids = list(set(rel_line_ids))
        else:
            raise NotImplementedError(f"Strategy {globals_opt.opt_to_func_diff_context} for building "
                                      f"function diff context is not supported yet.")

        return rel_line_ids


    @staticmethod
    def _extract_relevant_lines_in_class(
            source: SourceFileType,
            class_node: PySimNode,
            relevant_child_nodes: List[PySimNode],
            code_lines: List[str],
            diff_lines: List[DiffLine]
    ) -> List[int]:
        """Extract relevant lines in class."""
        rel_line_ids: List[int] = []

        # (1) Add relevant lines in class body
        for child_node in relevant_child_nodes:
            # 1.1 Class unit containing diff lines
            if child_node.type == PySimNodeType.CLASS_UNIT:
                child_rel_line_ids = child_node.get_full_range()
                rel_line_ids.extend(child_rel_line_ids)

            # 1.2 Inclass methods containing diff lines
            if child_node.type == PySimNodeType.CLASS_METHOD:
                child_rel_line_ids = PyDiffContextBuilder._extract_relevant_lines_in_func(
                    source, child_node, code_lines, diff_lines
                )
                rel_line_ids.extend(child_rel_line_ids)

        # (2) Add class signature lines
        class_start, class_end = class_node.range
        class_code = PyDiffContextBuilder._adjust_code_snippet_indent(code_lines[class_start - 1: class_end])
        sig_line_ids = extract_class_sig_lines_from_py_code(class_code, class_start, detailed=False)

        rel_line_ids.extend(sig_line_ids)

        # (3) Normalize
        rel_line_ids = sorted(list(set(rel_line_ids)))

        return rel_line_ids


    @staticmethod
    def _extract_relevant_lines_in_main(
            main_node: PySimNode,
            relevant_child_nodes: List[PySimNode],
            code_lines: List[str],
    ) -> List[int]:
        """Extract relevant lines in main block."""
        rel_line_ids: List[int] = []

        # 1. Add relevant lines in main block body
        for child_node in relevant_child_nodes:
            child_rel_line_ids = child_node.get_full_range()
            rel_line_ids.extend(child_rel_line_ids)

        # 2. Add main block signature line
        sig_line_id = None
        for line_id in main_node.get_full_range():
            if PyASTParser.is_main_line(code_lines[line_id - 1]):
                sig_line_id = line_id
                break
        assert sig_line_id is not None
        if sig_line_id not in rel_line_ids:
            rel_line_ids.append(sig_line_id)

        return rel_line_ids


    @staticmethod
    def extract_relevant_lines_in_file(
            source: SourceFileType,
            diff_lines: List[DiffLine],
            code: str,
            all_nodes: Dict[int, PySimNode],
            li2node_map: Dict[int, int]
    ) -> List[int]:
        """
        For all deleted / added lines, extract detailed and complete code lines containing them from the old / new file.

        For now, the extraction principles are as follows:
        #1. For lines in the top-level function, extract the following lines:
            Option 1:
                - All lines in the function.
            Option 2 (Default):
                - Function signature, i.e. the function definition.
                - Diff lines and their context (range is -3 <= x <= +3).
        #2. For lines in the (top-level) class, consider two situations:
            - a. For lines in the class method, refer to #1.
            - b. For the rest lines, extract all lines of the AST node where they are located,
                which is a top level child of the class root node.
            - Besides, extract lines of the class signature, which contains only the class definition and assign signatures,
                not class method signatures.
        #3. For lines in the if_main block, refer to #2b, besides, extract lines like 'if __name__ == "__main__":'
        #4. For the rest lines, refer to #2b.
        Simply summarized as the range of line location where the diff line is located.

        NOTE 1: Only for Python file.
        NOTE 2: Only for modified file.
        """
        code_lines = code.splitlines(keepends=False)

        # ------------------ I. Find relevant Simple Nodes ------------------ #
        all_imports: List[int] = []
        relevant_units: List[int] = []
        relevant_funcs: List[int] = []
        relevant_classes: Dict[int, List[int]] = defaultdict(list)
        relevant_mains: Dict[int, List[int]] = defaultdict(list)

        ## (1) Find all import statements
        for node_id, node in all_nodes.items():
            if node.father is not None and all_nodes[node.father].type == PySimNodeType.ROOT and \
                    (node.ast == "Import" or node.ast == "ImportFrom"):
                all_imports.append(node_id)

        ## (2) Find Simple Nodes where the diff lines locate
        for diff_line in diff_lines:
            if diff_line.source == source:
                node_id = li2node_map[diff_line.lineno]
                node = all_nodes[node_id]

                if node.type == PySimNodeType.FUNCTION:
                    # (1) Relevant functions
                    if node_id not in relevant_funcs:
                        relevant_funcs.append(node_id)
                elif node.type == PySimNodeType.CLASS_UNIT or node.type == PySimNodeType.CLASS_METHOD:
                    # (2) Relevant classes
                    class_node_id = node.father
                    if node_id not in relevant_classes[class_node_id]:
                        relevant_classes[class_node_id].append(node_id)
                elif node.type == PySimNodeType.MAIN_UNIT:
                    # (3) Relevant main blocks
                    main_loc_id = node.father
                    if node_id not in relevant_mains[main_loc_id]:
                        relevant_mains[main_loc_id].append(node_id)
                else:
                    # (4) Relevant top-level statements
                    assert node.type == PySimNodeType.UNIT
                    if node_id not in relevant_units:
                        relevant_units.append(node_id)

        # ------------------ II. Find relevant line ids ------------------ #
        relevant_line_ids: List[int] = []

        ## (1) Add all lines in import statements
        for node_id in all_imports:
            # 1. Add all lines of the statement
            import_line_ids = all_nodes[node_id].get_full_range()

            # 2. Add to all
            relevant_line_ids.extend(import_line_ids)

        ## (2) Add relevant lines in relevant functions
        for node_id in relevant_funcs:
            func_node = all_nodes[node_id]

            # 1. Add relevant lines in function
            func_rel_line_ids = PyDiffContextBuilder._extract_relevant_lines_in_func(
                source, func_node, code_lines, diff_lines
            )

            # 2. Add to all
            relevant_line_ids.extend(func_rel_line_ids)

        ## (3) Add relevant lines in relevant classes
        for class_node_id, child_node_ids in relevant_classes.items():
            class_node = all_nodes[class_node_id]
            child_nodes = [all_nodes[child_node_id] for child_node_id in child_node_ids]

            # 1. Add relevant lines in class
            class_rel_line_ids = PyDiffContextBuilder._extract_relevant_lines_in_class(
                source, class_node, child_nodes, code_lines, diff_lines
            )

            # 2. Add to all
            relevant_line_ids.extend(class_rel_line_ids)

        ## (4) Add relevant lines in relevant main blocks
        for main_node_id, child_node_ids in relevant_mains.items():
            main_node = all_nodes[main_node_id]
            child_nodes = [all_nodes[child_node_id] for child_node_id in child_node_ids]

            # 1. Add relevant lines in main block
            main_rel_line_ids = PyDiffContextBuilder._extract_relevant_lines_in_main(main_node, child_nodes, code_lines)

            # 2. Add to all
            relevant_line_ids.extend(main_rel_line_ids)

        ## (5) Add relevant lines in relevant top-level statements
        for node_id in relevant_units:
            # 1. Add all lines of the statement
            unit_line_ids = all_nodes[node_id].get_full_range()

            # 2. Add to all
            relevant_line_ids.extend(unit_line_ids)

        return relevant_line_ids


class JavaDiffContextBuilder(DiffContextBuilder):
    """Tool class for building diff content of Java file."""
    @staticmethod
    def _extract_relevant_lines_in_iface(
            source: SourceFileType,
            iface_node: JavaSimNode,
            code_lines: List[str],
            diff_lines: List[DiffLine]
    ) -> List[int]:
        """Extract relevant lines in interface."""
        rel_line_ids: List[int] = []

        if globals_opt.opt_to_iface_diff_context == 1:
            rel_line_ids = iface_node.get_full_range()
        elif globals_opt.opt_to_iface_diff_context == 2:
            iface_start, iface_end = iface_node.range
            iface_code = JavaDiffContextBuilder._adjust_code_snippet_indent(code_lines[iface_start - 1: iface_end])

            # (1) Add iface signature lines
            sig_line_ids = extract_iface_sig_lines_from_java_code(iface_code, iface_start)

            # TODO: FOR TEST (Output line ids should not be None)
            assert sig_line_ids is not None

            rel_line_ids.extend(sig_line_ids)

            # (2) Add context of diff lines in the interface
            dlc_line_ids = JavaDiffContextBuilder._extract_diff_lines_context(source, diff_lines, iface_start, iface_end)
            rel_line_ids.extend(dlc_line_ids)

            # (3) Normalize
            rel_line_ids = list(set(rel_line_ids))
        else:
            raise NotImplementedError(f"Strategy {globals_opt.opt_to_func_diff_context} for building "
                                      f"function diff context is not supported yet.")

        return rel_line_ids

    @staticmethod
    def _extract_relevant_lines_in_class_child(
            source: SourceFileType,
            child_node: JavaSimNode,
            code_lines: List[str],
            diff_lines: List[DiffLine]
    ) -> List[int]:
        """Extract relevant lines in class child struct.

        Strategy:
        - 1) Focus on 6 types of inclass structures:
             1. method
             2. interface: normal interface, annotation type
             3. class: normal class, enum, record
        - 2) We only extract 2 parts of it
             1. base signature, i.e., outer part outside the body ('{...}')
             2. context of diff lines in it.
        """
        assert child_node.type in [JavaSimNodeType.CLASS_INTERFACE, JavaSimNodeType.CLASS_CLASS, JavaSimNodeType.CLASS_METHOD]

        rel_line_ids: List[int] = []

        child_start, child_end = child_node.range
        child_code = JavaDiffContextBuilder._adjust_code_snippet_indent(code_lines[child_start - 1: child_end])

        # (1) Add base signature lines
        if child_node.type == JavaSimNodeType.CLASS_INTERFACE:
            bsig_line_ids = extract_iface_sig_lines_from_java_code(child_code, child_start)
        elif child_node.type == JavaSimNodeType.CLASS_CLASS:
            bsig_line_ids = extract_class_sig_lines_from_java_code(child_code, child_start, base=True, detailed=False)
        else:
            bsig_line_ids = extract_method_sig_lines_from_java_code(child_code, child_start)

        # TODO: FOR TEST (Output line ids should not be None)
        assert bsig_line_ids is not None

        rel_line_ids.extend(bsig_line_ids)

        # (2) Add context of diff lines
        dlc_line_ids = JavaDiffContextBuilder._extract_diff_lines_context(source, diff_lines, child_start, child_end)
        rel_line_ids.extend(dlc_line_ids)

        # (3) Normalize
        rel_line_ids = list(set(rel_line_ids))

        return rel_line_ids


    @staticmethod
    def _extract_relevant_lines_in_class(
            source: SourceFileType,
            class_node: JavaSimNode,
            relevant_child_nodes: List[JavaSimNode],
            code_lines: List[str],
            diff_lines: List[DiffLine]
    ) -> List[int]:
        """Extract relevant lines in class."""
        rel_line_ids: List[int] = []

        # (1) Add relevant lines in class body
        for child_node in relevant_child_nodes:
            # 1.1 Class unit containing diff lines
            if child_node.type == JavaSimNodeType.CLASS_UNIT:
                child_rel_line_ids = child_node.get_full_range()
                rel_line_ids.extend(child_rel_line_ids)

            # 1.2 Inclass interface / class / method containing diff lines
            if child_node.type == JavaSimNodeType.CLASS_INTERFACE or \
                    child_node.type == JavaSimNodeType.CLASS_CLASS or \
                    child_node.type == JavaSimNodeType.CLASS_METHOD:
                child_rel_line_ids = JavaDiffContextBuilder._extract_relevant_lines_in_class_child(
                    source, child_node, code_lines, diff_lines
                )
                rel_line_ids.extend(child_rel_line_ids)

        # (2) Add class signature lines
        class_start, class_end = class_node.range
        class_code = JavaDiffContextBuilder._adjust_code_snippet_indent(code_lines[class_start - 1: class_end])
        sig_line_ids = extract_class_sig_lines_from_java_code(class_code, class_start, detailed=False)

        rel_line_ids.extend(sig_line_ids)

        # (3) Normalize
        rel_line_ids = sorted(list(set(rel_line_ids)))

        return rel_line_ids


    @staticmethod
    def extract_relevant_lines_in_file(
            source: SourceFileType,
            diff_lines: List[DiffLine],
            code: str,
            all_nodes: Dict[int, JavaSimNode],
            li2node_map: Dict[int, int]
    ) -> List[int]:
        """
        For all deleted / added lines, extract detailed and complete code lines containing them from the old / new file.

        NOTE 1: Only for Java file.
        NOTE 2: Only for modified file.
        """
        code_lines = code.splitlines(keepends=False)

        # ------------------ I. Find relevant Simple Nodes ------------------ #
        all_imports: List[int] = []
        relevant_units: List[int] = []
        relevant_ifaces: List[int] = []
        relevant_classes: Dict[int, List[int]] = defaultdict(list)

        ## (1) Find all import statements
        for node_id, node in all_nodes.items():
            if node.father is not None and all_nodes[node.father].type == JavaSimNodeType.ROOT and node.ast == "IMPORT_DECLARATION":
                all_imports.append(node_id)

        ## (2) Find Simple Nodes where the diff lines locate
        for diff_line in diff_lines:
            if diff_line.source == source:
                node_id = li2node_map[diff_line.lineno]
                node = all_nodes[node_id]

                if node.type == JavaSimNodeType.INTERFACE:
                    # (1) Relevant interfaces
                    if node_id not in relevant_ifaces:
                        relevant_ifaces.append(node_id)
                elif node.type == JavaSimNodeType.CLASS_UNIT or node.type == JavaSimNodeType.CLASS_INTERFACE or \
                        node.type == JavaSimNodeType.CLASS_CLASS or node.type == JavaSimNodeType.CLASS_METHOD:
                    # (2) Relevant classes
                    class_node_id = node.father
                    if node_id not in relevant_classes[class_node_id]:
                        relevant_classes[class_node_id].append(node_id)
                else:
                    # (4) Relevant top-level statements
                    assert node.type == JavaSimNodeType.UNIT
                    if node_id not in relevant_units:
                        relevant_units.append(node_id)

        # ------------------ II. Find relevant line ids ------------------ #
        relevant_line_ids: List[int] = []

        ## (1) Add all lines in import statements
        for node_id in all_imports:
            # 1. Add all lines of the statement
            import_line_ids = all_nodes[node_id].get_full_range()

            # 2. Add to all
            relevant_line_ids.extend(import_line_ids)

        ## (2) Add relevant lines in relevant interfaces
        for node_id in relevant_ifaces:
            iface_node = all_nodes[node_id]

            # 1. Add relevant lines in interface
            iface_rel_line_ids = JavaDiffContextBuilder._extract_relevant_lines_in_iface(
                source, iface_node, code_lines, diff_lines
            )

            # 2. Add to all
            relevant_line_ids.extend(iface_rel_line_ids)

        ## (3) Add relevant lines in relevant classes
        for class_node_id, child_node_ids in relevant_classes.items():
            class_node = all_nodes[class_node_id]
            child_nodes = [all_nodes[child_node_id] for child_node_id in child_node_ids]

            # 1. Add relevant lines in class
            class_rel_line_ids = JavaDiffContextBuilder._extract_relevant_lines_in_class(
                source, class_node, child_nodes, code_lines, diff_lines
            )

            # 2. Add to all
            relevant_line_ids.extend(class_rel_line_ids)

        ## (4) Add relevant lines in relevant top-level statements
        for node_id in relevant_units:
            # 1. Add all lines of the statement
            unit_line_ids = all_nodes[node_id].get_full_range()

            # 2. Add to all
            relevant_line_ids.extend(unit_line_ids)

        return relevant_line_ids


def build_file_diff_context(diff_lines: List[DiffLine], diff_file_info: DiffFileInfo) -> str:
    """Extract a more detailed and complete context containing all diff lines from a file.

    NOTE 1: Only for modified file.
    NOTE 2: Valid for Python file and Java file.
    """
    ## (1) Extract relevant line ids in old code and new code respectively
    if isinstance(diff_file_info, PyDiffFileInfo):
        old_relevant_line_ids = PyDiffContextBuilder.extract_relevant_lines_in_file(
            source=SourceFileType.OLD,
            diff_lines=diff_lines,
            code=diff_file_info.old_code,
            all_nodes=diff_file_info.old_nodes,
            li2node_map=diff_file_info.old_li2node
        )
        new_relevant_line_ids = PyDiffContextBuilder.extract_relevant_lines_in_file(
            source=SourceFileType.NEW,
            diff_lines=diff_lines,
            code=diff_file_info.new_code,
            all_nodes=diff_file_info.new_nodes,
            li2node_map=diff_file_info.new_li2node
        )
    elif isinstance(diff_file_info, JavaDiffFileInfo):
        old_relevant_line_ids = JavaDiffContextBuilder.extract_relevant_lines_in_file(
            source=SourceFileType.OLD,
            diff_lines=diff_lines,
            code=diff_file_info.old_code,
            all_nodes=diff_file_info.old_nodes,
            li2node_map=diff_file_info.old_li2node
        )
        new_relevant_line_ids = JavaDiffContextBuilder.extract_relevant_lines_in_file(
            source=SourceFileType.NEW,
            diff_lines=diff_lines,
            code=diff_file_info.new_code,
            all_nodes=diff_file_info.new_nodes,
            li2node_map=diff_file_info.new_li2node
        )
    else:
        raise NotImplementedError(f"Language {diff_file_info.lang} is not supported yet.")

    ## (2) Combine relevant line ids
    relevant_line_ids: List[int] = []

    for line_id in old_relevant_line_ids:
        comb_line_id = diff_file_info.line_id_old2merge[line_id]
        if comb_line_id not in relevant_line_ids:
            relevant_line_ids.append(comb_line_id)

    for line_id in new_relevant_line_ids:
        comb_line_id = diff_file_info.line_id_new2merge[line_id]
        if comb_line_id not in relevant_line_ids:
            relevant_line_ids.append(comb_line_id)

    relevant_line_ids = sorted(list(set(relevant_line_ids)))

    ## (3) Extract code snippets
    comb_code_lines = diff_file_info.merge_code.splitlines(keepends=False)
    context = ""

    for i in range(len(relevant_line_ids)):
        line_id = relevant_line_ids[i]
        # (1) Add sep '...'
        if i == 0:
            if line_id != 1:
                context = "..."
        else:
            last_line_id = relevant_line_ids[i - 1]
            if line_id != last_line_id + 1:
                context += "\n..."
        # (2) Add code line
        context += f"\n{comb_code_lines[line_id - 1]}"

    if relevant_line_ids[-1] != len(comb_code_lines):
        context += "\n..."

    context = context.strip('\n')

    return context


"""MAIN ENTRY"""


def analyse_deleted_py_file(ast_parser: PyASTParser, old_code: str, comb_code: str) -> PyDiffFileInfo:
    ast_parser.reset()

    ## (1) Initialization
    diff_file_info = PyDiffFileInfo(old_code=old_code, new_code=None, merge_code=comb_code)

    ## (2) Update
    ast_parser.set(code=old_code, code_fpath=None)
    ast_parser.parse_python_code()

    # 1. Simple Nodes
    diff_file_info.old_nodes = ast_parser.all_nodes
    # 2. Mapping from line id to Simple Node id
    diff_file_info.old_li2node = ast_parser.li2node_map
    # 3. Structure indexes
    diff_file_info.old_func_index = ast_parser.all_funcs
    diff_file_info.old_class_index = ast_parser.all_classes
    diff_file_info.old_inclass_method_index = ast_parser.all_inclass_methods
    diff_file_info.old_imports = ast_parser.all_imports

    return diff_file_info


def analyse_added_py_file(ast_parser: PyASTParser, new_code: str, comb_code: str) -> PyDiffFileInfo:
    ast_parser.reset()

    ## (1) Initialization
    diff_file_info = PyDiffFileInfo(old_code=None, new_code=new_code, merge_code=comb_code)

    ## (2) Update
    ast_parser.set(code=new_code, code_fpath=None)
    ast_parser.parse_python_code()

    # 1. Simple Nodes
    diff_file_info.new_nodes = ast_parser.all_nodes
    # 2. Mapping from line id to Simple Node id
    diff_file_info.new_li2node = ast_parser.li2node_map
    # 3. Structure indexes
    diff_file_info.new_func_index = ast_parser.all_funcs
    diff_file_info.new_class_index = ast_parser.all_classes
    diff_file_info.new_inclass_method_index = ast_parser.all_inclass_methods
    diff_file_info.old_imports = ast_parser.all_imports

    return diff_file_info


def analyse_modified_py_file(
        ast_parser: PyASTParser,
        old_ori_code: str,
        new_ori_code: str,
        diff_file_info: Dict
) -> Tuple[PyDiffFileInfo, str] | None:
    """Analyse the modified Python file."""
    ## Step 1: Reset the parser
    ast_parser.reset()

    ## Step 2: Get all diff lines within a file
    ori_file_diff_lines = extract_all_diff_lines_within_file(diff_file_info)

    ## Step 3: Filter out blank and comment lines
    # Filtering reason:
    # - 1. AST in python does not analyse the comments.
    # - 2. We do not consider the code files with only changed comments.
    # (1) Filter for code file
    old_filtered_code, old_line_id_map = filter_py_code_content(old_ori_code)
    new_filtered_code, new_line_id_map = filter_py_code_content(new_ori_code)
    # (2) Filter for commit info
    filtered_file_diff_lines = filter_file_diff_content(ori_file_diff_lines, old_line_id_map, new_line_id_map)

    ## Step 4: Parse the old and new filtered code
    if filtered_file_diff_lines:
        ## NOTE: The code analyzed below are all FILTERED code.
        # Step 4.1 Initialize the DiffFileInfo
        diff_file_info = PyDiffFileInfo(old_code=old_filtered_code, new_code=new_filtered_code)

        # Step 4.2 Combine the old and new code
        comb_code, line_id_old2new, line_id_old2comb, line_id_new2comb = combine_code_old_and_new(
            diff_file_info.old_code, diff_file_info.new_code, filtered_file_diff_lines
        )

        diff_file_info.merge_code = comb_code
        diff_file_info.line_id_old2new = line_id_old2new
        diff_file_info.line_id_old2merge = line_id_old2comb
        diff_file_info.line_id_new2merge = line_id_new2comb

        # Step 4.3 Parse the old and new code respectively
        # (1) Parse the old code and update
        ast_parser.set(code=old_filtered_code, code_fpath=None)
        ast_parser.parse_python_code()

        diff_file_info.old_func_index = ast_parser.all_funcs
        diff_file_info.old_class_index = ast_parser.all_classes
        diff_file_info.old_inclass_method_index = ast_parser.all_inclass_methods
        diff_file_info.old_imports = ast_parser.all_imports

        # (2) Parse the new code and update
        ast_parser.set(code=new_filtered_code, code_fpath=None)
        ast_parser.parse_python_code()

        diff_file_info.new_func_index = ast_parser.all_funcs
        diff_file_info.new_class_index = ast_parser.all_classes
        diff_file_info.new_inclass_method_index = ast_parser.all_inclass_methods
        diff_file_info.new_imports = ast_parser.all_imports

        # Step 4.4 Build diff content of file
        if globals_opt.opt_to_file_diff_context == 1:
            diff_context = diff_lines_to_str(filtered_file_diff_lines)
        elif globals_opt.opt_to_file_diff_context == 2:
            diff_context = build_file_diff_context(filtered_file_diff_lines, diff_file_info)
        else:
            raise NotImplementedError(f"Strategy {globals_opt.opt_to_file_diff_context} for building file diff context "
                                      f"is not supported yet.")

        return diff_file_info, diff_context
    else:
        return None


def analyse_deleted_java_file(ast_parser: JavaASTParser, old_code: str, comb_code: str) -> JavaDiffFileInfo:
    ast_parser.reset()

    ## (1) Initialization
    diff_file_info = JavaDiffFileInfo(old_code=old_code, new_code=None, merge_code=comb_code)

    ## (2) Update
    ast_parser.set(code=old_code, code_fpath=None)
    ast_parser.parse_java_code()

    # 1. Simple Nodes
    diff_file_info.old_nodes = ast_parser.all_nodes
    # 2. Mapping from line id to Simple Node id
    diff_file_info.old_li2node = ast_parser.li2node_map
    # 3. Structure indexes
    diff_file_info.old_iface_index = ast_parser.all_interfaces
    diff_file_info.old_class_index = ast_parser.all_classes
    diff_file_info.old_inclass_iface_index = ast_parser.all_inclass_interfaces
    diff_file_info.old_inclass_class_index = ast_parser.all_inclass_classes
    diff_file_info.old_inclass_method_index = ast_parser.all_inclass_methods
    diff_file_info.old_imports = ast_parser.all_imports

    return diff_file_info


def analyse_added_java_file(ast_parser: JavaASTParser, new_code: str, comb_code: str) -> JavaDiffFileInfo:
    ast_parser.reset()

    ## (1) Initialization
    diff_file_info = JavaDiffFileInfo(old_code=None, new_code=new_code, merge_code=comb_code)

    ## (2) Update
    ast_parser.set(code=new_code, code_fpath=None)
    ast_parser.parse_java_code()

    # 1. Simple Nodes
    diff_file_info.new_nodes = ast_parser.all_nodes
    # 2. Mapping from line id to Simple Node id
    diff_file_info.new_li2node = ast_parser.li2node_map
    # 3. Structure indexes
    diff_file_info.new_iface_index = ast_parser.all_interfaces
    diff_file_info.new_class_index = ast_parser.all_classes
    diff_file_info.new_inclass_iface_index = ast_parser.all_inclass_interfaces
    diff_file_info.new_inclass_class_index = ast_parser.all_inclass_classes
    diff_file_info.new_inclass_method_index = ast_parser.all_inclass_methods
    diff_file_info.old_imports = ast_parser.all_imports

    return diff_file_info


def analyse_modified_java_file(
        ast_parser: JavaASTParser,
        old_ori_code: str,
        new_ori_code: str,
        diff_file_info: Dict
) -> Tuple[JavaDiffFileInfo, str] | None:
    """Analyse the modified Java file."""
    ## Step 1: Reset the parser
    ast_parser.reset()

    ## Step 2: Get all diff lines within a file
    ori_file_diff_lines = extract_all_diff_lines_within_file(diff_file_info)

    ## Step 3: Filter out blank and comment lines
    # Filtering reason: follow the setting of analysing the Python file
    # (1) Filter for code file
    old_filter_res = filter_java_code_content(old_ori_code)
    assert old_filter_res is not None
    old_filtered_code, old_line_id_map = old_filter_res

    new_filter_res = filter_java_code_content(new_ori_code)
    assert new_filter_res is not None
    new_filtered_code, new_line_id_map = new_filter_res
    # (2) Filter for commit info
    filtered_file_diff_lines = filter_file_diff_content(ori_file_diff_lines, old_line_id_map, new_line_id_map)

    ## Step 4: Parse the old and new filtered code
    if filtered_file_diff_lines:
        ## NOTE: The code analyzed below are all FILTERED code.
        # Step 4.1 Initialize the DiffFileInfo
        diff_file_info = JavaDiffFileInfo(old_code=old_filtered_code, new_code=new_filtered_code)

        # Step 4.2 Combine the old and new code
        comb_code, line_id_old2new, line_id_old2comb, line_id_new2comb = combine_code_old_and_new(
            diff_file_info.old_code, diff_file_info.new_code, filtered_file_diff_lines
        )

        diff_file_info.merge_code = comb_code
        diff_file_info.line_id_old2new = line_id_old2new
        diff_file_info.line_id_old2merge = line_id_old2comb
        diff_file_info.line_id_new2merge = line_id_new2comb

        # Step 4.3 Parse the old and new code respectively
        # (1) Parse the old code and update
        ast_parser.set(code=old_filtered_code, code_fpath=None)
        ast_parser.parse_java_code()

        diff_file_info.old_iface_index = ast_parser.all_interfaces
        diff_file_info.old_class_index = ast_parser.all_classes
        diff_file_info.old_inclass_iface_index = ast_parser.all_inclass_interfaces
        diff_file_info.old_inclass_class_index = ast_parser.all_inclass_classes
        diff_file_info.old_inclass_method_index = ast_parser.all_inclass_methods
        diff_file_info.old_imports = ast_parser.all_imports

        # (2) Parse the new code and update
        ast_parser.set(code=new_filtered_code, code_fpath=None)
        ast_parser.parse_java_code()

        diff_file_info.new_iface_index = ast_parser.all_interfaces
        diff_file_info.new_class_index = ast_parser.all_classes
        diff_file_info.new_inclass_iface_index = ast_parser.all_inclass_interfaces
        diff_file_info.new_inclass_class_index = ast_parser.all_inclass_classes
        diff_file_info.new_inclass_method_index = ast_parser.all_inclass_methods
        diff_file_info.new_imports = ast_parser.all_imports

        # Step 4.4 Build diff content of file
        if globals_opt.opt_to_file_diff_context == 1:
            diff_context = diff_lines_to_str(filtered_file_diff_lines)
        elif globals_opt.opt_to_file_diff_context == 2:
            diff_context = build_file_diff_context(filtered_file_diff_lines, diff_file_info)
        else:
            raise NotImplementedError(f"Strategy {globals_opt.opt_to_file_diff_context} for building file diff context "
                                      f"is not supported yet.")

        return diff_file_info, diff_context
    else:
        return None
