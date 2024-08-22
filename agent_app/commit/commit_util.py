from __future__ import annotations

import os
import re
import ast
import tokenize
import json
import subprocess
import bisect

from typing import *
from io import StringIO
from dataclasses import dataclass, asdict
from collections import namedtuple
from enum import Enum

from loguru import logger

from agent_app.static_analysis.parse import (
    LocationType, Location,
    line_loc_types, top_level_loc_types, no_children_loc_types, children_loc_types,
    class_child_loc_types, main_child_loc_types,
    parse_python_file_locations)
from utils import LineRange, same_line_range, run_command


class SourceFileType(str, Enum):
    OLD = "before_commit"
    NEW = "after_commit"

    @staticmethod
    def attributes():
        return [k.value for k in SourceFileType]


"""Get The File Content Before or After Commit"""


def get_file_before_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str) -> str | None:
    """
    Get file content before applying the given commit.

    Args:
        local_repo_dpath (str): Path to the local repository dir.
        commit_hash (str): Commit hash.
        rel_fpath (str): Relative (to the local repo root) file path.
    Returns:
        str | None: Content of file before applying the given commit. None if failed to get the content.
    """
    git_show_cmd = ['git', 'show', f'{commit_hash}^:{rel_fpath}']

    result, _ = run_command(git_show_cmd, raise_error=False,
                            cwd=local_repo_dpath, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result is not None:
        return result.stdout
    else:
        return None


def get_file_after_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str) -> str | None:
    """
       Get file content after applying the given commit.

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


"""Extract Raw Commit Content Info"""


def extract_commit_content_info(commit_content: str, file_suffix: List[str] | None = None) -> List:
    """
        Extract commit content from saved commit file, and only information is extracted without any other processing.
        A commit is generally organized in the following format:

        +++++++++++++++++++++++ <commit> +++++++++++++++++++++++
        commit <commit_id>
        Author: <author>
        Date: <timestamp>

        <description>

        <changed_file_info / section-1>
        <changed_file_info / section-2>
        ...
        ++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        Each <changed_file_info / section-i> corresponds to info of one changed file,
        while <changed_file_info / section-1> is generally organized in the following format:

        =========== <changed_file_info / section-i> ===========
        diff --git <old_file_path> <new_file_path>
        ((new / deleted) file mode <id1>)
        index <old_id>..<new_id> (id2)
        --- <old_file_path>
        +++ <new_file_path>
        <changed_code_snippet_info / hunk-1>
        <changed_code_snippet_info / hunk-2>
        ...
        =======================================================

        Each <changed_code_snippet_info / hunk-j> corresponds to info of one changed code snippet,
        while <changed_code_snippet_info / hunk-j> is generally organized in the following format:

        -------- <changed_code_snippet_info / hunk-j> --------
        @@ -<old_file_line_start_idx>,<old_file_line_scope> +<new_file_line_start_idx>,<new_file_line_scope> @@ (<function name>)
        <changed_code_snippet>
        ------------------------------------------------------

        Args:
            commit_content (str): The raw commit content.
                Assumption: This commit content is the full content generated directly from cmd 'git show <commit_id> >'
            file_suffix (List[str] | None): Selection of the suffix of files involved in the commit.

        Returns:
            List: The info of commit content.
                Format:
                [
                    # <section-1>
                    {
                        "old_fpath": relative path of the file before commit, "/dev/null" for adding new file.
                        "new_fpath": relative path of the file before commit, "/dev/null" for deleting old file.
                        "file_type": "added" / "removed" / "modified
                        "changed_code_snippets_info":
                        [
                            # <hunk-1>
                            {
                                "old_line_start_idx":
                                "old_line_scope":
                                "new_line_start_idx":
                                "new_line_scope":
                                "changed_code_snippet":
                                    [
                                        <code_line_seq_1>
                                        <code_line_seq_2>
                                        ...
                                    ]
                            }
                            # <hunk-2>
                            {...}
                            ...
                        ]
                    }
                    # <section-2>
                    {...}
                    ...
                ]
    """
    if file_suffix is None:
        # file_suffix = [".c", ".cc", ".java", ".py", ".js", ".php", ".h", ".rb", ".go", ".ts", ".tsx"]
        file_suffix = [".py"]

    diff_line_pattern = r"diff --git (.+) (.+)"
    add_file_line_pattern = r"new file mode (\d+)"
    remove_file_line_pattern = r"deleted file mode (\d+)"
    index_line_pattern = r"index (\w+)\.\.(\w+)(?: .*)?$"
    old_fpath_pattern = r"--- (.+)"
    new_fpath_pattern = r"\+\+\+ (.+)"
    line_id_pattern = r"@@ -(\d+),(\d+) \+(\d+),(\d+) (.*)$"

    commit_content_lines = commit_content.splitlines(keepends=False)

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
        old_fpath, new_fpath = changed_fpath_lines[section_start_line_idx]
        if not (any(old_fpath.endswith(suf) for suf in file_suffix) and
                any(new_fpath.endswith(suf) for suf in file_suffix)):
            continue

        # Current section start and end line idx
        section_end_line_idx = list(changed_fpath_lines.keys())[i + 1] - 1 \
            if i < len(changed_fpath_lines) - 1 else len(commit_content_lines) - 1

        current_line_idx = section_start_line_idx

        # Match the modification pattern of the file:
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

        assert re.match(index_line_pattern, commit_content_lines[current_line_idx + 1])
        current_line_idx += 1

        # Match the file path before and after commit
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
            "old_fpath": old_fpath,  # (str | None) old file path / None
            "new_fpath": new_fpath,  # (str | None) new file path / None
            "file_type": file_type,  # (str) modified / added / removed
            "code_diff": []
        }

        assert re.match(line_id_pattern, commit_content_lines[current_line_idx + 1])
        current_line_idx += 1

        # Match the hunk start line (@@ -idx_1,scope_1 +idx_2,scope_2 @@ xxx)
        diff_code_info_start_list = []
        for idx in range(current_line_idx, section_end_line_idx + 1):
            if re.match(line_id_pattern, commit_content_lines[idx]):
                diff_code_info_start_list.append(idx)

        # Extract changed code snippet hunk-by-hunk
        for j, hunk_start_line_idx in enumerate(diff_code_info_start_list):
            ## Current section start and end line idx
            hunk_end_line_idx = diff_code_info_start_list[j + 1] - 1 \
                if j < len(diff_code_info_start_list) - 1 else section_end_line_idx

            ## Code snippet loc info before and after commit
            del_line_start_idx, del_line_scope, add_line_start_idx, add_line_scope, rest = (
                re.match(line_id_pattern, commit_content_lines[hunk_start_line_idx]).groups())

            ## Changed code snippet
            diff_code_snippet = commit_content_lines[hunk_start_line_idx + 1: hunk_end_line_idx + 1]

            ## Delete line (in old file) and add line (in new line) ids
            # (1) changed_code_snippet index
            diff_line_indexes: List[int] = []
            # (2) changed_code_snippet index -> (old / new) file line id
            del_line_index2id: Dict[int, int] = {}
            add_line_index2id: Dict[int, int] = {}

            cur_old_line_id = int(del_line_start_idx) - 1
            cur_new_line_id = int(add_line_start_idx) - 1
            for k, line in enumerate(diff_code_snippet):
                if line.startswith("+"):
                    cur_new_line_id += 1
                    diff_line_indexes.append(k)
                    add_line_index2id[k] = cur_new_line_id
                elif line.startswith("-"):
                    cur_old_line_id += 1
                    diff_line_indexes.append(k)
                    del_line_index2id[k] = cur_old_line_id
                else:
                    cur_new_line_id += 1
                    cur_old_line_id += 1

            curr_code_diff = {
                # For all diff lines
                "diff_line_indexes": diff_line_indexes,  # (List, 0-based)
                "diff_code_snippet": diff_code_snippet,  # (List[str])
                # For diff lines in file before
                "del_start_line_id": int(del_line_start_idx),  # (int, 1-based)
                "del_line_scope": int(del_line_scope),  # (int)
                "del_line_index2id": del_line_index2id,  # (Dict, 0-based -> 1-based)
                # For diff lines in file after
                "add_start_line_id": int(add_line_start_idx),  # (int, 1-based)
                "add_line_scope": int(add_line_scope),  # (int)
                "add_line_index2id": add_line_index2id  # (Dict, 0-based -> 1-based)
            }

            curr_diff_file_info["code_diff"].append(curr_code_diff)

        commit_content_info.append(curr_diff_file_info)

    return commit_content_info


"""Extract Only Diff Lines in single file"""


@dataclass
class DiffLine:
    """For recording a diff line."""
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


def combine_diff_code_info_within_file(diff_file_info: Dict) -> List[DiffLine]:
    """
    Combine diff code within file, using sep to separate discontinuous diff lines.

    NOTE: Only for modified files.

    Args:
        diff_file_info (Dict): Element of commit info which is obtained from `extract_commit_content_info`
                               Form:
                                   {
                                       "old_fpath": str | None
                                       "new_fpath": str | None
                                       "file_type": str
                                       "code_diff": List
                                   }
    Returns:
        List[DiffLine]: List of diff lines within file.
    """
    diff_lines: List[DiffLine] = []

    for diff_code_info in diff_file_info["code_diff"]:
        last_line_is_diff = False

        cur_diff_code = diff_code_info["diff_code_snippet"]
        cur_del_line_index2id = diff_code_info["del_line_index2id"]
        cur_add_line_index2id = diff_code_info["add_line_index2id"]

        for ind, line in enumerate(cur_diff_code):
            if line.startswith("-") or line.startswith("+"):
                source = _get_diff_line_source_file(line)
                line_id = cur_del_line_index2id[ind] if ind in cur_del_line_index2id else cur_add_line_index2id[ind]

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


"""Filter Blank Lines and Comment Lines"""


def _is_only_comment(line: str) -> bool:
    """
    Check if the given line contains only a comment.

    Args:
        line (str): Python code line, which does not contain line breaks.
    Returns:
        bool: True if the line contains only a comment, False otherwise.
    """
    assert re.search(r'#(.*)$', line)
    return line.strip().startswith('#')


def find_comment_lines(code: str) -> List[int]:
    """
    Find lines containing comment like "# xxx"
    NOTE: We do not consider Docstrings here.
    """
    comment_lines: List[int] = []

    # Step 1: Find all comment lines
    code_io = StringIO(code)
    tokens = tokenize.generate_tokens(code_io.readline)
    for token in tokens:
        if token.type == tokenize.COMMENT:
            comment_lines.append(token.start[0])

    # Step 2: Find all comment lines containing only comment
    code_lines = code.splitlines(keepends=False)

    single_comment_lines: List[int] = []
    for comment_line in comment_lines:
        if _is_only_comment(code_lines[comment_line - 1]):
            single_comment_lines.append(comment_line)

    return single_comment_lines


def filter_blank_lines_in_file(code: str, filter_comment: bool = True) -> Tuple[str, Dict[int, int]]:
    """
    Filter blank lines in file.

    Args:
        code (str): File content.
        filter_comment (bool): Filter comment.
            FIXME: Since ast does not consider comment lines while analyzing, so we filter out lines which
                contain only comments. More detailed comment classification will be considered in the future.
    Returns:
        str: Filtered file.
        Dict[int, int]: line id in original file (1-based) -> line id in filtered file (1-based).
    """
    lines = code.splitlines(keepends=False)
    nb_lines: List[str] = []
    line_id_lookup: Dict[int, int] = {}

    # Find comment lines if needed, otherwise empty
    if filter_comment:
        comment_lines = find_comment_lines(code)
    else:
        comment_lines = []

    # Fiter blank lines (and comment lines)
    for i, line in enumerate(lines):
        if line.strip() != "" and (i + 1) not in comment_lines:
            nb_lines.append(line)
            line_id_lookup[i + 1] = len(nb_lines)

    return "\n".join(nb_lines), line_id_lookup


def filter_blank_lines_in_commit(
        file_diff_lines: List[DiffLine],
        old_line_id_lookup: Dict[int, int],
        new_line_id_lookup: Dict[int, int]
) -> List[DiffLine]:
    """
    Filter blank lines and comment lines in commit, including lines deleted / added / unchanged.

    NOTE 1: Only for modified files.
    NOTE 2: `file_diff_lines` is obtained from `combine_diff_code_info_within_file`.
    NOTE 3: Whether to filter comment lines depends on the parameters `old_line_id_lookup` and `new_line_id_lookup`,
            which are obtained by method `filter_blank_lines_in_file`, and in both look-up dict, there are no
            corresponding key-value pairs for blank lines or comment lines.

    Args:
        file_diff_lines (List[DiffLine]): List of original diff lines within file.
        old_line_id_lookup (Dict[int, int]): line id in original file -> line id in filtered file
        new_line_id_lookup (Dict[int, int]): line id in original file -> line id in filtered file
    Returns:
        List[DiffLine]: List of filtered diff lines within file.
    """
    nb_file_diff_lines: List[DiffLine] = []
    last_is_sep = False

    for diff_line in file_diff_lines:
        # Sep
        if diff_line.sep:
            if len(nb_file_diff_lines) == 0 or last_is_sep:
                # Do not add sep in the beginning or after sep
                pass
            else:
                # Update sep info
                diff_line.id = len(nb_file_diff_lines)

                nb_file_diff_lines.append(diff_line)
                last_is_sep = True
            continue

        # Code
        if diff_line.source == SourceFileType.OLD and diff_line.lineno in old_line_id_lookup:
            nb_line_id = old_line_id_lookup[diff_line.lineno]

            # Update diff line info
            diff_line.id = len(nb_file_diff_lines)
            diff_line.lineno = nb_line_id

            nb_file_diff_lines.append(diff_line)
            last_is_sep = False
        elif diff_line.source == SourceFileType.NEW and diff_line.lineno in new_line_id_lookup:
            nb_line_id = new_line_id_lookup[diff_line.lineno]

            # Update diff line info
            diff_line.id = len(nb_file_diff_lines)
            diff_line.lineno = nb_line_id

            nb_file_diff_lines.append(diff_line)
            last_is_sep = False

    if nb_file_diff_lines[-1].sep:
        nb_file_diff_lines.pop(-1)

    return nb_file_diff_lines


"""Combine File Content Before and After Commit"""


def combine_old_content_and_new_content(
        old_file_content: str,
        new_file_content: str,
        file_diff_lines: List[DiffLine]
) -> Tuple[str, Dict[int, int], Dict[int, int]]:
    """
    Combine old content and new content, reflecting the changes.

    NOTE: Old content, new content and diff lines need to be in the same state.
          By default, blank lines and comment lines are filtered out.
    Args:
        old_file_content (str): Content of code before commit.
        new_file_content (str): Content of code after commit.
        file_diff_lines (List[DiffLine]): List of diff lines.
    Returns:
        List[str]: List of combined content lines.
        Dict[int, int]: Lookup dict for old content, line id in original content -> line id in combined content.
        Dict[int, int]: Lookup dict for new content, line id in original content -> line id in combined content.
    """
    diff_lines_groups: List[List[DiffLine]] = []
    cur_diff_line_group: List[DiffLine] = []

    old_file_lines = old_file_content.splitlines(keepends=False)
    new_file_lines = new_file_content.splitlines(keepends=False)

    ############### Step I: Group continuous diff lines ###############
    for diff_line in file_diff_lines:
        if diff_line.sep:
            continue

        if len(cur_diff_line_group) == 0:
            cur_diff_line_group.append(diff_line)
        elif diff_line.id == cur_diff_line_group[-1].id + 1:
            cur_diff_line_group.append(diff_line)
        else:
            assert diff_line.id == cur_diff_line_group[-1].id + 2
            diff_lines_groups.append(cur_diff_line_group)
            cur_diff_line_group = [diff_line]

    if len(cur_diff_line_group) > 0:
        diff_lines_groups.append(cur_diff_line_group)

    ############### Step II: Add unchanged lines to combine old content and new content ###############
    old_line_id_lookup_nb2comb: Dict[int, int] = {}  # 1-based, 1-based
    new_line_id_lookup_nb2comb: Dict[int, int] = {}  # 1-based, 1-based

    ####### (1) Add unchanged lines in the beginning
    start_diff_line = diff_lines_groups[0][0]
    assert old_file_lines[:start_diff_line.lineno - 1] == new_file_lines[:start_diff_line.lineno - 1]

    lines_before: List[str] = old_file_lines[:start_diff_line.lineno - 1]

    for i in range(len(lines_before)):
        old_line_id_lookup_nb2comb[i + 1] = i + 1
        new_line_id_lookup_nb2comb[i + 1] = i + 1

    ####### (2) Add unchanged lines between diff line groups
    cur_old_line_id = cur_new_line_id = len(lines_before)
    lines_between: List[str] = []

    for i, diff_line_group in enumerate(diff_lines_groups):
        # 1. Add unchanged lines, until reaching the first diff line of the current diff_line_group
        group_start_diff_line = diff_line_group[0]
        while (
                group_start_diff_line.source == SourceFileType.OLD and cur_old_line_id < group_start_diff_line.lineno - 1) or \
                (
                        group_start_diff_line.source == SourceFileType.NEW and cur_new_line_id < group_start_diff_line.lineno - 1):
            cur_old_line_id += 1
            cur_new_line_id += 1
            assert old_file_lines[cur_old_line_id - 1] == new_file_lines[cur_new_line_id - 1]

            lines_between.append(old_file_lines[cur_old_line_id - 1])

            old_line_id_lookup_nb2comb[cur_old_line_id] = len(lines_between) + len(lines_before)
            new_line_id_lookup_nb2comb[cur_new_line_id] = len(lines_between) + len(lines_before)

        # 2. Add diff lines
        for diff_line in diff_line_group:
            lines_between.append(diff_line.code)

            if diff_line.source == SourceFileType.OLD:
                cur_old_line_id += 1
                old_line_id_lookup_nb2comb[cur_old_line_id] = len(lines_between) + len(lines_before)
            else:
                cur_new_line_id += 1
                new_line_id_lookup_nb2comb[cur_new_line_id] = len(lines_between) + len(lines_before)

    ####### (3) Add unchanged lines in the end
    assert old_file_lines[cur_old_line_id:] == new_file_lines[cur_new_line_id:]

    lines_after: List[str] = old_file_lines[cur_old_line_id:]

    for i in range(len(lines_after)):
        old_line_id_lookup_nb2comb[cur_old_line_id + i + 1] = i + 1 + len(lines_between) + len(lines_before)
        new_line_id_lookup_nb2comb[cur_new_line_id + i + 1] = i + 1 + len(lines_between) + len(lines_before)

    comb_file_content = "\n".join(lines_before + lines_between + lines_after)

    return comb_file_content, old_line_id_lookup_nb2comb, new_line_id_lookup_nb2comb


"""Match the Structs of Functions / Classes / ClassFunctions / IfMains"""

LocationPair = namedtuple('LocationPair', ['before', 'after'])


def is_subset(list1: List, list2: List) -> bool:
    """Whether list1 is a subset of list2"""
    set1 = set(list1)
    set2 = set(list2)
    return set1.issubset(set2)


def has_same_elements(list1: List, list2: List) -> bool:
    """Whether list1 and list2 have duplicate elements"""
    set1 = set(list1)
    set2 = set(list2)
    return not set1.isdisjoint(set2)


def _is_modified_struct(
        old_file_lines: List[str], old_diff_line_ids: List[int], old_struct_location: Location,
        new_file_lines: List[str], new_diff_line_ids: List[int], new_struct_location: Location
) -> bool:
    """
    Determine whether the two structs from the file before and after modification are the same.
    NOTE: Only support struct MAIN, FUNCTION, CLASS, CLASSFUNCTION.
    """
    old_struct_line_ids = old_struct_location.get_full_range()
    old_rest_line_ids = sorted(list(set(old_struct_line_ids) - set(old_diff_line_ids)))

    new_struct_line_ids = new_struct_location.get_full_range()
    new_rest_line_ids = sorted(list(set(new_struct_line_ids) - set(new_diff_line_ids)))

    if len(old_rest_line_ids) != len(new_rest_line_ids):
        return False

    for old_line_id, new_line_id in zip(old_rest_line_ids, new_rest_line_ids):
        if old_file_lines[old_line_id - 1] != new_file_lines[new_line_id - 1]:
            # print(old_line_id)
            # print(new_line_id)
            # print(old_content[old_line_id - 1], new_content[new_line_id - 1])
            return False

    return True


def _build_map_from_ori_name_to_now_names(
        structs: List[int],
        locations: Dict[int, Location]
) -> Dict[str, Dict[str, int]]:
    """
    Build a dictionary that maps original name (like "xxx") to now names (like "xxx@num").
    NOTE: Only support struct FUNCTION, CLASS, CLASSFUNCTION.
    """
    # original name -> now name -> location id
    ori_name2no_names: Dict[str, Dict[str, int]] = {}
    for loc_id in structs:
        now_name = locations[loc_id].name
        ori_name = now_name.split("@")[0]
        if ori_name not in ori_name2no_names:
            ori_name2no_names[ori_name] = {}
        assert now_name not in ori_name2no_names[ori_name]
        ori_name2no_names[ori_name][now_name] = loc_id

    return ori_name2no_names


def _match_ifMain_before_and_after(
        old_file_lines: List[str], old_locations: Dict[int, Location], old_diff_line_ids: List[int],
        old_ifMains: List[int],
        new_file_lines: List[str], new_locations: Dict[int, Location], new_diff_line_ids: List[int],
        new_ifMains: List[int]
) -> List[LocationPair]:
    """
    Match if_main structs in code before and code after.

    NOTE 1: Only for MAIN.
    NOTE 2: There will not be more than one if_main structure in a code.
    """
    assert len(old_ifMains) <= 1 and len(new_ifMains) <= 1

    if len(old_ifMains) == 0 and len(new_ifMains) == 0:
        return []

    if len(old_ifMains) == 1 and len(new_ifMains) == 0:
        return [LocationPair(before=old_ifMains[0], after=None)]

    if len(old_ifMains) == 0 and len(new_ifMains) == 1:
        return [LocationPair(before=None, after=new_ifMains[0])]

    old_ifMain_loc = old_locations[old_ifMains[0]]
    new_ifMain_loc = new_locations[new_ifMains[0]]

    assert _is_modified_struct(
        old_file_lines, old_diff_line_ids, old_ifMain_loc,
        new_file_lines, new_diff_line_ids, new_ifMain_loc
    )

    return [LocationPair(before=old_ifMains[0], after=new_ifMains[0])]


def _match_diff_class_or_func(
        old_file_lines: List[str], old_locations: Dict[int, Location], old_diff_line_ids: List[int],
        old_structs: List[int],
        new_file_lines: List[str], new_locations: Dict[int, Location], new_diff_line_ids: List[int],
        new_structs: List[int]
) -> List[LocationPair]:
    """
    Match the diff structs (structs containing diff lines).

    NOTE 1: Only for CLASS or FUNCTION.
    NOTE 2: Since we have added "@<start>" to the class / func name, it is possible that names of
            not renamed classes / funcs may be different between old_structs and new_structs.
    """
    # (1) Deleted structs
    # (2) Added structs
    # (3) Modified structs (three types: a. delete + add; b. delete only; c. add only)
    diff_struct_pairs: List[LocationPair] = []

    old_mod_structs: List[int] = []
    new_mod_structs: List[int] = []

    ########## STEP 1: Select `del_structs` and `old_mod_structs` from structs in old file ##########
    for loc_id in old_structs:
        range_line_ids = old_locations[loc_id].get_full_range()
        if is_subset(range_line_ids, old_diff_line_ids):
            diff_struct_pairs.append(LocationPair(before=loc_id, after=None))
        elif has_same_elements(range_line_ids, old_diff_line_ids):
            old_mod_structs.append(loc_id)

    ########## STEP 2: Select `add_structs` and `new_mod_structs` from structs in new file ##########
    for loc_id in new_structs:
        range_line_ids = new_locations[loc_id].get_full_range()
        if is_subset(range_line_ids, new_diff_line_ids):
            diff_struct_pairs.append(LocationPair(before=None, after=loc_id))
        elif has_same_elements(range_line_ids, new_diff_line_ids):
            new_mod_structs.append(loc_id)

    ########## STEP 3: Match items in `old_mod_structs` and `new_mod_structs` to construct `mod_structs` ##########
    old_ori_name2no_names: Dict[str, Dict[str, int]] = _build_map_from_ori_name_to_now_names(old_structs, old_locations)
    new_ori_name2no_names: Dict[str, Dict[str, int]] = _build_map_from_ori_name_to_now_names(new_structs, new_locations)

    def find_match_loc_by_name(
            _searcher_name: str,
            _ori_name2no_names_for_target: Dict[str, Dict[str, int]],
            _diff_line_ids_for_searcher: List[int],
            _diff_line_ids_for_target: List[int]) -> int:
        _ori_name, _searcher_start = _searcher_name.split("@")
        _searcher_start = int(_searcher_start)  # 1-based
        _searcher_diff_lines_num = bisect.bisect_left(_diff_line_ids_for_searcher, _searcher_start)

        _obj_loc_id = None
        for _no_name, _loc_id in _ori_name2no_names_for_target[_ori_name].items():
            _no_struct_start = int(_no_name.split("@")[1])
            _no_diff_lines_num = bisect.bisect_left(_diff_line_ids_for_target, _no_struct_start)

            if _searcher_start - _searcher_diff_lines_num == _no_struct_start - _no_diff_lines_num:
                _obj_loc_id = _loc_id
                break

        assert _obj_loc_id is not None
        return _obj_loc_id

    while old_mod_structs:
        old_loc_id = old_mod_structs.pop(0)
        old_loc = old_locations[old_loc_id]
        match = False

        i = 0
        while i < len(new_mod_structs):
            new_loc_id = new_mod_structs[i]
            new_loc = new_locations[new_loc_id]

            if _is_modified_struct(
                    old_file_lines, old_diff_line_ids, old_loc,
                    new_file_lines, new_diff_line_ids, new_loc):
                # 1) struct modified with both delete and add
                diff_struct_pairs.append(LocationPair(before=old_loc_id, after=new_loc_id))
                new_mod_structs.pop(i)
                match = True
                break

            i += 1

        if not match:
            # 2) struct modified with delete only
            # NOTE: Must use the original name to search
            new_loc_id = find_match_loc_by_name(
                _searcher_name=old_loc.name,
                _ori_name2no_names_for_target=new_ori_name2no_names,
                _diff_line_ids_for_searcher=old_diff_line_ids,
                _diff_line_ids_for_target=new_diff_line_ids
            )
            diff_struct_pairs.append(LocationPair(before=old_loc_id, after=new_loc_id))

    if new_mod_structs:
        # 3) struct modified with add only
        for new_loc_id in new_mod_structs:
            # NOTE: Must use the original name to search
            new_loc = new_locations[new_loc_id]
            old_loc_id = find_match_loc_by_name(
                _searcher_name=new_loc.name,
                _ori_name2no_names_for_target=old_ori_name2no_names,
                _diff_line_ids_for_searcher=new_diff_line_ids,
                _diff_line_ids_for_target=old_diff_line_ids
            )
            diff_struct_pairs.append(LocationPair(before=old_loc_id, after=new_loc_id))

    return diff_struct_pairs


def _match_diff_classFunction(
        old_file_lines: List[str], old_locations: Dict[int, Location], old_diff_line_ids: List[int],
        old_classFuncs: Dict[int, List[int]],
        new_file_lines: List[str], new_locations: Dict[int, Location], new_diff_line_ids: List[int],
        new_classFuncs: Dict[int, List[int]],
        diff_class_pairs: List[LocationPair]
) -> Dict[LocationPair, List[LocationPair]]:
    """
    Match the diff CLASS_FUNCTION structs.

    NOTE 1: Only for CLASS_FUNCTION.
    """
    diff_classFunc_pairs: Dict[LocationPair, List[LocationPair]] = {}

    for diff_class_pair in diff_class_pairs:
        cur_class_classFunc_pairs: List[LocationPair] = []

        # (1) For deleted classes
        if diff_class_pair.after is None:
            assert diff_class_pair.before is not None
            for classFunc_loc_id in old_classFuncs[diff_class_pair.before]:
                cur_class_classFunc_pairs.append(LocationPair(before=classFunc_loc_id, after=None))

        # (2) For added classes
        elif diff_class_pair.before is None:
            assert diff_class_pair.after is not None
            for classFunc_loc_id in new_classFuncs[diff_class_pair.after]:
                cur_class_classFunc_pairs.append(LocationPair(before=None, after=classFunc_loc_id))

        # (3) For modified classes
        else:
            cur_old_classFuncs: List[int] = old_classFuncs[diff_class_pair.before]
            cur_new_classFuncs: List[int] = new_classFuncs[diff_class_pair.after]

            cur_class_classFunc_pairs = _match_diff_class_or_func(
                old_file_lines, old_locations, old_diff_line_ids, cur_old_classFuncs,
                new_file_lines, new_locations, new_diff_line_ids, cur_new_classFuncs
            )

        diff_classFunc_pairs[diff_class_pair] = cur_class_classFunc_pairs

    return diff_classFunc_pairs


def _split_del_and_add_line_ids(diff_lines: List[DiffLine]) -> Tuple[List[int], List[int]]:
    del_line_ids: List[int] = []
    add_line_ids: List[int] = []

    for diff_line in diff_lines:
        if not diff_line.sep and diff_line.source == SourceFileType.OLD:
            del_line_ids.append(diff_line.lineno)
        if not diff_line.sep and diff_line.source == SourceFileType.NEW:
            add_line_ids.append(diff_line.lineno)

    return del_line_ids, add_line_ids


@dataclass(frozen=True)
class AllDiffStructInfo:
    """
    For recording all diff structs in single file.

    NOTE: Only for modified files.
    """
    if_mains: List[LocationPair]
    classes: List[LocationPair]
    functions: List[LocationPair]
    class_functions: Dict[LocationPair, List[LocationPair]]


def match_diff_structs_within_file(
        diff_lines: List[DiffLine],
        old_file_content: str, old_location_parse_res: Tuple[Dict[int, Location], Dict[int, int], Dict],
        new_file_content: str, new_location_parse_res: Tuple[Dict[int, Location], Dict[int, int], Dict]
) -> AllDiffStructInfo:
    """
    Match the structs in code before and after commit.

    NOTE 1: Only for modified files.
    NOTE 2: Only for MAIN (if_main), FUNCTION, CLASS and CLASSFUNCTION.

    Args:
        diff_lines (List[DiffLine]): List of diff lines.
        old_file_content: File content before applying the commit.
        old_location_parse_res: Result from `agent_app.static_analysis.parse.parse_python_file_locations`
        new_file_content: File content after applying the commit.
        new_location_parse_res: Result from `agent_app.static_analysis.parse.parse_python_file_locations`
    Returns:
        AllDiffStructInfo:
    """
    old_file_lines: List[str] = old_file_content.splitlines(keepends=False)
    new_file_lines: List[str] = new_file_content.splitlines(keepends=False)

    old_locations, _, old_structs_info = old_location_parse_res
    new_locations, _, new_structs_info = new_location_parse_res

    del_line_ids, add_line_ids = _split_del_and_add_line_ids(diff_lines)

    # (1) Distinguish the types of if_main modifications
    diff_ifMain_pairs = _match_ifMain_before_and_after(
        old_file_lines, old_locations, del_line_ids, old_structs_info["if_mains"],
        new_file_lines, new_locations, add_line_ids, new_structs_info["if_mains"]
    )

    # (2) Distinguish the types of function modifications
    diff_func_pairs = _match_diff_class_or_func(
        old_file_lines, old_locations, del_line_ids, old_structs_info["funcs"],
        new_file_lines, new_locations, add_line_ids, new_structs_info["funcs"]
    )

    # (2) Distinguish the types of class modifications
    diff_class_pairs = _match_diff_class_or_func(
        old_file_lines, old_locations, del_line_ids, old_structs_info["classes"],
        new_file_lines, new_locations, add_line_ids, new_structs_info["classes"]
    )

    # (4) Distinguish the types of class function modifications
    diff_classFunc_pairs = _match_diff_classFunction(
        old_file_lines, old_locations, del_line_ids, old_structs_info["classes_funcs"],
        new_file_lines, new_locations, add_line_ids, new_structs_info["classes_funcs"],
        diff_class_pairs
    )

    res = AllDiffStructInfo(
        if_mains=diff_ifMain_pairs,
        functions=diff_func_pairs,
        classes=diff_class_pairs,
        class_functions=diff_classFunc_pairs
    )

    return res


"""Group Diff Lines"""


@dataclass
class DiffLocation(Location):
    # Indicate whether the file where the Location in is before commit or after commit.
    file_type: SourceFileType


class DiffLocationNotFoundError(Exception):
    def __init__(self, loc: DiffLocation):
        self.loc = loc

    def __str__(self):
        print_msg = (f"\n"
                     f"- File: {self.loc.file_type}\n"
                     f"- Id: {self.loc.id}\n"
                     f"- Father: {self.loc.father}\n"
                     f"- Type: {self.loc.type}\n"
                     f"- Name: {self.loc.name}\n"
                     f"- Range: {self.loc.range.start}-{self.loc.range.end}\n")

        return print_msg


def loc_to_diff_loc(loc: Location, file_type: SourceFileType) -> DiffLocation:
    assert file_type in SourceFileType.attributes()
    return DiffLocation(**asdict(loc), file_type=file_type)


def get_diff_loc_of_diff_line(
        diff_line: DiffLine,
        old_locations: Dict[int, Location], old_line_id2loc_id: Dict[int, int],
        new_locations: Dict[int, Location], new_line_id2loc_id: Dict[int, int]
) -> DiffLocation:
    if diff_line.source == SourceFileType.OLD:
        loc_id = old_line_id2loc_id[diff_line.lineno]
        loc = old_locations[loc_id]
    else:
        loc_id = new_line_id2loc_id[diff_line.lineno]
        loc = new_locations[loc_id]
    assert loc.type in line_loc_types
    return loc_to_diff_loc(loc, diff_line.source)


@dataclass
class DiffLineGroup:
    """
    For recording diff lines in the same struct.
    NOTE: Only contain diff lines.
    """
    loc_type: LocationType
    lines: List[DiffLine] | None
    children: List[DiffLineGroup] | None


def _get_struct_with_no_children_line_group(
        loc_type: LocationType,
        diff_lines: List[DiffLine] | None = None
) -> DiffLineGroup:
    """
    Construct a LineGroup for struct with no children.

    NOTE: Only for GLOBAL / FUNCTION / CLASSGLOBAL / CLASSFUNCTION / MAINGLOBAL
    """
    assert loc_type in no_children_loc_types
    diff_lines = diff_lines if diff_lines is not None else []

    return DiffLineGroup(loc_type=loc_type, lines=diff_lines, children=None)


def _get_struct_with_children_line_group(
        loc_type: LocationType,
        children: List[DiffLineGroup] | None = None
) -> DiffLineGroup:
    """
    Construct a LineGroup for struct with children.

    NOTE: Only for CLASS / MAIN
    """
    assert loc_type in children_loc_types
    children = children if children is not None else []

    if not children:
        for child in children:
            if loc_type == LocationType.CLASS:
                assert child.loc_type in class_child_loc_types
            else:
                assert child.loc_type in main_child_loc_types

    return DiffLineGroup(loc_type=loc_type, lines=None, children=children)


def group_diff_lines_by_struct_within_file(
        old_locations: Dict[int, Location], old_line_loc_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_line_loc_lookup: Dict[int, int],
        file_diff_lines: List[DiffLine], all_diff_structs_info: AllDiffStructInfo
) -> List[DiffLineGroup]:
    """
    NOTE 1: Only for modified files.
    NOTE 2: For all diff lines in single file, group them by struct (Global, Function, Class, Main),
            also, we will refine the Class group and Main group.
    """

    ######################## Inner Function For Step I ########################

    def _get_new_group(_line_loc_type: LocationType, _diff_line: DiffLine) -> DiffLineGroup:
        assert _line_loc_type in no_children_loc_types
        _group = _get_struct_with_no_children_line_group(_line_loc_type, [_diff_line])

        if _line_loc_type in class_child_loc_types:
            father_loc_type = LocationType.CLASS
        elif _line_loc_type in main_child_loc_types:
            father_loc_type = LocationType.MAIN
        else:
            return _group

        return _get_struct_with_children_line_group(father_loc_type, [_group])

    def _update_cur_group(_cur_group: DiffLineGroup, _line_loc_type: LocationType,
                          _diff_line: DiffLine) -> DiffLineGroup:
        if _cur_group.loc_type == LocationType.CLASS:
            assert _line_loc_type in class_child_loc_types

            _child = _get_struct_with_no_children_line_group(_line_loc_type, [_diff_line])
            _cur_group.children.append(_child)

        elif _cur_group.loc_type == LocationType.MAIN:
            assert _line_loc_type in main_child_loc_types

            _child = _get_struct_with_no_children_line_group(_line_loc_type, [_diff_line])
            _cur_group.children.append(_child)

        else:
            assert _line_loc_type not in class_child_loc_types and _line_loc_type not in main_child_loc_types

            _cur_group.lines.append(_diff_line)

        return _cur_group

    def _is_same_location(_loc1: Location, _loc2: Location) -> bool:
        """
        NOTE 1: loc_1, loc_2 must be in the same file (old / new).
        NOTE 2: loc_1, loc_2 can be DiffLocation.
        """
        return _loc1.name == _loc2.name and same_line_range(_loc1.range, _loc2.range)

    def _in_same_function(
            _last_line_diffloc: DiffLocation,
            _curr_line_diffloc: DiffLocation,
            _diff_func_pairs: List[LocationPair]
    ) -> bool:
        """
        NOTE: Last line and current line are both in Location FUNCTION or CLASSFUNCTION.
        """
        _same_func: bool = False

        ######## CASE 1 ########
        # Last line and current line are in the same file (old / new)
        if _last_line_diffloc.file_type == _curr_line_diffloc.file_type:
            if _last_line_diffloc.id == _curr_line_diffloc.id:
                _same_func = True
            else:
                _same_func = False

        ######## CASE 2 ########
        # Last line is in the old file, i.e. a deleted line
        # Current line is in the new file, i.e. an added line
        elif _last_line_diffloc.file_type == SourceFileType.OLD:
            _find_flag = False

            for _diff_func_pair in _diff_func_pairs:
                if _last_line_diffloc.id == _diff_func_pair.before:
                    _find_flag = True

                    if _diff_func_pair.after is None:
                        # Deleted function (last line) cannot have an added line (curr line), thus in different groups
                        _same_func = False
                    elif _is_same_location(_curr_line_diffloc, new_locations[_diff_func_pair.after]):
                        _same_func = True
                    else:
                        _same_func = False

            assert _find_flag

        ######## CASE 3 ########
        # Last line is in the new file, i.e. an added line
        # Current line is in the old file, i.e. a deleted line
        elif _last_line_diffloc.file_type == SourceFileType.NEW:
            _find_flag = False

            for _diff_func_pair in _diff_func_pairs:
                if _last_line_diffloc.id == _diff_func_pair.after:
                    _find_flag = True

                    if _diff_func_pair.before is None:
                        # Added function (last line) cannot have a deleted line (curr line), thus in different groups
                        _same_func = False
                    elif _is_same_location(_curr_line_diffloc, old_locations[_diff_func_pair.before]):
                        _same_func = True
                    else:
                        _same_func = False

            assert _find_flag

        return _same_func

    def _in_same_father(
            _last_line_diffloc: DiffLocation,
            _curr_line_diffloc: DiffLocation,
            _diff_father_pairs: List[LocationPair]
    ) -> bool:
        """
        CASE 1: Last line and current line are both in Location MAINGLOBAL, father indicates MAIN
        CASE 2: Last line and current line are both in Location CLASSGLOBAL or CLASSFUNCTION, father indicates CLASS.
        """
        _same_father: bool = False

        ######## CASE 1 ########
        # Last line and current line are in the same file (old / new)
        if _last_line_diffloc.file_type == _curr_line_diffloc.file_type:
            if _last_line_diffloc.father == _curr_line_diffloc.father:
                _same_father = True
            else:
                _same_father = False

        ######## CASE 2 ########
        # Last line is in the old file, i.e. a deleted line
        # Current line is in the new file, i.e. an added line
        elif _last_line_diffloc.file_type == SourceFileType.OLD:
            _find_flag = False

            for _diff_father_pair in _diff_father_pairs:
                if _last_line_diffloc.father == _diff_father_pair.before:
                    _find_flag = True

                    if _diff_father_pair.after is None:
                        # Deleted class / main (last line) cannot have an added line (curr line), thus in different groups
                        _same_father = False
                    elif _curr_line_diffloc.father == _diff_father_pair.after:
                        _same_father = True
                    else:
                        _same_father = False

            assert _find_flag

        ######## CASE 3 ########
        # Last line is in the new file, i.e. an added line
        # Current line is in the old file, i.e. a deleted line
        elif _last_line_diffloc.file_type == SourceFileType.NEW:
            _find_flag = False

            for _diff_father_pair in _diff_father_pairs:
                if _last_line_diffloc.father == _diff_father_pair.after:
                    _find_flag = True

                    if _diff_father_pair.before is None:
                        # Added class / main (last line) cannot have a deleted line (curr line), thus in different groups
                        _same_father = False
                    elif _curr_line_diffloc.father == _diff_father_pair.before:
                        _same_father = True
                    else:
                        _same_father = False

            assert _find_flag

        return _same_father

    ######################## Inner Function For Step I ########################

    # Group diff lines in the same struct
    # - GLOBAL
    # - FUNCTION
    # - CLASS
    # |- CLASSGLOBAL
    # |- CLASSFUNCTION
    # - MAIN
    # |- MAINGLOBAL
    diff_line_groups: List[DiffLineGroup] = []

    ######################## Step I: Group all diff lines by struct ########################
    # NOTE 1: When facing CLASSGLOBAL or CLASSFUNCTION, only consider whether they are in the same CLASS
    # NOTE 2: When facing MAINGLOBAL, only consider whether they are in the same MAIN
    last_line_diffloc: DiffLocation | None = None
    cur_group: DiffLineGroup | None = None

    for diff_line in file_diff_lines:
        if diff_line.sep:
            continue

        ############## (1) Find location of current line ##############
        cur_line_diffloc = get_diff_loc_of_diff_line(
            diff_line, old_locations, old_line_loc_lookup, new_locations, new_line_loc_lookup
        )

        ############## (2) Group current line and last line ##############
        if last_line_diffloc is None:
            # Last line does not exist -> beginning, open a new group
            new_group_flag = True
        else:
            # Last line exists -> determine whether current line and last line are in the same group
            if last_line_diffloc.type in class_child_loc_types and cur_line_diffloc.type in class_child_loc_types:
                new_group_flag = not _in_same_father(last_line_diffloc,
                                                     cur_line_diffloc,
                                                     all_diff_structs_info.classes)
            elif last_line_diffloc.type != cur_line_diffloc.type:
                new_group_flag = True
            elif last_line_diffloc.type == LocationType.MAIN_GLOBAL:
                assert _in_same_father(last_line_diffloc,
                                       cur_line_diffloc,
                                       all_diff_structs_info.if_mains)
                new_group_flag = False
            elif last_line_diffloc.type == LocationType.FUNCTION:
                new_group_flag = not _in_same_function(last_line_diffloc,
                                                       cur_line_diffloc,
                                                       all_diff_structs_info.functions)
            else:
                # last_line_loc.type == LocationType.GLOBAL
                # NOTE: We do not distinguish the corresponding modification relationships between global statements,
                #       but group all continous global statements into one group
                #       For example:
                #         - a = 1
                #         - s = call()
                #         + a = 2
                #         + s = safe_call()
                #       We do not link "- a = 1" with "+ a = 2" and "- s = call()" with "+ s = safe_call()",
                #       but divide these four statements into one group in the order they were originally in the commit
                new_group_flag = False

        ############## (3) Update current group ##############
        if new_group_flag:
            # Add the last group to the groups
            if cur_group is not None:
                diff_line_groups.append(cur_group)
            # Open a new group
            cur_group = _get_new_group(cur_line_diffloc.type, diff_line)
        else:
            cur_group = _update_cur_group(cur_group, cur_line_diffloc.type, diff_line)

        ############## (4) Current line becomes last line ##############
        last_line_diffloc = cur_line_diffloc

    if cur_group is not None:
        diff_line_groups.append(cur_group)

    ######################## Inner Function For Step II ########################

    def _in_same_classFunction(
            _last_line_diffloc: DiffLocation,
            _curr_line_diffloc: DiffLocation,
            _diff_classFunc_pairs: Dict[LocationPair, List[LocationPair]]
    ) -> bool:
        """
        NOTE: Last line and current line are in the same class!
        """
        _same_classFunc: bool = False

        ######## CASE 1 ########
        # Last line and current line are in the same file (old / new)
        if _last_line_diffloc.file_type == _curr_line_diffloc.file_type:
            assert _last_line_diffloc.father == _curr_line_diffloc.father

            if _last_line_diffloc.id == _curr_line_diffloc.id:
                _same_classFunc = True
            else:
                _same_classFunc = False

        ######## CASE 2 ########
        # Last line is in the old file, i.e. a deleted line
        # Current line is in the new file, i.e. an added line
        elif _last_line_diffloc.file_type == SourceFileType.OLD:
            _cur_diff_class_pair = LocationPair(before=_last_line_diffloc.father, after=_curr_line_diffloc.father)
            assert _cur_diff_class_pair in _diff_classFunc_pairs
            _same_classFunc = _in_same_function(
                _last_line_diffloc, _curr_line_diffloc, _diff_classFunc_pairs[_cur_diff_class_pair]
            )

        ######## CASE 3 ########
        # Last line is in the new file, i.e. an added line
        # Current line is in the old file, i.e. a deleted line
        elif _last_line_diffloc.file_type == SourceFileType.NEW:
            _cur_diff_class_pair = LocationPair(before=_curr_line_diffloc.father, after=_last_line_diffloc.father)
            assert _cur_diff_class_pair in _diff_classFunc_pairs
            _same_classFunc = _in_same_function(
                _last_line_diffloc, _curr_line_diffloc, _diff_classFunc_pairs[_cur_diff_class_pair]
            )

        return _same_classFunc

    ######################## Inner Function For Step II ########################

    ######################## Step II: Group the children in the same Class / Main ########################
    for line_group in diff_line_groups:
        assert line_group.loc_type in top_level_loc_types

        if line_group.loc_type == LocationType.MAIN:
            updt_children: List[DiffLineGroup] = []

            cur_updt_child: DiffLineGroup | None = None

            ############## (1) Group diff lines in the same MAIN to get new children ##############
            for cur_ori_child in line_group.children:
                assert cur_ori_child.loc_type in main_child_loc_types and len(cur_ori_child.lines) == 1
                # NOTE: Since the child_location type of MAIN is only MAINGLOBAL, so for a MAIN children,
                #       there is only one group of MAINGLOBAL type, which contains all the diff lines in MAIN.
                if cur_updt_child is None:
                    cur_updt_child = cur_ori_child
                else:
                    cur_updt_child.lines.extend(cur_ori_child.lines)

            if cur_updt_child is not None:
                updt_children.append(cur_updt_child)

            ############## (2) Update children info of current MAIN line group ##############
            line_group.children = updt_children

        if line_group.loc_type == LocationType.CLASS:
            updt_children: List[DiffLineGroup] = []

            cur_updt_child: DiffLineGroup | None = None
            last_line_diffloc: DiffLocation | None = None

            ############## (1) Group diff lines in the same CLASS to get new children ##############
            for cur_ori_child in line_group.children:
                assert cur_ori_child.loc_type in class_child_loc_types and len(cur_ori_child.lines) == 1

                ############## 1) Find location of current line ##############
                cur_line_diffloc = get_diff_loc_of_diff_line(
                    cur_ori_child.lines[0], old_locations, old_line_loc_lookup, new_locations, new_line_loc_lookup
                )

                ############## 2) Group current line and last line in the same class ##############
                if last_line_diffloc is None:
                    # Last line does not exist -> beginning, open a new sub_group
                    new_group_flag = True
                else:
                    # Last line exists -> determine whether current line and last line are in the same sub_group
                    if last_line_diffloc.type != cur_line_diffloc.type:
                        new_group_flag = True
                    elif last_line_diffloc.type == LocationType.CLASS_FUNCTION:
                        new_group_flag = not _in_same_classFunction(last_line_diffloc,
                                                                    cur_line_diffloc,
                                                                    all_diff_structs_info.class_functions)
                    else:
                        # last_sub_struct.group_name == LocationType.CLASSGLOBAL
                        new_group_flag = False

                ############## 3) Update current sub_group ##############
                if new_group_flag:
                    # Add current sub_group
                    if cur_updt_child is not None:
                        updt_children.append(cur_updt_child)
                    # Open a new sub_group
                    cur_updt_child = cur_ori_child
                else:
                    cur_updt_child.lines.extend(cur_ori_child.lines)

                ############## 4) Current line becomes last line ##############
                last_line_diffloc = cur_line_diffloc

            if cur_updt_child is not None:
                updt_children.append(cur_updt_child)

            ############## (2) Update children info of current CLASS line group ##############
            line_group.children = updt_children

    ######################## Inner Function For Step III ########################

    def _split_diff_lines_in_global(_global_line_group: DiffLineGroup) -> List[DiffLineGroup]:
        """
        Split discontinuous diff lines in global line group, and return the line group list after separation.

        NOTE: Only for GLOBAL / MAINGLOBAL / CLASSGLOBAL
        """
        assert _global_line_group.loc_type in (LocationType.GLOBAL, LocationType.MAIN_GLOBAL, LocationType.CLASS_GLOBAL)

        _cont_diff_lines_groups: List[List[DiffLine]] = []
        _cur_cont_diff_lines: List[DiffLine] = []

        ######## Step 1: Split discontinuous diff lines ########
        for _diff_line in _global_line_group.lines:
            if len(_cur_cont_diff_lines) == 0:
                _cur_cont_diff_lines.append(_diff_line)
            elif _diff_line.id == _cur_cont_diff_lines[-1].id + 1:
                _cur_cont_diff_lines.append(_diff_line)
            else:
                _cont_diff_lines_groups.append(_cur_cont_diff_lines)
                _cur_cont_diff_lines = [_diff_line]

        if len(_cur_cont_diff_lines) > 0:
            _cont_diff_lines_groups.append(_cur_cont_diff_lines)

        ######## Step 2: Build line group for each set of continuous diff lines ########
        _global_line_groups: List[DiffLineGroup] = []
        for _cont_diff_lines in _cont_diff_lines_groups:
            _global_line_group = _get_struct_with_no_children_line_group(_global_line_group.loc_type, _cont_diff_lines)
            _global_line_groups.append(_global_line_group)

        return _global_line_groups

    def _update_class_diff_line_group(_class_line_group: DiffLineGroup) -> DiffLineGroup:
        assert _class_line_group.loc_type == LocationType.CLASS

        _updt_children: List[DiffLineGroup] = []

        for _child in _class_line_group.children:
            if _child.loc_type == LocationType.CLASS_GLOBAL:
                _updt_children.extend(_split_diff_lines_in_global(_child))
            else:
                _updt_children.append(_child)

        _class_line_group.children = _updt_children

        return _class_line_group

    def _update_main_diff_line_group(_main_line_group: DiffLineGroup) -> DiffLineGroup:
        assert _main_line_group.loc_type == LocationType.MAIN

        assert len(_main_line_group.children) == 1
        _updt_children = _split_diff_lines_in_global(_main_line_group.children[0])

        _main_line_group.children = _updt_children

        return _main_line_group

    ######################## Inner Function For Step III ########################

    ######################## Step III: Split discontinuous diff lines in global  ########################
    # NOTE: For Global / ClassGlobal / MainGlobal
    updt_diff_line_groups: List[DiffLineGroup] = []

    for line_group in diff_line_groups:
        assert line_group.loc_type in top_level_loc_types

        if line_group.loc_type == LocationType.GLOBAL:
            updt_line_groups = _split_diff_lines_in_global(line_group)
            updt_diff_line_groups.extend(updt_line_groups)

        elif line_group.loc_type == LocationType.CLASS:
            updt_line_group = _update_class_diff_line_group(line_group)
            updt_diff_line_groups.append(updt_line_group)

        elif line_group.loc_type == LocationType.MAIN:
            updt_line_group = _update_main_diff_line_group(line_group)
            updt_diff_line_groups.append(updt_line_group)

        else:
            updt_diff_line_groups.append(line_group)

    return updt_diff_line_groups


"""Prepare Description of Modified File"""


def diff_line_group_to_seq(
        diff_line_group: DiffLineGroup,
        old_locations: Dict[int, Location], old_line_loc_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_line_loc_lookup: Dict[int, int]
) -> str:
    if diff_line_group.loc_type == LocationType.MAIN:
        main_seq = ""
        for child_line_group in diff_line_group.children:
            child_seq = diff_line_group_to_seq(
                child_line_group, old_locations, old_line_loc_lookup, new_locations, new_line_loc_lookup
            )
            main_seq += child_seq + "\n"

        return main_seq

    elif diff_line_group.loc_type == LocationType.CLASS:

        li = diff_line_group.children[0].lines[0]
        if li.source == SourceFileType.OLD:
            loc = old_locations[old_line_loc_lookup[li.lineno]]
            class_loc = old_locations[loc.father]
        else:
            loc = new_locations[new_line_loc_lookup[li.lineno]]
            class_loc = new_locations[loc.father]
        class_prefix = f"<class>{class_loc.name.split('@')[0]}</class> "

        class_seq = ""
        for child_line_group in diff_line_group.children:
            child_seq = diff_line_group_to_seq(
                child_line_group, old_locations, old_line_loc_lookup, new_locations, new_line_loc_lookup
            )
            child_seq = class_prefix + child_seq
            class_seq += child_seq + "\n"

        return class_seq

    elif diff_line_group.loc_type == LocationType.FUNCTION or diff_line_group.loc_type == LocationType.CLASS_FUNCTION:

        diff_lines = diff_line_group.lines

        # (1) Get diff code snippet
        lines: List[str] = []
        for i in range(len(diff_lines)):
            if i != 0 and diff_lines[i].id != diff_lines[i - 1].id + 1:
                lines.append("...")
            lines.append(diff_lines[i].code)

        code = "\n".join(lines)

        # (2) Get function name
        if diff_lines[0].source == SourceFileType.OLD:
            loc = old_locations[old_line_loc_lookup[diff_lines[0].lineno]]
        else:
            loc = new_locations[new_line_loc_lookup[diff_lines[0].lineno]]
        func_name = loc.name.split("@")[0]

        return f"<func>{func_name}<func>\n<code>\n{code}\n</code>\n"

    else:
        # GLOBAL / CLASS_GLOBAL / MAIN_GLOBAL
        diff_lines = diff_line_group.lines

        lines: List[str] = []
        for i in range(len(diff_lines)):
            if i != 0:
                assert diff_lines[i].id == diff_lines[i - 1].id + 1
            lines.append(diff_lines[i].code)

        code = "\n".join(lines)

        return f"<global></global>\n<code>\n{code}\n</code>\n"


def get_description_of_modified_file(
        old_locations: Dict[int, Location], old_line_loc_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_line_loc_lookup: Dict[int, int],
        file_diff_lines: List[DiffLine], all_diff_structs_info: AllDiffStructInfo
) -> str:
    """
    Get description of modified file, including class name, function name and code of each diff code snippet.

    NOTE: Only for modified files.
    """
    ########## Step I: Group diff lines by struct type ##########
    diff_line_groups: List[DiffLineGroup] = group_diff_lines_by_struct_within_file(
        old_locations, old_line_loc_lookup,
        new_locations, new_line_loc_lookup,
        file_diff_lines, all_diff_structs_info
    )

    ########## Step II: Get description of current modified file ##########
    diff_file_desc = ""
    for diff_line_group in diff_line_groups:
        seq = diff_line_group_to_seq(
            diff_line_group, old_locations, old_line_loc_lookup, new_locations, new_line_loc_lookup
        )

        diff_file_desc += seq + "\n"

    return diff_file_desc


"""Analyse Structs (class / function / class_function) in Common Code"""


def parse_common_content_structs(
        content: str,
) -> Tuple[List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:
    locations, _, structs_info = parse_python_file_locations(content)

    funcs: List[Tuple[str, LineRange]] = []
    classes: List[Tuple[str, LineRange]] = []
    classes_funcs: List[Tuple[str, List[Tuple[str, LineRange]]]] = []

    for loc_id in structs_info["funcs"]:
        loc = locations[loc_id]
        funcs.append((loc.name.split("@")[0], loc.range))

    for loc_id in structs_info["classes"]:
        loc = locations[loc_id]
        classes.append((loc.name.split("@")[0], loc.range))

    for class_loc_id, classFunc_loc_ids in structs_info["classes_funcs"].items():
        cur_class_funcs: List[Tuple[str, LineRange]] = []
        for loc_id in classFunc_loc_ids:
            loc = locations[loc_id]
            cur_class_funcs.append((loc.name.split("@")[0], loc.range))

        class_loc = locations[class_loc_id]
        classes_funcs.append((class_loc.name.split("@")[0], cur_class_funcs))

    return funcs, classes, classes_funcs


"""Analyse Structs (class / function / class_function) in Combined Code"""


def _align_func_info_in_combined_content(
        all_old_funcs: List[int], diff_func_pairs: List[LocationPair],
        old_locations: Dict[int, Location], old_comb_line_id_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_comb_line_id_lookup: Dict[int, int]
) -> List[Tuple[str, LineRange]]:
    comb_funcs: List[Tuple[str, LineRange]] = []

    ########### Step I: Align diff funcs ###########
    record_old_funcs: List[int] = []

    for diff_func_pair in diff_func_pairs:
        old_func_loc_id = diff_func_pair.before
        new_func_loc_id = diff_func_pair.after

        if new_func_loc_id is None:
            assert old_func_loc_id is not None
            old_loc = old_locations[old_func_loc_id]
            record_old_funcs.append(old_func_loc_id)

            comb_name = old_loc.name.split("@")[0]
            comb_range = LineRange(start=old_comb_line_id_lookup[old_loc.range.start],
                                   end=old_comb_line_id_lookup[old_loc.range.end])

        elif old_func_loc_id is None:
            assert new_func_loc_id is not None
            new_loc = new_locations[new_func_loc_id]

            comb_name = new_loc.name.split("@")[0]
            comb_range = LineRange(start=new_comb_line_id_lookup[new_loc.range.start],
                                   end=new_comb_line_id_lookup[new_loc.range.end])

        else:
            old_loc = old_locations[old_func_loc_id]
            new_loc = new_locations[new_func_loc_id]
            record_old_funcs.append(old_func_loc_id)

            old_name = old_loc.name.split("@")[0]
            old_start = old_loc.range.start
            old_end = old_loc.range.end

            new_name = new_loc.name.split("@")[0]
            new_start = new_loc.range.start
            new_end = new_loc.range.end

            comb_name = old_name if old_name == new_name else old_name + "@" + new_name
            comb_start = min(old_comb_line_id_lookup[old_start], new_comb_line_id_lookup[new_start])
            comb_end = max(old_comb_line_id_lookup[old_end], new_comb_line_id_lookup[new_end])
            comb_range = LineRange(start=comb_start, end=comb_end)

        comb_funcs.append((comb_name, comb_range))

    ########### Step II: Align unchanged funcs ###########
    rest_old_funcs: List[int] = list(set(all_old_funcs) - set(record_old_funcs))

    for func_loc_id in rest_old_funcs:
        func_loc = old_locations[func_loc_id]

        comb_name = func_loc.name.split("@")[0]
        comb_range = LineRange(start=old_comb_line_id_lookup[func_loc.range.start],
                               end=old_comb_line_id_lookup[func_loc.range.end])

        comb_funcs.append((comb_name, comb_range))

    return comb_funcs


def _align_class_info_in_combined_content(
        all_old_classes: List[int], diff_class_pairs: List[LocationPair],
        old_locations: Dict[int, Location], old_comb_line_id_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_comb_line_id_lookup: Dict[int, int]
) -> List[Tuple[str, LineRange]]:
    comb_classes: List[Tuple[str, LineRange]] = []

    ########### Step I: Align diff classes ###########
    record_old_classes: List[int] = []

    for diff_class_pair in diff_class_pairs:
        old_class_loc_id = diff_class_pair.before
        new_class_loc_id = diff_class_pair.after

        if new_class_loc_id is None:
            assert old_class_loc_id is not None
            old_loc = old_locations[old_class_loc_id]
            record_old_classes.append(old_class_loc_id)

            comb_name = old_loc.name.split("@")[0]
            comb_range = LineRange(start=old_comb_line_id_lookup[old_loc.range.start],
                                   end=old_comb_line_id_lookup[old_loc.range.end])

        elif old_class_loc_id is None:
            assert new_class_loc_id is not None
            new_loc = new_locations[new_class_loc_id]

            comb_name = new_loc.name.split("@")[0]
            comb_range = LineRange(start=new_comb_line_id_lookup[new_loc.range.start],
                                   end=new_comb_line_id_lookup[new_loc.range.end])

        else:
            old_loc = old_locations[old_class_loc_id]
            new_loc = new_locations[new_class_loc_id]
            record_old_classes.append(old_class_loc_id)

            old_name = old_loc.name.split("@")[0]
            old_start = old_loc.range.start
            old_end = old_loc.range.end

            new_name = new_loc.name.split("@")[0]
            new_start = new_loc.range.start
            new_end = new_loc.range.end

            comb_name = old_name if old_name == new_name else old_name + "@" + new_name
            comb_start = min(old_comb_line_id_lookup[old_start], new_comb_line_id_lookup[new_start])
            comb_end = max(old_comb_line_id_lookup[old_end], new_comb_line_id_lookup[new_end])
            comb_range = LineRange(start=comb_start, end=comb_end)

        comb_classes.append((comb_name, comb_range))

    ########### Step II: Align unchanged classes ###########
    rest_old_classes: List[int] = list(set(all_old_classes) - set(record_old_classes))

    for class_loc_id in rest_old_classes:
        class_loc = old_locations[class_loc_id]

        comb_name = class_loc.name.split("@")[0]
        comb_range = LineRange(start=old_comb_line_id_lookup[class_loc.range.start],
                               end=old_comb_line_id_lookup[class_loc.range.end])

        comb_classes.append((comb_name, comb_range))

    return comb_classes


def _align_class_func_info_in_combined_content(
        all_old_classFuncs: Dict[int, List[int]], diff_classFuncs_pairs: Dict[LocationPair, List[LocationPair]],
        old_locations: Dict[int, Location], old_comb_line_id_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_comb_line_id_lookup: Dict[int, int]
) -> List[Tuple[str, List[Tuple[str, LineRange]]]]:
    comb_classesFuncs: List[Tuple[str, List[Tuple[str, LineRange]]]] = []

    ########### Step I: Align diff and unchanged classFuncs of diff classes ###########
    record_old_classes: List[int] = []

    for diff_class_pair, cur_diff_classFunc_pairs in diff_classFuncs_pairs.items():
        if diff_class_pair.before is None:
            assert diff_class_pair.after is not None
            comb_classFuncs = _align_func_info_in_combined_content(
                [], cur_diff_classFunc_pairs,
                old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
            )

            new_class_loc = new_locations[diff_class_pair.after]
            comb_class_name = new_class_loc.name.split("@")[0]

        elif diff_class_pair.after is None:
            record_old_classes.append(diff_class_pair.before)

            assert diff_class_pair.before is not None
            comb_classFuncs = _align_func_info_in_combined_content(
                all_old_classFuncs[diff_class_pair.before], cur_diff_classFunc_pairs,
                old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
            )

            old_class_loc = old_locations[diff_class_pair.before]
            comb_class_name = old_class_loc.name.split("@")[0]

        else:
            record_old_classes.append(diff_class_pair.before)

            comb_classFuncs = _align_func_info_in_combined_content(
                all_old_classFuncs[diff_class_pair.before], cur_diff_classFunc_pairs,
                old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
            )

            old_class_loc = old_locations[diff_class_pair.before]
            new_class_loc = new_locations[diff_class_pair.after]

            old_class_name = old_class_loc.name.split("@")[0]
            new_class_name = new_class_loc.name.split("@")[0]

            comb_class_name = old_class_name if old_class_name == new_class_name else \
                old_class_name + "@" + new_class_name

        comb_classesFuncs.append((comb_class_name, comb_classFuncs))

    ########### Step II: Align unchanged classFuncs of unchanged classes ###########
    rest_old_classes: List[int] = list(set(all_old_classFuncs.keys()) - set(record_old_classes))

    for class_loc_id in rest_old_classes:
        old_class_loc = old_locations[class_loc_id]

        comb_class_name = old_class_loc.name.split("@")[0]
        comb_classFuncs: List[Tuple[str, LineRange]] = []

        for old_classFunc in all_old_classFuncs[class_loc_id]:
            old_classFunc_loc = old_locations[old_classFunc]

            comb_classFunc_name = old_classFunc_loc.name.split("@")[0]
            comb_classFunc_range = LineRange(start=old_comb_line_id_lookup[old_classFunc_loc.range.start],
                                             end=old_comb_line_id_lookup[old_classFunc_loc.range.end])

            comb_classFuncs.append((comb_classFunc_name, comb_classFunc_range))

        comb_classesFuncs.append((comb_class_name, comb_classFuncs))

    return comb_classesFuncs


def parse_combine_content_structs(
        all_diff_structs_info: AllDiffStructInfo,
        all_old_funcs: List[int], all_old_classes: List[int], all_old_classFuncs: Dict[int, List[int]],
        old_locations: Dict[int, Location], old_comb_line_id_lookup: Dict[int, int],
        new_locations: Dict[int, Location], new_comb_line_id_lookup: Dict[int, int]
) -> Tuple[List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:
    comb_funcs: List[Tuple[str, LineRange]] = _align_func_info_in_combined_content(
        all_old_funcs, all_diff_structs_info.functions,
        old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
    )

    comb_classes: List[Tuple[str, LineRange]] = _align_class_info_in_combined_content(
        all_old_classes, all_diff_structs_info.classes,
        old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
    )

    comb_classesFuncs: List[Tuple[str, List[Tuple[str, LineRange]]]] = _align_class_func_info_in_combined_content(
        all_old_classFuncs, all_diff_structs_info.class_functions,
        old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
    )

    return comb_funcs, comb_classes, comb_classesFuncs


"""Main Entry"""


def combine_and_parse_modified_file(
        old_file_content: str, old_locations: Dict[int, Location], old_structs_info: Dict,
        new_file_content: str, new_locations: Dict[int, Location],
        file_diff_lines: List[DiffLine],
        all_diff_structs_info: AllDiffStructInfo
) -> Tuple[str, Dict[int, int], Dict[int, int], List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[
    Tuple[str, List[Tuple[str, LineRange]]]]]:
    """
    Combine code before and after commit, and then analyze the structs of it.

    NOTE: Only for modified files.
    """
    ########## Step I: Combine old code and new code ##########
    comb_file_content, old_comb_line_id_lookup, new_comb_line_id_lookup = \
        combine_old_content_and_new_content(old_file_content, new_file_content, file_diff_lines)

    ########## Step II: Align the diff structs ##########
    comb_funcs, comb_classes, comb_classesFuncs = parse_combine_content_structs(
        all_diff_structs_info,
        old_structs_info["funcs"], old_structs_info["classes"], old_structs_info["classes_funcs"],
        old_locations, old_comb_line_id_lookup, new_locations, new_comb_line_id_lookup
    )

    return (comb_file_content, old_comb_line_id_lookup, new_comb_line_id_lookup,
            comb_funcs, comb_classes, comb_classesFuncs)


def analyse_modified_file(
        old_ori_content: str,
        new_ori_content: str,
        diff_file_info: Dict
) -> Tuple[str, str, str, str, Dict[int, int], Dict[int, int], List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:
    ########### Step I: Get complete diff lines info ###########
    ori_diff_lines = combine_diff_code_info_within_file(diff_file_info)

    ########### Step II: Filter out blank lines and comment lines ###########
    ## (1) Code Content
    old_nb_content, old_nb_line_id_lookup = filter_blank_lines_in_file(old_ori_content)
    new_nb_content, new_nb_line_id_lookup = filter_blank_lines_in_file(new_ori_content)

    ## (2) Commit Info
    nb_diff_lines = filter_blank_lines_in_commit(ori_diff_lines, old_nb_line_id_lookup, new_nb_line_id_lookup)

    ########### Step III: Parse locations of old code and new code (filtered) ###########
    old_res = parse_python_file_locations(old_nb_content)
    new_res = parse_python_file_locations(new_nb_content)

    ########## Step IV: Match the diff structs ##########
    all_diff_structs_info = match_diff_structs_within_file(
        nb_diff_lines, old_nb_content, old_res, new_nb_content, new_res
    )

    ########## Step V: Get description of current modified file ##########
    old_locations, old_line_loc_lookup, old_structs_info = old_res
    new_locations, new_line_loc_lookup, new_structs_info = new_res

    file_diff_desc = get_description_of_modified_file(
        old_locations, old_line_loc_lookup, new_locations, new_line_loc_lookup, nb_diff_lines, all_diff_structs_info
    )

    ########## Step VI: Combine and extract the structs ##########
    comb_nb_content, old_comb_line_id_lookup, new_comb_line_id_lookup, comb_funcs, comb_classes, comb_classesFuncs \
        = combine_and_parse_modified_file(
            old_nb_content, old_locations, old_structs_info,
            new_nb_content, new_locations,
            nb_diff_lines, all_diff_structs_info
        )

    return (file_diff_desc, old_nb_content, new_nb_content, comb_nb_content,
            old_comb_line_id_lookup, new_comb_line_id_lookup,
            comb_funcs, comb_classes, comb_classesFuncs)


"""Get full diff code"""


def _get_full_diff_func_code(
        all_indexes: List[int],
        old_content: List[str], old_locations: Dict[int, Location], old_line_id2loc_id: Dict[int, int],
        new_content: List[str], new_locations: Dict[int, Location], new_line_id2loc_id: Dict[int, int],
        del_line_index2id: Dict[int, int], add_line_index2id: Dict[int, int], diff_code_snippet: List[str]
) -> str:
    ## Find Function / ClassFunction locations before and after
    loc_before = None
    loc_after = None

    for ind in all_indexes:
        loc = get_diff_loc_of_diff_line(
            ind,
            old_locations, old_line_id2loc_id,
            new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id
        )
        if loc.file_type == SourceFileType.OLD and loc_before is None:
            loc_before = loc
        elif loc.file_type == SourceFileType.NEW and loc_after is None:
            loc_after = loc

        if loc_before is not None and loc_after is not None:
            break

    assert loc_before is not None or loc_after is not None

    if loc_before is not None:
        assert loc_before.type == LocationType.FUNCTION or loc_before.type == LocationType.CLASS_FUNCTION
    if loc_after is not None:
        assert loc_after.type == LocationType.FUNCTION or loc_after.type == LocationType.CLASS_FUNCTION

    ## Case 1: Function without adding
    if loc_after is None:
        func_code = old_content[loc_before.range.start - 1: loc_before.range.end]

        for ind in all_indexes:
            del_line_id = del_line_index2id[ind]
            # TODO: Check 1, delete after
            assert diff_code_snippet[ind][1:] == func_code[del_line_id - loc_before.range.start]
            func_code[del_line_id - loc_before.range.start] = diff_code_snippet[ind]

    ## Case 2: Function without deleting
    elif loc_before is None:
        func_code = new_content[loc_after.range.start - 1: loc_after.range.end]

        for ind in all_indexes:
            add_line_id = add_line_index2id[ind]
            # TODO: Check 2, delete after
            assert diff_code_snippet[ind][1:] == func_code[add_line_id - loc_after.range.start]
            func_code[add_line_id - loc_after.range.start] = diff_code_snippet[ind]

    ## Case 3: Function with both adding and deleting
    else:
        func_code: List[str] = []

        curr_before_line_id = loc_before.range.start
        curr_after_line_id = loc_after.range.start

        i = 0
        while i < len(all_indexes):
            ind = all_indexes[i]

            if ind in del_line_index2id:
                del_line_id = del_line_index2id[ind]

                assert del_line_id >= curr_before_line_id
                while del_line_id > curr_before_line_id:
                    # TODO: Check 3, delete after
                    assert old_content[curr_before_line_id - 1] == new_content[curr_after_line_id - 1]
                    func_code.append(old_content[curr_before_line_id - 1])
                    curr_before_line_id += 1
                    curr_after_line_id += 1

                assert del_line_id == curr_before_line_id
                # TODO: Check 4, delete after
                assert diff_code_snippet[ind][1:] == old_content[curr_before_line_id - 1]
                func_code.append(diff_code_snippet[ind])
                curr_before_line_id += 1

            else:
                add_line_id = add_line_index2id[ind]

                assert add_line_id >= curr_after_line_id
                while add_line_id > curr_after_line_id:
                    # TODO: Check 5, delete after
                    assert old_content[curr_before_line_id - 1] == new_content[curr_after_line_id - 1]
                    func_code.append(old_content[curr_before_line_id - 1])
                    curr_before_line_id += 1
                    curr_after_line_id += 1

                assert add_line_id == curr_after_line_id
                # TODO: Check 6, delete after
                assert diff_code_snippet[ind][1:] == new_content[curr_after_line_id - 1]
                func_code.append(diff_code_snippet[ind])
                curr_after_line_id += 1

            i += 1

        while curr_before_line_id <= loc_before.range.end:
            # TODO: Check 5, delete after
            assert old_content[curr_before_line_id - 1] == new_content[curr_after_line_id - 1]
            func_code.append(old_content[curr_before_line_id - 1])
            curr_before_line_id += 1
            curr_after_line_id += 1

        assert curr_before_line_id == loc_before.range.end + 1
        assert curr_after_line_id == loc_after.range.end + 1

    return "\n".join(func_code)


def _get_full_diff_global_code(
        cont_indexes: List[int], diff_code_snippet: List[str]
) -> str:
    """
    NOTE: The input line indexes must be continuous.
    """
    code = []
    for i, ind in enumerate(cont_indexes):
        if i > 0:
            assert ind == cont_indexes[i - 1] + 1
        code.append(diff_code_snippet[ind])

    return "\n".join(code)
