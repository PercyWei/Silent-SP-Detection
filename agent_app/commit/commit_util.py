from __future__ import annotations

import os
import re
import ast
import tokenize
import json
import copy
import subprocess
import bisect

from typing import *
from io import StringIO
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

from loguru import logger

from agent_app.static_analysis.parse import LocationType, Location, parse_python_file_locations
from agent_app.data_structures import CodeSnippetLocation
from utils import LineRange, same_line_range, run_command


class SourceFileType(str, Enum):
    OLD = "before_commit"
    NEW = "after_commit"

    @staticmethod
    def attributes():
        return [k.value for k in SourceFileType]


"""GET FILE CONTENT"""


def get_code_before_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str) -> str | None:
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


def get_code_after_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str) -> str | None:
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


"""EXTRACT RAW COMMIT CONTENT INFO"""


def extract_commit_content_info(commit_content: str, file_suffix: List[str] | None = None) -> List:
    """Extract and collate commit content from saved commit file without any other processing.

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


"""CODE FILTER"""


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


def filter_blank_and_comment_in_code(code: str, filter_comment: bool = True) -> Tuple[str, Dict[int, int]]:
    """Filter out blank lines and comment lines in file.

    Args:
        code (str): File content.
        filter_comment (bool): Whether to filter out comment.
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


"""COMBINE"""


@dataclass
class CombLocation(Location):
    name_before: str | None
    name_after: str | None


@dataclass
class CombineInfo:
    """Dataclass for hold info of combined file, etc."""
    # -------------------- Original --------------------
    # (1) Code
    code_before: str
    code_after: str
    # (2) Location
    locs_before: Dict[int, Location]
    locs_after: Dict[int, Location]
    # (3) line_id -> location_id
    li2loc_before: Dict[int, int]
    li2loc_after: Dict[int, int]
    # -------------------- Combined --------------------
    # (1) Code and line_id
    code_comb: str = ""
    li_lookup_before2comb: Dict[int, int] = field(default_factory=dict)  # line id: code_before -> code_comb
    li_lookup_after2comb: Dict[int, int] = field(default_factory=dict)   # line id: code_after  -> code_comb
    # (2) Location and location_id
    locs_comb: Dict[int, CombLocation] = field(default_factory=dict)
    loc_lookup_before2comb: Dict[int, int] = field(default_factory=dict)         # loc id: code_before -> code_comb
    loc_lookup_after2comb: Dict[int, int] = field(default_factory=dict)          # loc id: code_after  -> code_comb
    loc_lookup_comb2before: Dict[int, int | None] = field(default_factory=dict)  # loc id: code_comb   -> code_before
    loc_lookup_comb2after: Dict[int, int | None] = field(default_factory=dict)   # loc id: code_comb   -> code_after
    # (3) line_id -> location_id
    li2loc_comb: Dict[int, int] = field(default_factory=dict)


def sort_locations(locs: List[Location]) -> List[Location]:
    """Sort locations by range start (small -> large).

    NOTE: No overlap between the ranges of all locations.
    """
    sorted_locs = sorted(locs, key=lambda x: x.range.start)
    return sorted_locs


def combine_code_before_and_after(comb_info: CombineInfo, file_diff_lines: List[DiffLine]) -> CombineInfo:
    """Combine old code and new code while reflecting the changes.

    NOTE 1: Only for modified files.
    NOTE 2: Code lines start with '-' or '+' appear in combined code.
    NOTE 3: Old code, new code and diff lines need to be in the same state.
            By default, blank lines and comment lines are filtered out.
    Args:
        comb_info (CombineInfo): Info of combined file.
        file_diff_lines (List[DiffLine]): List of diff lines.
    Returns:
        comb_info (CombineInfo): Updated info of combined file. The updated info includes:
            - code_comb
            - line_id_lookup_before2comb
            - line_id_lookup_after2comb
    """
    #######################################
    # Step I: Group continuous diff lines #
    #######################################

    diff_line_groups: List[List[DiffLine]] = []
    cur_diff_line_group: List[DiffLine] = []

    for diff_line in file_diff_lines:
        if diff_line.sep:
            continue

        if len(cur_diff_line_group) == 0:
            cur_diff_line_group.append(diff_line)
        elif diff_line.id == cur_diff_line_group[-1].id + 1:
            cur_diff_line_group.append(diff_line)
        else:
            assert diff_line.id == cur_diff_line_group[-1].id + 2
            diff_line_groups.append(cur_diff_line_group)
            cur_diff_line_group = [diff_line]

    if len(cur_diff_line_group) > 0:
        diff_line_groups.append(cur_diff_line_group)

    #################################################################
    # Step II: Add unchanged lines to combine old code and new code #
    #################################################################

    old_file_lines = comb_info.code_before.splitlines(keepends=False)
    new_file_lines = comb_info.code_after.splitlines(keepends=False)

    old_line_id_lookup_nb2comb: Dict[int, int] = {}  # 1-based, 1-based
    new_line_id_lookup_nb2comb: Dict[int, int] = {}  # 1-based, 1-based

    ####### (1) Add unchanged lines in the beginning #######
    start_diff_line = diff_line_groups[0][0]
    assert old_file_lines[:start_diff_line.lineno - 1] == new_file_lines[:start_diff_line.lineno - 1]

    lines_before: List[str] = old_file_lines[:start_diff_line.lineno - 1]

    for i in range(len(lines_before)):
        old_line_id_lookup_nb2comb[i + 1] = i + 1
        new_line_id_lookup_nb2comb[i + 1] = i + 1

    ####### (2) Add unchanged lines between diff line groups #######
    cur_old_line_id = cur_new_line_id = len(lines_before)
    lines_between: List[str] = []

    for i, diff_line_group in enumerate(diff_line_groups):
        # 1. Add unchanged lines, until reaching the first diff line of the current diff_line_group
        group_start_dl = diff_line_group[0]
        while (group_start_dl.source == SourceFileType.OLD and cur_old_line_id < group_start_dl.lineno - 1) or \
                (group_start_dl.source == SourceFileType.NEW and cur_new_line_id < group_start_dl.lineno - 1):
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

    ####### (3) Add unchanged lines in the end #######
    assert old_file_lines[cur_old_line_id:] == new_file_lines[cur_new_line_id:]

    lines_after: List[str] = old_file_lines[cur_old_line_id:]

    for i in range(len(lines_after)):
        old_line_id_lookup_nb2comb[cur_old_line_id + i + 1] = i + 1 + len(lines_between) + len(lines_before)
        new_line_id_lookup_nb2comb[cur_new_line_id + i + 1] = i + 1 + len(lines_between) + len(lines_before)

    ####### (4) End #######
    code_comb = "\n".join(lines_before + lines_between + lines_after)

    #############################
    # Step III: Update CombInfo #
    #############################

    comb_info.code_comb = code_comb
    comb_info.li_lookup_before2comb = old_line_id_lookup_nb2comb
    comb_info.li_lookup_after2comb = new_line_id_lookup_nb2comb

    return comb_info


def combine_locations_before_and_after(comb_info: CombineInfo, file_diff_lines: List[DiffLine]) -> CombineInfo:
    ## Preparation
    old_locations: Dict[int, Location] = copy.deepcopy(comb_info.locs_before)
    new_locations: Dict[int, Location] = copy.deepcopy(comb_info.locs_after)
    old_li_lookup: Dict[int, int] = comb_info.li_lookup_before2comb
    new_li_lookup: Dict[int, int] = comb_info.li_lookup_after2comb

    del_line_ids: List[int] = []
    add_line_ids: List[int] = []
    for dl in file_diff_lines:
        if not dl.sep and dl.source == SourceFileType.OLD:
            del_line_ids.append(dl.lineno)
        elif not dl.sep and dl.source == SourceFileType.NEW:
            add_line_ids.append(dl.lineno)

    comb_locations: Dict[int, CombLocation] = {}
    old_loc_lookup: Dict[int, int] = {}
    new_loc_lookup: Dict[int, int] = {}
    comb2old_loc_lookup: Dict[int, int | None] = {}
    comb2new_loc_lookup: Dict[int, int | None] = {}

    # ----------------------------------- INNER FUNCTION ----------------------------------- #

    def _get_curr_loc_id() -> int:
        return len(comb_locations)

    def _get_comb_name(old_name: str, new_name: str) -> str:
        # NOTE: For modified class / function / class_function, it may have a name like ‘xx@xx’ or ‘xx’.
        return old_name if old_name == new_name else old_name + '@' + new_name

    def _get_comb_range(old_lo: Location | None, new_lo: Location | None) -> LineRange:
        assert old_lo is not None or new_lo is not None
        old_start = old_li_lookup[old_lo.range.start] if old_lo is not None else 10 ** 10
        new_start = new_li_lookup[new_lo.range.start] if new_lo is not None else 10 ** 10
        comb_start = min(old_start, new_start)

        old_end = old_li_lookup[old_lo.range.end] if old_lo is not None else -1
        new_end = new_li_lookup[new_lo.range.end] if new_lo is not None else -1
        comb_end = max(old_end, new_end)

        return LineRange(comb_start, comb_end)

    def _is_del_loc(lo: Location) -> bool:
        range_ids = lo.get_full_range()
        for li in range_ids:
            if li not in del_line_ids:
                return False
        return True

    def _is_add_loc(lo: Location) -> bool:
        range_ids = lo.get_full_range()
        for li in range_ids:
            if li not in add_line_ids:
                return False
        return True

    def _is_same_loc(old_lo: Location, new_lo: Location) -> bool:
        # (1) Get the first unchanged line in old and new location separately
        old_start_li = None
        new_start_li = None

        for li in old_lo.get_full_range():
            if li not in del_line_ids:
                old_start_li = li
                break

        for li in new_lo.get_full_range():
            if li not in add_line_ids:
                new_start_li = li
                break

        # (2) Compare
        if old_start_li is None or new_start_li is None:
            return False

        res = old_li_lookup[old_start_li] == new_li_lookup[new_start_li]
        if res:
            assert old_lo.type == new_lo.type
        return res

    def _collect_children(los: Dict[int, Location], father_id: int) -> Tuple[List[Location], Dict[int, Location]]:
        children: List[Location] = []
        res_los: Dict[int, Location] = {}

        for lo_id, lo in los.items():
            if lo.father == father_id:
                children.append(lo)
            else:
                res_los[lo_id] = lo
        return children, res_los

    def _combine_children(old_children: List[Location], new_children: List[Location], father_id: int) -> None:
        i = 0
        j = 0
        while i < len(old_children) or j < len(new_children):
            old_child = old_children[i] if i < len(old_children) else None
            new_child = new_children[j] if j < len(new_children) else None

            if new_child is None:
                i += 1
                # Prepare
                assert _is_del_loc(old_child)
                curr_id = _get_curr_loc_id()
                comb_range = _get_comb_range(old_child, None)
                comb_name = old_child.name
                comb_lo = CombLocation(id=curr_id, father=father_id, type=old_child.type,
                                       ast=old_child.ast, name=comb_name, range=comb_range,
                                       name_before=old_child.name, name_after=None)
                # Update
                comb_locations[curr_id] = comb_lo
                old_loc_lookup[old_child.id] = curr_id
                comb2old_loc_lookup[curr_id] = old_child.id
                comb2new_loc_lookup[curr_id] = None

            elif old_child is None:
                j += 1
                # Prepare
                assert _is_add_loc(new_child)
                curr_id = _get_curr_loc_id()
                comb_range = _get_comb_range(None, new_child)
                comb_name = new_child.name
                comb_lo = CombLocation(id=curr_id, father=father_id, type=new_child.type,
                                       ast=new_child.ast, name=comb_name, range=comb_range,
                                       name_before=None, name_after=new_child.name)
                # Update
                comb_locations[curr_id] = comb_lo
                new_loc_lookup[new_child.id] = curr_id
                comb2old_loc_lookup[curr_id] = None
                comb2new_loc_lookup[curr_id] = new_child.id

            else:
                cmp_now = True

                if _is_del_loc(old_child):
                    i += 1
                    cmp_now = False
                    # Prepare
                    curr_id = _get_curr_loc_id()
                    comb_range = _get_comb_range(old_child, None)
                    comb_name = old_child.name
                    comb_lo = CombLocation(id=curr_id, father=father_id, type=old_child.type,
                                           ast=old_child.ast, name=comb_name, range=comb_range,
                                           name_before=old_child.name, name_after=None)
                    # Update
                    comb_locations[curr_id] = comb_lo
                    old_loc_lookup[old_child.id] = curr_id
                    comb2old_loc_lookup[curr_id] = old_child.id
                    comb2new_loc_lookup[curr_id] = None

                if _is_add_loc(new_child):
                    j += 1
                    cmp_now = False
                    # Prepare
                    curr_id = _get_curr_loc_id()
                    comb_range = _get_comb_range(None, new_child)
                    comb_name = new_child.name
                    comb_lo = CombLocation(id=curr_id, father=father_id, type=new_child.type,
                                           ast=new_child.ast, name=comb_name, range=comb_range,
                                           name_before=None, name_after=new_child.name)
                    # Update
                    comb_locations[curr_id] = comb_lo
                    new_loc_lookup[new_child.id] = curr_id
                    comb2old_loc_lookup[curr_id] = None
                    comb2new_loc_lookup[curr_id] = new_child.id

                if cmp_now:
                    i += 1
                    j += 1
                    # Prepare
                    assert _is_same_loc(old_child, new_child)
                    curr_id = _get_curr_loc_id()
                    comb_range = _get_comb_range(old_child, new_child)
                    comb_name = _get_comb_name(old_child.name, new_child.name)
                    comb_lo = CombLocation(id=curr_id, father=father_id, type=new_child.type,
                                           ast=new_child.ast, name=comb_name, range=comb_range,
                                           name_before=old_child.name, name_after=new_child.name)
                    # Update
                    comb_locations[curr_id] = comb_lo
                    old_loc_lookup[old_child.id] = curr_id
                    new_loc_lookup[new_child.id] = curr_id
                    comb2old_loc_lookup[curr_id] = old_child.id
                    comb2new_loc_lookup[curr_id] = new_child.id

    def collect_and_combine_children(
            old_los: Dict[int, Location],
            new_los: Dict[int, Location],
            old_father_id: int | None,
            new_father_id: int | None,
            comb_father_id: int,
    ) -> Tuple[Dict[int, Location], Dict[int, Location]]:
        # (1) Collect children
        old_children: List[Location] = []
        new_children: List[Location] = []

        if old_father_id is not None:
            old_children, old_los = _collect_children(old_los, old_father_id)

        if new_father_id is not None:
            new_children, new_los = _collect_children(new_los, new_father_id)

        assert len(old_children) > 0 or len(new_children) > 0

        # (2) Sort children
        old_children = sort_locations(old_children)
        new_children = sort_locations(new_children)

        # (3) Combine
        _combine_children(old_children, new_children, comb_father_id)

        return old_los, new_los


    # ----------------------------------- INNER FUNCTION ----------------------------------- #

    ###############################
    # Step 1: Add combined MODULE #
    ###############################

    old_root = old_locations.pop(0)
    new_root = new_locations.pop(0)

    assert old_root.type == LocationType.MODULE and new_root.type == LocationType.MODULE

    start = min(old_li_lookup[old_root.range.start], new_li_lookup[new_root.range.start])
    end = max(old_li_lookup[old_root.range.end], new_li_lookup[new_root.range.end])
    name = _get_comb_name(old_root.name, new_root.name)

    curr_id = _get_curr_loc_id()
    comb_root = CombLocation(id=curr_id, father=None, type=LocationType.MODULE,
                             ast=old_root.ast, name=name, range=LineRange(start, end),
                             name_before=old_root.name, name_after=new_root.name)
    comb_locations[curr_id] = comb_root

    ##################################################
    # Step 2: Collect children of MODULE and combine #
    ##################################################

    old_locations, new_locations = collect_and_combine_children(
        old_locations, new_locations, old_root.id, new_root.id, comb_root.id
    )

    ################################################
    # Step 3: Collect children of MAIN and combine #
    ################################################

    # (1) Get MAIN location
    comb_main_id: int | None = None
    for _, comb_loc in comb_locations.items():
        if comb_loc.type == LocationType.MAIN:
            assert comb_main_id is None
            comb_main_id = comb_loc.id

    # (2) Combine old and new children of MAIN location
    if comb_main_id is not None:
        old_main_id = comb2old_loc_lookup[comb_main_id]
        new_main_id = comb2new_loc_lookup[comb_main_id]

        old_locations, new_locations = \
            collect_and_combine_children(old_locations, new_locations, old_main_id, new_main_id, comb_main_id)

    #################################################
    # Step 3: Collect children of CLASS and combine #
    #################################################

    # (1) Collect all CLASS location
    comb_class_ids: List[int] = []
    for _, comb_loc in comb_locations.items():
        if comb_loc.type == LocationType.CLASS:
            comb_class_ids.append(comb_loc.id)

    # (2) Combine old and new children of each CLASS location
    for comb_class_id in comb_class_ids:
        old_class_id = comb2old_loc_lookup[comb_class_id]
        new_class_id = comb2new_loc_lookup[comb_class_id]

        old_locations, new_locations = \
            collect_and_combine_children(old_locations, new_locations, old_class_id, new_class_id, comb_class_id)

    #############################
    # Step IV: Update comb_info #
    #############################

    # Ensure that all locations are considered
    assert len(old_locations) == 0 and len(new_locations) == 0

    comb_info.locs_comb = comb_locations
    comb_info.loc_lookup_before2comb = old_loc_lookup
    comb_info.loc_lookup_after2comb = new_loc_lookup
    comb_info.loc_lookup_comb2before = comb2old_loc_lookup
    comb_info.loc_lookup_comb2after = comb2new_loc_lookup

    return comb_info


def main_combine_of_modified_file(
        old_code: str, old_locations: Dict[int, Location], old_li2loc: Dict[int, int],
        new_code: str, new_locations: Dict[int, Location], new_li2loc: Dict[int, int],
        file_diff_lines: List[DiffLine],
) -> CombineInfo:
    """Main method to combine code before and after commit, and then analyze the structs of it.

    NOTE: Only for modified files.
    """
    ## Step 1: Initiation
    comb_info = CombineInfo(old_code, new_code, old_locations, new_locations, old_li2loc, new_li2loc)

    ## Step 2: Combine old code and new code
    comb_info = combine_code_before_and_after(comb_info, file_diff_lines)

    ## Step 3: Combine old locations and new locations
    comb_info = combine_locations_before_and_after(comb_info, file_diff_lines)

    ## Step 4: Update look-up dict (line id -> loc id) for code_comb
    li2loc_comb: Dict[int, int] = {}
    for old_li, old_loc_id in comb_info.li2loc_before.items():
        comb_li = comb_info.li_lookup_before2comb[old_li]
        comb_loc_id = comb_info.loc_lookup_before2comb[old_loc_id]
        li2loc_comb[comb_li] = comb_loc_id

    for new_li, new_loc_id in comb_info.li2loc_after.items():
        comb_li = comb_info.li_lookup_after2comb[new_li]
        comb_loc_id = comb_info.loc_lookup_after2comb[new_loc_id]
        if comb_li not in li2loc_comb:
            li2loc_comb[comb_li] = comb_loc_id
        else:
            assert li2loc_comb[comb_li] == comb_loc_id

    comb_info.li2loc_comb = li2loc_comb

    return comb_info


"""DIFF CODE SNIPPET"""


@dataclass
class DiffCodeSnippet(CodeSnippetLocation):
    """
    In some cases, the class name or method name where the code snippet is located may change, so we:
    - For deleted class or function, use its name before
    - For added / modified class or function, use its name after
    """
    diff_indexes: List[int]  # Indexes of diff lines
    range: LineRange  # Range of full code snippet in code

    def get_only_diff_code(self) -> str:
        code_lines = self.code.splitlines(keepends=False)
        diff_code = "..."
        for i, ind in enumerate(self.diff_indexes):
            if i > 0 and ind != self.diff_indexes[i - 1] + 1:
                diff_code += "\n..."
            diff_code += "\n" + code_lines[ind]
        diff_code += "\n..."

        return diff_code

    def to_only_diff_str(self) -> str:
        prefix = self.to_tagged_upto_func()
        code_part = f"<code>\n{self.get_only_diff_code()}\n</code>"
        return f"{prefix}\n{code_part}"

    def to_str(self) -> str:
        return self.to_tagged_str()


def _get_comb_line_id_of_diff_line(diff_li: DiffLine, comb_info: CombineInfo) -> int:
    if diff_li.source == SourceFileType.OLD:
        comb_li = comb_info.li_lookup_before2comb[diff_li.lineno]
    else:
        comb_li = comb_info.li_lookup_after2comb[diff_li.lineno]
    return comb_li


def build_diff_code_snippet(file_path: str, diff_comb_lines: List[int], comb_info: CombineInfo) -> DiffCodeSnippet:
    comb_loc_id = comb_info.li2loc_comb[diff_comb_lines[0]]
    comb_loc = comb_info.locs_comb[comb_loc_id]
    comb_loc_full_range = comb_loc.get_full_range()

    # (1) class_name, func_name
    class_name = None
    func_name = None

    if comb_loc.type == LocationType.FUNCTION:
        func_name = comb_loc.name_after if not comb_loc.name_after else comb_loc.name_before

    elif comb_loc.type == LocationType.CLASS_UNIT:
        father = comb_info.locs_comb[comb_loc.father]
        class_name = father.name_after if not father.name_after else father.name_before

    elif comb_loc.type == LocationType.CLASS_FUNCTION:
        father = comb_info.locs_comb[comb_loc.father]
        class_name = father.name_after if not father.name_after else father.name_before
        func_name = comb_loc.name_after if not comb_loc.name_after else comb_loc.name_before

    else:
        assert comb_loc.type == LocationType.UNIT or comb_loc.type == LocationType.MAIN_UNIT

    # (2) diff_indexes
    diff_indexes: List[int] = []
    for diff_comb_li in diff_comb_lines:
        diff_indexes.append(comb_loc_full_range.index(diff_comb_li))

    # (3) code
    comb_code_lines = comb_info.code_comb.splitlines(keepends=False)
    comb_loc_code = "\n".join(comb_code_lines[comb_loc.range.start - 1: comb_loc.range.end])

    return DiffCodeSnippet(file_path=file_path, class_name=class_name, func_name=func_name, code=comb_loc_code,
                           diff_indexes=diff_indexes, range=comb_loc.range)


def build_diff_code_snippets_from_comb_info(
        file_path: str,
        comb_info: CombineInfo,
        file_diff_lines: List[DiffLine]
) -> List[DiffCodeSnippet]:
    diff_code_snips: List[DiffCodeSnippet] = []
    diff_comb_lines: List[int] = []

    for diff_li in file_diff_lines:
        if diff_li.sep:
            continue
        curr_comb_li = _get_comb_line_id_of_diff_line(diff_li, comb_info)

        if len(diff_comb_lines) == 0:
            diff_comb_lines.append(curr_comb_li)
            continue

        last_comb_li = diff_comb_lines[-1]
        if curr_comb_li not in comb_info.li2loc_comb:
            print(curr_comb_li)
        if comb_info.li2loc_comb[curr_comb_li] == comb_info.li2loc_comb[last_comb_li]:
            diff_comb_lines.append(curr_comb_li)
        else:
            diff_code_snip = build_diff_code_snippet(file_path, diff_comb_lines, comb_info)
            diff_code_snips.append(diff_code_snip)

            diff_comb_lines = [curr_comb_li]

    if len(diff_comb_lines) > 0:
        diff_code_snip = build_diff_code_snippet(file_path, diff_comb_lines, comb_info)
        diff_code_snips.append(diff_code_snip)

    return diff_code_snips


"""STRUCT INDEX"""


def build_struct_indexes_from_comb_info(
        comb_info: CombineInfo
) -> Tuple[List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:

    locs_comb = comb_info.locs_comb

    funcs: List[Tuple[str, LineRange]] = []
    classes: List[Tuple[str, LineRange]] = []
    classes_funcs: List[Tuple[str, List[Tuple[str, LineRange]]]] = []

    loc_classes_funcs: Dict[int, List[Tuple[str, LineRange]]] = defaultdict(list)

    # NOTE: Name of location may be "xx@xx" or "xx", so for name like "xx@xx",
    #       we add both structs before and after, although they point to the same code snippet
    for _, loc_comb in locs_comb.items():
        if loc_comb.type == LocationType.FUNCTION:
            for name in loc_comb.name.split('@'):
                if name != "":
                    funcs.append((name, loc_comb.range))

        elif loc_comb.type == LocationType.CLASS:
            for name in loc_comb.name.split('@'):
                if name != "":
                    classes.append((name, loc_comb.range))

        elif loc_comb.type == LocationType.CLASS_FUNCTION:
            class_id = locs_comb[loc_comb.father].id
            for name in loc_comb.name.split('@'):
                if name != "":
                    loc_classes_funcs[class_id].append((name, loc_comb.range))

    for class_id, class_funcs in loc_classes_funcs.items():
        classes_funcs.append((locs_comb[class_id].name, class_funcs))

    return funcs, classes, classes_funcs



def build_struct_indexes_from_common_code(
        code: str,
) -> Tuple[List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:
    locations, _, structs_info = parse_python_file_locations(code)

    funcs: List[Tuple[str, LineRange]] = []
    classes: List[Tuple[str, LineRange]] = []
    classes_funcs: List[Tuple[str, List[Tuple[str, LineRange]]]] = []

    for loc_id in structs_info["funcs"]:
        loc = locations[loc_id]
        funcs.append((loc.name, loc.range))

    for loc_id in structs_info["classes"]:
        loc = locations[loc_id]
        classes.append((loc.name, loc.range))

    for class_loc_id, classFunc_loc_ids in structs_info["classes_funcs"].items():
        cur_class_funcs: List[Tuple[str, LineRange]] = []
        for loc_id in classFunc_loc_ids:
            loc = locations[loc_id]
            cur_class_funcs.append((loc.name, loc.range))

        class_loc = locations[class_loc_id]
        classes_funcs.append((class_loc.name, cur_class_funcs))

    return funcs, classes, classes_funcs


"""MAIN ENTRY"""


def analyse_modified_file(
        file_path: str,
        old_ori_code: str,
        new_ori_code: str,
        diff_file_info: Dict
) -> Tuple[CombineInfo, List[DiffCodeSnippet], List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:

    # --------------------------- Step I: Get complete diff lines info --------------------------- #
    ori_diff_lines = combine_diff_code_info_within_file(diff_file_info)

    # --------------------------- Step II: Filter out blank and comment lines --------------------------- #
    ## (1) Filter code file
    old_nb_code, old_nb_li_lookup = filter_blank_and_comment_in_code(old_ori_code)
    new_nb_code, new_nb_li_lookup = filter_blank_and_comment_in_code(new_ori_code)

    ## (2) Filter commit Info
    nb_diff_lines = filter_blank_lines_in_commit(ori_diff_lines, old_nb_li_lookup, new_nb_li_lookup)

    # --------------------------- Step III: Parse locations --------------------------- #
    # NOTE: All we analyse after is the FILTERED code
    old_nb_locs, old_nb_li2loc, _ = parse_python_file_locations(old_nb_code)
    new_nb_locs, new_nb_li2loc, _ = parse_python_file_locations(new_nb_code)

    # --------------------------- Step IV: Combine --------------------------- #
    nb_comb_info = main_combine_of_modified_file(
        old_nb_code, old_nb_locs, old_nb_li2loc, new_nb_code, new_nb_locs, new_nb_li2loc, nb_diff_lines
    )

    # --------------------------- Step V: Build struct index  --------------------------- #
    funcs, classes, classes_funcs = build_struct_indexes_from_comb_info(nb_comb_info)

    # --------------------------- Step VI: Build DiffCodeSnippet  --------------------------- #
    diff_code_snips = build_diff_code_snippets_from_comb_info(file_path, nb_comb_info, nb_diff_lines)

    return nb_comb_info, diff_code_snips, funcs, classes, classes_funcs

