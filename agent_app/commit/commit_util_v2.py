from __future__ import annotations

import re
import tokenize
import subprocess
from collections import defaultdict

from typing import *
from io import StringIO
from dataclasses import dataclass
from enum import Enum

from agent_app.commit.parse import is_main_line, parse_python_file_locations
from agent_app.static_analysis.ast_parse import (
    are_overlap_lines,
    extract_func_sig_lines_from_code, extract_class_sig_lines_from_code)
from agent_app.data_structures import LineRange, Location, line_loc_types, CombineInfo, LocationType
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


def combine_diff_code_info_within_file(diff_file_info: Dict) -> List[DiffLine]:
    """Combine diff code within file, using sep to separate discontinuous diff lines.

    NOTE: Only for modified files.
    Args:
        diff_file_info (Dict): For detailed format, see the method `extract_diff_files_info`.
    Returns:
        List[DiffLine]: List of diff lines within file.
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


def find_comment_lines(code: str) -> List[int]:
    """Find lines containing comment like "# xxx".
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
    """Filter blank lines and comment lines in commit, including lines deleted / added / unchanged.

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

    if nb_file_diff_lines and nb_file_diff_lines[-1].sep:
        nb_file_diff_lines.pop(-1)

    return nb_file_diff_lines


"""COMBINE"""


def init_comb_info_for_del_file(old_code: str, comb_code: str) -> CombineInfo:
    ## (1) Initialization
    comb_info = CombineInfo(old_code=old_code, new_code=None, comb_code=comb_code)

    ## (2) Update
    locations, lookup_li2loc, structs_info = parse_python_file_locations(old_code)
    # 1. Location
    comb_info.old_locations = locations
    # 2. Look-up dict
    comb_info.old_li2loc = lookup_li2loc
    # 3. Structures
    funcs, classes, classes_funcs = build_struct_index_from_locations(locations, structs_info)
    comb_info.old_func_index = funcs
    comb_info.old_class_index = classes
    comb_info.old_classFunc_index = classes_funcs

    return comb_info


def init_comb_info_for_add_file(new_code: str, comb_code: str) -> CombineInfo:
    ## (1) Initialization
    comb_info = CombineInfo(old_code=None, new_code=new_code, comb_code=comb_code)

    ## (2) Update
    locations, lookup_li2loc, structs_info = parse_python_file_locations(new_code)
    # 1. Location
    comb_info.new_locations = locations
    # 2. Look-up dict
    comb_info.new_li2loc = lookup_li2loc
    # 3. Structures
    funcs, classes, classes_funcs = build_struct_index_from_locations(locations, structs_info)
    comb_info.new_func_index = funcs
    comb_info.new_class_index = classes
    comb_info.new_classFunc_index = classes_funcs

    return comb_info


def combine_code_old_and_new(comb_info: CombineInfo, file_diff_lines: List[DiffLine]) -> CombineInfo:
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
            - comb_code
            - li_lookup_old2new
            - li_lookup_old2comb
            - li_lookup_new2comb
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

    old_lines = comb_info.old_code.splitlines(keepends=False)
    new_lines = comb_info.new_code.splitlines(keepends=False)

    li_lookup_old2new : Dict[int, int] = {}  # 1-based, 1-based
    li_lookup_old2comb: Dict[int, int] = {}  # 1-based, 1-based
    li_lookup_new2comb: Dict[int, int] = {}  # 1-based, 1-based

    cur_old_li = cur_new_li = 0

    ####### (1) Add unchanged lines in the beginning #######
    start_diff_li = diff_li_groups[0][0]
    assert old_lines[:start_diff_li.lineno - 1] == new_lines[:start_diff_li.lineno - 1]

    lines_before: List[str] = old_lines[:start_diff_li.lineno - 1]

    for cur_comb_li in range(1, len(lines_before) + 1):
        cur_old_li = cur_new_li = cur_comb_li
        # Update lookup dict
        li_lookup_old2new[cur_old_li] = cur_new_li
        li_lookup_old2comb[cur_old_li] = cur_comb_li
        li_lookup_new2comb[cur_new_li] = cur_comb_li

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
            assert old_lines[cur_old_li - 1] == new_lines[cur_new_li - 1]
            # Add comb line and update current line (comb)
            lines_between.append(old_lines[cur_old_li - 1])
            cur_comb_li = len(lines_before) + len(lines_between)

            # Update lookup dict
            li_lookup_old2new[cur_old_li] = cur_new_li
            li_lookup_old2comb[cur_old_li] = cur_comb_li
            li_lookup_new2comb[cur_new_li] = cur_comb_li

        # 2. Add diff lines
        for diff_li in diff_line_group:
            # Add comb line and update current line (comb)
            lines_between.append(diff_li.code)
            cur_comb_li = len(lines_before) + len(lines_between)

            # Update current line (old / new) and lookup dict
            if diff_li.source == SourceFileType.OLD:
                cur_old_li += 1
                li_lookup_old2comb[cur_old_li] = cur_comb_li
            else:
                cur_new_li += 1
                li_lookup_new2comb[cur_new_li] = cur_comb_li

    ####### (3) Add unchanged lines in the end #######
    assert old_lines[cur_old_li:] == new_lines[cur_new_li:]

    lines_after: List[str] = old_lines[cur_old_li:]

    for i in range(len(lines_after)):
        # Update current line (old / new / comb)
        cur_old_li += 1
        cur_new_li += 1
        cur_comb_li = len(lines_before) + len(lines_between) + i + 1
        # Update lookup dict
        li_lookup_old2new[cur_old_li] = cur_new_li
        li_lookup_old2comb[cur_old_li] = cur_comb_li
        li_lookup_new2comb[cur_new_li] = cur_comb_li

    ####### (4) End #######
    code_comb = "\n".join(lines_before + lines_between + lines_after)

    #############################
    # Step III: Update CombInfo #
    #############################

    comb_info.comb_code = code_comb
    comb_info.lime_id_old2new = li_lookup_old2new
    comb_info.line_id_old2comb = li_lookup_old2comb
    comb_info.line_id_new2comb = li_lookup_new2comb

    return comb_info


"""STRUCT INDEX"""


def build_struct_index_from_locations(
        locations: Dict[int, Location], structs_info: Dict
) -> Tuple[List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:
    func_index: List[Tuple[str, LineRange]] = []
    class_index: List[Tuple[str, LineRange]] = []
    class_func_index: List[Tuple[str, List[Tuple[str, LineRange]]]] = []

    func_loc_ids: List[int] = structs_info["funcs"]
    class_loc_ids: List[int] = structs_info["classes"]
    class_func_loc_ids: Dict[int, List[int]] = structs_info["classes_funcs"]

    for loc_id in func_loc_ids:
        loc = locations[loc_id]
        func_index.append((loc.name, loc.range))

    for loc_id in class_loc_ids:
        loc = locations[loc_id]
        class_index.append((loc.name, loc.range))

    for class_loc_id, func_loc_ids in class_func_loc_ids.items():
        class_name = locations[class_loc_id].name
        class_funcs: List[Tuple[str, LineRange]] = []
        for func_loc_id in func_loc_ids:
            loc = locations[func_loc_id]
            class_funcs.append((loc.name, loc.range))
        class_func_index.append((class_name, class_funcs))

    return func_index, class_index, class_func_index


def update_comb_info_with_struct_index(
        comb_info: CombineInfo, old_structs_info: Dict, new_structs_info: Dict
) -> CombineInfo:
    # (1) Update comb_info with old struct index
    old_func_index, old_class_index, old_class_func_index = \
        build_struct_index_from_locations(comb_info.old_locations, old_structs_info)
    comb_info.old_func_index = old_func_index
    comb_info.old_class_index = old_class_index
    comb_info.old_classFunc_index = old_class_func_index

    # (2) Update comb_info with new struct index
    new_func_index, new_class_index, new_class_func_index = \
        build_struct_index_from_locations(comb_info.new_locations, new_structs_info)
    comb_info.new_func_index = new_func_index
    comb_info.new_class_index = new_class_index
    comb_info.new_classFunc_index = new_class_func_index

    return comb_info


"""EXTRACT DIFF CODE SNIPPETS"""


def adjust_code_snippet_indent(code_lines: List[str]) -> str:
    """Remove spare indent based on the first code line."""
    first_line = code_lines[0]

    indent_len = len(first_line) - len(first_line.lstrip())
    stripped_code_lines = [line[indent_len:] for line in code_lines]

    return '\n'.join(stripped_code_lines)


def diff_lines_to_str(diff_lines: List[DiffLine]) -> str:
    assert not diff_lines[0].sep and not diff_lines[-1].sep

    desc = "..."
    last_sep = True

    for diff_line in diff_lines:
        if diff_line.sep:
            assert not last_sep
            desc += "\n..."
            last_sep = True
        else:
            desc += f"\n{diff_line.code}"
            last_sep = False

    assert not last_sep
    desc += "\n..."

    return desc


def extract_diff_lines_context(
        source: SourceFileType,
        diff_lines: List[DiffLine],
        start_line_id: int,
        end_line_id: int,
        offset: int = 3
) -> List[int]:
    """Extract the context of diff lines from a code snippet."""
    context_line_ids: List[int] = []

    for diff_line in diff_lines:
        if diff_line.source == source and start_line_id <= diff_line.lineno <= end_line_id:
            li_context_start = max(start_line_id, diff_line.lineno - offset)
            li_context_end = min(end_line_id, diff_line.lineno + offset)
            li_context = list(range(li_context_start, li_context_end + 1))
            context_line_ids.extend(li_context)

    context_line_ids = list(set(context_line_ids))

    return context_line_ids


def extract_relevant_lines_in_func(
        source: SourceFileType,
        func_loc: Location,
        code_lines: List[str],
        diff_lines: List[DiffLine]
) -> List[int]:
    """Extract relevant lines in function, including top-level functions and class methods."""
    func_rel_line_ids: List[int] = []

    # Option 1:
    # func_rel_line_ids = func_loc.get_full_range()

    # Option 2:
    func_start, func_end = func_loc.range
    func_code = adjust_code_snippet_indent(code_lines[func_start - 1: func_end])

    # 1) Add func signature lines
    func_sig_line_ids = extract_func_sig_lines_from_code(func_code)
    func_sig_line_ids = [func_start + line_id - 1 for line_id in func_sig_line_ids]
    func_rel_line_ids.extend(func_sig_line_ids)

    # 2) Add context of diff lines in the func
    diff_context_line_ids = extract_diff_lines_context(source, diff_lines, func_start, func_end)
    func_rel_line_ids.extend(diff_context_line_ids)

    func_rel_line_ids = list(set(func_rel_line_ids))

    return func_rel_line_ids


def extract_relevant_lines_in_file(
        source: SourceFileType,
        diff_lines: List[DiffLine],
        code: str,
        locations: Dict[int, Location],
        li2loc_lookup: Dict[int, int]
) -> List[int]:
    """
    For all deleted / added lines, extract detailed and complete code lines containing them from the old / new files.

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

    NOTE: Only for modified files.
    """
    code_lines = code.splitlines(keepends=False)

    # ------------------ I. Find relevant line locations ------------------ #
    all_imports: List[int] = []
    relevant_units: List[int] = []
    relevant_funcs: List[int] = []
    relevant_classes: Dict[int, List[int]] = defaultdict(list)
    relevant_mains: Dict[int, List[int]] = defaultdict(list)

    ## (1) Find all import statements
    for loc_id, loc in locations.items():
        if loc.father is not None and locations[loc.father].type == LocationType.MODULE and \
                (loc.ast == "Import" or loc.ast == "ImportFrom"):
            all_imports.append(loc_id)

    ## (2) Find line locations where the diff lines
    for diff_line in diff_lines:
        if diff_line.source == source:
            loc_id = li2loc_lookup[diff_line.lineno]
            loc = locations[loc_id]

            if loc.type == LocationType.FUNCTION:
                # (1) Relevant functions
                if loc_id not in relevant_funcs:
                    relevant_funcs.append(loc_id)
            elif loc.type == LocationType.CLASS_UNIT or loc.type == LocationType.CLASS_FUNCTION:
                # (2) Relevant classes
                class_loc_id = loc.father
                if loc_id not in relevant_classes[class_loc_id]:
                    relevant_classes[class_loc_id].append(loc_id)
            elif loc.type == LocationType.MAIN_UNIT:
                # (3) Relevant main blocks
                main_loc_id = loc.father
                if loc_id not in relevant_mains[main_loc_id]:
                    relevant_mains[main_loc_id].append(loc_id)
            else:
                # (4) Relevant top-level statements
                assert loc.type == LocationType.UNIT
                if loc_id not in relevant_units:
                    relevant_units.append(loc_id)

    # ------------------ II. Find relevant line ids ------------------ #
    relevant_line_ids: List[int] = []

    ## (1) Add all lines in import statements
    for loc_id in all_imports:
        # 1. Add all lines of the statement
        import_line_ids = locations[loc_id].get_full_range()

        # 2. Add to all
        assert not are_overlap_lines(relevant_line_ids, import_line_ids)
        relevant_line_ids.extend(import_line_ids)

    ## (2) Add relevant lines in relevant functions
    for loc_id in relevant_funcs:
        func_loc = locations[loc_id]

        # 1. Add relevant lines in function
        func_rel_line_ids = extract_relevant_lines_in_func(source, func_loc, code_lines, diff_lines)

        # 2. Add to all
        assert not are_overlap_lines(relevant_line_ids, func_rel_line_ids)
        relevant_line_ids.extend(func_rel_line_ids)

    ## (3) Add relevant lines in relevant classes
    for class_loc_id, children in relevant_classes.items():
        class_rel_line_ids: List[int] = []

        # 1. Add relevant lines in class body
        for loc_id in children:
            child_loc = locations[loc_id]

            # 1.1 Class unit containing diff lines
            if child_loc.type == LocationType.CLASS_UNIT:
                class_unit_line_ids = child_loc.get_full_range()

                assert not are_overlap_lines(class_rel_line_ids, class_unit_line_ids)
                class_rel_line_ids.extend(class_unit_line_ids)

            # 2.1 Class methods containing diff lines
            if child_loc.type == LocationType.CLASS_FUNCTION:
                class_func_rel_line_ids = extract_relevant_lines_in_func(source, child_loc, code_lines, diff_lines)

                assert not are_overlap_lines(class_rel_line_ids, class_func_rel_line_ids)
                class_rel_line_ids.extend(class_func_rel_line_ids)

        # 2. Add class signature lines
        class_start, class_end = locations[class_loc_id].range
        class_code = adjust_code_snippet_indent(code_lines[class_start - 1: class_end])
        class_sig_line_ids = extract_class_sig_lines_from_code(class_code, include_func_sig=False)
        class_sig_line_ids = [class_start + line_id - 1 for line_id in class_sig_line_ids]

        class_rel_line_ids.extend(class_sig_line_ids)

        # 3. Add to all
        assert not are_overlap_lines(relevant_line_ids, class_rel_line_ids)
        relevant_line_ids.extend(class_rel_line_ids)

    ## (4) Add relevant lines in relevant main blocks
    for main_loc_id, children in relevant_mains.items():
        main_rel_line_ids: List[int] = []

        # 1. Add relevant lines in main block body
        for loc_id in children:
            child_loc = locations[loc_id]

            main_unit_line_ids = child_loc.get_full_range()

            assert not are_overlap_lines(main_rel_line_ids, main_unit_line_ids)
            main_rel_line_ids.extend(main_unit_line_ids)

        # 2. Add main block signature line
        main_sig_line_id = None
        for line_id in locations[main_loc_id].get_full_range():
            if is_main_line(code_lines[line_id - 1]):
                main_sig_line_id = line_id
                break
        assert main_sig_line_id is not None
        if main_sig_line_id not in main_rel_line_ids:
            main_rel_line_ids.append(main_sig_line_id)

        # 3. Add to all
        assert not are_overlap_lines(relevant_line_ids, main_rel_line_ids)
        relevant_line_ids.extend(main_rel_line_ids)

    ## (5) Add relevant lines in relevant top-level statements
    for loc_id in relevant_units:
        # 1. Add all lines of the statement
        unit_line_ids = locations[loc_id].get_full_range()

        # 2. Add to all
        relevant_line_ids.extend(unit_line_ids)

    return relevant_line_ids


def extract_diff_context_in_file(diff_lines: List[DiffLine], comb_info: CombineInfo) -> str:
    """Extract a more detailed and complete context containing all diff lines.

    NOTE: Only for modified files.
    """
    ## (1) Extract relevant line ids in old code and new code respectively
    old_relevant_line_ids = extract_relevant_lines_in_file(
        source=SourceFileType.OLD,
        diff_lines=diff_lines,
        code=comb_info.old_code,
        locations=comb_info.old_locations,
        li2loc_lookup=comb_info.old_li2loc
    )

    new_relevant_line_ids = extract_relevant_lines_in_file(
        source=SourceFileType.NEW,
        diff_lines=diff_lines,
        code=comb_info.new_code,
        locations=comb_info.new_locations,
        li2loc_lookup=comb_info.new_li2loc
    )

    ## (2) Combine relevant line ids
    relevant_line_ids: List[int] = []

    for line_id in old_relevant_line_ids:
        comb_line_id = comb_info.line_id_old2comb[line_id]
        if comb_line_id not in relevant_line_ids:
            relevant_line_ids.append(comb_line_id)

    for line_id in new_relevant_line_ids:
        comb_line_id = comb_info.line_id_new2comb[line_id]
        if comb_line_id not in relevant_line_ids:
            relevant_line_ids.append(comb_line_id)

    relevant_line_ids = sorted(relevant_line_ids)

    ## (3) Extract code snippets
    comb_code_lines = comb_info.comb_code.splitlines(keepends=False)
    snippet = ""

    for i in range(len(relevant_line_ids)):
        line_id = relevant_line_ids[i]
        # (1) Add sep '...'
        if i == 0:
            if line_id != 1:
                snippet = "..."
        else:
            last_line_id = relevant_line_ids[i - 1]
            if line_id != last_line_id + 1:
                snippet += "\n..."
        # (2) Add code line
        snippet += f"\n{comb_code_lines[line_id - 1]}"

    if relevant_line_ids[-1] != len(comb_code_lines):
        snippet += "\n..."

    snippet = snippet.strip('\n')

    return snippet


"""MAIN ENTRY"""


def analyse_modified_file(
        old_ori_code: str,
        new_ori_code: str,
        diff_file_info: Dict
) -> Tuple[CombineInfo, str] | None:

    # --------------------------- Step I: Get complete diff lines info --------------------------- #
    ori_diff_lines = combine_diff_code_info_within_file(diff_file_info)

    # --------------------------- Step II: Filter out blank and comment lines --------------------------- #
    ## (1) Filter code file
    old_nb_code, old_nb_li_lookup = filter_blank_and_comment_in_code(old_ori_code)
    new_nb_code, new_nb_li_lookup = filter_blank_and_comment_in_code(new_ori_code)

    ## (2) Filter commit Info
    nb_diff_lines = filter_blank_lines_in_commit(ori_diff_lines, old_nb_li_lookup, new_nb_li_lookup)

    if nb_diff_lines:
        # NOTE: All we analyse after is the FILTERED code!
        # --------------------------- Step III: Parse file --------------------------- #
        old_locations, old_li2loc, old_structs_info = parse_python_file_locations(old_nb_code)
        new_locations, new_li2loc, new_structs_info = parse_python_file_locations(new_nb_code)

        # --------------------------- Step IV: Initialize comb_info --------------------------- #
        comb_info = CombineInfo(
            old_code=old_nb_code, new_code=new_nb_code,
            old_locations=old_locations, new_locations=new_locations,
            old_li2loc=old_li2loc, new_li2loc=new_li2loc
        )

        # --------------------------- Step V: Combine code --------------------------- #
        nb_comb_info = combine_code_old_and_new(comb_info, nb_diff_lines)

        # --------------------------- Step VI: Build struct indexes  --------------------------- #
        nb_comb_info = update_comb_info_with_struct_index(nb_comb_info, old_structs_info, new_structs_info)

        # --------------------------- Step VII: Build DiffCodeSnippet  --------------------------- #
        # diff_code_snips = diff_lines_to_str(nb_diff_lines)
        diff_context = extract_diff_context_in_file(nb_diff_lines, comb_info)

        return nb_comb_info, diff_context
    else:
        return None
