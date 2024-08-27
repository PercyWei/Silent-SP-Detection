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
    parse_python_file_locations)
from utils import LineRange, same_line_range, run_command


class SourceFileType(str, Enum):
    OLD = "before_commit"
    NEW = "after_commit"

    @staticmethod
    def attributes():
        return [k.value for k in SourceFileType]


def show_and_save_commit_content(repo_dpath: str, cve_id: str, commit_id: str,
                                 commit_content_save_root: str) -> Optional[str]:
    """
        Extract commit content from local repo cloned.
        Save code changes in the following format.
        commit_content_save_root
            |- CVE_id
                |- commit_id
                    |- all_code_changes
                    |- code_changes_of_changed_file_1
                    |- code_changes_of_changed_file_2
                    |- ...

        Args:
        repo_dpath:
        cve_id:
        commit_id:
        commit_content_save_root:

        Returns:
            commit_content_save_fpath: path to save commit content.
            None: failed to save commit content.
    """
    assert os.path.exists(commit_content_save_root)

    cve_dpath = os.path.join(commit_content_save_root, cve_id)
    if not os.path.exists(cve_dpath):
        os.makedirs(cve_dpath, exist_ok=True)

    commit_dpath = os.path.join(cve_dpath, commit_id)
    if not os.path.exists(commit_dpath):
        os.makedirs(commit_dpath, exist_ok=True)

    commit_content_fpath = os.path.join(commit_dpath, "commit_content.txt")
    try:
        with open(commit_content_fpath, "w") as f:
            subprocess.run(['git', '-C', repo_dpath, 'show', commit_id], stdout=f, text=True, check=True)
        logger.info(f"[{cve_id}] Commit_id: {commit_id}, Result: success.")

        return commit_content_fpath
    except subprocess.CalledProcessError as e:
        logger.info(f"[{cve_id}] Commit_id: {commit_id}, Result: failed.")
        logger.error(f"Error msg: {str(e)}")

        return None


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
                "diff_line_indexes": diff_line_indexes,        # (List, 0-based)
                "diff_code_snippet": diff_code_snippet,        # (List[str])
                # For diff lines in file before
                "del_start_line_id": int(del_line_start_idx),  # (int, 1-based)
                "del_line_scope": int(del_line_scope),         # (int)
                "del_line_index2id": del_line_index2id,        # (Dict, 0-based -> 1-based)
                # For diff lines in file after
                "add_start_line_id": int(add_line_start_idx),  # (int, 1-based)
                "add_line_scope": int(add_line_scope),         # (int)
                "add_line_index2id": add_line_index2id         # (Dict, 0-based -> 1-based)
            }

            curr_diff_file_info["code_diff"].append(curr_code_diff)

        commit_content_info.append(curr_diff_file_info)

    return commit_content_info


"""Extract Only Diff Lines in single file"""


@dataclass
class DiffLine:
    id: int  # 0-based
    source: SourceFileType | None
    lineno: int | None
    code: str | None
    sep: bool


def _sep_for_diff_lines(cur_id: int) -> DiffLine:
    return DiffLine(id=cur_id, source=None, lineno=None, code=None, sep=True)


def _diff_line_source_file(diff_line: str) -> SourceFileType:
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
                last_line_is_diff = True

                source = _diff_line_source_file(line)
                line_id = cur_del_line_index2id[ind] if ind in cur_del_line_index2id else cur_add_line_index2id[ind]

                if len(diff_lines) == 0:
                    # Do not add "..." in the beginning anyway
                    diff_line = DiffLine(id=len(diff_lines), source=source, lineno=line_id, code=line, sep=False)
                    diff_lines.append(diff_line)
                elif last_line_is_diff:
                    diff_line = DiffLine(id=len(diff_lines), source=source, lineno=line_id, code=line, sep=False)
                    diff_lines.append(diff_line)
                else:
                    sep = _sep_for_diff_lines(len(diff_lines))
                    diff_lines.append(sep)

                    diff_line = DiffLine(id=len(diff_lines), source=source, lineno=line_id, code=line, sep=False)
                    diff_lines.append(diff_line)
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


# def filter_blank_lines_in_commit(
#         diff_file_info: Dict,
#         old_line_id_lookup: Dict[int, int],
#         new_line_id_lookup: Dict[int, int]
# ) -> Tuple[Dict[int, int], Dict[int, int], List[str]]:
#     """
#     Filter blank lines in commit, including lines deleted or added or unchanged.
#     NOTE: Whether to filter comment lines depends on the parameters `old_line_id_lookup` and `new_line_id_lookup`,
#             which are obtained by method `filter_blank_lines_in_file`.
#
#     """
#     ## Step 1: Combine all code snippets containing diff lines about this file, and only extract diff lines
#     # NOTE: Use "..." to separate not continous diff lines
#     diff_code_snippet: List[str] = []
#     del_line_index2id: Dict[int, int] = {}  # 0-based -> 1-based, deleted lines in file before commit
#     add_line_index2id: Dict[int, int] = {}  # 0-based -> 1-based, added lines in file after commit
#
#     for diff_code_info in diff_file_info["code_diff"]:
#         last_code_is_diff = False
#         for ind, code in enumerate(diff_code_info["diff_code_snippet"]):
#             if code.startswith("-") or code.startswith("+"):
#                 last_code_is_diff = True
#                 # (1)
#                 if len(diff_code_snippet) == 0:
#                     # Do not add "..." in the beginning anyway
#                     diff_code_snippet.append(code)
#                 elif last_code_is_diff:
#                     diff_code_snippet.append(code)
#                 else:
#                     diff_code_snippet.append("...")
#                     diff_code_snippet.append(code)
#
#                 cur_diff_line_ind = len(diff_code_snippet) - 1
#                 # (2) and (3)
#                 if code.startswith("-"):
#                     del_line_index2id[cur_diff_line_ind] = diff_code_info["del_line_index2id"][ind]
#                 else:
#                     add_line_index2id[cur_diff_line_ind] = diff_code_info["add_line_index2id"][ind]
#             else:
#                 last_code_is_diff = False
#
#     ## Step 2: Filter blank lines and redundant sep "..."
#     nb_del_line_index2id: Dict[int, int] = {}  # 0-based -> 1-based, deleted lines in file before commit
#     nb_add_line_index2id: Dict[int, int] = {}  # 0-based -> 1-based, added lines in file after commit
#     nb_diff_code_snippet: List[str] = []
#
#     last_is_sep = False
#     for ind, code in enumerate(diff_code_snippet):
#         # Sep
#         if code == "...":
#             if len(nb_diff_code_snippet) == 0:
#                 # Do not add "..." in the beginning
#                 pass
#             elif last_is_sep:
#                 # Do not add "..." after "..."
#                 pass
#             else:
#                 nb_diff_code_snippet.append(code)
#                 last_is_sep = True
#             continue
#
#         # Code
#         if ind in del_line_index2id:
#             line_id = del_line_index2id[ind]
#             if line_id in old_line_id_lookup:
#                 nb_line_id = old_line_id_lookup[line_id]
#
#                 nb_diff_code_snippet.append(code)
#                 nb_del_line_index2id[len(nb_diff_code_snippet) - 1] = nb_line_id
#
#                 last_is_sep = False
#         else:
#             line_id = add_line_index2id[ind]
#             if line_id in new_line_id_lookup:
#                 nb_line_id = new_line_id_lookup[line_id]
#
#                 nb_diff_code_snippet.append(code)
#                 nb_add_line_index2id[len(nb_diff_code_snippet) - 1] = nb_line_id
#
#                 last_is_sep = False
#
#     if nb_diff_code_snippet[-1] == "...":
#         nb_diff_code_snippet.pop(-1)
#
#     return nb_del_line_index2id, nb_add_line_index2id, nb_diff_code_snippet


def filter_blank_lines_in_commit(
        file_diff_lines: List[DiffLine],
        old_line_id_lookup: Dict[int, int],
        new_line_id_lookup: Dict[int, int]
) -> List[DiffLine]:
    """
    Filter blank lines and comment lines in commit, including lines deleted or added or unchanged.

    NOTE 1: Only for modified files.
    NOTE 2: `file_diff_lines` is obtained from `combine_diff_code_info_within_file`.
    NOTE 3: Whether to filter comment lines depends on the parameters `old_line_id_lookup` and `new_line_id_lookup`,
            which are obtained by method `filter_blank_lines_in_file`, and in both look-up dict, there are no
            corresponding key-value pairs for blank lines or comment lines.

    Args:
        file_diff_lines (List[DiffLine]): List of diff lines within file.
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


"""Get The File Content Before or After Applying The Commit"""


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


"""Analyse The Changes to Functions (including async) and Classes Before and After Applying The Commit"""


def is_subset(subset: List, container: List) -> bool:
    set1 = set(subset)
    set2 = set(container)

    return set1.issubset(set2)


def has_same_elements(list1: List, list2: List) -> bool:
    set1 = set(list1)
    set2 = set(list2)

    return not set1.isdisjoint(set2)


def is_modified_struct(
        old_content: List[str], old_diff_line_ids: List[int], old_struct_location: Location,
        new_content: List[str], new_diff_line_ids: List[int], new_struct_location: Location
) -> bool:
    """
    Determine whether the two structs from the file before and after modification are the same.
    Only support struct CLASS, FUNCTION and CLASSFUNCTION.

    """
    old_struct_line_ids = old_struct_location.get_full_range()
    old_rest_line_ids = sorted(list(set(old_struct_line_ids) - set(old_diff_line_ids)))

    new_struct_line_ids = new_struct_location.get_full_range()
    new_rest_line_ids = sorted(list(set(new_struct_line_ids) - set(new_diff_line_ids)))

    if len(old_rest_line_ids) != len(new_rest_line_ids):
        return False

    for old_line_id, new_line_id in zip(old_rest_line_ids, new_rest_line_ids):
        if old_content[old_line_id - 1] != new_content[new_line_id - 1]:
            # print(old_line_id)
            # print(new_line_id)
            # print(old_content[old_line_id - 1], new_content[new_line_id - 1])
            return False

    return True


def build_map_from_ori_name_to_now_names(
        structs: List[int],
        locations: Dict[int, Location]
) -> Dict[str, Dict[str, int]]:
    """Build a dictionary that maps struct original name (like "xxx") to now names (like "xxx@num")."""
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


def classify_diff_struct(
        old_content: List[str], old_diff_line_ids: List[int], old_structs: List[int], old_locations: Dict[int, Location],
        new_content: List[str], new_diff_line_ids: List[int], new_structs: List[int], new_locations: Dict[int, Location],
) -> Tuple[List, List, Dict]:
    """
    Classify the types (delete, add, modify) of diff structs (only for CLASS or FUNCTION).
    Since adding "@<start>" to the class / func name, it is possible that
    names of not renamed classes / functions may be different between old_structs and new_structs.
    """
    ## (1) Deleted structs, List of location id
    del_structs: List[int] = []
    ## (2) Added structs, List of location id
    add_structs: List[int] = []
    ## (3) Three types of modified structs (three types: a. delete + add; b. delete only; c. add only)
    # location id before modified -> location id after modified
    mod_structs: Dict[int, int] = {}

    old_mod_structs: List[int] = []
    new_mod_structs: List[int] = []

    # STEP 1: Select del_structs and old_mod_structs from structs in old file (old_structs)
    for loc_id in old_structs:
        range_line_ids = old_locations[loc_id].get_full_range()
        if is_subset(range_line_ids, old_diff_line_ids):
            del_structs.append(loc_id)
        elif has_same_elements(range_line_ids, old_diff_line_ids):
            old_mod_structs.append(loc_id)

    # STEP 2: Select add_structs and new_mod_structs from structs in new file (new_structs)
    for loc_id in new_structs:
        range_line_ids = new_locations[loc_id].get_full_range()
        if is_subset(range_line_ids, new_diff_line_ids):
            add_structs.append(loc_id)
        elif has_same_elements(range_line_ids, new_diff_line_ids):
            new_mod_structs.append(loc_id)

    # STEP 3: Match items in old_mod_structs and new_mod_structs to construct mod_structs
    old_ori_name2no_names: Dict[str, Dict[str, int]] = build_map_from_ori_name_to_now_names(old_structs, old_locations)
    new_ori_name2no_names: Dict[str, Dict[str, int]] = build_map_from_ori_name_to_now_names(new_structs, new_locations)

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

            if is_modified_struct(
                    old_content, old_diff_line_ids, old_loc,
                    new_content, new_diff_line_ids, new_loc):
                # 1) struct modified with both delete and add
                mod_structs[old_loc_id] = new_loc_id
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
            mod_structs[old_loc_id] = new_loc_id

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
            mod_structs[old_loc_id] = new_loc_id

    return del_structs, add_structs, mod_structs


def classify_diff_classFunction(
        old_content: List[str], old_diff_line_ids: List[int], old_classFuncs: Dict[int, List[int]], old_locations: Dict[int, Location],
        new_content: List[str], new_diff_line_ids: List[int], new_classFuncs: Dict[int, List[int]], new_locations: Dict[int, Location],
        del_classes: List[int], add_classes: List[int], mod_classes: Dict[int, int],
) -> Tuple[Dict, Dict, Dict]:
    del_classFuncs: Dict[int, List[int]] = {}
    add_classFuncs: Dict[int, List[int]] = {}
    mod_classFuncs: Dict[Tuple[int, int], Dict] = {}

    # (1) For deleted classes
    for class_loc_id in del_classes:
        del_classFuncs[class_loc_id] = old_classFuncs[class_loc_id]

    # (2) For added classes
    for class_loc_id in add_classes:
        add_classFuncs[class_loc_id] = new_classFuncs[class_loc_id]

    # (3) For modified class pairs
    for old_class_loc_id, new_class_loc_id in mod_classes.items():
        cur_old_classFuncs: List[int] = old_classFuncs[old_class_loc_id]
        cur_new_classFuncs: List[int] = new_classFuncs[new_class_loc_id]

        cur_del_classFuncs, cur_add_classFuncs, cur_mod_classFuncs = classify_diff_struct(
            old_content, old_diff_line_ids, cur_old_classFuncs, old_locations,
            new_content, new_diff_line_ids, cur_new_classFuncs, new_locations
        )

        mod_classFuncs[(old_class_loc_id, new_class_loc_id)] = {
            "del": cur_del_classFuncs,
            "add": cur_add_classFuncs,
            "mod": cur_mod_classFuncs,
        }

    return del_classFuncs, add_classFuncs, mod_classFuncs


def analyse_diff_structs_within_file(
        old_file_lines: List[str],
        old_location_parse_res: Tuple[List[int], List[int], Dict, Dict, Dict[int, int]],
        del_line_index2id: Dict[int, int],
        new_file_lines: List[str],
        new_location_parse_res: Tuple[List[int], List[int], Dict, Dict, Dict[int, int]],
        add_line_index2id: Dict[int, int]
) -> Tuple[Dict, Dict, Dict]:
    """
    Struct includes Class, Function and ClassFunction.

    Args:
        old_file_lines: File content before applying the commit, split into list.
        old_location_parse_res: Result from `agent_app.static_analysis.parse.parse_python_file_locations`
        del_line_index2id:
        new_file_lines: File content after applying the commit, split into list.
        new_location_parse_res: Result from `agent_app.static_analysis.parse.parse_python_file_locations`
        add_line_index2id:
    Returns:
        Dict: Diff classes info.
        Dict: Diff functions info.
        Dict: Diff class functions info.
    """
    old_classes, old_funcs, old_classFuncs, old_locations, _ = old_location_parse_res
    new_classes, new_funcs, new_classFuncs, new_locations, _ = new_location_parse_res

    del_line_ids: List[int] = list(del_line_index2id.values())
    add_line_ids: List[int] = list(add_line_index2id.values())

    # (1) Distinguish the types of class modifications
    del_classes, add_classes, mod_classes = classify_diff_struct(
        old_file_lines, del_line_ids, old_classes, old_locations,
        new_file_lines, add_line_ids, new_classes, new_locations
    )

    # (2) Distinguish the types of function modifications
    del_funcs, add_funcs, mod_funcs = classify_diff_struct(
        old_file_lines, del_line_ids, old_funcs, old_locations,
        new_file_lines, add_line_ids, new_funcs, new_locations
    )

    # (3) Distinguish the types of class function modifications
    del_classFuncs, add_classFuncs, mod_classFuncs = classify_diff_classFunction(
        old_file_lines, del_line_ids, old_classFuncs, old_locations,
        new_file_lines, add_line_ids, new_classFuncs, new_locations,
        del_classes, add_classes, mod_classes,
    )

    diff_classes_info = {
        "del": del_classes,
        "add": add_classes,
        "mod": mod_classes
    }

    diff_funcs_info = {
        "del": del_funcs,
        "add": add_funcs,
        "mod": mod_funcs
    }

    diff_classFuncs_info = {
        "del": del_classFuncs,
        "add": add_classFuncs,
        "mod": mod_classFuncs
    }

    return diff_classes_info, diff_funcs_info, diff_classFuncs_info


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


def get_diff_loc_by_line_ind(
        line_ind: int,
        old_locations: Dict[int, Location], old_line_id2loc_id: Dict[int, int],
        new_locations: Dict[int, Location], new_line_id2loc_id: Dict[int, int],
        del_line_index2id: Dict[int, int], add_line_index2id: Dict[int, int]
) -> DiffLocation | None:
    if line_ind in del_line_index2id:
        line_id = del_line_index2id[line_ind]
        loc_id = old_line_id2loc_id[line_id]
        return loc_to_diff_loc(old_locations[loc_id], SourceFileType.OLD)
    else:
        line_id = add_line_index2id[line_ind]
        loc_id = new_line_id2loc_id[line_id]
        return loc_to_diff_loc(new_locations[loc_id], SourceFileType.NEW)


## For struct Global, Function, ClassGlobal, ClassFunction
# - struct_type: LocationType
# - indexes: List[int]
IndStructType = namedtuple("IndStructType", ["struct_type", "indexes"])
## For struct Class
# - struct_type: LocationType
# - children: List[IndStructType]
IndClassType = namedtuple("IndClassType", ["struct_type", "children"])
## For top level items of root (Global, Function, Class)
IndType = IndStructType | IndClassType


def group_diff_lines_by_struct_within_file(
        old_locations: Dict[int, Location], old_line_id2loc_id: Dict[int, int],
        new_locations: Dict[int, Location], new_line_id2loc_id: Dict[int, int],
        del_line_index2id: Dict[int, int], add_line_index2id: Dict[int, int], diff_code_snippet: List[str],
        diff_classes_info: Dict, diff_funcs_info: Dict, diff_classFuncs_info: Dict
):
    """
    NOTE 1: Only for modified files.
    NOTE 2: For all diff lines (not blank) in a file, group them by struct (Global, Function, Class),
    also, we will refine the Class group by ClassGlobal and ClassFunction.
    """
    ######################## Inner Function ########################

    support_line_type = (LocationType.FUNCTION, LocationType.UNIT, LocationType.CLASS_UNIT, LocationType.CLASS_FUNCTION)
    top_level_item_type = (LocationType.CLASS, LocationType.FUNCTION, LocationType.UNIT)
    class_child_type = (LocationType.CLASS_UNIT, LocationType.CLASS_FUNCTION)

    def _new_group(_ind: int, _loc_type: LocationType) -> IndType:
        ind_struct = IndStructType(struct_type=_loc_type, indexes=[_ind])
        if _loc_type in class_child_type:
            return IndClassType(struct_type=LocationType.CLASS, children=[ind_struct])
        else:
            return ind_struct

    def _is_same_location(loc_1: Location, loc_2: Location) -> bool:
        """
        NOTE 1: loc_1, loc_2 must be in the same file (old / new).
        NOTE 2: loc_1, loc_2 can be DiffLocation.
        """
        return loc_1.name == loc_2.name and same_line_range(loc_1.range, loc_2.range)

    def _in_same_function(
            _last_line_diffloc: DiffLocation,
            _curr_line_diffloc: DiffLocation,
            _diff_funcs: Dict
    ) -> bool:
        """
        NOTE: last line and current line are both in Location FUNCTION or CLASSFUNCTION.
        """
        _del_funcs: List[int] = _diff_funcs["del"]
        _add_funcs: List[int] = _diff_funcs["add"]
        _mod_funcs: Dict[int, int] = _diff_funcs["mod"]

        same_func: bool = False

        ####################### CASE 1 #######################
        # Last line and current line are in the same file (old / new)
        if _last_line_diffloc.file_type == _curr_line_diffloc.file_type:
            if _last_line_diffloc.id == _curr_line_diffloc.id:
                same_func = True
            else:
                same_func = False

        ####################### CASE 2 #######################
        # Last line is in the old file, i.e. a deleted line
        # Current line is in the new file, i.e. an added line
        elif _last_line_diffloc.file_type == SourceFileType.OLD:
            # Deleted line (last line) cannot be in an added function
            assert _last_line_diffloc.id not in _add_funcs

            if _last_line_diffloc.id in _del_funcs:
                # Deleted function (last line) cannot have an added line (curr line), thus in different groups
                same_func = False
            else:
                assert _last_line_diffloc.id in _mod_funcs, DiffLocationNotFoundError(_last_line_diffloc)

                _last_func_after_id = _mod_funcs[_last_line_diffloc.id]

                if _is_same_location(_curr_line_diffloc, new_locations[_last_func_after_id]):
                    same_func = True
                else:
                    same_func = False

        ####################### CASE 3 #######################
        # Last line is in the new file, i.e. an added line
        # Current line is in the old file, i.e. a deleted line
        elif _last_line_diffloc.file_type == SourceFileType.NEW:
            # Added line (last line) cannot be in a deleted function
            assert _last_line_diffloc.id not in _del_funcs

            if _last_line_diffloc.id in _add_funcs:
                # Added function (last line) cannot have a deleted line (curr line), thus in different groups
                same_func = False
            else:
                assert _last_line_diffloc.id in list(_mod_funcs.values()), DiffLocationNotFoundError(_last_line_diffloc)

                _last_func_before_id = None
                for _func_before_id, _func_after_id in _mod_funcs.items():
                    if _func_after_id == _last_line_diffloc.id:
                        _last_func_before_id = _func_before_id
                        break

                if _is_same_location(_curr_line_diffloc, old_locations[_last_func_before_id]):
                    same_func = True
                else:
                    same_func = False

        return same_func

    def _in_same_class(
            _last_line_diffloc: DiffLocation,
            _curr_line_diffloc: DiffLocation,
            _diff_classes: Dict
    ) -> bool:
        """
        NOTE: last line and current line are both in Location CLASSGLOBAL or CLASSFUNCTION.
        """
        _del_classes: List[int] = _diff_classes["del"]
        _add_classes: List[int] = _diff_classes["add"]
        _mod_classes: Dict[int, int] = _diff_classes["mod"]

        same_class: bool = False

        ####################### CASE 1 #######################
        # Last line and current line are in the same file (old / new)
        if _last_line_diffloc.file_type == _curr_line_diffloc.file_type:
            if _last_line_diffloc.father == _curr_line_diffloc.father:
                same_class = True
            else:
                same_class = False

        ####################### CASE 2 #######################
        # Last line is in the old file, i.e. a deleted line
        # Current line is in the new file, i.e. an added line
        elif _last_line_diffloc.file_type == SourceFileType.OLD:
            # Deleted line (last line) cannot be in an added class
            assert _last_line_diffloc.father not in _add_classes

            if _last_line_diffloc.father in _del_classes:
                # Deleted class (last line) cannot have an added line (curr line), thus in different groups
                same_class = False
            else:
                assert _last_line_diffloc.father in _mod_classes, DiffLocationNotFoundError(_last_line_diffloc)

                if _curr_line_diffloc.father == _mod_classes[_last_line_diffloc.father]:
                    same_class = True
                else:
                    same_class = False

        ####################### CASE 3 #######################
        # Last line is in the new file, i.e. an added line
        # Current line is in the old file, i.e. a deleted line
        elif _last_line_diffloc.file_type == SourceFileType.NEW:
            # Added line (last line) cannot be in a deleted class
            assert _last_line_diffloc.id not in _del_classes

            if _last_line_diffloc.id in _add_classes:
                # Added function (last line) cannot have a deleted line (curr line), thus in different groups
                same_class = False
            else:
                assert _last_line_diffloc.father in list(_mod_classes.values()), DiffLocationNotFoundError(
                    _last_line_diffloc)

                _last_func_before_id = None
                for _class_before_id, _class_after_id in _mod_classes.items():
                    if _class_after_id == _last_line_diffloc.father:
                        _last_func_before_id = _class_before_id
                        break

                if _curr_line_diffloc.father == _last_func_before_id:
                    same_class = True
                else:
                    same_class = False

        return same_class

    def _in_same_classFunction(
            _last_li_ind_struct: IndStructType,
            _curr_li_ind_struct: IndStructType,
            _diff_classFuncs: Dict
    ) -> bool:
        """
        NOTE 1: This function is for IndStructType.
        NOTE 2: last line and current line are in the same class!
        """
        _del_class_classFuncs: Dict[int, List[int]] = _diff_classFuncs["del"]
        _add_class_classFuncs: Dict[int, List[int]] = _diff_classFuncs["add"]
        _mod_class_classFuncs: Dict[Tuple[int, int], Dict] = _diff_classFuncs["mod"]

        same_classFunc: bool = False
        _last_line_diffloc = get_diff_loc_by_line_ind(
            _last_li_ind_struct.indexes[0],
            old_locations, old_line_id2loc_id,
            new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id
        )
        _curr_line_diffloc = get_diff_loc_by_line_ind(
            _curr_li_ind_struct.indexes[0],
            old_locations, old_line_id2loc_id,
            new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id
        )
        assert _last_line_diffloc is not None and _curr_line_diffloc is not None

        ####################### CASE 1 #######################
        # Last line and current line are in the same file (old / new)
        if _last_line_diffloc.file_type == _curr_line_diffloc.file_type:
            assert _last_line_diffloc.father == _curr_line_diffloc.father

            if _last_line_diffloc.id == _curr_line_diffloc.id:
                same_classFunc = True
            else:
                same_classFunc = False

        ####################### CASE 2 #######################
        # Last line is in the old file, i.e. a deleted line
        # Current line is in the new file, i.e. an added line
        elif _last_line_diffloc.file_type == SourceFileType.OLD:
            assert _last_line_diffloc.father not in _del_class_classFuncs
            assert _last_line_diffloc.father not in _add_class_classFuncs
            assert (_last_line_diffloc.father, _curr_line_diffloc.father) in _mod_class_classFuncs
            same_classFunc = _in_same_function(
                _last_line_diffloc,
                _curr_line_diffloc,
                _mod_class_classFuncs[(_last_line_diffloc.father, _curr_line_diffloc.father)]
            )

        ####################### CASE 3 #######################
        # Last line is in the new file, i.e. an added line
        # Current line is in the old file, i.e. a deleted line
        elif _last_line_diffloc.file_type == SourceFileType.NEW:
            assert _last_line_diffloc.father not in _del_class_classFuncs
            assert _last_line_diffloc.father not in _add_class_classFuncs
            assert (_curr_line_diffloc.father, _last_line_diffloc.father) in _mod_class_classFuncs
            same_classFunc = _in_same_function(
                _last_line_diffloc,
                _curr_line_diffloc,
                _mod_class_classFuncs[(_curr_line_diffloc.father, _last_line_diffloc.father)]
            )

        return same_classFunc

    ######################## Inner Function ########################

    # Group diff lines in the same struct
    # - GLOBAL
    # - FUNCTION
    # - CLASS
    # |- CLASSGLOBAL
    # |- CLASSFUNCTION
    diff_line_index_groups: List[IndType] = []

    ## Step 1: Group all diff lines by struct, when facing CLASSGLOBAL or CLASSFUNCTION,
    #          only consider whether they are in the same class
    last_line_diffloc: DiffLocation | None = None
    cur_group: IndType | None = None

    for diff_line_ind, code in enumerate(diff_code_snippet):
        if code == "...":
            continue

        # (1) Find basic info (DiffLocation) of current line:
        cur_line_diffloc = get_diff_loc_by_line_ind(
            diff_line_ind,
            old_locations, old_line_id2loc_id,
            new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id
        )

        assert cur_line_diffloc.type in support_line_type

        # (2) Determine if current line and last line are in the same group (struct)
        # Beginning
        if last_line_diffloc is None:
            cur_group = _new_group(diff_line_ind, cur_line_diffloc.type)
            last_line_diffloc = cur_line_diffloc
            continue

        # Deciding whether in the same group
        if last_line_diffloc.type in class_child_type and cur_line_diffloc.type in class_child_type:
            new_group_flag = not _in_same_class(
                last_line_diffloc,
                cur_line_diffloc,
                diff_classes_info
            )
        elif last_line_diffloc.type != cur_line_diffloc.type:
            new_group_flag = True
        elif last_line_diffloc.type == LocationType.FUNCTION:
            new_group_flag = not _in_same_function(
                last_line_diffloc,
                cur_line_diffloc,
                diff_funcs_info
            )
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

        # (3) Update
        if new_group_flag:
            # Add the last group to the groups
            assert cur_group is not None
            diff_line_index_groups.append(cur_group)
            # Open a new group
            cur_group = _new_group(diff_line_ind, cur_line_diffloc.type)
        else:
            if isinstance(cur_group, IndClassType):
                # Current group is for Class
                ind_struct = IndStructType(struct_type=cur_line_diffloc.type, indexes=[diff_line_ind])
                cur_group.children.append(ind_struct)
            else:
                # Current group is for Function or Global
                cur_group.indexes.append(diff_line_ind)

        last_line_diffloc = cur_line_diffloc

    if cur_group is not None:
        diff_line_index_groups.append(cur_group)

    ## Step 2: Group continuous class items by class
    for i in range(len(diff_line_index_groups)):
        item = diff_line_index_groups[i]
        assert item.struct_type in top_level_item_type

        if isinstance(item, IndClassType):
            children: List[IndStructType] = []

            last_child: IndStructType | None = None
            updt_cur_child: IndStructType | None = None

            for child in item.children:
                assert child.struct_type in class_child_type and len(child.indexes) == 1

                if last_child is None:
                    updt_cur_child = child
                    last_child = child
                    continue

                if last_child.struct_type != child.struct_type:
                    new_group_flag = True
                elif last_child.struct_type == LocationType.CLASS_FUNCTION:
                    new_group_flag = not _in_same_classFunction(
                        last_child,
                        child,
                        diff_classFuncs_info
                    )
                else:
                    # last_sub_struct.group_name == LocationType.CLASSGLOBAL
                    new_group_flag = False

                if new_group_flag:
                    # Add current sub_group
                    assert updt_cur_child is not None
                    children.append(updt_cur_child)
                    # Open a new sub_group
                    updt_cur_child = child
                else:
                    updt_cur_child.indexes.append(child.indexes[0])

                last_child = child

            if updt_cur_child is not None:
                children.append(updt_cur_child)

            updt_class: IndClassType = IndClassType(struct_type=LocationType.CLASS, children=children)
            diff_line_index_groups[i] = updt_class

    return diff_line_index_groups


################### For recording the diff struct ###################
## For struct Global, Function, ClassGlobal and ClassFunction
# - struct_type: LocationType
# - struct_name: str
# - code: str
DiffStructType = namedtuple("DiffStructType", ["struct_type", "struct_name", "code"])
## For struct Class
# - struct_type: LocationType
# - struct_name: str
# - children: List[DiffStructType]
DiffClassType = namedtuple("DiffClassType", ["struct_type", "struct_name", "children"])
## For top level items of root (Global, Function, Class)
DiffType = DiffStructType | DiffClassType


################### For grouping continous lines in the same struct into the same group ###################
## For struct Global, Function, ClassGlobal and ClassFunction
# - group_name: LocationType
# - struct_name: str
# - all_indexes: List[List[int]]
ContIndStructType = namedtuple("ContIndStructType", ["struct_type", "struct_name", "all_indexes"])
## For struct Class
# - group_name: LocationType
# - struct_name: str
# - children: List[ContIndStructType]
ContIndClassType = namedtuple("ContIndClassType", ["struct_type", "struct_name", "children"])
## For top level items of root (Global, Function, Class)
ContIndType = ContIndStructType | ContIndClassType


"""Group continuous lines"""


def _split_discontinuous_line_indexes(all_indexes: List[int]) -> List[List[int]]:
    # Procedure: List[int] -> List[List[int]]
    # Basis for Judgement: Whether lines are continuous in `diff_code_snippet`
    all_cont_indexes: List[List[int]] = []
    cur_cont_indexes: List[int] = []

    for ind in all_indexes:
        if not cur_cont_indexes:
            cur_cont_indexes = [ind]
            continue

        if ind == cur_cont_indexes[-1] + 1:
            cur_cont_indexes.append(ind)
        else:
            all_cont_indexes.append(cur_cont_indexes)
            cur_cont_indexes = [ind]

    if len(cur_cont_indexes) > 0:
        all_cont_indexes.append(cur_cont_indexes)

    return all_cont_indexes


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
        loc = get_diff_loc_by_line_ind(
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
        func_code = old_content[loc_before.range.start-1: loc_before.range.end]

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
                    assert old_content[curr_before_line_id-1] == new_content[curr_after_line_id-1]
                    func_code.append(old_content[curr_before_line_id-1])
                    curr_before_line_id += 1
                    curr_after_line_id += 1

                assert del_line_id == curr_before_line_id
                # TODO: Check 4, delete after
                assert diff_code_snippet[ind][1:] == old_content[curr_before_line_id-1]
                func_code.append(diff_code_snippet[ind])
                curr_before_line_id += 1

            else:
                add_line_id = add_line_index2id[ind]

                assert add_line_id >= curr_after_line_id
                while add_line_id > curr_after_line_id:
                    # TODO: Check 5, delete after
                    assert old_content[curr_before_line_id-1] == new_content[curr_after_line_id-1]
                    func_code.append(old_content[curr_before_line_id-1])
                    curr_before_line_id += 1
                    curr_after_line_id += 1

                assert add_line_id == curr_after_line_id
                # TODO: Check 6, delete after
                assert diff_code_snippet[ind][1:] == new_content[curr_after_line_id-1]
                func_code.append(diff_code_snippet[ind])
                curr_after_line_id += 1

            i += 1

        while curr_before_line_id <= loc_before.range.end:
            # TODO: Check 5, delete after
            assert old_content[curr_before_line_id-1] == new_content[curr_after_line_id-1]
            func_code.append(old_content[curr_before_line_id-1])
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
            assert ind == cont_indexes[i-1] + 1
        code.append(diff_code_snippet[ind])

    return "\n".join(code)


""""""


def _parse_ind_struct(
        ind_struct: IndStructType,
        old_content: List[str], old_locations: Dict[int, Location], old_line_id2loc_id: Dict[int, int],
        new_content: List[str], new_locations: Dict[int, Location], new_line_id2loc_id: Dict[int, int],
        del_line_index2id: Dict[int, int], add_line_index2id: Dict[int, int], diff_code_snippet: List[str]
) -> Tuple[List[ContIndStructType], List[DiffStructType]]:
    """
    Task 1: Group continuous indexes in the same struct.
    Task 2: Get full diff code for each struct after grouping.

    NOTE 1: Only for struct Global, Function, ClassGlobal or ClassFunction.
    NOTE 2: For Global and ClassGlobal, struct only contains continuous lines, so one `IndStructType` may
            get multiple `ContIndStructType` after processing, like:
            IndStructType[1, 2, 3, 5, 6] -> ContIndStructType[[1, 2, 3]], ContIndStructType[[5, 6]]
    NOTE 3: For Function and ClassFunction, struct must contain all lines involved, so one `IndStructType` only
            get one `ContIndStructType` after processing, like:
            IndStructType[1, 2, 3, 5, 6] -> ContIndStructType[[1, 2, 3], [5, 6]]
    """
    # Split discontinuous lines indexes
    all_cont_indexes = _split_discontinuous_line_indexes(ind_struct.indexes)

    ## Case 1
    if ind_struct.struct_type in (LocationType.UNIT, LocationType.CLASS_UNIT):
        cont_ind_globals: List[ContIndStructType] = []
        diff_globals: List[DiffStructType] = []

        for cont_indexes in all_cont_indexes:
            cont_ind_global = ContIndStructType(struct_type=ind_struct.struct_type,
                                                struct_name="",
                                                all_indexes=[cont_indexes])
            cont_ind_globals.append(cont_ind_global)

            diff_global = DiffStructType(struct_type=ind_struct.struct_type,
                                         struct_name="",
                                         code=_get_full_diff_global_code(cont_indexes, diff_code_snippet))
            diff_globals.append(diff_global)

        return cont_ind_globals, diff_globals
    ## Case 2
    else:
        assert ind_struct.struct_type in (LocationType.FUNCTION, LocationType.CLASS_FUNCTION)

        # Find Function location in the file after
        loc_after: DiffLocation | None = None
        for ind in ind_struct.indexes:
            loc = get_diff_loc_by_line_ind(
                ind,
                old_locations, old_line_id2loc_id,
                new_locations, new_line_id2loc_id,
                del_line_index2id, add_line_index2id
            )
            if loc.file_type == SourceFileType.NEW:
                loc_after = loc
                break
        if loc_after is None:
            loc_after = get_diff_loc_by_line_ind(
                ind_struct.indexes[0],
                old_locations, old_line_id2loc_id,
                new_locations, new_line_id2loc_id,
                del_line_index2id, add_line_index2id
            )

        cont_ind_func = ContIndStructType(struct_type=ind_struct.struct_type,
                                          struct_name=loc_after.name.split("@")[0],
                                          all_indexes=all_cont_indexes)
        diff_func = DiffStructType(struct_type=ind_struct.struct_type,
                                   struct_name=loc_after.name.split("@")[0],
                                   code=_get_full_diff_func_code(
                                       ind_struct.indexes,
                                       old_content, old_locations, old_line_id2loc_id,
                                       new_content, new_locations, new_line_id2loc_id,
                                       del_line_index2id, add_line_index2id, diff_code_snippet
                                   ))

        return [cont_ind_func], [diff_func]


def parse_diff_lines_within_top_struct(
        ind_struct: IndType,
        old_content: List[str], old_locations: Dict[int, Location], old_line_id2loc_id: Dict[int, int],
        new_content: List[str], new_locations: Dict[int, Location], new_line_id2loc_id: Dict[int, int],
        del_line_index2id: Dict[int, int], add_line_index2id: Dict[int, int], diff_code_snippet: List[str]
) -> Tuple[List[ContIndType], List[DiffType]]:
    """
    For a top level struct (Global, Function, Class) with diff line indexes:
        Task 1: Separate discontinuous diff lines into different groups.
        Task 2: Get full diff code.
    NOTE 1: The type of data to be processed is IndType!
    NOTE 2: Only for struct in modified files.
    """
    ######################## Inner Function ########################

    def _get_father_diff_loc_by_line_ind(_line_id: int) -> DiffLocation:
        _loc = get_diff_loc_by_line_ind(
            _line_id,
            old_locations, old_line_id2loc_id,
            new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id
        )
        if _loc.file_type == SourceFileType.OLD:
            return loc_to_diff_loc(old_locations[_loc.father], SourceFileType.OLD)
        else:
            return loc_to_diff_loc(new_locations[_loc.father], SourceFileType.NEW)

    ######################## Inner Function ########################

    if isinstance(ind_struct, IndClassType):
        # For saving continuous lines indexes
        cont_ind_children: List[ContIndStructType] = []
        # For saving full diff code
        diff_children: List[DiffStructType] = []

        for ind_child in ind_struct.children:
            cont_ind_childs, diff_childs = _parse_ind_struct(
                ind_child,
                old_content, old_locations, old_line_id2loc_id,
                new_content, new_locations, new_line_id2loc_id,
                del_line_index2id, add_line_index2id, diff_code_snippet
            )

            cont_ind_children.extend(cont_ind_childs)
            diff_children.extend(diff_childs)

        # FIXME: Need update to find class location in the file after
        class_loc = _get_father_diff_loc_by_line_ind(cont_ind_children[0].all_indexes[0][0])
        cont_ind_class = ContIndClassType(struct_type=LocationType.CLASS,
                                          struct_name=class_loc.name.split("@")[0],
                                          children=cont_ind_children)
        diff_class = DiffClassType(struct_type=LocationType.CLASS,
                                   struct_name=class_loc.name.split("@")[0],
                                   children=diff_children)

        return [cont_ind_class], [diff_class]
    else:
        cont_ind_structs, diff_structs = _parse_ind_struct(
            ind_struct,
            old_content, old_locations, old_line_id2loc_id,
            new_content, new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id, diff_code_snippet
        )

        return cont_ind_structs, diff_structs


def analyse_diff_within_file(
        old_file_content: str,
        new_file_content: str,
        del_line_index2id: Dict[int, int],
        add_line_index2id: Dict[int, int],
        diff_code_snippet: List[str]
) -> Tuple[List[ContIndType], List]:
    """
    NOTE 1: Only for modified files.
    NOTE 2: For code before commit and code after commit, we filter blank lines in them,
          also, for info extracted from commit `del_line_index2id`, `add_line_index2id`, `diff_code_snippet`,
          we filter blank lines in them and align it with the no blank code before commit and after commit.
    """
    old_content: List[str] = old_file_content.splitlines(keepends=False)
    new_content: List[str] = new_file_content.splitlines(keepends=False)

    old_res = parse_python_file_locations(old_file_content)
    new_res = parse_python_file_locations(new_file_content)

    diff_classes_info, diff_funcs_info, diff_classFuncs_info = \
        analyse_diff_structs_within_file(old_content, old_res, del_line_index2id,
                                         new_content, new_res, add_line_index2id)

    _, _, _, old_locations, old_line_id2loc_id = old_res
    _, _, _, new_locations, new_line_id2loc_id = new_res

    ########## Step 1: Group diff lines by struct ##########
    diff_line_ind_structs: List[IndType] = group_diff_lines_by_struct_within_file(
        old_locations, old_line_id2loc_id,
        new_locations, new_line_id2loc_id,
        del_line_index2id, add_line_index2id, diff_code_snippet,
        diff_classes_info, diff_funcs_info, diff_classFuncs_info
    )

    ########## Step 2: Group continuous diff lines into the same group and get full diff code of them ##########
    cont_ind_structs: List[ContIndType] = []
    diff_structs: List[DiffType] = []

    for ind_struct in diff_line_ind_structs:
        curr_cont_ind_structs, curr_diff_structs = parse_diff_lines_within_top_struct(
            ind_struct,
            old_content, old_locations, old_line_id2loc_id,
            new_content, new_locations, new_line_id2loc_id,
            del_line_index2id, add_line_index2id, diff_code_snippet
        )

        cont_ind_structs.extend(curr_cont_ind_structs)
        diff_structs.extend(curr_diff_structs)

    return cont_ind_structs, diff_structs
