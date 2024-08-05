import ast
import os
import re
import json
import subprocess
import bisect

from typing import *

from agent_app.static_analysis.parse import (
    LocationType, Location,
    parse_python_file_locations)
from utils import LineRange, same_line_range, run_command


def show_and_save_commit_content(logger, repo_dpath: str, cve_id: str, commit_id: str,
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


def extract_commit_content_info(commit_content: str) -> List:
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
    commit_content = commit_content.splitlines(keepends=False)

    exec_file_suffix = [".c",
                        ".cc",
                        ".java",
                        ".py",
                        ".js",
                        ".php",
                        ".h",
                        ".rb",
                        ".go",
                        ".ts", ".tsx"]

    diff_line_pattern = r"diff --git (.+) (.+)"
    add_file_line_pattern = r"new file mode (\d+)"
    remove_file_line_pattern = r"deleted file mode (\d+)"
    index_line_pattern = r"index (\w+)\.\.(\w+)(?: .*)?$"
    old_fpath_pattern = r"--- (.+)"
    new_fpath_pattern = r"\+\+\+ (.+)"
    line_id_pattern = r"@@ -(\d+),(\d+) \+(\d+),(\d+) (.*)$"

    # Match the section start line (diff --git xxx xxx)
    # diff line id -> (old fpath, new fpath)
    changed_fpath_lines: Dict[int, Tuple[str, str]] = {}
    for idx, line in enumerate(commit_content):
        line = line.rstrip('\n')
        diff_line_match = re.match(diff_line_pattern, line)
        if diff_line_match:
            changed_fpath_lines[idx] = (diff_line_match.group(1), diff_line_match.group(2))

    # Extract code change info section-by-section
    commit_content_info: List[Dict] = []
    for i, section_start_line_idx in enumerate(changed_fpath_lines.keys()):
        # Select only code changes in the executable files
        old_fpath, new_fpath = changed_fpath_lines[section_start_line_idx]
        if not (any(old_fpath.endswith(suf) for suf in exec_file_suffix) and
                any(new_fpath.endswith(suf) for suf in exec_file_suffix)):
            continue

        # Current section start and end line idx
        section_end_line_idx = list(changed_fpath_lines.keys())[i + 1] - 1 \
            if i < len(changed_fpath_lines) - 1 else len(commit_content) - 1

        current_line_idx = section_start_line_idx

        # Match the modification pattern of the file:
        # File type: added, removed, modified
        file_type = "modified"
        add_file_flag = False
        remove_file_flag = False
        if re.match(add_file_line_pattern, commit_content[section_start_line_idx + 1]):
            add_file_flag = True
            file_type = "added"
            current_line_idx += 1
        if re.match(remove_file_line_pattern, commit_content[section_start_line_idx + 1]):
            remove_file_flag = True
            file_type = "removed"
            current_line_idx += 1

        assert not (add_file_flag and remove_file_flag)

        assert re.match(index_line_pattern, commit_content[current_line_idx + 1])
        current_line_idx += 1

        # Match the file path before and after commit
        assert re.match(old_fpath_pattern, commit_content[current_line_idx + 1])
        assert re.match(new_fpath_pattern, commit_content[current_line_idx + 2])

        old_fpath = re.match(old_fpath_pattern, commit_content[current_line_idx + 1]).group(1)
        new_fpath = re.match(new_fpath_pattern, commit_content[current_line_idx + 2]).group(1)
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

        assert re.match(line_id_pattern, commit_content[current_line_idx + 1])
        current_line_idx += 1

        # Match the hunk start line (@@ -idx_1,scope_1 +idx_2,scope_2 @@ xxx)
        diff_code_info_start_list = []
        for idx in range(current_line_idx, section_end_line_idx + 1):
            if re.match(line_id_pattern, commit_content[idx]):
                diff_code_info_start_list.append(idx)

        # Extract changed code snippet hunk-by-hunk
        for j, hunk_start_line_idx in enumerate(diff_code_info_start_list):
            ## Current section start and end line idx
            hunk_end_line_idx = diff_code_info_start_list[j + 1] - 1 \
                if j < len(diff_code_info_start_list) - 1 else section_end_line_idx

            ## Code snippet loc info before and after commit
            old_line_start_idx, old_line_scope, new_line_start_idx, new_line_scope, rest = (
                re.match(line_id_pattern, commit_content[hunk_start_line_idx]).groups())

            ## Structure (class / func / ...)
            struc_name = None
            struc_type = None

            class_pattern = r"@@ class (\w+)"
            class_match = re.match(class_pattern, rest)
            if class_match:
                struc_name = class_match.group(1)
                struc_type = 'class'

            def_pattern = r"@@ def (\w+)"
            def_match = re.match(def_pattern, rest)
            if def_match:
                assert struc_name is None
                struc_name = def_match.group(1)
                struc_type = 'func'

            ## Changed code snippet
            diff_code_snippet = commit_content[hunk_start_line_idx + 1: hunk_end_line_idx + 1]

            ## Delete line (in old file) and add line (in new line) ids
            # (1) changed_code_snippet index
            diff_lines_index: List[int] = []
            # (2) changed_code_snippet index -> (old / new) file line id
            old_diff_lines_index2id: Dict[int, int] = {}
            new_diff_lines_index2id: Dict[int, int] = {}

            cur_old_line_id = int(old_line_start_idx) - 1
            cur_new_line_id = int(new_line_start_idx) - 1
            for k, line in enumerate(diff_code_snippet):
                if line.startswith("+"):
                    cur_new_line_id += 1
                    diff_lines_index.append(k)
                    new_diff_lines_index2id[k] = cur_new_line_id
                elif line.startswith("-"):
                    cur_old_line_id += 1
                    diff_lines_index.append(k)
                    old_diff_lines_index2id[k] = cur_old_line_id
                else:
                    cur_new_line_id += 1
                    cur_old_line_id += 1

            curr_code_diff = {
                "diff_lines_index": diff_lines_index,                # (List, 0-based)
                "old_start_line_id": int(old_line_start_idx),        # (int, 1-based)
                "old_line_scope": int(old_line_scope),               # (int)
                "old_diff_lines_index2id": old_diff_lines_index2id,  # (Dict, key: 0-based, value: 1-based)
                "new_start_line_id": int(new_line_start_idx),        # (int, 1-based)
                "new_line_scope": int(new_line_scope),               # (int)
                "new_diff_lines_index2id": new_diff_lines_index2id,  # (Dict, key: 0-based, value: 1-based)
                "struc_name": struc_name,                            # (str | None)
                "struc_type": struc_type,                            # (str | None)
                "diff_code_snippet": diff_code_snippet               # (List[str])
            }

            curr_diff_file_info["code_diff"].append(curr_code_diff)

        commit_content_info.append(curr_diff_file_info)

    return commit_content_info


def extract_useful_commit_content_info(commit_content: str) -> List:
    """
    Filtering out commits with empty lines before and after a change.
    like:
        1.
        before:
            -
            +
        after:
            <delete>
        2.
        before:
            -
            - xx
            +
            + xxx
        after:
            - xx
            + xxx
    """

    def is_blank(_line: str) -> bool:
        if _line.strip() == '':
            return True
        else:
            return False

    filter_commit_content_info = []
    commit_content_info = extract_commit_content_info(commit_content)
    for changed_file_content in commit_content_info:
        if changed_file_content["file_type"] == "modified":
            hunks = changed_file_content["changed_code_snippets_info"]
            hunk_retain_flags: List[bool] = [False] * len(hunks)

            for i, hunk_info in enumerate(hunks):
                hunk = hunk_info["changed_code_snippet"]

                # TODO: We will delete all empty change lines in a hunk
                # Find all changed lines ('+ xxx' or '- xxx')
                changed_lines: Dict[int, str] = {}
                for j, line in enumerate(hunk):
                    if line.startswith("+") or line.startswith("-"):
                        changed_lines[j] = line

                # Separate non-black changed lines and black changed lines
                retain_changed_lines: Dict[int, str] = {}
                del_changed_lines_id = []
                for line_id, line in changed_lines.items():
                    if not is_blank(line[1:]):
                        retain_changed_lines[line_id] = line
                    else:
                        del_changed_lines_id.append(line_id)

                # Retain the hunk which has > 0 non-black changed lines
                if len(retain_changed_lines) > 0:
                    hunk_retain_flags[i] = True

                    # FIXME: We only change "changed_code_snippet" attr about this hunk,
                    #  other attrs ('old_file_line_start_idx', 'old_file_line_scope',
                    #  'new_file_line_start_idx', 'new_file_line_scope') should change together
                    # Retain only the code within three lines above and below the earliest and latest non-blank change lines
                    min_changed_line_id = min(retain_changed_lines.keys())
                    max_changed_line_id = max(retain_changed_lines.keys())

                    new_hunk_start = ori_hunk_start = max(0, min_changed_line_id - 3)
                    new_hunk_end = ori_hunk_end = min(len(hunk) - 1, max_changed_line_id + 3)

                    if ori_hunk_start != 0:
                        add_num = 0
                        for line_id in del_changed_lines_id:
                            if ori_hunk_start <= line_id < min_changed_line_id:
                                add_num += 1
                        new_hunk_start = max(0, ori_hunk_start - add_num)

                    if ori_hunk_end != len(hunk) - 1:
                        add_num = 0
                        for line_id in del_changed_lines_id:
                            if max_changed_line_id < line_id <= ori_hunk_end:
                                add_num += 1
                        new_hunk_end = min(len(hunk) - 1, ori_hunk_end + add_num)

                    new_hunk: List[str] = []
                    for line_id, line in enumerate(hunk):
                        if new_hunk_start <= line_id <= new_hunk_end and line_id not in del_changed_lines_id:
                            new_hunk.append(line)

                    hunk_info["changed_code_snippet"] = new_hunk

            retain_hunks = []
            for flag, hunk in zip(hunk_retain_flags, hunks):
                if flag:
                    retain_hunks.append(hunk)

            if len(retain_hunks) > 0:
                changed_file_content["changed_code_snippets_info"] = retain_hunks
            else:
                continue

        filter_commit_content_info.append(changed_file_content)

    return filter_commit_content_info


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
        old_content: List[str], old_diff_line_ids: List[int], old_struct_range: LineRange,
        new_content: List[str], new_diff_line_ids: List[int], new_struct_range: LineRange
) -> bool:
    old_struct_line_ids = list(range(old_struct_range.start, old_struct_range.end + 1))
    old_rest_line_ids = sorted(list(set(old_struct_line_ids) - set(old_diff_line_ids)))

    new_struct_line_ids = list(range(new_struct_range.start, new_struct_range.end + 1))
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


def classify_diff_struct(
        old_content: List[str], old_diff_line_ids: List[int], old_structs: Dict[str, LineRange],
        new_content: List[str], new_diff_line_ids: List[int], new_structs: Dict[str, LineRange]
) -> Tuple[Dict, Dict, List]:
    """
    Classify the types (delete, add, modify) of diff structs (class or function).
    """
    ## (1) Delete structs
    del_structs: Dict[str, LineRange] = {}
    ## (2) Delete structs
    add_structs: Dict[str, LineRange] = {}
    ## (3) modified structs (three types: a. delete + add; b. delete only; c. add only)
    mod_structs: List[List[Tuple[str, LineRange]]] = []

    old_mod_structs: Dict[str, LineRange] = {}
    new_mod_structs: Dict[str, LineRange] = {}

    # (1) Select del_structs and old_mod_structs from structs in old file (old_structs)
    for struct_name, struct_range in old_structs.items():
        range_line_ids = list(range(struct_range.start, struct_range.end + 1))
        if is_subset(range_line_ids, old_diff_line_ids):
            del_structs[struct_name] = struct_range
        elif has_same_elements(range_line_ids, old_diff_line_ids):
            old_mod_structs[struct_name] = struct_range

    # (2) Select add_structs and new_mod_structs from structs in new file (new_structs)
    for struct_name, struct_range in new_structs.items():
        range_line_ids = list(range(struct_range.start, struct_range.end + 1))
        if is_subset(range_line_ids, new_diff_line_ids):
            add_structs[struct_name] = struct_range
        elif has_same_elements(range_line_ids, new_diff_line_ids):
            new_mod_structs[struct_name] = struct_range

    # (3) Match items in old_mod_structs and new_mod_structs to construct mod_structs
    old_mod_struct_list = list(old_mod_structs.items())
    new_mod_struct_list = list(new_mod_structs.items())
    while old_mod_struct_list:
        old_name, old_range = old_mod_struct_list.pop(0)
        match = False

        i = 0
        while i < len(new_mod_struct_list):
            new_name, new_range = new_mod_struct_list[i]

            if is_modified_struct(
                    old_content, old_diff_line_ids, old_range,
                    new_content, new_diff_line_ids, new_range):
                # 1) Structure modified with both delete and add
                mod_structs.append(
                    [
                        (old_name, old_range),
                        (new_name, new_range)
                    ]
                )
                new_mod_struct_list.pop(i)
                match = True
                break

            i += 1

        if not match:
            # 2) Structure modified with delete only
            new_range = new_structs[old_name]
            mod_structs.append(
                [
                    (old_name, old_range),
                    (old_name, new_range)
                ]
            )

    if new_mod_struct_list:
        # 3) Structure modified with add only
        for new_name, new_range in new_mod_struct_list:
            old_range = old_structs[new_name]
            mod_structs.append(
                [
                    (new_name, old_range),
                    (new_name, new_range)
                ]
            )

    return del_structs, add_structs, mod_structs


def classify_diff_asyncFunc(
        old_content: List[str], old_diff_line_ids: List[int], old_asyncFuncs: Dict[str, LineRange],
        new_content: List[str], new_diff_line_ids: List[int], new_asyncFuncs: Dict[str, LineRange]
) -> Tuple[Dict, Dict, List]:
    """
    Classify the types (delete, add, modify) of diff async functions.
    Since adding "@<start>" to the async funcs name, it is possible that
    names of not renamed async functions may be different between old_asyncFuncs and new_asyncFuncs.
    """
    ## (1) Delete asyncFuncs
    del_asyncFuncs: Dict[str, LineRange] = {}
    ## (2) Delete asyncFuncs
    add_asyncFuncs: Dict[str, LineRange] = {}
    ## (3) Three types of modified asyncFuncs (three types: a. delete + add; b. delete only; c. add only)
    mod_asyncFuncs: List[List[Tuple[str, LineRange]]] = []

    old_mod_asyncFuncs: Dict[str, LineRange] = {}
    new_mod_asyncFuncs: Dict[str, LineRange] = {}

    # (1) Select del_asyncFuncs and old_mod_asyncFuncs from asyncFuncs in old file (old_asyncFuncs)
    for asyncFunc_name, asyncFunc_range in old_asyncFuncs.items():
        range_line_ids = list(range(asyncFunc_range.start, asyncFunc_range.end + 1))
        if is_subset(range_line_ids, old_diff_line_ids):
            del_asyncFuncs[asyncFunc_name] = asyncFunc_range
        elif has_same_elements(range_line_ids, old_diff_line_ids):
            old_mod_asyncFuncs[asyncFunc_name] = asyncFunc_range

    # (2) Select add_asyncFuncs and new_mod_asyncFuncs from asyncFuncs in new file (new_asyncFuncs)
    for asyncFunc_name, asyncFunc_range in new_asyncFuncs.items():
        range_line_ids = list(range(asyncFunc_range.start, asyncFunc_range.end + 1))
        if is_subset(range_line_ids, new_diff_line_ids):
            add_asyncFuncs[asyncFunc_name] = asyncFunc_range
        elif has_same_elements(range_line_ids, new_diff_line_ids):
            new_mod_asyncFuncs[asyncFunc_name] = asyncFunc_range

    # (3) Match items in old_mod_asyncFuncs and new_mod_asyncFuncs to construct mod_asyncFuncs
    def build_ref_from_ori_name_to_now_names(asyncFuncs: Dict[str, LineRange]) -> Dict[str, List[str]]:
        """Build a dictionary that maps async function original names (like "xxx") to now names(like "xxx@num")."""
        ori_name2no_names: Dict[str, List[str]] = {}
        for _now_name in asyncFuncs.keys():
            _ori_name = _now_name.split("@")[0]
            if _ori_name not in ori_name2no_names:
                ori_name2no_names[_ori_name] = []
            ori_name2no_names[_ori_name].append(_now_name)

        return ori_name2no_names

    old_ori_name2no_names: Dict[str, List[str]] = build_ref_from_ori_name_to_now_names(old_asyncFuncs)
    new_ori_name2no_names: Dict[str, List[str]] = build_ref_from_ori_name_to_now_names(new_asyncFuncs)

    old_mod_asyncFunc_list = list(old_mod_asyncFuncs.items())
    new_mod_asyncFunc_list = list(new_mod_asyncFuncs.items())
    while old_mod_asyncFunc_list:
        old_name, old_range = old_mod_asyncFunc_list.pop(0)
        match = False

        i = 0
        while i < len(new_mod_asyncFunc_list):
            new_name, new_range = new_mod_asyncFunc_list[i]

            if is_modified_struct(
                    old_content, old_diff_line_ids, old_range,
                    new_content, new_diff_line_ids, new_range):
                # 1) asyncFunc modified with both delete and add
                mod_asyncFuncs.append(
                    [
                        (old_name, old_range),
                        (new_name, new_range)
                    ]
                )
                new_mod_asyncFunc_list.pop(i)
                match = True
                break

            i += 1

        if not match:
            # 2) asyncFunc modified with delete only
            # NOTE: Can not use old_name directly
            # Find new name after change first
            ori_name = old_name.split("@")[0]
            old_name_start = int(old_name.split("@")[1])
            del_lines = bisect.bisect_left(old_diff_line_ids, old_name_start)

            if len(new_ori_name2no_names[ori_name]) == 1:
                new_name = new_ori_name2no_names[ori_name][0]
            else:
                new_name = None
                for no_name in new_ori_name2no_names[ori_name]:
                    no_name_start = int(no_name.split("@")[1])
                    add_lines = bisect.bisect_left(new_diff_line_ids, no_name_start)

                    if old_name_start - del_lines + add_lines == no_name_start:
                        new_name = no_name
                        break

                assert new_name is not None

            new_range = new_asyncFuncs[new_name]
            mod_asyncFuncs.append(
                [
                    (old_name, old_range),
                    (new_name, new_range)
                ]
            )

    if new_mod_asyncFunc_list:
        # 3) asyncFunc modified with add only
        for new_name, new_range in new_mod_asyncFunc_list:
            # NOTE: Can not use new_name directly
            # Find old name after change first
            ori_name = new_name.split("@")[0]
            new_name_start = int(new_name.split("@")[1])
            add_lines = bisect.bisect_left(new_diff_line_ids, new_name_start)

            if len(old_ori_name2no_names[ori_name]) == 1:
                old_name = old_ori_name2no_names[ori_name][0]
            else:
                old_name = None
                for no_name in old_ori_name2no_names[ori_name]:
                    no_name_start = int(no_name.split("@")[1])
                    del_lines = bisect.bisect_left(old_diff_line_ids, no_name_start)

                    if no_name_start - del_lines + add_lines == new_name_start:
                        old_name = no_name
                        break

                assert old_name is not None

            old_range = old_asyncFuncs[old_name]
            mod_asyncFuncs.append(
                [
                    (old_name, old_range),
                    (new_name, new_range)
                ]
            )

    return del_asyncFuncs, add_asyncFuncs, mod_asyncFuncs


def analyse_diff_structs_within_file(
        old_content: List[str], old_location_parse_res: Tuple[Dict, Dict, Dict, List[Location], List[int], ast.Module],
        new_content: List[str], new_location_parse_res: Tuple[Dict, Dict, Dict, List[Location], List[int], ast.Module],
        diff_file_info: Dict
) -> Tuple[Dict, Dict, Dict]:
    """
    Struct includes class, functions and async functions.

    Args:
        old_content: File content before applying the commit, split into list.
        old_location_parse_res: Result from `agent_app.static_analysis.parse.parse_python_file_locations`
        new_content: File content after applying the commit, split into list.
        new_location_parse_res: Result from `agent_app.static_analysis.parse.parse_python_file_locations`
        diff_file_info:

    Returns:
        Dict: Diff classes info.
        Dict: Diff functions info.
        Dict: Diff async functions info.
    """
    old_classes, old_funcs, old_asyncFuncs, *_ = old_location_parse_res
    new_classes, new_funcs, new_asyncFuncs, *_ = new_location_parse_res

    old_diff_line_ids = []
    new_diff_line_ids = []
    for diff_code_info in diff_file_info["code_diff"]:
        curr_diff_lines_index = diff_code_info["diff_lines_index"]
        curr_old_diff_lines_index2id = diff_code_info["old_diff_lines_index2id"]
        curr_new_diff_lines_index2id = diff_code_info["new_diff_lines_index2id"]

        for diff_ind in curr_diff_lines_index:
            if diff_ind in curr_old_diff_lines_index2id:
                old_diff_line_ids.append(curr_old_diff_lines_index2id[diff_ind])
            elif diff_ind in curr_new_diff_lines_index2id:
                new_diff_line_ids.append(curr_new_diff_lines_index2id[diff_ind])
            else:
                raise RuntimeError

    # (1) Distinguish the types of class modifications
    del_classes, add_classes, mod_classes = classify_diff_struct(
        old_content, old_diff_line_ids, old_classes, new_content, new_diff_line_ids, new_classes
    )

    # (2) Distinguish the types of function modifications
    del_funcs, add_funcs, mod_funcs = classify_diff_struct(
        old_content, old_diff_line_ids, old_funcs, new_content, new_diff_line_ids, new_funcs
    )

    # (3) Distinguish the types of async function modifications
    del_asyncFuncs, add_asyncFuncs, mod_asyncFuncs = classify_diff_asyncFunc(
        old_content, old_diff_line_ids, old_asyncFuncs, new_content, new_diff_line_ids, new_asyncFuncs
    )

    diff_classes_info = {
        "del_classes": del_classes,
        "add_classes": add_classes,
        "mod_classes": mod_classes
    }

    diff_funcs_info = {
        "del_funcs": del_funcs,
        "add_funcs": add_funcs,
        "mod_funcs": mod_funcs
    }

    diff_asyncFuncs_info = {
        "del_asyncFuncs": del_asyncFuncs,
        "add_asyncFuncs": add_asyncFuncs,
        "mod_asyncFuncs": mod_asyncFuncs
    }

    return diff_classes_info, diff_funcs_info, diff_asyncFuncs_info


# def in_struct(structs: Dict[str, LineRange], line_id: int) -> Tuple[str, LineRange] | None:
#     for name, line_range in structs.items():
#         if line_range.start <= line_id <= line_range.end:
#             return name, line_range
#     return None
#
#
# def get_diff_structs(
#         file_structs: Dict[str, LineRange],
#         diff_line_ids: List[int]
# ) -> Dict[Tuple[str, LineRange], List[int]]:
#     diff_structs: Dict[Tuple[str, LineRange], List[int]] = {}
#
#     for diff_line_id in diff_line_ids:
#         res = in_struct(file_structs, diff_line_id)
#
#         if res is not None:
#             struct_name, struct_range = res
#
#             key = (struct_name, struct_range)
#             if key not in diff_structs:
#                 diff_structs[key] = []
#             diff_structs[key].append(diff_line_id)
#
#     return diff_structs


def analyse_diff_within_file(
        old_file_content: str, new_file_content: str, diff_file_info: Dict
) -> Tuple[List[int], Dict[int, int], Dict[int, int], List[str], List[Tuple[str, str, List[int]]]] | None:
    old_content: List[str] = old_file_content.splitlines(keepends=True)
    new_content: List[str] = new_file_content.splitlines(keepends=True)

    old_res = parse_python_file_locations(old_file_content)
    new_res = parse_python_file_locations(new_file_content)

    if old_res is None or new_res is None:
        # AST parsing failed
        return None

    diff_classes_info, diff_funcs_info, diff_asyncFuncs_info = \
        analyse_diff_structs_within_file(old_content, old_res, new_content, new_res, diff_file_info)

    _, _, _, old_locations, old_refs, _ = old_res
    _, _, _, new_locations, new_refs, _ = new_res

    all_diff_lines_index: List[int] = []              # 0-based
    all_old_diff_lines_index2id: Dict[int, int] = {}  # 0-based -> 1-based
    all_new_diff_lines_index2id: Dict[int, int] = {}  # 0-based -> 1-based
    all_diff_code_snippet: List[str] = []
    for diff_code_info in diff_file_info["code_diff"]:
        prev_len = len(all_diff_code_snippet)
        # A. All diff (delete, add) code lines index (to `all_diff_code_snippet`)
        curr_diff_lines_index = [ind + prev_len for ind in diff_code_info["diff_lines_index"]]
        all_diff_lines_index.extend(curr_diff_lines_index)

        # B. Lookup dict for all deleted code lines index (to `all_diff_code_snippet`) to id
        curr_old_diff_lines_index2id = {ind + prev_len: id
                                        for ind, id in diff_code_info["old_diff_lines_index2id"].items()}
        all_old_diff_lines_index2id.update(curr_old_diff_lines_index2id)

        # C. Lookup dict for all added code lines index (to `all_diff_code_snippet`) to id
        curr_new_diff_lines_index2id = {ind + prev_len: id
                                        for ind, id in diff_code_info["new_diff_lines_index2id"].items()}
        all_new_diff_lines_index2id.update(curr_new_diff_lines_index2id)

        # D. All code snippets containing diff code lines within this file
        all_diff_code_snippet.extend(diff_code_info["diff_code_snippet"])


    all_diff_lines_index_groups: List[Tuple[str, List[int]]] = []

    last_line_loc: Location | None = None
    last_line_file_type: str | None = None
    last_diff_lines_index_group: Tuple[str, List[int]] | None = None

    def _in_same_struct(loc_type: str,
                        del_structs: Dict[str, LineRange],
                        add_structs: Dict[str, LineRange],
                        mod_structs: List[List[Tuple[str, LineRange]]]) -> bool:
        same_struct: bool = False

        # Get struct name and range where last line in
        last_struct_name = last_line_loc.name
        if loc_type == LocationType.ASYNCFUNCTION:
            last_struct_name += f"@{last_line_loc.start}"
        last_struct_range = LineRange(last_line_loc.start, last_line_loc.end)

        # Get struct name and range where current line in
        cur_struct_name = cur_line_loc.name
        if loc_type == LocationType.ASYNCFUNCTION:
            cur_struct_name += f"@{cur_line_loc.start}"
        cur_struct_range = LineRange(cur_line_loc.start, cur_line_loc.end)

        ####################### CASE 1 #######################
        # Last line and current line are in the same file (old / new)
        # Only need to compare the name and range of the class they are in
        if last_line_file_type == cur_line_file_type:
            if last_struct_name == cur_struct_name and same_line_range(last_struct_range, cur_struct_range):
                # In the same struct, thus in the same group
                same_struct = True
            else:
                # In the different structs, thus in the different groups
                same_struct = False

        ####################### CASE 2 #######################
        elif last_line_file_type == "old":
            # Last line is in the old file, i.e. a deleted line
            # Current line is in the new file, i.e. an added line
            if last_struct_name in del_structs:
                # Deleted struct cannot have an added line, thus in the different groups
                same_struct = False
            elif last_struct_name in add_structs:
                # Deleted line (last line) cannot be in an added struct, thus ERROR!
                raise RuntimeError
            else:
                last_struct_pair = None
                for mod_struct_pair in mod_structs:
                    if last_struct_name == mod_struct_pair[0][0] and \
                            same_line_range(last_struct_range, mod_struct_pair[0][1]):
                        last_struct_pair = mod_struct_pair
                        break

                assert last_struct_pair is not None, \
                    f"OLD - {last_struct_name}: {last_struct_range.start}-{last_struct_range.end}"

                if cur_struct_name != last_struct_pair[1][0] or \
                        not same_line_range(cur_struct_range, last_struct_pair[1][1]):
                    # Current added line is not in the same class as the last deleted line, thus in the different groups
                    same_struct = False
                else:
                    same_struct = True

        ####################### CASE 3 #######################
        elif last_line_file_type == "new":
            # Last line is in the new file, i.e. an added line
            # Current line is in the old file, i.e. a deleted line
            if last_struct_name in del_structs:
                # Added line (last line) cannot be in a deleted struct, thus ERROR!
                raise RuntimeError
            elif last_struct_name in add_structs:
                # Added struct cannot have a deleted line, thus in the different groups
                same_struct = False
            else:
                last_struct_pair = None
                for mod_struct_pair in mod_structs:
                    if last_struct_name == mod_struct_pair[1][0] and \
                            same_line_range(last_struct_range, mod_struct_pair[1][1]):
                        last_struct_pair = mod_struct_pair
                        break

                assert last_struct_pair is not None, \
                    f"NEW - {last_struct_name}: {last_struct_range.start}-{last_struct_range.end}"

                if cur_struct_name != last_struct_pair[0][0] or \
                        not same_line_range(cur_struct_range, last_struct_pair[0][1]):
                    # Current deleted line is not in the same class as the last added line, thus in the different groups
                    same_struct = False
                else:
                    same_struct = True

        return same_struct

    # Group all diff line indexes (to the all_diff_code_snippet)
    for diff_line_ind in all_diff_lines_index:
        # (1) Find basic info of current line:
        # - cur_line_loc
        # - cur_line_file_type
        if diff_line_ind in all_old_diff_lines_index2id:
            cur_line_file_type = "old"

            cur_line_id = all_old_diff_lines_index2id[diff_line_ind]
            cur_line_loc_ind = old_refs[cur_line_id-1]
            cur_line_loc = old_locations[cur_line_loc_ind]
        elif diff_line_ind in all_new_diff_lines_index2id:
            cur_line_file_type = "new"

            cur_line_id = all_new_diff_lines_index2id[diff_line_ind]
            cur_line_loc_ind = new_refs[cur_line_id-1]
            cur_line_loc = new_locations[cur_line_loc_ind]
        else:
            raise RuntimeError

        # (2) Determine if current line and last line are in the same group
        if last_line_loc is None:
            # Beginning
            last_diff_lines_index_group = (cur_line_loc.type, [diff_line_ind])
            last_line_loc = cur_line_loc
            last_line_file_type = cur_line_file_type
            continue

        if last_line_loc.type != cur_line_loc.type:
            new_group_flag = True
        elif last_line_loc.type == LocationType.CLASS:
            new_group_flag = not _in_same_struct(LocationType.CLASS,
                                                 diff_classes_info["del_classes"],
                                                 diff_classes_info["add_classes"],
                                                 diff_classes_info["mod_classes"])
        elif last_line_loc.type == LocationType.FUNCTION:
            new_group_flag = not _in_same_struct(LocationType.FUNCTION,
                                                 diff_funcs_info["del_funcs"],
                                                 diff_funcs_info["add_funcs"],
                                                 diff_funcs_info["mod_funcs"])
        elif last_line_loc.type == LocationType.ASYNCFUNCTION:
            new_group_flag = not _in_same_struct(LocationType.ASYNCFUNCTION,
                                                 diff_asyncFuncs_info["del_asyncFuncs"],
                                                 diff_asyncFuncs_info["add_asyncFuncs"],
                                                 diff_asyncFuncs_info["mod_asyncFuncs"])
        else:
            # last_line_loc.type == LocationType.GLOBAL or LocationType.BLANK
            new_group_flag = False

        # (3) Update current group and all groups
        # - last_line_loc
        # - last_line_file_type
        if new_group_flag:
            # Step 1: Add the last group to the groups
            assert last_diff_lines_index_group is not None
            all_diff_lines_index_groups.append(last_diff_lines_index_group)
            # Step 2: Open a new group
            last_diff_lines_index_group = (cur_line_loc.type, [diff_line_ind])
            last_line_loc = cur_line_loc
            last_line_file_type = cur_line_file_type
        else:
            last_diff_lines_index_group[1].append(diff_line_ind)
            last_line_loc = cur_line_loc
            last_line_file_type = cur_line_file_type

    if last_diff_lines_index_group is not None:
        all_diff_lines_index_groups.append(last_diff_lines_index_group)

    ## Clean
    # (1) Filter BLANK groups which only contain blank lines
    # (2) Filter blank lines in CLASS / FUNCTION / ASYNCFUNCTION / GLOBAL groups
    # (3) Split discontinuous lines in the same GLOBAL group into different groups
    def is_blank_line(li: str):
        return li[1:].strip() == ""

    updt_diff_lines_index_groups: List[Tuple[str, str, List[int]]] = []
    for group_name, line_indexes in all_diff_lines_index_groups:
        if group_name == LocationType.GLOBAL:
            # Decompose into subgroups
            sub_groups: List[Tuple[str, str, List[int]]] = []
            cur_sub_group: List[int] | None = None

            for ind in line_indexes:
                if cur_sub_group is None:
                    cur_sub_group = [ind]
                    continue

                assert len(cur_sub_group) > 0

                if ind == cur_sub_group[-1] + 1:
                    cur_sub_group.append(ind)
                else:
                    sub_groups.append((group_name, "", cur_sub_group))
                    cur_sub_group = [ind]

            if len(cur_sub_group) > 0:
                sub_groups.append((group_name, "", cur_sub_group))

            updt_diff_lines_index_groups.extend(sub_groups)

        elif group_name != LocationType.BLANK:
            # Filter blank lines
            updt_line_indexes: List[int] = []
            for ind in line_indexes:
                if not is_blank_line(all_diff_code_snippet[ind]):
                    updt_line_indexes.append(ind)

            if len(updt_line_indexes) > 0:
                line_ind = updt_line_indexes[0]
                if line_ind in all_old_diff_lines_index2id:
                    line_id = all_old_diff_lines_index2id[line_ind]
                    loc_ind = old_refs[line_id-1]
                    struct_name = old_locations[loc_ind].name
                elif line_ind in all_new_diff_lines_index2id:
                    line_id = all_new_diff_lines_index2id[line_ind]
                    loc_ind = new_refs[line_id-1]
                    struct_name = new_locations[loc_ind].name
                else:
                    raise RuntimeError

                if group_name == LocationType.ASYNCFUNCTION:
                    struct_name = struct_name.split("@")[0]

                updt_diff_lines_index_groups.append((group_name, struct_name, updt_line_indexes))

    return (all_diff_lines_index, all_old_diff_lines_index2id, all_new_diff_lines_index2id,
            all_diff_code_snippet, updt_diff_lines_index_groups)


def prepare_commit_file_info_seq(old_file_content: str, new_file_content: str, diff_file_info: Dict) -> str:

    _, _, _, diff_code_snippet, diff_lines_index_groups = analyse_diff_within_file(old_file_content, new_file_content, diff_file_info)

    file_seq = ""
    for group_name, struct_name, line_indexes in diff_lines_index_groups:
        group_seq = ""

        last_ind: int | None = None
        for ind in line_indexes:
            if last_ind is not None and ind != last_ind + 1:
                group_seq += "...\n"
            group_seq += diff_code_snippet[ind] + "\n"
            last_ind = ind

        if group_name == LocationType.GLOBAL:
            prefix = ""
        elif group_name == LocationType.CLASS:
            prefix = f"<class>{struct_name}</class>"
        elif group_name == LocationType.FUNCTION or group_name == LocationType.ASYNCFUNCTION:
            prefix = f"<func>{struct_name}</func>"
        else:
            raise RuntimeError

        file_seq += f"{prefix}\n<code>\n{group_seq}</code>\n\n"

    return file_seq



