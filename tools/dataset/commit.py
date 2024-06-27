import os
import re
import subprocess
from typing import *


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


def extract_commit_content_info(commit_content_save_fpath) -> Dict:
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
        commit_content_save_fpath:

        Returns:
            The info of commit content.
            Dict format:
            {
                "1":           # <section-1>
                {
                    "old_file_path": relative path of the file before commit, "/dev/null" for adding new file.
                    "new_file_path": relative path of the file before commit, "/dev/null" for deleting old file.
                    "file_type": "added" / "removed" / "modified
                    "changed_code_snippets_info":
                    [
                        {      # <hunk-1>
                            "old_file_line_start_idx":
                            "old_file_line_scope":
                            "new_file_line_start_idx":
                            "new_file_line_scope":
                            "changed_code_snippet":
                                [
                                    <code_line_seq_1>
                                    <code_line_seq_2>
                                    ...
                                ]
                        }
                        {...}  # <hunk-2>
                        ...
                    ]
                }
                "2": {...}     # <section-2>
                ...
            }
    """
    with open(commit_content_save_fpath, "r") as f:
        commit_content = [line.rstrip('\n') for line in f.readlines()]

    diff_line_pattern = r"diff --git (.+) (.+)"
    add_file_line_pattern = r"new file mode (\d+)"
    remove_file_line_pattern = r"deleted file mode (\d+)"
    index_line_pattern = r"index (\w+)\.\.(\w+)(?: .*)?$"
    old_fpath_pattern = r"--- (.+)"
    new_fpath_pattern = r"\+\+\+ (.+)"
    line_id_pattern = r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@.*?$"

    # Match the section start line (diff --git xxx xxx)
    changed_file_info_start_list = []
    for idx, line in enumerate(commit_content):
        line = line.rstrip('\n')
        if re.match(diff_line_pattern, line):
            changed_file_info_start_list.append(idx)

    # Extract code change info section-by-section
    commit_content_info = {}
    for i, section_start_line_idx in enumerate(changed_file_info_start_list):
        # Current section start and end line idx
        section_end_line_idx = changed_file_info_start_list[i+1] - 1 \
            if i < len(changed_file_info_start_list) - 1 else -1

        current_line_idx = section_start_line_idx

        # Match the modification pattern of the file:
        # File type: added, removed, modified
        file_type = "modified"
        add_file_flag = False
        remove_file_flag = False
        if re.match(add_file_line_pattern, commit_content[section_start_line_idx+1]):
            add_file_flag = True
            file_type = "added"
            current_line_idx += 1
        if re.match(remove_file_line_pattern, commit_content[section_start_line_idx+1]):
            remove_file_flag = True
            file_type = "removed"
            current_line_idx += 1

        assert add_file_flag and remove_file_flag

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

        if not old_fpath:
            old_fpath = './' + '/'.join(old_fpath.split('/')[1:])
        if not new_fpath:
            new_fpath = './' + '/'.join(new_fpath.split('/')[1:])

        current_changed_file_info = {
            "old_file_path": old_fpath,
            "new_file_path": new_fpath,
            "file_type": file_type,
            "changed_code_snippets_info": []
        }

        assert re.match(line_id_pattern, commit_content[current_line_idx + 1])
        current_line_idx += 1

        # Match the hunk start line (@@ -idx_1,scope_1 +idx_2,scope_2 @@ xxx)
        changed_code_snippet_info_start_list = []
        for idx in range(current_line_idx, section_end_line_idx + 1):
            if re.match(line_id_pattern, commit_content[idx]):
                changed_code_snippet_info_start_list.append(idx)

        # Extract changed code snippet hunk-by-hunk
        for j, hunk_start_line_idx in enumerate(changed_code_snippet_info_start_list):
            # Current section start and end line idx
            hunk_end_line_idx = changed_code_snippet_info_start_list[j+1] - 1 \
                if j < len(changed_code_snippet_info_start_list) - 1 else section_end_line_idx

            # Code snippet loc info before and after commit
            old_file_line_start_idx, old_file_line_scope, new_file_line_start_idx, new_file_line_scope = (
                re.match(line_id_pattern, commit_content[hunk_start_line_idx]).groups())
            # Changed code snippet
            changed_code_snippet = commit_content[hunk_start_line_idx+1: hunk_end_line_idx+1]

            current_changed_code_snippet_info = {
                "old_file_line_start_idx": old_file_line_start_idx,
                "old_file_line_scope": old_file_line_scope,
                "new_file_line_start_idx": new_file_line_start_idx,
                "new_file_line_scope": new_file_line_scope,
                "changed_code_snippet": changed_code_snippet
            }

            current_changed_file_info["changed_code_snippets_info"].append(current_changed_code_snippet_info)

        commit_content_info[f"{i}"] = current_changed_file_info

    return commit_content_info


def process_commit_changed_code_snippet():
    # TODO
    pass
