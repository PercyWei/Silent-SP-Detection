from agent_app.data_structures import LineRange, CodeSnippetLocation
from utils import run_command
def get_code_before_commit(local_repo_dpath: str, commit_hash: str, rel_fpath: str, parent_id: int = 1) -> str | None:
        parent_id (int): ID of the parent comment.
    git_show_cmd = ['git', 'show', f'{commit_hash}^{parent_id}:{rel_fpath}']
    diff_line_pattern = r"diff --git (.+) (.+)"               # must exist
    add_file_line_pattern = r"new file mode (\d+)"            # may exist
    remove_file_line_pattern = r"deleted file mode (\d+)"     # may exist
    index_line_pattern = r"index (\w+)\.\.(\w+)(?: .*)?$"     # must exist
    old_fpath_pattern = r"--- (.+)"                           # may exist
    new_fpath_pattern = r"\+\+\+ (.+)"                        # may exist
    line_id_pattern = r"@@ -(\d+),(\d+) \+(\d+),(\d+) (.*)$"  # may exist
        # TODO: Only extract commit content related to Python code.
        # ----------------- format: new file mode <index> / deleted file mode <index> ------------------ #
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
        if current_line_idx > section_end_line_idx:
            # TODO: When adding or removing an empty file, there is no subsequent content.
            # ex: https://github.com/cobbler/cobbler/commit/d8f60bbf14a838c8c8a1dba98086b223e35fe70a
            #     tests/actions/__init__.py
            continue

        # ----------------- format: diff --git <file_path_1> <file_path_2> ----------------- #
        # ----------------- format: @@ -<idx_1>,<scope_1> +<idx_2>,<scope_2> @@ xxx ----------------- #
        # ----------------- Extract changed code snippet of each hunk ----------------- #
    if nb_file_diff_lines and nb_file_diff_lines[-1].sep:
            # assert old_file_lines[cur_old_line_id - 1] == new_file_lines[cur_new_line_id - 1]
            if old_file_lines[cur_old_line_id - 1] != new_file_lines[cur_new_line_id - 1]:
                print("ok")
) -> Tuple[CombineInfo | None, List[DiffCodeSnippet], List[Tuple[str, LineRange]], List[Tuple[str, LineRange]], List[Tuple[str, List[Tuple[str, LineRange]]]]]:
    if nb_diff_lines:
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
    else:
        return None, [], [], [], []