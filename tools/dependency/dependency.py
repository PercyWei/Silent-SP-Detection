import os
import subprocess
import copy
import json
import sys
import shutil
from typing import *
from typing import Union
from bs4 import BeautifulSoup

from utils.logging import start_with_logger
from utils.commit import checkout_commit, clone_repo
from utils.utils import execute_command, traverse_directory


def find_dot_path(logger) -> str:
    """
        Find the path to the dot executable.
    """
    logger.info(f'>>>> Find the path to the dot executable ...')

    try:
        dot_path = subprocess.check_output(['which', 'dot']).decode().strip()
        logger.info(f'Result: {dot_path}.')
        return dot_path
    except subprocess.CalledProcessError:
        logger.warning(f'Result: failed.')
        return ''


def generate_default_doxygen_config(logger, doxygen_fpath, repo_path) -> bool:
    """
        Generate a default Doxygen configuration file.
    """
    logger.info('>>>> Generating Default Doxygen configuration file ...')
    logger.info(f'>>>> Default Doxygen configuration file path: {doxygen_fpath}.')

    command = ['doxygen', '-g', doxygen_fpath]
    stdout, stderr = execute_command(command, cwd=repo_path)
    if stderr:
        logger.error(">>>> Failed!")
        logger.error(f"Error msg: {stderr}")
        return False
    else:
        logger.info('>>>> Done!')
        return True


def modify_doxygen_config(logger, doxygen_fpath, dot_path, repo_path, output_dpath, out_doxygen_fpath=None):
    """
        Modify the Doxygen configuration file to enable call graphs and set input/output paths.
    """
    logger.info('>>> Modifying Doxygen configuration file ...')
    if out_doxygen_fpath is None:
        out_doxygen_fpath = doxygen_fpath
    logger.info(f'>>> Modified Doxygen configuration file path: {out_doxygen_fpath}.')

    with open(doxygen_fpath, 'r') as file:
        config = file.readlines()

    config = [line.replace('INPUT                  =', f'INPUT                  = {repo_path}')
              .replace('OUTPUT_DIRECTORY       =', f'OUTPUT_DIRECTORY       = {output_dpath}')
              .replace('CALL_GRAPH             = NO', 'CALL_GRAPH             = YES')
              .replace('CALLER_GRAPH           = NO', 'CALLER_GRAPH           = YES')
              .replace('HAVE_DOT               = NO', 'HAVE_DOT               = YES')
              .replace('DOT_CLEANUP            = YES', 'DOT_CLEANUP            = NO')
              .replace('EXTRACT_ALL            = NO', 'EXTRACT_ALL            = YES')
              .replace('EXTRACT_PRIVATE        = NO', 'EXTRACT_PRIVATE        = YES')
              .replace('EXTRACT_STATIC         = NO', 'EXTRACT_STATIC         = YES')
              .replace('RECURSIVE              = NO', 'RECURSIVE              = YES')
              .replace('DOT_PATH               =', f'DOT_PATH               = {dot_path}')
              .replace('DOTFILE_DIRS           =', f'DOTFILE_DIRS           = {output_dpath}')
              for line in config]

    with open(out_doxygen_fpath, 'w') as file:
        file.writelines(config)


def run_doxygen(logger, doxygen_fpath, repo_path) -> bool:
    """
        Run Doxygen to generate the documentation and call graphs.
    """
    logger.info('>>> Running Doxygen ...')

    doxygen_run_command = ['doxygen', doxygen_fpath]
    stdout, stderr = execute_command(doxygen_run_command, cwd=repo_path)

    if stderr:
        logger.error(">>> Failed!")
        logger.error(f"Error msg: {stderr}.")
        return False
    else:
        logger.info(">>> Done!")
        return True


def parse_files_html(logger, files_hpath: str) -> Dict:
    """
        Parse the `files.html` file in html dir and extract the href of all parsed files.

        Args:
        logger:
        files_hpath: Path to the `files.html` file.

        Returns:
            Dict of parsed files info, including file/dir_level, file/dir_name and href.
            {
                "level_id_path":
                {
                    "path": path to the parsed file in repo.
                    "href": path to the html output file of the parsed file.
                }
            }
    """
    logger.info(">> Parsing the `files.html` file ...")

    with open(files_hpath, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')

    contents_div = soup.find('div', class_='contents')
    if not contents_div:
        logger.warning("No contents div found in `files.html`!")
        return {}

    directory_table = contents_div.find('table', class_='directory')
    if not directory_table:
        logger.warning("No directory table found in the contents div of `files.html`!")
        return {}

    # Extract entries info in `files.html` file
    entries_info = []
    for row in directory_table.find_all('tr'):
        row_id = row.get("id")
        levels = []
        for level in row_id.split('_'):
            if level.isdigit():
                levels.append(level)

        entry_td = row.find('td', class_='entry')
        if entry_td:
            link = entry_td.find('a', class_='el')
            if link:
                href = link['href']
                name = link.text
                entries_info.append({
                    "levels": levels,
                    "name": name,
                    "href": href
                })

    # Rearrange the extracted entries info
    update_entries_info = {}
    while len(entries_info) > 0:
        entry_info = entries_info.pop(0)

        levels = entry_info["levels"]
        if len(levels) == 1:
            update_entries_info[levels[0]] = {
                "path": entry_info["name"],
                "href": entry_info["href"]
            }
        else:
            father_level = '_'.join(levels[:-1])
            current_level = '_'.join(levels)
            if father_level in update_entries_info:
                update_entries_info[current_level] = {
                    "path": os.path.join(update_entries_info[father_level]["path"], entry_info["name"]),
                    "href": entry_info["href"]
                }
            else:
                entries_info.append(entry_info)

    return update_entries_info


def struct_files_info(logger, files_info: List[Tuple], repo_dpath: str) -> Dict:
    """
        Traverse the repo dir to get the file structure, and merge it with the doxygen `files_html` info.

        Args:
        logger:
        files_info:
        repo_dpath:

        Returns:
            Repo structure with doxygen info.
    """
    # TODO: need update
    c_suffix_filters = ['.c', '.h']
    cpp_suffix_filters = ['.cpp', '.hpp', '.cxx', '.hxx', '.cc', '.hh', '.c++', '.h++']
    java_suffix_filters = ['.java']
    python_suffix_filters = ['.py']
    js_suffix_filters = ['.js', '.ts']
    php_suffix_filters = ['.php', '.php3', '.php4', '.php5', '.phps', '.phtml']
    suffix_filters = (c_suffix_filters + cpp_suffix_filters + java_suffix_filters +
                      python_suffix_filters + js_suffix_filters + php_suffix_filters)

    repo_structure = traverse_directory(repo_dpath, suffix_filters)
    left_files_info = copy.deepcopy(files_info)

    def find_structure_corresponding_file_info(structure):
        for child_name, child_item in structure.items():
            if "info" in child_item:
                # child is dir
                file_flag = False
                level = child_item["info"]["level"]
                path = child_item['info']['path']
            else:
                # child is file
                file_flag = True
                level = child_item["level"]
                path = child_item['path']

            find_flag = False
            for file_info in left_files_info:
                if len(file_info[0].split('_')) == level:
                    if file_info[1] == child_name:
                        if not file_flag:
                            child_item["info"]["href"] = file_info[2]
                        else:
                            child_item["href"] = file_info[2]
                        find_flag = True
                        left_files_info.remove(file_info)
                        break
            if not find_flag:
                print(f"{path} not found corresponding doxygen out info!")

            if not file_flag:
                assert "children" in child_item
                find_structure_corresponding_file_info(child_item["children"])

    find_structure_corresponding_file_info(repo_structure["children"])
    if len(left_files_info) != 0:
        for file_info in left_files_info:
            print(f"{file_info} not found corresponding structure!")

    # print(json.dumps(repo_structure, indent=4))

    return repo_structure


def parse_file_href_to_extract_file_relations(logger, file_href, output_dpath):
    file_href_hpath = os.path.join(output_dpath, "html", file_href)
    logger.info(">> Parsing file href ...")
    logger.info(f">> File href path: {file_href_hpath}.")

    if not os.path.exists(file_href_hpath):
        logger.warning(f"File href {file_href_hpath} does not exist!")
        return

    with open(file_href_hpath, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')

    contents_div = soup.find('div', class_='contents')
    if not contents_div:
        logger.warning("No contents div found!")
        return

    # TODO: For now, only support .c\.h
    textblock_divs = contents_div.find_all('div', class_='textblock')
    file_name = file_href.split('.')[0]
    logger.info(f"Number of textblock_divs: {len(textblock_divs)}.")
    if len(textblock_divs) == 0 or len(textblock_divs) == 1:
        assert file_name.endswith('_8h')
        assert file_name.endswith('_8h')
    elif len(textblock_divs) == 2:
        assert file_name.endswith('_8h') or file_name.endswith('_8c')
    elif len(textblock_divs) == 3:
        assert file_name.endswith('_8h')
    else:
        assert 1 == 0


def parse_doxygen_html_output(logger, repo_dpath, output_dpath):
    """
        Parse the call graph from the Doxygen html output.
    """
    logger.info(">>> Parsing Doxygen HTML output ...")
    logger.info(f"Doxygen output path: {output_dpath}.")

    # Step 1: parse file `/html/files.html`
    files_hpath = os.path.join(output_dpath, "html", "files.html")
    if not os.path.exists(files_hpath):
        logger.warning('`files.html` not found in Doxygen HTML output!')
        return None

    files_info = parse_files_html(logger, files_hpath)
    if len(files_info) == 0:
        logger.warning("No parsed files info found in `files.html`!")
        return None

    # Step 2:

    return files_info


def test_doxygen_parse_call_graph(logger, repo_dpath, commit_id, save_root):
    checkout_commit(logger, repo_dpath, commit_id, False)

    repo_name = repo_dpath.split('/')[-1]
    output_dpath = os.path.join(save_root, repo_name, commit_id)
    if not os.path.exists(output_dpath):
        os.makedirs(output_dpath, exist_ok=True)

    doxygen_fpath = os.path.join(output_dpath, "Doxyfile")
    dot_path = find_dot_path(logger)

    generate_default_doxygen_config(logger, doxygen_fpath, repo_dpath)
    modify_doxygen_config(logger, doxygen_fpath, dot_path, repo_dpath, output_dpath, doxygen_fpath)
    run_doxygen(logger, doxygen_fpath, repo_dpath)

    # files_info = parse_doxygen_html_output(logger, output_dpath, output_dpath)


def test_textblock_number(logger, dataset_jpath, repos_dpath, save_root):
    """
         Test if the number of textblock_div in href files of .c and .h is <=3, 
         and only =2 for .c.
    """
    with open(dataset_jpath, 'r') as f:
        c = json.load(f)
    all_c_repo_commits = {}
    for repo, repo_item in c.items():
        for commit_id, commit_item in repo_item.items():
            for file_name, item in commit_item.items():
                if file_name != "cve_list" and "PL" in item and item["PL"] == 'C':
                    if repo not in all_c_repo_commits:
                        all_c_repo_commits[repo] = [commit_id]
                    else:
                        all_c_repo_commits[repo].append(commit_id)

    # Default Doxygen setting
    default_oxygen_fpath = os.path.join(save_root, "Doxyfile")
    dot_path = find_dot_path(logger)
    flag = generate_default_doxygen_config(logger, default_oxygen_fpath, repos_dpath)
    if not flag:
        return

    i = 0
    #
    for repo, commits in all_c_repo_commits.items():
        i += 1
        if i > 10:
            break

        logger.info('=' * 100 + f" {i} " + '=' * 100)
        logger.info(f">>> Repo: {repo}")
        repo_name = '_'.join(repo.split('/'))
        repo_dpath = os.path.join(repos_dpath, repo_name)

        # Clone
        rm_flag = False
        if not os.path.exists(repo_dpath):
            logger.info(f"Repo path does not exist!")
            rm_flag = True
            clone_result = clone_repo(logger, repo, repo_dpath)
            if not clone_result:
                _run_rm_command(logger, repo_dpath, repos_dpath)
                continue
        else:
            logger.info(f"Repo path exists.")

        size_mb = get_folder_size(repo_dpath) / (1024 * 1024)
        logger.info(f"Size of repo: {size_mb} MB.")
        if size_mb > 50:
            continue

        #
        for commit_id in commits:
            logger.info('-' * 100)
            logger.info(f">>> Commit ID: {commit_id}.")
            # Checkout
            checkout_commit(logger, repo_dpath, commit_id, False)

            # Doxygen run
            output_dpath = os.path.join(save_root, repo_name, commit_id)
            if not os.path.exists(output_dpath):
                os.makedirs(output_dpath, exist_ok=True)
            current_doxygen_fpath = os.path.join(output_dpath, "Doxyfile")

            modify_doxygen_config(logger, default_oxygen_fpath, dot_path, repo_dpath, output_dpath,
                                  current_doxygen_fpath)
            run_doxygen(logger, current_doxygen_fpath, repo_dpath)

            # Revert state
            logger.info('>> Revert state ...')
            revert_command = ['git', 'checkout', '-']
            stdout, stderr = execute_command(revert_command, cwd=repo_dpath)
            if stderr:
                logger.warning('Failed!')
            else:
                logger.info(f'Done!')

            # Parse Doxygen output
            files_info = parse_doxygen_html_output(logger, repo_dpath, output_dpath)
            if files_info is None:
                continue

            for entry_level, entry_item in files_info.items():
                # TODO: Find all .c and .h file
                if entry_item["path"].endswith('.c') or entry_item["path"].endswith('.h'):
                    logger.info('*' * 50)
                    logger.info(f">> File name: {entry_item['path'].split('/')[-1]}.")
                    parse_file_href_to_extract_file_relations(logger, entry_item['href'], output_dpath)

        # Delete
        if rm_flag:
            _run_rm_command(logger, repo_dpath, repos_dpath)


def _run_rm_command(logger, repo_dpath, repos_dpath):
    logger.info(f">>> Delete repo ...")
    rm_command = ['rm', '-rf', repo_dpath]
    stdout, stderr = execute_command(rm_command, cwd=repos_dpath)

    if stderr:
        logger.warning("Failed!")
        return False
    else:
        logger.info("Done.")
        return True


def get_folder_size(folder_path):
    """计算文件夹大小"""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


if __name__ == '__main__':
    # Test
    # logger, _ = start_with_logger(__name__, log_fname=f"Test_doxygen_parse_call_graph", mode='a')

    # repo_path = "/root/projects/clone_projects/file_file"
    # commit_id = "f97486ef5dc3e8735440edc4fc8808c63e1a3ef0"
    # save_root = "/root/projects/doxygen_output"

    # repo_path = "/root/projects/clone_projects/file_file"
    # commit_id = "f97486ef5dc3e8735440edc4fc8808c63e1a3ef0"
    # save_root = "/root/projects/doxygen_output"
    # test_doxygen_parse_call_graph(logger, repo_path, commit_id, save_root)

    logger, _ = start_with_logger(__name__, log_fname=f"Test_textblock_number_in_doxygen_output", mode='a')

    cve_s_commit_s_file_jpath = './data/TreeVul-valid-cve_s_commit_s_file.json'
    repos_dpath = "/root/projects/clone_projects"
    save_root = "/root/projects/doxygen_output"

    test_textblock_number(logger, cve_s_commit_s_file_jpath, repos_dpath, save_root)
    # for repo in os.listdir(repos_dpath):
    #     repo_dpath = os.path.join(repos_dpath, repo)
    #     size_mb = get_folder_size(repo_dpath) / (1024 * 1024)
    #     print(f"{repo}: {size_mb} MB.")
