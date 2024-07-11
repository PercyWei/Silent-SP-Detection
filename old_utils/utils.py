import os
import re
import shutil
import subprocess
from typing import *


def execute_command(command: List[str], **run_params) -> Tuple:
    """
    Helper function to execute a command and return the result.

    Args:
        command : The command to execute.
        run_params: Params to pass to the `subprocess.run`.
    Returns:
        1. stdout (str): The stdout of the command, `None` if the command failed.
        2. stderr (str): The stderr of the command, `None` if the command succeed.
    """
    try:
        result = subprocess.run(command, check=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, **run_params)
        return result.stdout.strip(), None
    except subprocess.CalledProcessError as e:
        return None, e.output.strip()
    except Exception as e:
        return None, str(e)


def test_execute_command(token: str = ''):
    # repo_dpath = "/root/projects/clone_projects/Exiv2_exiv2"
    # commit_id = "eff0f52d0466d81beabf304e2500f3039fd90252"
    # repo_dpath = "/root/projects/clone_projects/radare_radare2"
    # commit_id = "9b46d38dd3c4de6048a488b655c7319f845af185"

    repo_url = f"https://{token}@github.com/onedotprojects/cdn.git"
    repo_dpath = "/root/projects/clone_projects/test_repo"

    clone_command = ["git", "clone", repo_url, repo_dpath]

    stdout, stderr = execute_command(clone_command, timeout=600)
    print(f"stdout: {stdout}")
    print(f"stderr: {stderr}")


def traverse_directory(root_dir, suffix_filters: Optional[List] = None) -> Dict:
    """
        Traverse the specified dir and its sub_dir, return its internal structure.

        Args:
        root_dir:
        file_extensions: List containing suffixes for filtering file, ['.py', '.txt'] for example.

        Returns:
             Dict containing dir structure.
    """

    def _traverse(current_dir, level: int = 0):
        structure = {
            "info":
                {
                    "level": level,
                    "path": os.path.relpath(current_dir, root_dir)
                },
            "children": {}
        }

        entries = os.listdir(current_dir)
        for entry in entries:
            entry_path = os.path.join(current_dir, entry)
            if os.path.isdir(entry_path):
                sub_structure = _traverse(entry_path, level + 1)
                if sub_structure["children"]:
                    structure["children"][entry] = sub_structure
            elif os.path.isfile(entry_path):
                file_info = {
                            "level": level + 1,
                            "path": os.path.relpath(entry_path, root_dir)
                        }

                if suffix_filters:
                    if any(entry.endswith(suffix) for suffix in suffix_filters):
                        structure["children"][entry] = file_info
                else:
                    structure["children"][entry] = file_info

        return structure

    dir_structure = _traverse(root_dir)
    return dir_structure


def set_value_in_dict(d: Dict, keys: List, value: Any):
    """
        Modify the value of a key in a deep dictionary

        Args:
            d:
            keys:
            value:
    """
    if len(keys) == 1:
        d[keys[0]] = value
    else:
        assert keys[0] in d, f"Current sub-dict: {d}, key not found: {keys[0]}."
        set_value_in_dict(d[keys[0]], keys[1:], value)


if __name__ == '__main__':
    test_execute_command()
