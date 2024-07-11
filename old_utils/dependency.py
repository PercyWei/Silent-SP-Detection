import os
from typing import *


def build_project_structure(project_root_dpath: str):
    project_structure = {}
    for root, dirs, files in os.walk(project_root_dpath):
        relative_path = os.path.relpath(root, project_root_dpath)
        if relative_path == ".":
            current_level = project_structure
        else:
            parts = relative_path.split(os.sep)
            current_level = project_structure
            for part in parts:
                if part not in current_level:
                    current_level[part] = {}
                current_level = current_level[part]

        for d in dirs:
            current_level[d] = {}
        for f in files:
            current_level[f] = None
    return project_structure


def traversal_proj_struct_find_spec_file_extension_files(current_root: Dict, current_path: Optional[List],
                                                         file_extension: str) -> List:
    assert current_root is not None

    file_paths = []
    for current, children in current_root.items():
        current_entry_path = current_path + [current]
        if children is None:
            if current.endswith(file_extension):
                file_paths.append(current_entry_path)
        else:
            file_paths.extend(
                traversal_proj_struct_find_spec_file_extension_files(children, current_entry_path, file_extension))

    return file_paths

