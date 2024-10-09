import os
import chardet
import pathlib

from agent_app.util import get_head_commit_hash, cd, repo_checkout
from agent_app.search import search_util

project_path = "/root/projects/clone_projects/python_cpython"
commit_hash = "0c2b6a3943aa7b022e8eb4bfd9bffcddebf9a587"
head_commit_hash = get_head_commit_hash(project_path)
print(f"HEAD: {head_commit_hash}")
with cd(project_path):
    repo_checkout(commit_hash)

try:
    file_path = "/root/projects/clone_projects/python_cpython/Tools/i18n/pygettext.py"
    # file_path = "/root/projects/clone_projects/python-imaging_Pillow/setup.py"
    with open(file_path, 'rb') as f:
        result = chardet.detect(f.read())
    print(result)

    file_content = pathlib.Path(file_path).read_text(encoding=result['encoding'])
    # print(file_content)
    struct_info = search_util_v2.parse_python_code(file_content)
finally:
    with cd(project_path):
        repo_checkout(head_commit_hash)
    head_commit_hash = get_head_commit_hash(project_path)
    print(f"HEAD: {head_commit_hash}")
