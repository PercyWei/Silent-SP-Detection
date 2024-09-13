
from agent_app.util import (
    get_head_commit_hash, cd, repo_checkout,
    get_commit_content
)
from agent_app.commit.commit_manage_v2 import CommitManager


project_path = "/root/projects/clone_projects/saltstack_salt"
commit_hash = "28aa9b105804ff433d8f663b2f9b804f2b75495a"

raw_commit = get_commit_content(commit_hash, project_path)

head_commit_hash = get_head_commit_hash(project_path)
print(f"HEAD: {head_commit_hash}")
with cd(project_path):
    repo_checkout(commit_hash)

try:
    manager = CommitManager(project_path, commit_hash, raw_commit)
finally:
    with cd(project_path):
        repo_checkout(head_commit_hash)
    head_commit_hash = get_head_commit_hash(project_path)
    print(f"HEAD: {head_commit_hash}")
