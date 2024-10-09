
from agent_app.util import (
    get_head_commit_hash, cd, repo_checkout,
    get_commit_content
)
from agent_app.commit.commit_manage import CommitManager


# Good example
# project_path = "/root/projects/clone_projects/xi_django-mfa3"
# commit_hash = "32f656e22df120b84bdf010e014bb19bd97971de"

project_path = "/root/projects/clone_projects/xi_django-mfa3"
commit_hash = "32f656e22df120b84bdf010e014bb19bd97971de"

raw_commit = get_commit_content(commit_hash, project_path)

head_commit_hash = get_head_commit_hash(project_path)
print(f"HEAD: {head_commit_hash}")
with cd(project_path):
    repo_checkout(commit_hash)

try:
    manager = CommitManager(project_path, commit_hash, raw_commit)

    # Test 1: Show the constructed commit init context
    print("\n\n" + "-" * 40 + "Commit Init Context" + "-" * 40 + "\n\n")
    print(manager.describe_commit_files())
    print("\n\n" + "-" * 100 + "\n\n")

finally:
    with cd(project_path):
        repo_checkout(head_commit_hash)
    head_commit_hash = get_head_commit_hash(project_path)
    print(f"HEAD: {head_commit_hash}")
