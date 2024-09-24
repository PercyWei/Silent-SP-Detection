
from agent_app import globals
from agent_app.globals import view_cwe_tree_files
from agent_app.util import (
    get_head_commit_hash, cd, repo_checkout,
    get_commit_content
)
from agent_app.raw_tasks import RawLocalTask
from agent_app.api.manage_v2 import ProcessManager


# Need modify
repo = "andialbrecht/sqlparse"
commit_hash = "b4a39d9850969b4e1d6940d32094ee0b42a2cf03"
output_dpath = "/root/projects/VDTest/agent_app/test/output"

# Main test
globals.view_id = "1000"
globals.cwe_entry_file = "data/CWE/VIEW_1000/CWE_entries.json"
globals.cwe_tree_file = "data/CWE/VIEW_1000/CWE_tree.json"
globals.all_weakness_entry_file = "data/CWE/VIEW_1000/CWE_entries.json"
globals.view_cwe_tree_files = [
    ("699", "data/CWE/VIEW_699/CWE_tree.json"),
    ("888", "data/CWE/VIEW_888/CWE_tree.json"),
    ("1400", "data/CWE/VIEW_1400/CWE_tree.json")
]

local_repo_path = "/root/projects/clone_projects/" + repo.replace('/', '_')
raw_commit = get_commit_content(commit_hash, local_repo_path)

head_commit_hash = get_head_commit_hash(local_repo_path)
print(f"HEAD: {head_commit_hash}")
with cd(local_repo_path):
    repo_checkout(commit_hash)

try:
    raw_task = RawLocalTask(
        task_id="",
        cve_id=None,
        commit_type=1,
        cwe_id=None,
        cwe_depth=None,
        repo_name=repo,
        commit_hash=commit_hash,
        local_repo_dpath=local_repo_path
    )
    manager = ProcessManager(raw_task.to_task(), output_dpath)

    # method_name = "_set_headers"
    # file_name = "rdiffweb/tools/security.py"
    # output, _, res = manager.search_manager.search_method_in_file(method_name, file_name)

    print('ok')
finally:
    with cd(local_repo_path):
        repo_checkout(head_commit_hash)
    head_commit_hash = get_head_commit_hash(local_repo_path)
    print(f"HEAD: {head_commit_hash}")