import json

from agent_app.util import get_commit_content
from agent_app.commit.commit_util import extract_commit_content_info


project_path = "/root/projects/clone_projects/saltstack_salt"
commit_hash = "28aa9b105804ff433d8f663b2f9b804f2b75495a"

raw_commit = get_commit_content(commit_hash, project_path)

info = extract_commit_content_info(raw_commit)
print(json.dumps(info, indent=4))
