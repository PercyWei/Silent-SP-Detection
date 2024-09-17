from agent_app.commit.parse import parse_python_file_locations
from agent_app.commit.commit_util import get_code_after_commit


project_path = ""
commit_hash = ""
rel_fpath = ""

content = get_code_after_commit(project_path, commit_hash, rel_fpath)
parse_python_file_locations(content)
