import os
import json
from typing import *





def expand_TreeVul(dateset_jpath, repos_dpath) -> Dict[]:

    with open(dateset_jpath, 'r') as f:
        items = json.load(f)

    repo_dname = '_'.join(items["repo"].split('/'))
    repo_dpath = os.path.join(repos_dpath, repo_dname)

    expand_items = {}
    commit_content =







