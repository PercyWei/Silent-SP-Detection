import os
import json


from preprocess.util import clone_repo, is_commit_exist_in_repo


if __name__ == "__main__":
    token = os.getenv('TOKEN', '')

    file = "/root/projects/VDTest/dataset/Intermediate/NVDVul/py_vul_tasks_2022.json"
    with open(file, 'r') as f:
        data = json.load(f)

    root = "/root/projects/clone_projects"
    repos = []
    for item in data:
        repo = item["repo"]
        repo_dir = os.path.join(root, repo.replace('/', '_'))
        if not os.path.exists(repo_dir) and repo not in repos:
            repos.append(repo)

    print(json.dumps(repos, indent=4))

    ## FUNCTION 1
    # for repo in repos:
    #     print("=" * 100 + "\n\n")
    #     repo_dpath = os.path.join(root, repo.replace('/', '_'))
    #     clone_repo(repo, repo_dpath, token=token, timeout=60)

    ## FUNCTION 3
    updt_items = []
    for item in data:
        repo = item["repo"]
        commit_hash = item["commit_hash"]

        repo_dir = os.path.join(root, repo.replace('/', '_'))
        is_repro = is_commit_exist_in_repo(repo_dir, commit_hash)
        item["reproducibility"] = is_repro
        updt_items.append(item)
    with open(file, 'w') as f:
        json.dump(updt_items, f, indent=4)
