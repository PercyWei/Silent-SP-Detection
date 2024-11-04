import os
import json
import shutil

from typing import *
from collections import defaultdict


def format_size(byte_size: int) -> str:
    if byte_size == 0:
        return "0 B"

    size_units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0

    while byte_size >= 1024 and i < len(size_units) - 1:
        byte_size /= 1024.0
        i += 1

    return f"{byte_size:.2f} {size_units[i]}"


def get_dir_size(dir_path: str) -> int:
    if not os.path.isdir(dir_path):
        print(f"Dir {dir_path} doesn't exist")
    total_size = 0
    for cur_dpath, _, file_names in os.walk(dir_path):
        for file_name in file_names:
            file_path = os.path.join(cur_dpath, file_name)
            try:
                total_size += os.path.getsize(file_path)
            except FileNotFoundError as e:
                pass
            except Exception as e:
                pass

    return total_size


def cal_repos_size(repo2size: Dict[str, int], threshold: int = 500) -> None:
    # Count repos <= x MB (default x = 500)
    size_threshold = threshold * 1024 * 1024

    num = 0
    over_size = 0
    left_size = 0
    for repo, size in repo2size.items():
        if size <= size_threshold:
            num += 1
            left_size += size
        else:
            over_size += size

    print(f"Repos <= {threshold} MB: {num} / {len(repo2size)}")
    print(f"Total left size: {format_size(left_size)}")
    print(f"Total over size: {format_size(over_size)}")


def check_dataset_repos(repo_names: List[str], local_repos_root: str = "/root/projects/clone_projects") -> Dict[str, int]:

    repo2size = {}

    repo_names = list(set(repo_names))

    for repo_name in repo_names:
        repo_dpath = os.path.join(local_repos_root, repo_name.replace("/", "_"))
        if os.path.isdir(repo_dpath):
            repo2size[repo_name] = get_dir_size(repo_dpath)
        else:
            print(f"Repo dir not found: {repo_dpath}")

    repo2size = dict(sorted(repo2size.items(), key=lambda x: x[1], reverse=True))

    return repo2size


def check_python_datasets(local_repos_root: str = "/root/projects/clone_projects"):
    repo2commit: Dict[str, List[str]] = defaultdict(list)

    dataset_fpaths = [
        "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000_v1.json",
        "/root/projects/VDTest/dataset/Final/py_vul_tasks_vulfix_view1000_v1.json",
        "/root/projects/VDTest/dataset/Final/py_vul_tasks_treevul_view1000_v1.json"
    ]

    # (1) Collect mapping from repo name to commits
    for dataset_fpath in dataset_fpaths:
        with open(dataset_fpath, 'r') as f:
            dataset = json.load(f)

        for data in dataset:
            commit_hash = data['commit_hash']
            repo = data['repo']

            assert commit_hash not in repo2commit[repo]
            repo2commit[repo].append(commit_hash)

    # (2) Calculate the number of tasks (commits) included in the repos
    repo2cnum: Dict[str, int] = {}
    for repo, commits in repo2commit.items():
        repo2cnum[repo] = len(commits)

    repo2cnum = dict(sorted(repo2cnum.items(), key=lambda x: x[1], reverse=True))

    cnum2repos: Dict[int, List[str]] = defaultdict(list)
    for repo, cnum in repo2cnum.items():
        cnum2repos[cnum].append(repo)

    # 1. Mapping from commit number to repo number
    cnum2rnum = {cnum: len(repos) for cnum, repos in cnum2repos.items()}

    # 2. Mapping from commit number to total repo size
    cnum2size: Dict[int, str] = {}
    for cnum, repos in cnum2repos.items():
        total_size = 0
        for repo in repos:
            repo_dpath = os.path.join(local_repos_root, repo.replace("/", "_"))
            total_size += get_dir_size(repo_dpath)
        cnum2size[cnum] = format_size(total_size)

    print(f"Repo number: {len(repo2cnum)}")
    print(f"Mapping from commit number to repo number: \n{json.dumps(cnum2rnum, indent=4)}")
    print(f"Mapping from commit number to total repo size: \n{json.dumps(cnum2size, indent=4)}")
    # print(json.dumps(repo2cnum, indent=4))

    # (3) Focus on repos with only single task
    # single_task_repos: List[str] = []
    # for repo, cnum in repo2cnum.items():
    #     if cnum == 1:
    #         single_task_repos.append(repo)
    #
    # single_task_repo2size = check_dataset_repos(single_task_repos, local_repos_root)
    #
    # cal_repos_size(single_task_repo2size)
    #
    # single_task_repo2fsize = {repo: format_size(size) for repo, size in single_task_repo2size.items()}
    #
    # print(f"Repo with single task number: {len(single_task_repos)}")
    # print(json.dumps(single_task_repo2fsize, indent=4))


def find_useless_repos(local_repos_root: str = "/root/projects/clone_projects"):

    dataset_fpaths = [
        "/root/projects/VDTest/dataset/Final/py_vul_tasks_nvdvul_view1000_v1.json",
        "/root/projects/VDTest/dataset/Final/py_vul_tasks_vulfix_view1000_v1.json",
        "/root/projects/VDTest/dataset/Final/py_vul_tasks_treevul_view1000_v1.json"
    ]

    useful_repos: List[str] = []

    for dataset_fpath in dataset_fpaths:
        with open(dataset_fpath, 'r') as f:
            dataset = json.load(f)

        for data in dataset:
            useful_repos.append(data['repo'])

    useful_repos = list(set(useful_repos))
    useful_repos = [repo.replace('/', '_') for repo in useful_repos]

    repos = os.listdir(local_repos_root)

    useless_repos = list(set(repos) - set(useful_repos))

    total_size = 0
    useless_repo2size = {}
    for repo in useless_repos:
        repo_dpath = os.path.join(local_repos_root, repo)
        size = get_dir_size(repo_dpath)
        assert size != 0
        useless_repo2size[repo] = format_size(size)
        total_size += size

    print(f"Useless repos total size: {format_size(total_size)}")
    print(f"Useless repos: \n{json.dumps(useless_repo2size, indent=4)}")

    ## Be Careful!
    # for repo in useless_repos:
    #     repo_dpath = os.path.join(local_repos_root, repo)
    #     shutil.rmtree(repo_dpath)


if __name__ == "__main__":
    pass

    # check_python_datasets()

    # find_useless_repos()
