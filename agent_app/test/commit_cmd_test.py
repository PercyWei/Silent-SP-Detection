import os.path

from preprocess.util import show_commit_file_names



def test_cmd_show_commit_file_name():
    repos_root = "/root/projects/clone_projects"
    repo = "ikus060/rdiffweb"
    repo_dpath = os.path.join(repos_root, repo.replace('/', "_"))
    commit_hash = "f2de2371c5e13ce1c6fd6f9a1ed3e5d46b93cd7e"
    res = show_commit_file_names(repo_dpath, commit_hash)
    print(res)


if __name__ == '__main__':
    test_cmd_show_commit_file_name()
