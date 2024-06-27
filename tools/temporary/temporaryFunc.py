import os
import re
import json
import pandas as pd
import csv


from utils.logging import start_with_logger


def read_TreeVul_clone_check_log(TreeVul_clone_check_log_fpath):
    with open(TreeVul_clone_check_log_fpath, 'r') as f:
        lines = f.readlines()

    repo_pattern = r".*\[(?P<auth_repo>.+)\].*"
    commit_id_pattern = r"INFO - \[(?P<auth_repo>.+)\] Checkout commit: (?P<commit_id>.+)"
    result_pattern = r"INFO - \[(?P<auth_repo>.+)\] Commit exist: (?P<result>.+)"

    success_repos = {}
    failed_repos = []

    i = 0
    current_repo = None
    current_repo_commit_num = 0
    while i < len(lines):
        repo_match = re.search(repo_pattern, lines[i])
        if repo_match:
            repo = repo_match.group('auth_repo')
            if current_repo != repo:
                if current_repo_commit_num == 0 and current_repo is not None:
                    failed_repos.append(current_repo)

                current_repo = repo
                current_repo_commit_num = 0
                i += 1
            else:
                commit_id_match = re.search(commit_id_pattern, lines[i])
                if commit_id_match:
                    commit_id = commit_id_match.group('commit_id')
                    result = re.search(result_pattern, lines[i+1]).group('result')
                    if current_repo in success_repos:
                        success_repos[current_repo][commit_id] = result
                    else:
                        success_repos[current_repo] = {commit_id: result}
                    i += 2
                else:
                    i += 1
        else:
            i += 1

    return success_repos, failed_repos


def combine_clone_check_result_and_fetch_check_result_log(fetch_check_result_fpath, clone_check_result_log_fpath,
                                                          save_dpath="./data"):
    """

    :param fetch_check_result_fpath: ./data/TreeVulCleaning_simplified_original.json
    :param clone_check_result_log_fpath: ./logs/TreeVulCleaning-Other.log
    :param save_dpath:
    """
    clone_check_success_repos, clone_check_failed_repos = read_TreeVul_clone_check_log(clone_check_result_log_fpath)

    with open(fetch_check_result_fpath, 'r') as f:
        c = json.load(f)

    fetch_check_failed_repos = c["Failed Results"]
    for repo, commit_list in fetch_check_failed_repos.items():
        if repo in clone_check_success_repos:
            commit_list = list(set(commit_list))
            if len(commit_list) != len(clone_check_success_repos[repo]):
                print(f"[Attention] {repo} has unchecked commit!")
        elif repo in clone_check_failed_repos:
            continue
        else:
            print(f"[Attention] {repo} not in clone_check_repos!")

    # Update fetch_check_repos with clone_check_success_repos
    fetch_check_repos = c["Checked Results"]
    new_fetch_check_repos = {}
    for item_id, items in fetch_check_repos.items():
        new_fetch_check_repos[item_id] = items
        if items["result"] == "Failed":
            if items["repo"] in clone_check_success_repos:
                new_fetch_check_repos[item_id]["result"] = clone_check_success_repos[items["repo"]][items["commit_id"]]

    # Update fetch_check_failed_repos with clone_check_success_repos
    new_fetch_check_failed_repos = {}
    for repo, commit_list in fetch_check_failed_repos.items():
        new_fetch_check_failed_repos[repo] = commit_list
        if repo in clone_check_success_repos:
            commit_list = list(set(commit_list))
            new_fetch_check_failed_repos[repo] = commit_list
            for commit in commit_list:
                if commit in clone_check_success_repos[repo]:
                    new_fetch_check_failed_repos[repo].remove(commit)

            if len(new_fetch_check_failed_repos[repo]) == 0:
                del new_fetch_check_failed_repos[repo]

    save = {
        "Checked Results": new_fetch_check_repos,
        "Failed Results": new_fetch_check_failed_repos
    }

    save_fpath = os.path.join(save_dpath, f"TreeVul-simplified-original-fetch&clone.json")
    with open(save_fpath, 'w') as f:
        json.dump(save, f, indent=4)


def rearrange_TreeVul_validity_check_results(result_jpath):
    with open(result_jpath, 'r') as f:
        c = json.load(f)

    failed_repo_check_results = {}
    for repo, commit_check in c["Failed Results"].items():
        failed_repo_check_results[repo] = {commit: False for commit in commit_check}

    for _, item in c["Checked Results"].items():
        if item["result"] is True:
            item["result"] = "Valid"
        elif item["result"] is False:
            item["result"] = "Invalid"

        repo = item["repo"]
        commit_id = item["commit_id"]
        checked_result = item["result"]
        if repo in c["Failed Results"]:
            if commit_id in c["Failed Results"][repo]:
                if checked_result == "Valid" or checked_result == "Invalid":
                    if failed_repo_check_results[repo][commit_id] is False:
                        failed_repo_check_results[repo][commit_id] = checked_result
                        print(f"Missing check in failed results: repo: {repo}, commit_id: {commit_id}, result: {checked_result}.")
                    else:
                        assert checked_result == failed_repo_check_results[repo][commit_id]
                else:
                    if failed_repo_check_results[repo][commit_id] is not False:
                        item["result"] = failed_repo_check_results[repo][commit_id]
                        print(f"Missing check in checked results: repo: {repo}, commit_id: {commit_id}, result: {failed_repo_check_results[repo][commit_id]}.")
            else:
                assert checked_result == "Valid" or checked_result == "Invalid"

    update_failed_repo_check_results = {}
    for repo, commit_check in failed_repo_check_results.items():
        update_failed_repo_check_results[repo] = []
        for commit, commit_check_result in commit_check.items():
            if commit_check_result is False:
                update_failed_repo_check_results[repo].append(commit)

    final_failed_repo_check_results = {}
    for repo, commit_list in update_failed_repo_check_results.items():
        if len(commit_list) > 0:
            final_failed_repo_check_results[repo] = commit_list

    c["Failed Results"] = final_failed_repo_check_results
    print(json.dumps(final_failed_repo_check_results, indent=4))

    with open(result_jpath, 'w') as f:
        json.dump(c, f, indent=4)


def find_not_found_repos_and_save(result_jpath):
    with open(result_jpath, 'r') as f:
        c = json.load(f)

    old_and_new_repos = {
        "rcook/rgpg": "eahanson/rgpg",
        "embedthis/goahead": "zoushipeng/goahead",
        "embedthis/appweb": "whoerau/appweb",
        "wuyouzhuguli/FEBS-Shiro": "XIOGit/https-github.com-wuyouzhuguli-FEBS-Shiro",
        "vintagedaddyo/MyBB_Plugin-Upcoming_Events": "MangaD/MyBB_Plugin-Upcoming_Events"
    }

    # update_not_found_repo_results = {}
    # for repo, commit_list in c["Not Found Results"].items():
    #     if repo in old_and_new_repos:
    #         assert repo not in c["Failed Results"]
    #
    #         new_repo = old_and_new_repos[repo]
    #         if new_repo in c["Failed Results"]:
    #             c["Failed Results"][new_repo] += commit_list
    #         else:
    #             c["Failed Results"][new_repo] = commit_list
    #     else:
    #         update_not_found_repo_results[repo] = commit_list
    #
    # c["Not Found Results"] = update_not_found_repo_results

    new_failed_results = {}
    for item_id, item in c["Checked Results"].items():
        if item["repo"] in old_and_new_repos:
            if item["result"] != "Failed":
                item["result"] = "Failed"
            new_repo = old_and_new_repos[item["repo"]]
            item["repo"] = new_repo

            if new_repo in new_failed_results:
                new_failed_results[new_repo].append(item["commit_id"])
                new_failed_results[new_repo] = list(set(new_failed_results[new_repo]))
            else:
                new_failed_results[new_repo] = [item["commit_id"]]

    update_failed_results = {}
    for repo, commit_list in c["Failed Results"].items():
        if repo not in old_and_new_repos:
            update_failed_results[repo] = list(set(commit_list))
    update_failed_results.update(new_failed_results)

    c["Failed Results"] = update_failed_results

    with open(result_jpath, 'w') as f:
        json.dump(c, f, indent=4)


def print_failed_and_not_found_repos_in_TreeVul_validity_check_results(result_jpath):
    with open(result_jpath, 'r') as f:
        c = json.load(f)

    print(">>> Failed repos:")
    for repo, _ in c["Failed Results"].items():
        print(repo)

    print(">>> Not found repos:")
    for repo, _ in c["Not Found Results"].items():
        print(repo)


def change_results(result_jpath):
    with open(result_jpath, 'r') as f:
        c = json.load(f)

    new_failed_commits = []
    for item_id, item in c["Checked Results"].items():
        if item["repo"] == "brianchandotcom/liferay-portal":
            item["result"] = "Failed"
            new_failed_commits.append(item["commit_id"])

    if "brianchandotcom/liferay-portal" in c["Failed Results"]:
        c["Failed Results"]["brianchandotcom/liferay-portal"] = new_failed_commits

    with open(result_jpath, 'w') as f:
        json.dump(c, f, indent=4)


def pl_count(dataset_jpath):
    with open(dataset_jpath, 'r') as f:
        c = json.load(f)

    pl_dict = {}
    for repo, repo_item in c.items():
        for commit_id , commit_item in repo_item.items():
            for file_name, item in commit_item.items():
                if file_name != "cve_list":
                    if "PL" in item:
                        pl = item["PL"]
                        if pl not in pl_dict:
                            pl_dict[pl] = 1
                        else:
                            pl_dict[pl] += 1

    pl_dict = dict(sorted(pl_dict.items(), key=lambda x: x[1], reverse=True))
    print(json.dumps(pl_dict, indent=4))


def print_all_repos(dataset_jpath):
    with open(dataset_jpath, 'r') as f:
        c = json.load(f)

    all_repos = []
    all_c_repos = []
    for repo, repo_item in c.items():
        all_repos.append(repo)
        for commit_id, commit_item in repo_item.items():
            for file_name, item in commit_item.items():
                if file_name != "cve_list" and "PL" in item and item["PL"] == 'C':
                    all_c_repos.append(repo)
    all_c_repos = list(set(all_c_repos))
    print(len(all_repos))
    print(len(all_c_repos))

    not_local_repos = []
    not_local_c_repos = []
    for repo in all_repos:
        repo_name = "_".join(repo.split("/"))
        if not os.path.exists(f"/root/projects/clone_projects/{repo_name}"):
            not_local_repos.append(repo)
            if repo in all_c_repos:
                not_local_c_repos.append(repo)
    print(len(not_local_repos))
    print(len(not_local_c_repos))





if __name__ == '__main__':
    # combine_clone_check_result_and_fetch_check_result_log(
    #     fetch_check_result_fpath="./data/TreeVul-simplified-original.json",
    #     clone_check_result_log_fpath="./logs/TreeVulCleaning-Other.log")

    # TreeVul_validity_check_results_jpath = "./data/TreeVul-valid_check.json"
    # rearrange_TreeVul_validity_check_results(TreeVul_validity_check_results_jpath)
    # print_failed_and_not_found_repos_in_TreeVul_validity_check_results(TreeVul_validity_check_results_jpath)
    # find_not_found_repos_and_save(TreeVul_validity_check_results_jpath)
    # change_results(TreeVul_validity_check_results_jpath)

    # cve_s_commit_s_file_jpath = './data/TreeVul-valid-cve_s_commit_s_file.json'
    # pl_count(cve_s_commit_s_file_jpath)
    # print_all_repos(cve_s_commit_s_file_jpath)

    csv_path = "./dataset/CoLeFunDa/java_2021_CVE_mod.csv"
    # pd.set_option('display.max_columns', None)
    # df = pd.read_csv(csv_path, nrows=5)
    # print(df)
    csv.field_size_limit(2147483647)
    with open(csv_path) as f:
        reader = csv.reader(f)
        title = next(reader)
        print(title)

        for i, row in enumerate(reader):
            for attr, val in zip(title, row):
                print('-' * 100)
                print(attr)
                print(val)

            if i == 15:
                break

