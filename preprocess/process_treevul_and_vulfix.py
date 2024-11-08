import os
import json

from typing import *


def find_duplicate_cves_between_treevul_and_vulfix(treevul_fpath: str, vulfix_fpath: str, log_fpath: str) -> None:
    with open(treevul_fpath, 'r') as f:
        treevul = json.load(f)

    with open(vulfix_fpath, 'r') as f:
        vulfix = json.load(f)

    treevul_cves = [data["cve_id"] for data in treevul]
    vulfix_cves = [data["cve_id"] for data in vulfix]

    duplicate_cves = list(set(treevul_cves).intersection(vulfix_cves))

    print(f"Duplicate CVE number: {len(duplicate_cves)}")
    # print(json.dumps(duplicate_cves, indent=4))

    treevul_cve_data = {data["cve_id"]: data for data in treevul}
    vulfix_cve_data = {data["cve_id"]: data for data in vulfix}

    retain_in_treevul_cves = []
    retain_in_vulfix_cves = []
    other_cves = []

    for cve_id in duplicate_cves:
        treevul_cve = treevul_cve_data[cve_id]
        vulfix_cve = vulfix_cve_data[cve_id]
        if treevul_cve['commit_hash'] == vulfix_cve['commit_hash']:
            if set(treevul_cve['cwe_list']) == set(vulfix_cve['cwe_list']):
                retain_in_treevul_cves.append(cve_id)
            elif set(treevul_cve['cwe_list']).issubset(set(vulfix_cve['cwe_list'])):
                retain_in_vulfix_cves.append(cve_id)
            else:
                other_cves.append(cve_id)
        else:
            other_cves.append(cve_id)

    with open(log_fpath, 'w') as f:
        log = {
            "retain in treevul": retain_in_treevul_cves,
            "retain in vulfix": retain_in_vulfix_cves,
            "other": other_cves
        }
        json.dump(log, f, indent=4)


def delete_duplicate_cves_in_treevul_and_vulfix(treevul_fpath: str, vulfix_fpath: str, log_fpath: str) -> None:
    with open(treevul_fpath, 'r') as f:
        treevul = json.load(f)

    with open(vulfix_fpath, 'r') as f:
        vulfix = json.load(f)

    with open(log_fpath, 'r') as f:
        log = json.load(f)

    assert len(log["other"]) == 0

    updt_treevul = []
    for data in treevul:
        if data["cve_id"] not in log["retain in vulfix"]:
            data["task_id"] = f"treevul-vul-{len(updt_treevul)}"
            updt_treevul.append(data)

    updt_vulfix = []
    for data in vulfix:
        if data["cve_id"] not in log["retain in treevul"]:
            data["task_id"] = f"vulfix-vul-{len(updt_vulfix)}"
            updt_vulfix.append(data)

    with open(treevul_fpath, 'w') as f:
        json.dump(updt_treevul, f, indent=4)

    with open(vulfix_fpath, 'w') as f:
        json.dump(updt_vulfix, f, indent=4)


if __name__ == '__main__':

    lang = "Java"  # "Python" / "Java"

    if lang == "Python":
        treevul_file = "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_treevul.json"
        vulfix_file = "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_vulfix.json"
        log_file = "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_duplicated.log"
    elif lang == "Java":
        treevul_file = "/root/projects/VDTest/dataset/Final/VIEW_1000/java_vul_tasks_treevul.json"
        vulfix_file = "/root/projects/VDTest/dataset/Final/VIEW_1000/java_vul_tasks_vulfix.json"
        log_file = "/root/projects/VDTest/dataset/Final/VIEW_1000/java_vul_tasks_duplicated.log"
    else:
        raise RuntimeError

    # find_duplicate_cves_between_treevul_and_vulfix(treevul_file, vulfix_file, log_file)

    delete_duplicate_cves_in_treevul_and_vulfix(treevul_file, vulfix_file, log_file)