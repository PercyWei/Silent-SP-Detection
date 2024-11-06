from __future__ import annotations

import os
import json
import requests

from typing import *

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException

from utils import selenium_driver_setup, selenium_driver_close


def crawl_cwe_tree(view_id: str):
    driver = selenium_driver_setup()

    url = f"https://cwe.mitre.org/data/definitions/{view_id}.html"


    def find_child(father_div) -> Dict:
        try:
            father_id = father_div.get_attribute('id')

            div_3 = father_div.find_element(By.XPATH, './div[3]')
            child_group_divs = div_3.find_elements(By.XPATH, './div[contains(@class, "group")]')

            children_dict = {}
            for child in child_group_divs:
                child_id = child.get_attribute('id')
                assert child_id.startswith(father_id)

                children_dict[child_id[len(father_id):]] = find_child(child)

            return children_dict
        except NoSuchElementException:
            return {}


    try:
        driver.get(url)

        target_div = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located(
                (By.XPATH, '/html/body/table/tbody/tr[2]/td/div[3]/div[5]/div[2]/div/div/div/div[2]'))
        )

        cwe_tree = {}
        level_1_divs = target_div.find_elements(By.XPATH, './div[contains(@class, "group")]')
        for div in level_1_divs:
            div_id = div.get_attribute('id')
            assert div_id.startswith(view_id)
            cwe_tree[div_id[len(view_id):]] = find_child(div)

        save_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/raw_cwe_tree.json"
        with open(save_file, "w") as f:
            json.dump(cwe_tree, f, indent=4)


    finally:
        selenium_driver_close(driver)


def count_cwe_tree(view_id: str):
    cwe_tree_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/raw_cwe_tree.json"
    with open(cwe_tree_file, "r") as f:
        cwe_tree = json.load(f)

    recorded_cwe_ids: List[str] = []
    duplicated_cwe_ids: List[str] = []


    def count_all_keys(tree):
        count = 0
        for father, children in tree.items():
            assert isinstance(children, dict)

            if father not in recorded_cwe_ids:
                recorded_cwe_ids.append(father)
            else:
                duplicated_cwe_ids.append(father)

            count += 1
            if children:
                count += count_all_keys(children)

        return count


    appeared_cwe_num = count_all_keys(cwe_tree)
    unduplicated_cwe_num = len(recorded_cwe_ids)

    print(f"unduplicated cwe num / appeared cwe num: {unduplicated_cwe_num} / {appeared_cwe_num}")

    duplicated_cwe_ids = list(set(duplicated_cwe_ids))
    print(json.dumps(duplicated_cwe_ids, indent=4))
    print(len(duplicated_cwe_ids))


def build_cwe_entry_from_cwe_tree(view_id: Literal["1400", "699", "888"]):
    cwe_entry_1000_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(cwe_entry_1000_file, "r") as f:
        all_weaknesses = json.load(f)
    all_weakness_ids = [entry["CWE-ID"] for entry in all_weaknesses]

    cwe_tree_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/raw_cwe_tree.json"
    with open(cwe_tree_file, "r") as f:
        cwe_tree = json.load(f)

    cwe_entries: Dict[str, Dict] = {}


    def add_tree_node(tree):
        for father, children in tree.items():
            if father not in cwe_entries:
                if father in all_weakness_ids:
                    cwe_entries[father] = {"CWE-ID": father, "Type": "weakness"}
                else:
                    cwe_entries[father] = {"CWE-ID": father, "Type": "category"}

                assert isinstance(children, dict)
                if children:
                    add_tree_node(children)


    add_tree_node(cwe_tree)

    print(len(cwe_entries))

    cwe_entry_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/raw_cwe_entries.json"
    with open(cwe_entry_file, "w") as f:
        json.dump(list(cwe_entries.values()), f, indent=4)


def crawl_view_category_name(view_id: Literal["1400", "699"]):
    driver = selenium_driver_setup()

    url = f"https://cwe.mitre.org/data/definitions/{view_id}.html"

    try:
        driver.get(url)

        target_div = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located(
                (By.XPATH, '/html/body/table/tbody/tr[2]/td/div[3]/div[5]/div[2]/div/div/div/div[2]'))
        )

        category_names = {}

        category_divs = target_div.find_elements(By.XPATH, './div[contains(@class, "group")]')
        for div in category_divs:
            div_id = div.get_attribute('id')
            assert div_id.startswith(view_id)

            span_a = div.find_element(By.XPATH, './span[2]/span[2]/a')
            span_text = span_a.text

            category_names[div_id[len(view_id):]] = span_text

        save_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/category_names.json"
        with open(save_file, "w") as f:
            json.dump(category_names, f, indent=4)


    finally:
        selenium_driver_close(driver)


def crawl_view_888_category_name(view_id: Literal["888"]):
    cwe_entry_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/raw_cwe_entries.json"
    with open(cwe_entry_file, "r") as f:
        cwe_entries = json.load(f)
    cwe_entries = {entry["CWE-ID"]: entry for entry in cwe_entries}


    def find_all_children(div, father_id):
        div_id = div.get_attribute('id')
        assert div_id.startswith(father_id)
        cwe_id = div_id[len(father_id):]

        try:
            span_graph_title = div.find_element(By.XPATH, './span[@class="graph_title"]')
            # span_graph_title = WebDriverWait(driver, 30).until(
            #     EC.presence_of_element_located((By.XPATH, './span[@class="graph_title"]'))
            # )
            span_primary = span_graph_title.find_element(By.XPATH, './span[@class="Primary"]/a')
            span_text = span_primary.text
        except Exception:
            raise RuntimeError

        if cwe_entries[cwe_id]["Type"] == "category":
            cwe_entries[cwe_id]["Name"] = span_text

        try:
            div_3 = div.find_element(By.XPATH, f'./div[@name="block_{div_id}"]')
            child_divs = div_3.find_elements(By.XPATH, './div[contains(@class, "group")]')

            for child_div in child_divs:
                find_all_children(child_div, div_id)
        except NoSuchElementException:
            pass


    url = f"https://cwe.mitre.org/data/definitions/{view_id}.html"
    driver = selenium_driver_setup()

    try:
        driver.get(url)

        target_div = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located(
                (By.XPATH, '/html/body/table/tbody/tr[2]/td/div[3]/div[5]/div[2]/div/div/div/div[2]'))
        )

        level_1_divs = target_div.find_elements(By.XPATH, './div[contains(@class, "group")]')
        for level_1_div in level_1_divs:
            find_all_children(level_1_div, view_id)

        with open(cwe_entry_file, "w") as f:
            json.dump(list(cwe_entries.values()), f, indent=4)
    finally:
        selenium_driver_close(driver)


def process_raw_cwe_tree(view_id: Literal["1400", "699", "888"]):
    file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/raw_cwe_tree.json"
    with open(file, 'r') as f:
        raw_cwe_tree = json.load(f)


    def iter_tree(tree: Dict, father: str | None = None):
        for node, children in tree.items():
            if node not in cwe_tree:
                cwe_tree[node] = {
                    "CWE-ID": node,
                    "father": [father] if father else [],
                    "children": list(children.keys())
                }
            else:
                if father and father not in cwe_tree[node]["father"]:
                    cwe_tree[node]["father"].append(father)

            assert isinstance(children, dict)
            iter_tree(children, node)

    cwe_tree = {}
    iter_tree(raw_cwe_tree)


    def find_cwe_paths(curr) -> List[List[str]]:
        paths: List[List[str]] = []
        fathers = cwe_tree[curr]["father"]
        if fathers:
            for father in fathers:
                father_paths = find_cwe_paths(father)
                paths += [path + [curr] for path in father_paths]
        else:
            paths.append([curr])
        return paths


    updt_cwe_tree = {}
    for cwe_id, info in cwe_tree.items():
        cwe_paths = find_cwe_paths(cwe_id)
        info["cwe_paths"] = cwe_paths
        updt_cwe_tree[cwe_id] = info

    save_file = f"/root/projects/VDTest/data/CWE/VIEW_{view_id}/CWE_tree.json"
    with open(save_file, "w") as f:
        json.dump(updt_cwe_tree, f, indent=4)


def compare_cwe_collected_with_treevul():
    """
    Compare CWE paths collected and in baseline TreeVul.
    """
    ## (1) Get CWE paths in TreeVul
    # NOTE: Only include CWE paths that appear in the TreeVul dataset
    treevul_cwe_paths_fpath = "/root/projects/TreeVul/data/cwe_path.json"
    with open(treevul_cwe_paths_fpath, "r") as f:
        treevul_full_cwe_paths = json.load(f)

    treevul_cwe_paths: Dict[str, List[str]] = {}
    for full_cwe_id, full_cwe_path in treevul_full_cwe_paths.items():
        cwe_id = full_cwe_id.split("-")[-1]
        cwe_path = [c.split("-")[-1] for c in full_cwe_path]
        treevul_cwe_paths[cwe_id] = cwe_path

    print(len(treevul_cwe_paths))

    ## (2) Get CWE paths collected
    coll_cwe_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(coll_cwe_tree_fpath, "r") as f:
        coll_cwe_tree = json.load(f)

    coll_cwe_paths: Dict[str, List[List[str]]] = {}
    for cwe_id, data in coll_cwe_tree.items():
        coll_cwe_paths[cwe_id] = data["cwe_paths"]

    print(len(coll_cwe_paths))

    ## (3) Compare
    for cwe_id, cwe_path in treevul_cwe_paths.items():
        coll_paths = coll_cwe_paths[cwe_id]
        if cwe_path not in coll_paths:
            print(f"CWE-{cwe_id}:" 
                  f"\n - Collected: {json.dumps([' '.join(path) for path in coll_paths], indent=4)}"
                  f"\n - In TreeVul: {cwe_path}"
                  f"\n\n")


def check_dataset_cwe_depth():

    treevul_cwe_paths_fpath = "/root/projects/TreeVul/data/cwe_path.json"

    with open(treevul_cwe_paths_fpath, "r") as f:
        treevul_cwe_paths = json.load(f)

    treevul_invalid_cwes_fpath = "/root/projects/VDTest/data/CWE/treevul_invalid_cwes.json"
    with open(treevul_invalid_cwes_fpath, "r") as f:
        treevul_invalid_cwes = json.load(f)

    dataset_fpaths = [
        "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_nvdvul_v1.json",
        "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_vulfix.json",
        "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_treevul.json"
    ]

    for dataset_fpath in dataset_fpaths:
        with open(dataset_fpath, "r") as f:
            dataset = json.load(f)

        for data in dataset:
            cwe_id = data["cwe_id"]

            if cwe_id in treevul_invalid_cwes:
                continue

            if cwe_id in treevul_cwe_paths:
                if len(treevul_cwe_paths[cwe_id]) != data["cwe_depth"]:
                    print(data["source"] + " " + data["commit_hash"])


def check_original_treevul_cwe_paths():
    treevul_cwe_paths_fpath = "/root/projects/TreeVul/data/cwe_path.json"
    with open(treevul_cwe_paths_fpath, "r") as f:
        treevul_cwe_paths = json.load(f)

    standard_cwe_paths_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(standard_cwe_paths_fpath, "r") as f:
        standard_cwe_paths = json.load(f)

    diff_cwe_ids = []

    for full_cwe_id, full_cwe_path in treevul_cwe_paths.items():
        cwe_id = full_cwe_id.split("-")[-1]
        cwe_path = [full_cwe_id.split("-")[-1] for full_cwe_id in full_cwe_path]

        assert cwe_id in standard_cwe_paths
        if cwe_path not in standard_cwe_paths[cwe_id]["cwe_paths"]:
            diff_cwe_ids.append(full_cwe_id)

    save_fpath = "/root/projects/VDTest/data/CWE/treevul_invalid_cwes.json"
    with open(save_fpath, "w") as f:
        json.dump(diff_cwe_ids, f, indent=4)


def group_cwe_by_depth(cwe_tree_fpath: str, output_dpath: str):
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    multi_path_cwes = {}
    all_cwes = [[], [], [], [], [], []]

    for cwe_id, data in cwe_tree.items():
        full_cwe_id = f"CWE-{cwe_id}"
        cwe_paths = data["cwe_paths"]
        all_depths = []

        for cwe_path in cwe_paths:
            depth = len(cwe_path)

            all_depths.append(depth)
            if full_cwe_id not in all_cwes[depth - 1]:
                all_cwes[depth - 1].append(full_cwe_id)

        if len(all_depths) > 1:
            all_depths = sorted(set(all_depths))
            multi_path_cwes[full_cwe_id] = " ".join([str(d) for d in all_depths])

    all_cwes_fpath = os.path.join(output_dpath, "processed_cwes.json")
    with open(all_cwes_fpath, "w") as f:
        json.dump(all_cwes, f, indent=4)

    multi_path_cwes_fpath = os.path.join(output_dpath, "multi_depth_cwes.json")
    with open(multi_path_cwes_fpath, "w") as f:
        json.dump(multi_path_cwes, f, indent=4)


def update_cwe_tree_by_depth(cwe_tree_fpath: str, ref_depth: int = 3, opt: int = 1):
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    updt_cwe_tree = {}

    for cwe_id, data in cwe_tree.items():

        depths = []
        for path in data["cwe_paths"]:
            depths.append(len(path))
        depths = sorted(set(depths))

        if opt == 1:
            # Strategy 1: Choose the deepest path
            cwe_depth = depths[-1]
        elif opt == 2:
            # Strategy 2: Based on reference depth
            if len(depths) == 1:
                cwe_depth = depths[0]
            else:
                more_than_ref_depths = [d for d in depths if d > 3]
                less_than_ref_depths = [d for d in depths if d < 3]

                if ref_depth in depths:
                    cwe_depth = ref_depth
                elif len(more_than_ref_depths) == len(depths):
                    cwe_depth = min(depths)
                elif len(less_than_ref_depths) == len(depths):
                    cwe_depth = max(depths)
                else:
                    cwe_depth = min(more_than_ref_depths)
        else:
            raise RuntimeError(f"Option {opt} is not supported yet.")

        data["cwe_depth"] = cwe_depth
        updt_cwe_tree[cwe_id] = data

    with open(cwe_tree_fpath, "w") as f:
        json.dump(updt_cwe_tree, f, indent=4)


def update_dataset_by_cwe_depth(dataset_fpath: str, cwe_tree_fpath: str):
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    with open(dataset_fpath, "r") as f:
        dataset = json.load(f)

    updt_dataset = []
    for data in dataset:
        cwe_id = data["cwe_id"].split("-")[-1]
        assert cwe_id in cwe_tree

        data["cwe_depth"] = cwe_tree[cwe_id]["cwe_depth"]
        updt_dataset.append(data)

    with open(dataset_fpath, "w") as f:
        json.dump(updt_dataset, f, indent=4)


if __name__ == '__main__':
    pass

    view_id = "888"
    # crawl_cwe_tree(view_id)
    # count_cwe_tree(view_id)

    # build_cwe_entry_from_cwe_tree(view_id)

    # crawl_view_category_name(view_id)
    # crawl_view_888_category_name(view_id)

    # process_raw_cwe_tree(view_id)

    # compare_cwe_collected_with_treevul()

    # check_dataset_cwe_depth()

    # check_original_treevul_cwe_paths()


    ## CWE Depth
    cwe_tree_file = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    output_dir = "/root/projects/VDTest/data/CWE/VIEW_1000"

    # 1. Update CWE tree
    # update_cwe_tree_by_depth(cwe_tree_file, opt=2)

    # 2. Update dataset
    # dataset_files = [
    #     # "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_nvdvul_v1.json",
    #     # "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_vulfix.json",
    #     # "/root/projects/VDTest/dataset/Final/VIEW_1000/py_vul_tasks_treevul.json",
    #     "/root/projects/VDTest/dataset/Final/VIEW_1000/java_vul_tasks_treevul.json"
    # ]
    # for dataset_file in dataset_files:
    #     update_dataset_by_cwe_depth(dataset_file, cwe_tree_file)
