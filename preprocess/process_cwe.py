from __future__ import annotations

import os
import json
import csv
import re
import numpy as np
import matplotlib.pyplot as plt
import torch

from typing import *

from tqdm import tqdm
from collections import defaultdict
from dataclasses import dataclass, field
from collections import Counter
from nltk import word_tokenize, pos_tag
from nltk.corpus import wordnet
from nltk.stem import WordNetLemmatizer

from openai import OpenAI
from openai.types.chat.completion_create_params import ResponseFormat
from transformers import BertTokenizer, BertModel
from sklearn.cluster import DBSCAN, KMeans
from sklearn.metrics import silhouette_score, davies_bouldin_score
from sklearn.metrics.pairwise import cosine_similarity
from scipy.cluster.hierarchy import dendrogram, linkage, fcluster
from scipy.spatial.distance import cdist, squareform

from agent_app.CWE.cwe_util import VIEWInfo


"""CWE ENTRIES"""


def read_cwe_csv(csv_path: str, save_dpath: str):
    cwe_entries: List[Dict] = []

    with open(csv_path) as f:
        reader = csv.reader(f)
        title = next(reader)

        for i, row in enumerate(reader):
            cwe_entry = {}
            for v, attr in zip(row, title):
                cwe_entry[attr] = v
            cwe_entries.append(cwe_entry)

    cwe_entries_fpath = os.path.join(save_dpath, 'CWE_entries.json')
    with open(cwe_entries_fpath, "w") as f:
        f.write(json.dumps(cwe_entries, indent=4))


"""CWE TREE"""
# FIXME: This section is not yet complete


def build_cwe_tree(cwe_entries_fpath: str, save_dpath: str):
    with open(cwe_entries_fpath, "r") as f:
        cwe_entries = json.load(f)

    cwe_tree: Dict[str, Dict] = {}

    father_children_list = []
    left_items = []
    for cwe_entry in cwe_entries:
        father = None
        current = str(cwe_entry["CWE-ID"])
        relations = cwe_entry["Related Weaknesses"]

        diff_view_relations = relations.split("::")
        for view_relations in diff_view_relations:
            if "VIEW ID:1003" in view_relations:
                rels = view_relations.split(':')
                for i, rel in enumerate(rels):
                    if rel == "ChildOf":
                        assert father is None
                        father = str(rels[i+2])

        if father is not None:
            left_flag = True
            for father_children in father_children_list:
                if father in father_children:
                    left_flag = False
                    father_children[father].append(current)
                    break
            if left_flag:
                left_items.append([father, current])
        else:
            for father_children in father_children_list:
                assert current not in father_children

            father_children_list.append({current: []})

    while left_items:
        current = left_items.pop()
        for father_children in father_children_list:
            if current[0] in father_children:
                father_children[current[0]].append(current[1])
                break

    root = "1003"
    cwe_tree[root] = father_children_list


def extract_view_rels_from_csv(csv_path, save_dpath):
    focus_view_ids = ['1000', '699']

    cwe_items_dict = {}
    cwe_simple_item_dict = {}

    with open(csv_path) as f:
        reader = csv.reader(f)
        title = next(reader)

        for i, row in enumerate(reader):
            cwe_id = None
            cwe_item = {}
            cwe_simple_item = {}
            for v, attr in zip(row, title):
                # Full info
                cwe_item[attr] = v

                # Simplified info
                if attr == 'CWE-ID':
                    cwe_simple_item[attr] = v
                    cwe_id = v
                elif attr == 'Related Weaknesses':
                    for view_id in focus_view_ids:
                        cwe_simple_item['VIEW-' + view_id] = {'father': [],
                                                              'children': []}

                    rels = v.split("::")
                    for rel in rels:
                        if rel == '':
                            continue

                        rel_items = rel.split(':')
                        if rel_items[5] in focus_view_ids:
                            current_view_attr = 'VIEW-' + rel_items[5]
                            rel_name = rel_items[1]
                            rel_cwe_id = rel_items[3]

                            if rel_name == 'ChildOf' or rel_name == 'MemberOf':
                                cwe_simple_item[current_view_attr]['father'].append(rel_cwe_id)
                            elif rel_name == 'ParentOf' or rel_name == 'HasMember':
                                cwe_simple_item[current_view_attr]['children'].append(rel_cwe_id)
                            elif rel_name in cwe_simple_item[current_view_attr]:
                                cwe_simple_item[current_view_attr][rel_name].append(rel_cwe_id)
                            else:
                                cwe_simple_item[current_view_attr][rel_name] = [rel_cwe_id]
                else:
                    pass

            assert cwe_id is not None
            cwe_items_dict[cwe_id] = cwe_item
            cwe_simple_item_dict[cwe_id] = cwe_simple_item

    for view_id in focus_view_ids:
        update_full_rels(cwe_simple_item_dict, view_id)
        break

    # Save
    if not os.path.exists(save_dpath):
        os.makedirs(save_dpath, exist_ok=True)

    prefix = csv_path.split('/')[-1][:-4]

    cwe_items_fpath = os.path.join(save_dpath, 'VIEW-' + prefix + '_CWEItems' + '.json')
    cwe_simple_items_fpath = os.path.join(save_dpath, 'VIEW-' + prefix + '_CWESimpleItems' + '.json')

    with open(cwe_items_fpath, "w") as f:
        f.write(json.dumps(cwe_items_dict, indent=4))

    with open(cwe_simple_items_fpath, "w") as f:
        f.write(json.dumps(cwe_simple_item_dict, indent=4))


def can_add(fathers: List, qualified_cwe_id_list: List) -> bool:
    flag = True
    for father in fathers:
        if father not in qualified_cwe_id_list:
            flag = False
            break

    return flag


def update_qualified_cwe_item(
        child, fathers: List,
        view_id: str,
        qualified_cwe_id_list: List,
        cwe_simple_item_dict: Dict
):
    """
        :param child: CWE-ID of CWE item to be added
        :param fathers: CWE-ID list of fathers of CWE item to be added
        :param view_id: VIEW ID
        :param qualified_cwe_id_list: CWE-ID list of all qualified CWE items
        :param cwe_simple_item_dict: List of all CWE items with simplified info

        Update a qualified CWE item, including `qualified_cwe_id_list` and `cwe_simple_item_list`
    """
    qualified_cwe_id_list.append(child)
    for father in fathers:
        # Add info about the child
        if child not in cwe_simple_item_dict[father]["VIEW-" + view_id]["children"]:
            cwe_simple_item_dict[father]["VIEW-" + view_id]["children"].append(child)


def update_full_rels(cwe_simple_item_dict: Dict, view_id: str = "1000"):
    """
        :param cwe_simple_item_dict: Each element is like -> CWE-ID: {attr1: v1, attr2: v2, ...}
        :param view_id: VIEW ID, by default = "1000"

         CWE items in `cwe_simple_item_list` only have complete father information,
         need update their children information.
         Note: VIEW-1000 and VIEW-699 only.
    """
    # By default, all item's father information is complete.

    qualified_cwe_id_list = []
    left_cwe_id_list = []

    for current_id, cwe_simple_item in cwe_simple_item_dict.items():

        if len(cwe_simple_item["VIEW-" + view_id]["father"]) == 0:
            qualified_cwe_id_list.append(current_id)
        else:
            can_add_flag = can_add(cwe_simple_item["VIEW-" + view_id]["father"], qualified_cwe_id_list)

            if can_add_flag:
                update_qualified_cwe_item(child=current_id, fathers=cwe_simple_item["VIEW-" + view_id]["father"],
                                          view_id=view_id,
                                          qualified_cwe_id_list=qualified_cwe_id_list,
                                          cwe_simple_item_dict=cwe_simple_item_dict)
            else:
                left_cwe_id_list.append(current_id)

    while left_cwe_id_list:
        current_id = left_cwe_id_list.pop(0)
        can_add_flag = can_add(cwe_simple_item_dict[current_id]["VIEW-" + view_id]["father"], qualified_cwe_id_list)

        if can_add_flag:
            update_qualified_cwe_item(child=current_id, fathers=cwe_simple_item_dict[current_id]["VIEW-" + view_id]["father"],
                                      view_id=view_id,
                                      qualified_cwe_id_list=qualified_cwe_id_list,
                                      cwe_simple_item_dict=cwe_simple_item_dict)
        else:
            left_cwe_id_list.append(current_id)


"""CWE PATH"""


def find_cwe_paths(cwe_id: str, cwe_tree: Dict[str, Dict]) -> List[List[str]]:
    if len(cwe_tree[cwe_id]["father"]) == 0:
        return [[cwe_id]]
    else:
        paths: List[List[str]] = []
        for father_id in cwe_tree[cwe_id]["father"]:
            father_paths = find_cwe_paths(father_id, cwe_tree)
            for father_path in father_paths:
                path = father_path + [cwe_id]
                paths.append(path)
        return paths


def refine_cwe_tree_with_paths(cwe_tree_fpath: str) -> None:
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    for cwe_id, data in cwe_tree.items():
        cwe_paths = find_cwe_paths(cwe_id, cwe_tree)
        cwe_tree[cwe_id]["cwe_paths"] = cwe_paths

    with open(cwe_tree_fpath, "w") as f:
        json.dump(cwe_tree, f, indent=4)


def check_cwe_paths_and_print(cwe_tree_fpath: str) -> None:
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    for cwe_id, data in cwe_tree.items():
        # Find CWE with multiple paths with different length (< 3)
        if len(data["cwe_paths"]) > 1:
            depth_3_flag = False
            depth_2_flag = False
            for path in data["cwe_paths"]:
                if len(path) == 3:
                    depth_3_flag = True
                if len(path) <= 2:
                    depth_2_flag = True
            if depth_3_flag and depth_2_flag:
                print(cwe_id)


def find_diff_depth_cwe(cwe_tree_fpath: str, save_dpath: str, max_depth: int = 3) -> None:
    with open(cwe_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    # depth -> [cwe_id]
    diff_depth_cwe_ids: Dict[int, List[str]] = defaultdict(list)
    depths = list(range(1, max_depth + 1))

    for cwe_id, data in cwe_tree.items():
        # TODO: For CWE with multiple paths, we only focus on one of those paths, i.e. the one with the shortest length
        #       This problem exists under VIEW-1000 (not under view VIEW-1003)
        min_path = min(data["cwe_paths"], key=len)
        if len(min_path) in depths:
            diff_depth_cwe_ids[len(min_path)].append(cwe_id)

    for depth, cwe_ids in diff_depth_cwe_ids.items():
        if len(cwe_ids) > 0:
            save_fpath = os.path.join(save_dpath, f"CWE_depth_{depth}.json")
            with open(save_fpath, "w") as f:
                json.dump(cwe_ids, f, indent=4)


"""COMPARISON WITH TREEVUL"""


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


"""SUMMARIZE CWE ATTRIBUTES"""


WEAKNESS_ATTRS_EXTRACTION_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information. 
Please summarise two important features of the given vulnerability:
- 1. Trigger Action: Direct behaviour leading to vulnerability.
- 2. Key Variables: Conditions, states or parameters directly related to the triggered action.

For trigger action, you should notice:
1. Consider the environment and context in which the trigger action occurs, such as the user role, whether there are specific inputs, whether there are access restrictions, etc.
2. Ensure that there is a difference between a trigger action and a normal action. For example, if the trigger action is an API call, the description should include specific parameters and possible exception inputs.

For key variables, you should notice：
1. Use the noun form wherever possible, making it point to a concretely existing entity or property rather than describing an abstract behaviour or result.
2. Do not use broad concepts, such as methods, interfaces, but rather more detailed descriptions, such as, variables that store sensitive data, access control list.

NOTE: Do not copy directly from any of the examples or descriptions I have given.
"""


WEAKNESS_ATTRS_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

interface Attributes {
    trigger_action: string;
    key_variables: string[];
};

Now based on the given context, write a JSON dict that conforms to the Attributes schema.
"""


def summarize_all_weakness_attributes(output_dpath: str, max_depth: int = 3):
    ## (1) Prepare attribute cwe trees
    all_categories: Dict[str, str] = {}
    all_attr_view_info: Dict[str, VIEWInfo] = {}

    # VIEW 699
    view_699_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_699/CWE_tree.json"
    with open(view_699_tree_fpath, "r") as f:
        view_699_tree = json.load(f)
    all_attr_view_info["699"] = VIEWInfo("concepts in software development", view_699_tree)

    view_699_entries_fpath = "/root/projects/VDTest/data/CWE/VIEW_699/CWE_entries.json"
    with open(view_699_entries_fpath, "r") as f:
        view_699_entries = json.load(f)
    for data in view_699_entries:
        if data["Type"] == "category":
            cwe_id = data["CWE-ID"]
            assert cwe_id not in all_categories
            all_categories[cwe_id] = data["Name"]

    # VIEW 888
    view_888_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_888/CWE_tree.json"
    with open(view_888_tree_fpath, "r") as f:
        view_888_tree = json.load(f)
    all_attr_view_info["888"] = VIEWInfo("software fault pattern", view_888_tree)

    view_888_entries_fpath = "/root/projects/VDTest/data/CWE/VIEW_888/CWE_entries.json"
    with open(view_888_entries_fpath, "r") as f:
        view_888_entries = json.load(f)
    for data in view_888_entries:
        if data["Type"] == "category":
            cwe_id = data["CWE-ID"]
            assert cwe_id not in all_categories
            all_categories[cwe_id] = data["Name"]

    # VIEW 1400
    view_1400_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1400/CWE_tree.json"
    with open(view_1400_tree_fpath, "r") as f:
        view_1400_tree = json.load(f)
    all_attr_view_info["1400"] = VIEWInfo("software assurance trends", view_1400_tree)

    view_1400_entries_fpath = "/root/projects/VDTest/data/CWE/VIEW_1400/CWE_entries.json"
    with open(view_1400_entries_fpath, "r") as f:
        view_1400_entries = json.load(f)
    for data in view_1400_entries:
        if data["Type"] == "category":
            cwe_id = data["CWE-ID"]
            assert cwe_id not in all_categories
            all_categories[cwe_id] = data["Name"]

    ## (2) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (3) Main
    view_1000_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(view_1000_tree_fpath, "r") as f:
        view_1000_tree = json.load(f)

    all_weakness_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(all_weakness_fpath, "r") as f:
        all_weakness = json.load(f)

    failed_weakness = []
    all_weakness_attrs: Dict[str, Dict] = {}
    with tqdm(total=len(all_weakness)) as pb:
        for weakness_data in all_weakness:
            weakness_id = weakness_data["CWE-ID"]
            weakness_name = weakness_data["Name"]
            basic_desc = weakness_data["Description"]
            extended_desc = weakness_data["Extended Description"]

            # Filter
            assert weakness_id in view_1000_tree
            cwe_paths = view_1000_tree[weakness_id]["cwe_paths"]
            if min([len(p) for p in cwe_paths]) > max_depth:
                continue

            # 1. Basic description
            usr_msg = (f"Now please analyse and summarize the vulnerability CWE-{weakness_id}: {weakness_name}."
                       f"\nDescription: {basic_desc}")

            # 2. Extended description
            if extended_desc != "":
                usr_msg += f"\nExtended Description: {extended_desc}"

            # 3. Attributes under other views
            all_view_desc: List[str] = []
            for view_id, view_info in all_attr_view_info.items():
                cl_basis = view_info.basis
                cwe_tree = view_info.cwe_tree

                if weakness_id in cwe_tree:
                    cwe_paths: List[List[str]] = cwe_tree[weakness_id]["cwe_paths"]

                    related_attrs = []
                    for path in cwe_paths:
                        for curr_id in reversed(path):
                            if curr_id in all_categories:
                                related_attrs.append(all_categories[curr_id])
                                break
                    related_attrs_str = ', '.join(related_attrs)

                    view_desc = f"In VIEW-{view_id}, CWEs are clustered according to {cl_basis}, while CWE-{weakness_id} is related to {related_attrs_str}."
                    all_view_desc.append(view_desc)

            if all_view_desc:
                entire_view_desc = f"Besides, it has the following attributes:"
                for i, view_desc in enumerate(all_view_desc):
                    entire_view_desc += f"\n{i+1}. {view_desc}"

                usr_msg += f"\n{entire_view_desc}"

            # 4. Format
            usr_msg += f"\n\n{WEAKNESS_ATTRS_FORMAT_PROMPT}"

            messages = [
                {
                    "role": "system",
                    "content": WEAKNESS_ATTRS_EXTRACTION_SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": usr_msg
                }
            ]

            # print("\n" + "=" * 30 + " SYSTEM " + "=" * 30 + "\n")
            # print(SYSTEM_PROMPT)
            # print("\n" + "-" * 30 + " USER " + "-" * 30 + "\n")
            # print(usr_msg)

            response = client.chat.completions.create(
                model="gpt-4o-2024-05-13",
                messages=messages,
                temperature=0.2,
                response_format=ResponseFormat(type="json_object")
            ).choices[0].message

            if response.content is None:
                response = ""
                failed_weakness.append(weakness_id)
            else:
                response = response.content

            json_response = json.loads(response)

            # print("\n" + "-" * 30 + " LLM " + "-" * 30 + "\n")
            # print(json.dumps(json_response, indent=4))

            if isinstance(json_response, dict) and \
                    "trigger_action" in json_response and \
                    "key_variables" in json_response and \
                    isinstance(json_response["key_variables"], list):
                all_weakness_attrs[weakness_id] = json_response

            pb.update(1)

    ## (4) Save
    save_fpath = os.path.join(output_dpath, "all_weakness_attrs.json")
    with open(save_fpath, "w") as f:
        json.dump(all_weakness_attrs, f, indent=4)

    failed_weakness_fpath = os.path.join(output_dpath, "failed_weakness.json")
    with open(failed_weakness_fpath, "w") as f:
        json.dump(failed_weakness, f, indent=4)


WEAKNESS_ATTRS_SUMMARY_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information. 
For each weakness, we have summarized its two important attributes:
- 1. Trigger Action: Direct behaviour leading to vulnerability.
- 2. Key Variables: Conditions, states or parameters directly related to the triggered action.

Now for the given weakness, since it is abstract, we cannot extract its attributes by analysing its description directly, therefore, we also give the description and attributes of all its child CWE.
Your task is to summarize the attributes of the weakness based on the information provided, satisfying the following requirements:
1. For key variables, their characteristics must not be too broad, but it can also cover the characteristics of the key variables of all child CWEs. 
2. DO NOT COPY key variables of child CWEs, you need to abstract them.

For trigger action, you should notice:
1. Consider the environment and context in which the trigger action occurs, such as the user role, whether there are specific inputs, whether there are access restrictions, etc.
2. Ensure that there is a difference between a trigger action and a normal action. For example, if the trigger action is an API call, the description should include specific parameters and possible exception inputs.

For key variables, you should notice：
1. Use the noun form wherever possible, making it point to a concretely existing entity or property rather than describing an abstract behaviour or result.
2. Do not use broad concepts, such as methods, interfaces, but rather more detailed descriptions, such as, variables that store sensitive data, access control list.

NOTE: Do not copy directly from any of the examples or descriptions I have given.
"""


def recap_all_weakness_attributes(output_dpath: str):

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    view_1000_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(view_1000_tree_fpath, "r") as f:
        view_1000_tree = json.load(f)

    all_weakness_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(all_weakness_fpath, "r") as f:
        all_weakness = json.load(f)
    all_weakness_dict = {weakness_data["CWE-ID"]: weakness_data for weakness_data in all_weakness}

    weakness_attrs_fpath = os.path.join(output_dpath, "all_weakness_attrs.json")
    with open(weakness_attrs_fpath, "r") as f:
        all_weakness_attrs = json.load(f)

    # Process weakness with depth = 2
    failed_weakness = []
    recap_weakness_attrs: Dict[str, Dict] = {}

    with tqdm(total=len(all_weakness_attrs)) as pb:
        for weakness_id, weakness_attrs in all_weakness_attrs.items():
            cwe_paths = view_1000_tree[weakness_id]["cwe_paths"]

            process_flag = False
            for cwe_path in cwe_paths:
                if len(cwe_path) == 2:
                    process_flag = True
                    break

            if process_flag:
                weakness_name = all_weakness_dict[weakness_id]["Name"]
                basic_desc = all_weakness_dict[weakness_id]["Description"]
                extended_desc = all_weakness_dict[weakness_id]["Extended Description"]

                # 1. Basic information
                usr_msg = (f"Now please analyse and summarize the vulnerability CWE-{weakness_id}: {weakness_name}."
                           f"\nDescription: {basic_desc}")

                # 2. Extended description
                if extended_desc != "":
                    usr_msg += f"\nExtended Description: {extended_desc}"

                # 3. Children information
                children_desc = ""
                for i, child in enumerate(view_1000_tree[weakness_id]["children"]):
                    child_name = all_weakness_dict[child]["Name"]
                    child_desc = all_weakness_dict[child]["Description"]
                    trigger_action = all_weakness_attrs[child]["trigger_action"]
                    key_variables_str = ', '.join(all_weakness_attrs[child]["key_variables"])
                    children_desc += (f"\n\nChild {i + 1}: CWE-{child} ({child_name})"
                                      f"\n- Description: {child_desc}"
                                      f"\n- Trigger Action: {trigger_action}"
                                      f"\n- Key Variables: {key_variables_str}")

                usr_msg += ("It has the following child CWEs:"
                            f"{children_desc}")

                # 4. Format
                usr_msg += f"\n\n{WEAKNESS_ATTRS_FORMAT_PROMPT}"

                messages = [
                    {
                        "role": "system",
                        "content": WEAKNESS_ATTRS_SUMMARY_SYSTEM_PROMPT
                    },
                    {
                        "role": "user",
                        "content": usr_msg
                    }
                ]

                # print("\n" + "=" * 30 + " SYSTEM " + "=" * 30 + "\n")
                # print(WEAKNESS_ATTRS_FORMAT_PROMPT)
                # print("\n" + "-" * 30 + " USER " + "-" * 30 + "\n")
                # print(usr_msg)

                response = client.chat.completions.create(
                    model="gpt-4o-2024-05-13",
                    messages=messages,
                    temperature=0.2,
                    response_format=ResponseFormat(type="json_object")
                ).choices[0].message

                if response.content is None:
                    response = ""
                    failed_weakness.append(weakness_id)
                else:
                    response = response.content

                json_response = json.loads(response)

                # print("\n" + "-" * 30 + " LLM " + "-" * 30 + "\n")
                # print(json.dumps(json_response, indent=4))

                if isinstance(json_response, dict) and \
                        "trigger_action" in json_response and \
                        "key_variables" in json_response and \
                        isinstance(json_response["key_variables"], list):
                    recap_weakness_attrs[weakness_id] = json_response

            pb.update(1)

    ## (4) Save
    save_fpath = os.path.join(output_dpath, "recap_weakness_attrs.json")
    with open(save_fpath, "w") as f:
        json.dump(recap_weakness_attrs, f, indent=4)

    failed_weakness_fpath = os.path.join(output_dpath, "failed_weakness.json")
    with open(failed_weakness_fpath, "w") as f:
        json.dump(failed_weakness, f, indent=4)


def update_all_weakness_attrs_with_recap_attrs(output_dpath: str):
    weakness_attrs_fpath = os.path.join(output_dpath, "all_weakness_attrs.json")
    with open(weakness_attrs_fpath, "r") as f:
        all_weakness_attrs = json.load(f)

    recap_weakness_attrs_fpath = os.path.join(output_dpath, "recap_weakness_attrs.json")
    with open(recap_weakness_attrs_fpath, "r") as f:
        recap_weakness_attrs = json.load(f)

    # Update
    old_weakness_attrs_fpath = weakness_attrs_fpath.replace("all_weakness_attrs.json", "old_all_weakness_attrs.json")
    with open(old_weakness_attrs_fpath, "w") as f:
        json.dump(all_weakness_attrs, f, indent=4)

    for weakness_id, _ in all_weakness_attrs.items():
        if weakness_id in recap_weakness_attrs:
            all_weakness_attrs[weakness_id] = recap_weakness_attrs[weakness_id]

    new_weakness_attrs_fpath = weakness_attrs_fpath
    with open(new_weakness_attrs_fpath, "w") as f:
        json.dump(all_weakness_attrs, f, indent=4)


def adjust_key_variable_format_of_weaknesses(weakness_attrs_fpath: str):
    with open(weakness_attrs_fpath, "r") as f:
        weakness_attrs = json.load(f)

    updt_weakness_attrs = {}
    for weakness_id, attrs in weakness_attrs.items():
        updt_attrs = {
            "trigger_action": attrs["trigger_action"],
            "key_variables": [key_var.replace('_', ' ').lower() for key_var in attrs["key_variables"]]
        }
        updt_weakness_attrs[weakness_id] = updt_attrs

    with open(weakness_attrs_fpath, "w") as f:
        json.dump(updt_weakness_attrs, f, indent=4)


"""KEY VARIABLE KNOWLEDGE GRAPH"""


KEY_VAR_GRAPH_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information. 
For each weakness, we have summarized its two important attributes:
- 1. Trigger Action: Direct behaviour leading to vulnerability.
- 2. Key Variables: Conditions, states or parameters directly related to the triggered action.

The goal is to construct a knowledge graph for key variables for all given weaknesses. The graph is constructed as follows:
1. Two types of nodes: 
- node_w (weakness_node): node representing the weakness
- node_v (key_variable_node): node representing the key variable
2. Two types of edges: 
- edge_c (contain_edge): edge from node_w to node_v, indicating that the weakness [node_w] contains the key variable [node_v]
- edge_p (parent_edge): edge from node_v1 to node_v2, indicating that the range of key variable [node_v1] contains the key variable [node_v2]

However, the existing key variables for each weakness are of various forms and lack of uniformity. There are two main problems:
1. Synonymous key variables: For example, 'input data' and 'input_data' are written differently, and 'input data' and 'input value' are expressed differently, but they represent the same thing.
2. Key variables with hierarchical relationships: For example, 'input data from user' can be regarded as a child word of 'input data'. The basic idea is that the parent word expresses a broader concept, while the child word provides more specific information.

Therefore, the idea of solving the above two problems is as follows:
1. For synonymous key variables, unify their expressions and use one node to represent them in the knowledge graph.
2. For key variables with hierarchical relationships, use edge_p to connect them from parent word to child word.

Next, I will provide you with several weaknesses and their trigger actions and key variables, please refine the knowledge graph of key variables.

NOTE: Do not copy directly from any of the examples or descriptions I have given.
"""


KEY_VAR_GRAPH_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

Each node has its own id, and the ids of all nodes (include weakness nodes and key variable nodes) cannot be duplicated. 
Besides, use the node id to indicate the start and end point of the edge. For example, [2, 4] indicates the edge from the node with id 2 to the node with id 4.

type NodeId = number;
type KeyVariableNode = [NodeId, string];
type Edge = [NodeId, NodeId];

interface Graph {
    key_variable_nodes: KeyVariableNode[];
    edges: Edge[];
};

Now based on the given context, write a JSON dict that conforms to the Graph schema.
"""


@dataclass
class KeyVariableGraph:
    weakness_nodes: Dict[int, str] = field(default_factory=dict)
    key_variable_nodes: Dict[int, str] = field(default_factory=dict)
    edges: List[Tuple[int, int]] = field(default_factory=list)

    def to_dict(self):
        return {
            "weakness_nodes": self.weakness_nodes,
            "key_variable_nodes": self.key_variable_nodes,
            "edges": self.edges
        }

    def to_str(self):
        graph_desc = "Graph construction:"

        graph_desc += "\n\n(1) Weakness Nodes:"
        for node_id, node_name in self.weakness_nodes.items():
            graph_desc += f"\n  {node_id}: {node_name}"

        graph_desc += "\n\n(2) Key Variable Nodes:"
        for node_id, node_name in self.key_variable_nodes.items():
            graph_desc += f"\n  {node_id}: {node_name}"

        graph_desc += "\n\n(3) Edges:"
        for node_from, node_to in self.edges:
            graph_desc += f"\n  {node_from} -> {node_to}"

        return graph_desc

    def is_empty(self):
        return len(self.weakness_nodes) == 0 and len(self.key_variable_nodes) == 0 and len(self.edges) == 0

    def node_exists(self, node_id):
        return node_id in self.weakness_nodes or node_id in self.key_variable_nodes

    def update_weakness_nodes(self, node_id: int, weakness_id: str) -> bool:
        if self.node_exists(node_id):
            return False
        self.weakness_nodes[node_id] = weakness_id
        return True

    def update_key_variable_nodes(self, node_id: int, key_variable_name: str) -> bool:
        if self.node_exists(node_id):
            return False
        self.key_variable_nodes[node_id] = key_variable_name
        return True

    def update_edges(self, node_from: int, node_in: int) -> bool:
        if self.node_exists(node_from) and self.node_exists(node_in):
            self.edges.append((node_from, node_in))
            self.edges = list(set(self.edges))
            return True
        else:
            return False


def update_key_variable_graph(graph: KeyVariableGraph, round_weakness_descs: List[str], client: OpenAI):
    weakness_msg = "Given the following weaknesses:"

    for weakness_desc in round_weakness_descs:
        weakness_msg += f"\n\n{weakness_desc}"

    graph_msg = ("\n\nNow the knowledge graph of key variables is shown below:"
                 f"\n{graph.to_str()}"
                 "\n\nNote that we have already added the necessary weakness nodes, so you cannot modify the weakness nodes."
                 f"\nBesides, while adding key variable nodes, their ids should not duplicate the ids of the weakness nodes (1-{len(graph.weakness_nodes)} is the range of ids of the weakness nodes)."
                 "\nPlease update the graph based on the information above."
                 f"\n\n{KEY_VAR_GRAPH_FORMAT_PROMPT}")

    messages = [
        {
            "role": "system",
            "content": KEY_VAR_GRAPH_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": weakness_msg
        },
        {
            "role": "user",
            "content": graph_msg
        }
    ]

    # print("\n" + "=" * 30 + " SYSTEM " + "=" * 30 + "\n")
    # print(KEY_VAR_GRAPH_SYSTEM_PROMPT)
    # print("\n" + "-" * 30 + " USER " + "-" * 30 + "\n")
    # print(weakness_msg)
    # print("\n" + "-" * 30 + " USER " + "-" * 30 + "\n")
    # print(graph_msg)

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.2,
        response_format=ResponseFormat(type="json_object")
    ).choices[0].message

    messages.append({"role": "assistant", "content": response})

    if response.content is None:
        raise RuntimeError
    else:
        response = response.content

    try:
        json_response = json.loads(response)
    except json.JSONDecodeError:
        print(response)
        raise RuntimeError

    # print("\n" + "-" * 30 + " LLM " + "-" * 30 + "\n")
    # print(json.dumps(json_response, indent=4))

    if isinstance(json_response, dict) and \
            "key_variable_nodes" in json_response and isinstance(json_response["key_variable_nodes"], list) and \
            "edges" in json_response and isinstance(json_response["edges"], list):

        # 1. Add key variable nodes
        for node_id, node_name in json_response["key_variable_nodes"]:
            if isinstance(node_id, str) and node_id.isdigit():
                node_id = int(node_id)
            elif isinstance(node_id, int):
                pass
            else:
                raise RuntimeError(f"Failed to add key variable node: {node_id} {node_name}")

            flag = graph.update_key_variable_nodes(node_id, node_name)
            if not flag:
                raise RuntimeError(f"Failed to add key variable node: {node_id} {node_name}")

        # 2. Add edges
        for node_from, node_in in json_response["edges"]:
            if isinstance(node_from, str) and node_from.isdigit():
                node_from = int(node_from)
            elif isinstance(node_from, int):
                pass
            else:
                raise RuntimeError(f"Failed to add edge: {node_from} {node_in}")

            if isinstance(node_in, str) and node_in.isdigit():
                node_in = int(node_in)
            elif isinstance(node_in, int):
                pass
            else:
                raise RuntimeError(f"Failed to add edge: {node_from} {node_in}")

            flag = graph.update_edges(node_from, node_in)
            if not flag:
                raise RuntimeError(f"Failed to add edge: {node_from} {node_in}")

    else:
        print(json_response)
        raise RuntimeError


def build_key_variable_graph_by_groups(graph_dpath: str):

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    all_weakness_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(all_weakness_fpath, "r") as f:
        all_weakness = json.load(f)
    all_weakness_dict = {weakness_data["CWE-ID"]: weakness_data for weakness_data in all_weakness}

    view_1000_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(view_1000_tree_fpath, "r") as f:
        view_1000_tree = json.load(f)

    recap_weakness_attrs_fpath = "/root/projects/VDTest/data/CWE/weakness_attributes/recap_weakness_attrs.json"
    with open(recap_weakness_attrs_fpath, "r") as f:
        recap_weakness_attrs = json.load(f)

    depth_1_weakness_ids = [
        "CWE-284",
        "CWE-435",
        "CWE-664",
        "CWE-682",
        "CWE-691",
        "CWE-693",
        "CWE-697",
        "CWE-703",
        "CWE-707",
        "CWE-710"
    ]

    group_weakness_num = 10
    added_weakness_ids = []

    for depth_1_full_weakness_id in depth_1_weakness_ids:
        depth_1_weakness_id = depth_1_full_weakness_id.split("-")[-1]

        children = view_1000_tree[depth_1_weakness_id]["children"]
        children_groups = [children[i:i + group_weakness_num] for i in range(0, len(children), group_weakness_num)]

        # Construct a graph for each group (10 child weaknesses) in the children of depth-1 weakness
        for i, children_group in enumerate(children_groups):
            print(f"{depth_1_full_weakness_id} ({i + 1}/{len(children_groups)}) ...")

            graph: KeyVariableGraph = KeyVariableGraph()

            node_id = 0
            group_weakness_descs: List[str] = []

            for weakness_id in children_group:
                assert weakness_id in recap_weakness_attrs
                if weakness_id not in added_weakness_ids:
                    added_weakness_ids.append(weakness_id)

                    ## 1. Init graph with weakness nodes
                    node_id += 1
                    graph.update_weakness_nodes(node_id=node_id, weakness_id="CWE-" + weakness_id)

                    ## 2. Get weakness attributes
                    # 2.1 Basic information
                    weakness_name = all_weakness_dict[weakness_id]["Name"]
                    basic_desc = all_weakness_dict[weakness_id]["Description"]

                    weakness_desc = (f"Vulnerability CWE-{weakness_id}: {weakness_name}."
                                     f"\n- Description: {basic_desc}")

                    # 2.2 Attributes
                    trigger_action = recap_weakness_attrs[weakness_id]["trigger_action"]
                    key_variables_str = ', '.join(recap_weakness_attrs[weakness_id]["key_variables"])

                    weakness_desc += (f"\n- Trigger Action: {trigger_action}"
                                      f"\n- Key Variables: {key_variables_str}")

                    group_weakness_descs.append(weakness_desc)

            update_key_variable_graph(graph, group_weakness_descs, client)

            graph_fpath = os.path.join(graph_dpath, f"cwe_{depth_1_weakness_id}_group_{i}_graph.json")
            with open(graph_fpath, "w") as f:
                json.dump(graph.to_dict(), f, indent=4)


CONTAIN_EDGE_CHECK_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information.
For each weakness, we have summarized its two important attributes:
- 1. Trigger Action: Direct behaviour leading to vulnerability.
- 2. Key Variables: Conditions, states or parameters directly related to the triggered action.

For a weakness, please determine if any of the given variables are not original key variables based on its attribute description.

NOTE: We do not require key variables to be expressed exactly the same.
For example, 'input_data', 'input data' and 'input_value' are not the same in the way they are written, but they express the same meaning, then we do not take this difference into account.
"""


CONTAIN_EDGE_CHECK_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

interface DifferentVariables {
    different_variables: string[];
};

Now based on the given context, write a JSON dict that conforms to the DifferentVariables schema.
"""


PARENT_EDGE_CHECK_SYSTEM_PROMPT = """
"""


def check_contain_edge(weakness_id: str, weakness_desc: str, new_key_variables: List[str]) -> List[str]:

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    usr_msg = (f"Given weakness CWE-{weakness_id}:"
               f"\n{weakness_desc}"
               "\n\nNow you need to determine which of the variables in the list below are completely different from the original key variables."
               f"{new_key_variables}"
               f"\n\n{CONTAIN_EDGE_CHECK_FORMAT_PROMPT}")

    messages = [
        {
            "role": "system",
            "content": CONTAIN_EDGE_CHECK_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": usr_msg
        }
    ]

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        temperature=0.2,
        response_format=ResponseFormat(type="json_object")
    ).choices[0].message

    messages.append({"role": "assistant", "content": response})

    if response.content is None:
        raise RuntimeError
    else:
        response = response.content

    try:
        json_response = json.loads(response)
    except json.JSONDecodeError:
        raise RuntimeError(f"\n{response}")

    if isinstance(json_response, dict) and \
            "different_variables" in json_response and isinstance(json_response["different_variables"], list):
        return json_response["different_variables"]
    else:
        raise RuntimeError(f"\n{json_response}")


def check_parent_edge() -> bool:
    pass


def check_edges_in_group_graphs(graph_dpath: str):
    all_weakness_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(all_weakness_fpath, "r") as f:
        all_weakness = json.load(f)
    all_weakness_dict = {weakness_data["CWE-ID"]: weakness_data for weakness_data in all_weakness}

    recap_weakness_attrs_fpath = "/root/projects/VDTest/data/CWE/weakness_attributes/recap_weakness_attrs.json"
    with open(recap_weakness_attrs_fpath, "r") as f:
        recap_weakness_attrs = json.load(f)

    graph_names = os.listdir(graph_dpath)

    for graph_name in graph_names:
        if graph_name.endswith("graph.json"):
            graph_fpath = os.path.join(graph_dpath, graph_name)

            print(f"{graph_name} ...")

            with open(graph_fpath, "r") as f:
                graph_dict = json.load(f)

            weakness_nodes: Dict[str, str] = graph_dict["weakness_nodes"]
            key_variable_nodes: Dict[str, str] = graph_dict["key_variable_nodes"]

            invalid_edges: List[Tuple[str, str]] = []

            weakness_contain_edges: Dict[str, List[str]] = defaultdict(list)
            weakness_parent_edges: List[Tuple[str, str]] = []
            for from_node_id, to_node_id in graph_dict["edges"]:
                from_node_id = str(from_node_id)
                to_node_id = str(to_node_id)

                if from_node_id in weakness_nodes and to_node_id in key_variable_nodes:
                    weakness_contain_edges[weakness_nodes[from_node_id]].append(key_variable_nodes[to_node_id])
                elif from_node_id in key_variable_nodes and to_node_id in key_variable_nodes:
                    weakness_parent_edges.append((key_variable_nodes[from_node_id], key_variable_nodes[to_node_id]))
                else:
                    invalid_edges.append((from_node_id, to_node_id))

            for full_weakness_id, new_key_variables in weakness_contain_edges.items():
                weakness_id = full_weakness_id.split("-")[-1]

                weakness_name = all_weakness_dict[weakness_id]["Name"]
                basic_desc = all_weakness_dict[weakness_id]["Description"]

                weakness_desc = (f"Vulnerability CWE-{weakness_id}: {weakness_name}."
                                 f"\n- Description: {basic_desc}")

                # 2.2 Attributes
                trigger_action = recap_weakness_attrs[weakness_id]["trigger_action"]
                key_variables_str = ', '.join(recap_weakness_attrs[weakness_id]["key_variables"])

                weakness_desc += (f"\n- Trigger Action: {trigger_action}"
                                  f"\n- Key Variables: {key_variables_str}")

                invalid_key_variables = check_contain_edge(weakness_id, weakness_desc, new_key_variables)

                for invalid_key_variable in invalid_key_variables:
                    invalid_edges.append((full_weakness_id, invalid_key_variable))

            invalid_edges_fpath = graph_fpath.replace(".json", "_invalid_edges.json")
            with open(invalid_edges_fpath, "w") as f:
                json.dump(invalid_edges, f, indent=4)


def merge_key_variable_graphs(graph_dpath: str):
    pass


"""CLUSTER KEY VARIABLES"""


def cal_dunn_index(embeddings: np.ndarray, labels: np.ndarray):
    unique_labels = np.unique(labels)
    num_clusters = len(unique_labels)

    # (1) Calculate the cluster center
    centers = np.array([embeddings[labels == label].mean(axis=0) for label in unique_labels])

    # (2) Calculate the max distance within a cluster
    max_distances = []
    for label in unique_labels:
        cluster_points = embeddings[labels == label]
        if len(cluster_points) > 1:
            intra_distances = cdist(cluster_points, cluster_points, metric='euclidean')
            max_dist = np.max(intra_distances)
            max_distances.append(max_dist)

    # (3) Calculate the min distance between clusters
    min_inter_distance = np.inf
    for i in range(num_clusters):
        for j in range(i + 1, num_clusters):
            inter_distance = np.linalg.norm(centers[i] - centers[j])
            if inter_distance < min_inter_distance:
                min_inter_distance = inter_distance

    dunn = min_inter_distance / max(max_distances)
    return dunn


def generate_key_variable_embeddings(key_vars: List[str], opt: int) -> np.ndarray:
    if opt == 1:
        model_dpath = "/root/models/google-bert/bert-large-uncased-whole-word-masking"
        tokenizer = BertTokenizer.from_pretrained(model_dpath)
        model = BertModel.from_pretrained(model_dpath)

        batch_size = 32
        key_var_embedding_list = []

        for i in range(0, len(key_vars), batch_size):
            batch_key_vars = key_vars[i:i + batch_size]
            inputs = tokenizer(batch_key_vars, return_tensors='pt', padding=True, truncation=True)
            with torch.no_grad():
                outputs = model(**inputs)
            batch_key_var_embeddings = outputs.last_hidden_state[:, 0, :].numpy()  # shape: [batch_size, hidden_size]
            key_var_embedding_list.append(batch_key_var_embeddings)

        key_var_embeddings = np.vstack(key_var_embedding_list)  # shape: [key_var_num, hidden_size]
    # elif opt == 2:
    #     pass
    else:
        raise RuntimeError(f"Option {opt} for embedding generation is not supported yet.")

    return key_var_embeddings


def cluster_key_variable_embeddings(
        key_vars: List[str],
        key_var_embeddings: np.ndarray,
        opt: int
) -> np.ndarray:
    if opt == 1:
        # Density-based clustering
        dbscan = DBSCAN(eps=0.15, min_samples=1, metric='cosine')
        clusters = dbscan.fit_predict(key_var_embeddings)
    elif opt == 2:
        # K-means
        cluster_num = 200
        kmeans = KMeans(n_clusters=cluster_num, random_state=0)
        clusters = kmeans.fit_predict(key_var_embeddings)
    elif opt == 3:
        # Hierarchical clustering
        # Use cosine distance (1 - cosine similarity) as a distance metric
        cosine_sim = cosine_similarity(key_var_embeddings)
        cosine_dist = 1 - cosine_sim
        np.fill_diagonal(cosine_dist, 0)
        condensed_dist = squareform(cosine_dist)

        linked = linkage(condensed_dist, method='ward')

        # plt.figure(figsize=(100, 70))
        # dendrogram(linked,
        #            orientation='right',
        #            labels=np.array(key_vars),
        #            distance_sort='descending',
        #            show_leaf_counts=True)
        # plt.title('Dendrogram for Key Variables')
        # xticks = np.arange(0, 1.1, 0.1)
        # plt.xticks(xticks)
        # plt.ylabel('Key Variables')
        # plt.xlabel('Distance')
        # plt.tight_layout()
        # plt.savefig("total_dendrogram.pdf", bbox_inches='tight', format='pdf')
        # plt.close()

        threshold = 0.1
        clusters = fcluster(linked, threshold, criterion='distance')
    else:
        raise RuntimeError(f"Option {opt} for clustering is not supported yet.")

    dbi = davies_bouldin_score(key_var_embeddings, clusters)
    dunn = cal_dunn_index(key_var_embeddings, clusters)
    silhouette_avg = silhouette_score(key_var_embeddings, clusters)
    print(f"DBI: {dbi}"
          f"\nDUNN: {dunn}"
          f"\nSilhouette Score: {silhouette_avg}")

    return clusters


def cluster_key_variables(groups_dpath: str):

    depth_2_weakness_attrs_fpath = "/root/projects/VDTest/data/CWE/weakness_attributes/recap_weakness_attrs.json"
    with open(depth_2_weakness_attrs_fpath, "r") as f:
        depth_2_weakness_attrs = json.load(f)

    key_vars: List[str] = []
    for _, weakness_attrs in depth_2_weakness_attrs.items():
        for key_var in weakness_attrs["key_variables"]:
            key_var = key_var.lower()
            if key_var not in key_vars:
                key_vars.append(key_var)

    print(f"Key variable number: {len(key_vars)}")

    # (1) Generate embeddings
    emb_generation_opt = 1
    key_var_embeddings = generate_key_variable_embeddings(key_vars, emb_generation_opt)

    # (2) Cluster
    cluster_opt = 1
    clusters = cluster_key_variable_embeddings(key_vars, key_var_embeddings, cluster_opt)

    key_var_groups: Dict[int, List[str]]= defaultdict(list)
    for key_var, cluster in zip(key_vars, clusters):
        key_var_groups[int(cluster)].append(key_var)

    print(f"Key variable cluster number: {len(key_var_groups)}")

    cluster_name = f"{emb_generation_opt}_{cluster_opt}_{len(key_var_groups)}_key_variable_groups.json"
    cluster_fpath = os.path.join(groups_dpath, cluster_name)
    with open(cluster_fpath, "w") as f:
        json.dump(key_var_groups, f, indent=4)


"""TOKEN FREQUENCY"""


def calculate_token_combination_frequency_of_key_variables(token_freq_dpath: str):

    depth_2_weakness_attrs_fpath = "/root/projects/VDTest/data/CWE/weakness_attributes/recap_weakness_attrs.json"
    with open(depth_2_weakness_attrs_fpath, "r") as f:
        depth_2_weakness_attrs = json.load(f)

    comb_token_lengths = [1, 2, 3]

    for l in comb_token_lengths:

        comb_tokens = []
        for _, weakness_attrs in depth_2_weakness_attrs.items():
            for key_var in weakness_attrs["key_variables"]:
                tokens = key_var.split()

                for i in range(len(tokens) - l + 1):
                    comb_token = ' '.join(tokens[i:i + l])
                    comb_tokens.append(comb_token)

        comb_token_counts = Counter(comb_tokens)

        comb_token_counts = dict(sorted(comb_token_counts.items(), key=lambda x: x[1], reverse=True))

        freq_fpath = os.path.join(token_freq_dpath, f"{l}_comb_token_frequencies.json")
        with open(freq_fpath, "w") as f:
            json.dump(comb_token_counts, f, indent=4)


def reduction_of_plural_noun(token: str) -> str:
    wnl = WordNetLemmatizer()
    token2tags = pos_tag(word_tokenize(token), tagset='universal')
    assert len(token2tags) == 1
    if token2tags[0][1] == "NOUN":
        return wnl.lemmatize(token, wordnet.NOUN)
    return token


def build_plural_to_singular_dict(l1_token_freq_fpath: str, freq_dpath: str):
    with open(l1_token_freq_fpath, "r") as f:
        token_frequencies = json.load(f)

    other_tokens = []
    pl2sg_dict = {}

    with tqdm(total=len(token_frequencies)) as pb:
        for token, _ in token_frequencies.items():
            if len(word_tokenize(token)) != 1:
                other_tokens.append(token)
                continue

            sg_token = reduction_of_plural_noun(token)
            if sg_token != token:
                assert token not in pl2sg_dict
                pl2sg_dict[token] = sg_token
            pb.update(1)

    dict_fpath = os.path.join(freq_dpath, "plural_token_dict.json")
    with open(dict_fpath, "w") as f:
        json.dump(pl2sg_dict, f, indent=4)

    other_tokens_fpath = os.path.join(freq_dpath, "other_tokens.json")
    with open(other_tokens_fpath, "w") as f:
        json.dump(other_tokens, f, indent=4)


def optimise_token_combination(plural_token_dict_fpath: str, token_freq_fpath: str):
    """Handle token combinations with plural forms"""
    with open(plural_token_dict_fpath, "r") as f:
        plural_token_dict = json.load(f)

    with open(token_freq_fpath, "r") as f:
        token_freqs = json.load(f)

    new_token_freqs: Dict[str, int] = {}
    for comb_token, freq in token_freqs.items():
        tokens = comb_token.split()
        new_tokens = []
        for token in tokens:
            if token in plural_token_dict:
                new_tokens.append(plural_token_dict[token])
            else:
                new_tokens.append(token)
        new_comb_token = ' '.join(new_tokens)

        if new_comb_token != comb_token:
            print(f"{comb_token} -> {new_comb_token}")

        if new_comb_token not in new_token_freqs:
            new_token_freqs[new_comb_token] = freq
        else:
            new_token_freqs[new_comb_token] += freq

    new_token_freqs = dict(sorted(new_token_freqs.items(), key=lambda x: x[1], reverse=True))
    new_token_freq_fpath = token_freq_fpath.replace(".json", "_new.json")
    with open(new_token_freq_fpath, "w") as f:
        json.dump(new_token_freqs, f, indent=4)


FILTER_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

interface ValidPhrases {
    valid_phrases: string[];
};

Now based on the given context, write a JSON dict that conforms to the ValidPhrases schema.
"""


def check_all_token_combination_and_save_log(token_freq_v2_fpath: str):

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    with open(token_freq_v2_fpath, "r") as f:
        token_freqs = json.load(f)

    valid_tokens = []
    invalid_tokens = []
    nocheck_tokens = []
    tokens = list(token_freqs.keys())

    batch_num = 100
    for i in range(0, len(tokens), batch_num):
        batch_tokens = tokens[i:i + batch_num]

        usr_msg = (f"Given a list of {batch_num} phrases, please identify and select those that represent a complete noun phrase (i.e., a term that refers to a specific entity or concept without grammatical errors). "
                   f"\nFor example, 'input data' is valid, while 'of input' is not."
                   f"\n\n{batch_tokens}"
                   f"\n\n{FILTER_FORMAT_PROMPT}")

        messages = [
            {
                "role": "user",
                "content": usr_msg
            }
        ]

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.2,
            response_format=ResponseFormat(type="json_object")
        ).choices[0].message

        messages.append({"role": "assistant", "content": response})

        if response.content is None:
            nocheck_tokens.extend(batch_tokens)
            continue
        else:
            response = response.content

        try:
            json_response = json.loads(response)
        except json.JSONDecodeError:
            nocheck_tokens.extend(batch_tokens)
            continue

        if isinstance(json_response, dict) and "valid_phrases" in json_response and isinstance(json_response["valid_phrases"], list):
            valid_phrases = json_response["valid_phrases"]

            cur_valid_tokens = []
            for token in valid_phrases:
                if token in batch_tokens:
                    cur_valid_tokens.append(token)
            cur_invalid_tokens = list(set(batch_tokens) - set(cur_valid_tokens))

            valid_tokens.extend(cur_valid_tokens)
            invalid_tokens.extend(cur_invalid_tokens)
        else:
            nocheck_tokens.extend(batch_tokens)

    filter_log_fpath = token_freq_v2_fpath.replace(".json", "_filter.log")
    with open(filter_log_fpath, "w") as f:
        log = {
            "valid_tokens": valid_tokens,
            "invalid_tokens": invalid_tokens,
            "nocheck_tokens": nocheck_tokens
        }
        json.dump(log, f, indent=4)


def check_missing_token_combination_and_save_log(token_freq_v2_fpath: str):
    with open(token_freq_v2_fpath, "r") as f:
        token_freqs = json.load(f)
    tokens = list(token_freqs.keys())

    filter_log_fpath = token_freq_v2_fpath.replace(".json", "_filter.log")
    with open(filter_log_fpath, "r") as f:
        log = json.load(f)

    checked_tokens = log["valid_tokens"] + log["invalid_tokens"]
    missing_tokens = list(set(tokens) - set(checked_tokens))
    log["missing_tokens"] = missing_tokens

    with open(filter_log_fpath, "w") as f:
        json.dump(log, f, indent=4)


def filter_token_combination_by_log(token_freq_v2_fpath: str):
    with open(token_freq_v2_fpath, "r") as f:
        token_freqs = json.load(f)

    filter_log_fpath = token_freq_v2_fpath.replace(".json", "_filter.log")
    with open(filter_log_fpath, "r") as f:
        log = json.load(f)

    filter_token_freqs = {}
    for token, freq in token_freqs.items():
        if token in log["valid_tokens"]:
            filter_token_freqs[token] = freq

    filter_token_freqs = dict(sorted(filter_token_freqs.items(), key=lambda x: x[1], reverse=True))

    token_freq_v3_fpath = token_freq_v2_fpath.replace("v2.json", "v3.json")
    with open(token_freq_v3_fpath, "w") as f:
        json.dump(filter_token_freqs, f, indent=4)


FIND_COMB_TOKEN_PARENT_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information.
For each weakness, we have summarized its two important attributes:
- 1. Trigger Action: Direct behaviour leading to vulnerability.
- 2. Key Variables: Conditions, states or parameters directly related to the triggered action.

Besides, we summarize 6 abstract properties for key variables: data, privilege, process, memory, function, network.
They reflect several basic and important dimensions of the vulnerability key variables.

Now given a list of key variables, your task is:
For each key variable, analyse which of the above properties it has.
"""


COMB_TOKEN_PARENT_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

type AbstractProperty = 
  | `data`
  | `privilege`
  | `process`
  | `memory`
  | `function`
  | `network`;
  
interface KeyVariable = {
    name: string;
    properties: AbstractProperty[];
}

interface  KeyVariables{
    key_variables: KeyVariable[];
};

Now based on the given context, write a JSON dict that conforms to the KeyVariables schema.
"""


def build_key_variable_knowledge_graph_by_token_combination_frequency(token_freq_v3_fpath: str):

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    # NOTE: manual summary + asking llm
    top_level_key_variables = ["data", "privilege", "process", "memory", "function", "network"]

    with open(token_freq_v3_fpath, "r") as f:
        token_freqs = json.load(f)

    comb_token_properties = {}
    cand_comb_tokens = [comb_token for comb_token, freq in token_freqs.items() if freq > 1]

    batch_num = 10

    for i in range(0, len(cand_comb_tokens), batch_num):
        batch_comb_tokens = cand_comb_tokens[i:i + batch_num]

        usr_msg = (f"Now {batch_comb_tokens} token combinations are as below, please analyse them one by one."
                   f"\n{batch_comb_tokens}"
                   f"\n\n{COMB_TOKEN_PARENT_FORMAT_PROMPT}")

        messages = [
            {
                "role": "assistant",
                "content": FIND_COMB_TOKEN_PARENT_SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": usr_msg
            }
        ]

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.2,
            response_format=ResponseFormat(type="json_object")
        ).choices[0].message

        messages.append({"role": "assistant", "content": response})

        if response.content is None:
            continue
        else:
            response = response.content

        try:
            json_response = json.loads(response)
        except json.JSONDecodeError:
            continue

        if isinstance(json_response, dict) and "key_variables" in json_response and isinstance(json_response["key_variables"], list):
            for key_variable in json_response["key_variables"]:
                if isinstance(key_variable, dict) and "name" in key_variable and "properties" in key_variable:
                    name = key_variable["name"]
                    if name not in batch_comb_tokens:
                        continue

                    if not isinstance(key_variable["properties"], list):
                        continue

                    comb_token_properties[name] = key_variable["properties"]

    token_properties_fpath = token_freq_v3_fpath.replace("freqs_v3.json", "properties.json")
    with open(token_properties_fpath, "w") as f:
        json.dump(comb_token_properties, f, indent=4)


def main_build_key_variable_knowledge_graph_by_token_combination_frequency():
    output_dir = "/root/projects/VDTest/data/CWE"

    ## Approach 1: ask LLM
    # TODO: Deprecated!
    graph_dir = os.path.join(output_dir, "key_var_graphs")
    os.makedirs(graph_dir, exist_ok=True)

    # build_key_variable_graph_by_groups(graph_dir)
    # check_edges_in_group_graphs(graph_dir)

    ## Approach 2: cluster key variables
    # TODO: Deprecated!
    groups_dir = os.path.join(output_dir, "key_var_groups")
    os.makedirs(groups_dir, exist_ok=True)
    # cluster_key_variables(groups_dir)

    ## Approach 3: calculate token combination frequency
    # TODO: Deprecated!
    freqs_dir = os.path.join(output_dir, "key_var_frequencies")
    os.makedirs(freqs_dir, exist_ok=True)

    """
    feat: weakness attributes -> v1
    v1: Extract from the weakness (depth = 2) attributes file directly
    """
    # calculate_token_combination_frequency_of_key_variables(freqs_dir)

    """
    feat: v1 -> v2
    v2: change all plural nouns to singular
    """
    l1_token_freq_v1_file = os.path.join(freqs_dir, "l1_token_freqs_v1.json")
    l2_token_freq_v1_file = os.path.join(freqs_dir, "l2_token_freqs_v1.json")
    # build_plural_to_singular_dict(l1_token_freq_file, freqs_dir)

    plural_token_dict_file = os.path.join(freqs_dir, "plural_token_dict.json")
    # for v1_file in [l1_token_freq_v1_file, l2_token_freq_v1_file]:
    #     optimise_token_combination(plural_token_dict_file, v1_file)

    """
    feat: v2 -> v3
    v3: filter token combinations which is not a complete noun phrase (ex: "of input")
    """
    l1_token_freq_v2_file = os.path.join(freqs_dir, "l1_token_freqs_v2.json")
    l2_token_freq_v2_file = os.path.join(freqs_dir, "l2_token_freqs_v2.json")
    # for v2_file in [l1_token_freq_v2_file, l2_token_freq_v2_file]:
    #     # check_all_token_combination_and_save_log(v2_file)
    #     # check_missing_token_combination_and_save_log(v2_file)
    #     filter_token_combination_by_log(v2_file)

    """
    feat: v3 -> token combination properties
    """
    l2_token_freq_v3_file = os.path.join(freqs_dir, "l2_token_freqs_v3.json")
    for v3_file in [l2_token_freq_v3_file]:
        build_key_variable_knowledge_graph_by_token_combination_frequency(v3_file)


"""COMMON PROPERTIES OF KEY VARIABLES"""


COMMON_PROPERTIES_SUMMARY_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information.
For each weakness, we have summarized its two important attributes:
1. Trigger Action: Direct behaviour leading to vulnerability.
2. Key Variables: Conditions, states or parameters directly related to the triggered action.

- Guidelines:
1. Child weaknesses delineate more specific characteristics in relation to their parent weakness.
Consequently, although child weaknesses under the same parent may address different specific scenarios, they inherently share certain common properties due to their lineage. 
These common properties are ultimately reflected in the key variables that they encompass, highlighting the interconnectedness of vulnerabilities within the classification framework.
2. We refer to the common properties mentioned above as generic key variables (in other words, parent key variables), and the key variables that have these common properties are child key variables.

- Task: Given a parent weakness and its child weaknesses, please identify and summarize the generic key variables.

- Request: The summarized generic key variables should encapsulate common attributes shared among the child weaknesses, reflecting the foundational characteristics underlying the parent weakness.

- Note:
1. Each generic key variable is not required to encompass all of the child weaknesses.
2. Each generic key variable is not required to include every key variable from the child weaknesses.
3. DO NOT COPY key variables of child CWEs, you need to abstract them.
"""


COMMON_PROPERTIES_SUMMARY_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

For each summarised generic key variable (in other words, parent key variable), provide its name and child key variables.
Here, child key variable refer to the key variable belong to the child weaknesses.

type ChildKeyVariable = string;

interface ParentKeyVariable = {
    name: string;
    children: ChildKeyVariable[];
};

interface ParentKeyVariables {
    key_variables: ParentKeyVariable[];
};

Now based on the given context, write a JSON dict that conforms to the ParentKeyVariables schema.
"""


def summarize_common_properties_for_d3_weakness_key_variables(weakness_attrs_dpath: str):

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    view_1000_tree_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_tree.json"
    with open(view_1000_tree_fpath, "r") as f:
        cwe_tree = json.load(f)

    view_1000_entries_fpath = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"
    with open(view_1000_entries_fpath, "r") as f:
        all_weakness = json.load(f)
    all_weakness_dict = {data["CWE-ID"]: data for data in all_weakness}

    weakness_attrs_fpath = "/root/projects/VDTest/data/CWE/weakness_attributes/all_weakness_attrs.json"
    with open(weakness_attrs_fpath, "r") as f:
        all_weakness_attrs = json.load(f)

    weakness_parent_key_variables = {}

    for weakness_id, attrs in all_weakness_attrs.items():
        if any(len(cwe_path) == 2 for cwe_path in cwe_tree[weakness_id]["cwe_paths"]):
            weakness_name = all_weakness_dict[weakness_id]["Name"]
            basic_desc = all_weakness_dict[weakness_id]["Description"]
            extended_desc = all_weakness_dict[weakness_id]["Extended Description"]

            # 1. Basic information
            usr_msg = (f"The parent weakness is CWE-{weakness_id}: {weakness_name}."
                       f"\n- Description: {basic_desc}")

            # 2. Extended description
            if extended_desc != "":
                usr_msg += f"\n- Extended Description: {extended_desc}"

            # 3. Children information

            child_key_variables = []
            children_desc = ""

            for i, child in enumerate(cwe_tree[weakness_id]["children"]):
                child_name = all_weakness_dict[child]["Name"]
                child_desc = all_weakness_dict[child]["Description"]
                trigger_action = all_weakness_attrs[child]["trigger_action"]
                key_variables_str = ', '.join(all_weakness_attrs[child]["key_variables"])

                child_key_variables.extend(all_weakness_attrs[child]["key_variables"])
                children_desc += (f"\n\nChild {i + 1}: CWE-{child} ({child_name})"
                                  f"\n- Description: {child_desc}"
                                  f"\n- Trigger Action: {trigger_action}"
                                  f"\n- Key Variables: {key_variables_str}")

            usr_msg += ("\n\nIt has the following child weaknesses:"
                        f"{children_desc}")

            # 4. Format
            usr_msg += f"\n\n{COMMON_PROPERTIES_SUMMARY_FORMAT_PROMPT}"

            messages = [
                {
                    "role": "system",
                    "content": WEAKNESS_ATTRS_SUMMARY_SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": usr_msg
                }
            ]

            response = client.chat.completions.create(
                model="gpt-4o-2024-05-13",
                messages=messages,
                temperature=0.2,
                response_format=ResponseFormat(type="json_object")
            ).choices[0].message

            if response.content is None:
                response = ""
            else:
                response = response.content

            json_response = json.loads(response)

            curr_parent_key_variables = {}

            if isinstance(json_response, dict) and "key_variables" in json_response and isinstance(json_response["key_variables"], list):
                for key_variable in json_response["key_variables"]:
                    name = key_variable.get("name", None)
                    children = key_variable.get("children", [])
                    if name and children:
                        curr_parent_key_variables[name] = children

            if curr_parent_key_variables:
                weakness_parent_key_variables[weakness_id] = curr_parent_key_variables

    parent_key_variables_fpath = os.path.join(weakness_attrs_dpath, "d2_weakness_key_variables.json")
    with open(parent_key_variables_fpath, "w") as f:
        json.dump(weakness_parent_key_variables, f, indent=4)


def build_init_key_variable_tree(weakness_attrs_dpath: str):

    d2_weakness_key_vars_fpath = os.path.join(weakness_attrs_dpath, "d2_weakness_key_variables.json")
    with open(d2_weakness_key_vars_fpath, "r") as f:
        weakness_key_vars = json.load(f)

    key_var_tree: Dict[str, List[str]]= {}

    for _, key_vars in weakness_key_vars.items():
        for parent_key_var, child_key_vars in key_vars.items():
            child_key_vars = list(set(child_key_vars))
            if parent_key_var in child_key_vars:
                child_key_vars.remove(parent_key_var)

            if parent_key_var not in key_var_tree:
                key_var_tree[parent_key_var] = child_key_vars
            else:
                key_var_tree[parent_key_var].extend(child_key_vars)
                key_var_tree[parent_key_var] = list(set(key_var_tree[parent_key_var]))

    key_var_tree_fpath = os.path.join(weakness_attrs_dpath, "key_variables_tree.json")
    with open(key_var_tree_fpath, "w") as f:
        json.dump(key_var_tree, f, indent=4)


def jaccard_similarity(phrase1: str, phrase2: str) -> float:
    set1 = set(word_tokenize(phrase1))
    set2 = set(word_tokenize(phrase2))

    insec = set1.intersection(set2)
    union = set1.union(set2)

    if len(union) == 0:
        return 0.0
    return len(insec) / len(union)


def find_similar_pairs_in_list(phrase_list: List[str], threshold: float) -> List[Tuple[str, str, float]]:
    similar_pairs = []

    n = len(phrase_list)
    for i in range(n):
        for j in range(i + 1, n):
            similarity = jaccard_similarity(phrase_list[i], phrase_list[j])
            if similarity > threshold:
                similar_pairs.append((phrase_list[i], phrase_list[j], similarity))

    return similar_pairs


def find_similar_key_variable_in_tree(weakness_attrs_dpath: str):
    """Target: grammar + semantics similar key variables"""
    # TODO: Deprecated!
    key_var_tree_fpath = os.path.join(weakness_attrs_dpath, "key_variables_tree.json")
    with open(key_var_tree_fpath, "r") as f:
        key_var_tree = json.load(f)

    similar_key_vars: List[Tuple[str, str, float]] = []

    threshold = 0.5
    parent_key_vars = []
    for parent_key_var, child_key_vars in key_var_tree.items():
        parent_key_vars.append(parent_key_var)

        cur_similar_child_key_vars = find_similar_pairs_in_list(child_key_vars, threshold)
        similar_key_vars.extend(cur_similar_child_key_vars)

    similar_parent_key_vars = find_similar_pairs_in_list(parent_key_vars, threshold)
    similar_key_vars.extend(similar_parent_key_vars)

    similar_key_vars_fpath = os.path.join(weakness_attrs_dpath, "similar_key_variables.json")
    with open(similar_key_vars_fpath, "w") as f:
        json.dump(similar_key_vars, f, indent=4)


KEY_VAR_NORMALISATION_SYSTEM_PROMPT = """I want you to act as a vulnerability analysis expert and analyse vulnerability knowledge based on the above information.
For each weakness, we have summarized its two important attributes:
1. Trigger Action: Direct behaviour leading to vulnerability.
2. Key Variables: Conditions, states or parameters directly related to the triggered action.

Your task is as follows:
Given a parent key variable and its child key variables, please standardise the wording of the child key variables so that there are no more synonymous key variables.
Example 1: for 'input data' and 'input value', use 'input data' consistently.
Example 2: for 'user input data' and 'input data', do not modify 'user input data' to 'input data'. Since 'user input data' and 'input data' do not cover the same scope, while 'user input data' carries the characteristic of user input.

NOTE: Do not copy directly from any of the examples or descriptions I have given.
"""


KEY_VAR_NORMALISATION_FORMAT_PROMPT = """Provide your answer in JSON structure and consider the following TypeScript Interface for the JSON schema:

For each key variable that needs to have its name modified, give the name before and after the modification.

interface ModifiedKeyVariable = {
    old_name: string;
    new_name: string;
};

interface ModifiedKeyVariables {
    key_variables: ModifiedKeyVariable[];
};

Now based on the given context, write a JSON dict that conforms to the ModifiedKeyVariables schema.
"""


def normalise_key_variable_in_tree(weakness_attrs_dpath: str):
    # TODO: Deprecated!

    ## (1) Prepare GPT
    api_key = os.getenv("OPENAI_KEY", None)
    api_base = os.getenv("OPENAI_API_BASE", None)
    assert api_key is not None and api_base is not None
    client = OpenAI(api_key=api_key, base_url=api_base)

    ## (2) Main
    key_var_tree_fpath = os.path.join(weakness_attrs_dpath, "key_variables_tree.json")
    with open(key_var_tree_fpath, "r") as f:
        key_var_tree = json.load(f)

    modified_key_vars = []

    with tqdm(total=len(key_var_tree)) as pb:
        for parent_key_var, child_key_vars in key_var_tree.items():
            if len(child_key_vars) > 1:
                usr_msg = (f"The parent key variable is '{parent_key_var}', and its child key variables are as follows:"
                           f"\n{child_key_vars}"
                           f"\n\n{KEY_VAR_NORMALISATION_FORMAT_PROMPT}")

                messages = [
                    {
                        "role": "system",
                        "content": KEY_VAR_NORMALISATION_SYSTEM_PROMPT
                    },
                    {
                        "role": "user",
                        "content": usr_msg
                    }
                ]

                response = client.chat.completions.create(
                    model="gpt-4o-2024-05-13",
                    messages=messages,
                    temperature=0.2,
                    response_format=ResponseFormat(type="json_object")
                ).choices[0].message

                if response.content is None:
                    response = ""
                else:
                    response = response.content

                json_response = json.loads(response)

                if isinstance(json_response, dict) and "key_variables" in json_response and isinstance(json_response["key_variables"], list):
                    for modified_key_var in json_response["key_variables"]:
                        old_name = modified_key_var.get("old_name", None)
                        new_name = modified_key_var.get("new_name", None)
                        if old_name and new_name and old_name in [parent_key_var] + child_key_vars:
                            modified_key_vars.append((old_name, new_name))

            pb.update(1)

    modified_key_vars_fpath = os.path.join(weakness_attrs_dpath, "modified_key_variables.json")
    with open(modified_key_vars_fpath, "w") as f:
        json.dump(modified_key_vars, f, indent=4)


def normalise_key_variable_with_plural_token_dict(key_var: str, plural_token_dict: Dict[str, str]) -> str:
    new_tokens = []
    tokens = key_var.split()

    for token in tokens:
        if token in plural_token_dict:
            new_tokens.append(plural_token_dict[token])
        else:
            new_tokens.append(token)

    return ' '.join(new_tokens)


def normalise_key_variable_in_v1_tree_with_plural_token_dict(weakness_attrs_dpath: str):
    plural_token_dict_file = "/root/projects/VDTest/data/CWE/key_var_frequencies/plural_token_dict.json"
    with open(plural_token_dict_file, "r") as f:
        plural_token_dict = json.load(f)

    key_var_v1_tree_fpath = os.path.join(weakness_attrs_dpath, "key_variable_tree_v1.json")
    with open(key_var_v1_tree_fpath, 'r') as f:
        key_var_tree = json.load(f)

    new_key_var_tree = {}
    for parent_key_var, children in key_var_tree.items():
        new_parent_key_var = normalise_key_variable_with_plural_token_dict(parent_key_var, plural_token_dict)
        new_children = [
            normalise_key_variable_with_plural_token_dict(child, plural_token_dict)
            for child in children
        ]
        new_children = list(set(new_children))
        new_key_var_tree[new_parent_key_var] = new_children

    key_var_v2_tree_fpath = os.path.join(weakness_attrs_dpath, "key_variable_tree_v2.json")
    with open(key_var_v2_tree_fpath, 'w') as f:
        json.dump(new_key_var_tree, f, indent=4)


if __name__ == '__main__':
    save_dir = "/root/projects/VDTest/data/CWE/VIEW_1000"
    # save_dir = "/root/projects/VDTest/data/CWE/VIEW_1003"

    ## Build CWE entries file
    csv_file = "/root/projects/VDTest/data/CWE/1000.csv"
    # csv_file = "/root/projects/VDTest/data/CWE/1003.csv"
    # read_cwe_csv(csv_file, save_dir)

    ## Refine CWE tree
    cwe_tree_file = os.path.join(save_dir, "CWE_tree.json")
    # refine_cwe_tree_with_paths(cwe_tree_file)
    # check_cwe_paths_and_print(cwe_tree_file)

    ## Extract CWE ids in different depths
    # find_diff_depth_cwe(cwe_tree_file, save_dir)

    ## Summarize weakness attributes (depth <= 3)
    # output_dir = "/root/projects/VDTest/data/CWE"
    # summarize_all_weakness_attributes(output_dir)
    # recap_all_weakness_attributes(output_dir)
    # update_all_weakness_attrs_with_recap_attrs(output_dir)

    # weakness_attrs_files = [
    #     "/root/projects/VDTest/data/CWE/weakness_attributes/all_weakness_attrs.json",
    #     "/root/projects/VDTest/data/CWE/weakness_attributes/recap_weakness_attrs.json"
    # ]
    # for weakness_attrs_file in weakness_attrs_files:
    #     adjust_key_variable_format_of_weaknesses(weakness_attrs_file)

    # ------------------------- Build Key Variable Knowledge Graph ------------------------- #
    # main_build_key_variable_knowledge_graph_by_token_combination_frequency()

    # ------------------------- Summarize the Common Properties of Key Variables ------------------------- #
    weakness_attrs_dir = "/root/projects/VDTest/data/CWE/weakness_attributes"
    # summarize_common_properties_for_d3_weakness_key_variables(weakness_attrs_dir)
    # build_init_key_variable_tree(weakness_attrs_dir)

    # normalise_key_variable_in_v1_tree_with_plural_token_dict(weakness_attrs_dir)



