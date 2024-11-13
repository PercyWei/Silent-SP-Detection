from __future__ import annotations

import os
import json
import csv

from typing import *

from scipy.stats import bernoulli
from tqdm import tqdm
from collections import defaultdict

from agent_app.CWE.cwe_util import VIEWInfo

from openai import OpenAI
from openai.types.chat.completion_create_params import ResponseFormat


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
    output_dir = "/root/projects/VDTest/data/CWE"
    # summarize_all_weakness_attributes(output_dir)
    # recap_all_weakness_attributes(output_dir)
    update_all_weakness_attrs_with_recap_attrs(output_dir)