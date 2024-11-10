import re
import json

from typing import *
from enum import Enum
from dataclasses import dataclass


@dataclass(frozen=True)
class WeaknessAttrs:
    trigger_action: str
    key_variables: List[str]


@dataclass(frozen=True)
class VIEWInfo:
    basis: str
    cwe_tree: Dict[str, Dict]


class CWEManager:
    def __init__(
            self,
            full_view_id: str,
            cwe_entry_fpath: str,
            cwe_tree_fpath: str,
            all_weakness_entries_fpath: str,
            weakness_attributes_fpath: str,
            view_cwe_entries_fpaths: Dict[str, str],
            view_cwe_tree_fpaths: Dict[str, str]
    ):
        self.full_view_id = full_view_id

        self.max_depth = 3
        view_id = self.full_view_id.split('-')[-1]
        if view_id == "1003":
            self.max_depth = 2


        ## (1) All CWE (category + weakness) info
        # NOTE: All CWE entries here refers to 939 weakness CWE entries, i.e. all CWE entries under VIEW-1000.
        self.all_category_entries: Dict[str, Dict] = {}  # CWE-ID -> CWE entry info
        self.all_weakness_entries: Dict[str, Dict] = {}  # CWE-ID -> CWE entry info

        self.update_all_weakness_entries(all_weakness_entries_fpath)
        self.update_all_category_entries(view_cwe_entries_fpaths)


        ## (2) Weakness attributes (depth <= 3)
        self.weakness_attributes: Dict[str, WeaknessAttrs] = {}

        self.update_weakness_attributes(weakness_attributes_fpath)


        ## (3) Useful VIEW info
        # VIEW-ID -> VIEW info
        self.all_view_cwe_trees: Dict[str, VIEWInfo] = {}

        self.update_all_view_cwe_trees(view_cwe_tree_fpaths)


        # NOTE: The CWE-IDs / VIEW-IDs following are all brief name, i.e. number only.
        ## (4) Supported / considered CWE ids and tree structures
        self.cwe_ids: List[str] = []         # CWE_ID
        self.cwe_tree: Dict[str, Dict] = {}  # CWE-ID -> CWE tree info

        self.update_supported_cwe_info(cwe_entry_fpath, cwe_tree_fpath)


    """UPDATE"""


    def update_all_weakness_entries(self, all_weakness_entries_fpath: str) -> None:
        with open(all_weakness_entries_fpath, 'r') as f:
            weakness_entries = json.load(f)

        for entry in weakness_entries:
            self.all_weakness_entries[entry["CWE-ID"]] = entry


    def update_all_category_entries(self, view_cwe_entries_fpaths: Dict[str, str]) -> None:
        for view_id, cwe_entries_fpath in view_cwe_entries_fpaths.items():
            with open(cwe_entries_fpath, 'r') as f:
                cwe_entries = json.load(f)

            for cwe_data in cwe_entries:
                if cwe_data["Type"] == "category":
                    cwe_id = cwe_data["CWE-ID"]
                    assert cwe_id not in self.all_category_entries
                    self.all_category_entries[cwe_id] = cwe_data


    def update_weakness_attributes(self, weakness_attributes_fpath: str) -> None:
        with open(weakness_attributes_fpath, 'r') as f:
            weakness_attrs = json.load(f)

        for cwe_id, attrs in weakness_attrs.items():
            self.weakness_attributes[cwe_id] = WeaknessAttrs(attrs["trigger_action"], attrs["key_variables"])


    def update_all_view_cwe_trees(self, view_cwe_tree_fpaths: Dict[str, str]) -> None:
        for view_id, cwe_tree_fpath in view_cwe_tree_fpaths.items():
            with open(cwe_tree_fpath, 'r') as f:
                cwe_tree = json.load(f)

            if view_id == "699":
                self.all_view_cwe_trees[view_id] = VIEWInfo("concepts in software development", cwe_tree)
            elif view_id == "888":
                self.all_view_cwe_trees[view_id] = VIEWInfo("software fault pattern", cwe_tree)
            elif view_id == "1400":
                self.all_view_cwe_trees[view_id] = VIEWInfo("software assurance trends", cwe_tree)
            else:
                raise RuntimeError(f"Unexpected view_id: {view_id}")


    def update_supported_cwe_info(self, cwe_entry_fpath: str, cwe_tree_fpath: str) -> None:
        """NOTE: Perform this operation after updating all CWE information."""
        assert self.all_weakness_entries

        # (1) Update supported CWE ids
        with open(cwe_entry_fpath, 'r') as f:
            cwe_entries = json.load(f)

        for entry in cwe_entries:
            cwe_id = entry["CWE-ID"]
            if cwe_id in self.all_weakness_entries:
                self.cwe_ids.append(cwe_id)

        # (2) Update supported CWE tree
        with open(cwe_tree_fpath, 'r') as f:
            self.cwe_tree = json.load(f)


    """MAPPING"""


    @staticmethod
    def get_standard_cwe_id(data: str) -> str | None:
        match_1 = re.match(r'CWE-(\d+)', data)
        match_2 = re.match(r'CWE (\d+)', data)

        if data.isdigit():
            # Brief CWE-ID like "20"
            cwe_id = data
        elif match_1:
            # Full CWE-ID like "CWE-20"
            cwe_id = match_1.group(1)
        elif match_2:
            # Full CWE-ID like "CWE 20"
            cwe_id = match_2.group(1)
        else:
            return None

        return cwe_id


    def get_cwe_entry(self, cwe_id: str) -> Dict | None:
        if cwe_id in self.all_weakness_entries:
            return self.all_weakness_entries[cwe_id]
        elif cwe_id in self.all_category_entries:
            return self.all_category_entries[cwe_id]
        else:
            return None


    def get_weakness_description(self, cwe_id: str) -> str | None:
        cwe_entry = self.get_cwe_entry(cwe_id)
        if cwe_entry is not None and cwe_entry["Type"] == "weakness":
            return cwe_entry["Description"]
        else:
            return None


    def get_category_description(self, cwe_id: str) -> str | None:
        cwe_entry = self.get_cwe_entry(cwe_id)
        if cwe_entry is not None and cwe_entry["Type"] == "category":
            # FIXME: For Category entries, they only have attributes "CWE-ID", "Name", and "Type".
            #        We will consider adding other attributes such as "Description" in the future.
            cwe_name = cwe_entry["Name"].lower()
            return (f"Weaknesses in this category are related to {cwe_name}. "
                    f"This CWE ID must not be used to map to real-world vulnerabilities, as Categories are "
                    f"informal organizational groupings of weaknesses that can help CWE users with data "
                    f"aggregation, navigation, and browsing, however, they are not weaknesses in themselves.")
        else:
            return None


    def get_weakness_attr_description(self, cwe_id: str) -> str | None:
        if cwe_id not in self.all_weakness_entries:
            return None

        # (1) Iterate over all views
        all_view_descs: List[str] = []

        for view_id, view_info in self.all_view_cwe_trees.items():
            cl_basis = view_info.basis
            cwe_tree = view_info.cwe_tree

            if cwe_id in cwe_tree:
                cwe_paths: List[List[str]] = cwe_tree[cwe_id]["cwe_paths"]

                related_attrs = []
                for path in cwe_paths:
                    # TODO-1: For now, we only use the most recent Category information in all parent CWE paths.
                    # TODO-2: For now, for Category information, we only use the name of the it.
                    for curr_id in reversed(path):
                        if curr_id in self.all_category_entries:
                            related_attrs.append(self.all_category_entries[curr_id]["Name"])
                            break
                related_attrs_str = ', '.join(related_attrs)

                view_desc = f"In VIEW-{view_id}, CWEs are clustered according to {cl_basis}, while CWE-{cwe_id} is related to {related_attrs_str}."
                all_view_descs.append(view_desc)

        # (2) Form a description containing all views
        entire_view_desc: str = ""

        if all_view_descs:
            entire_view_desc = f"CWE-{cwe_id} has the following attributes:"
            for i, view_desc in enumerate(all_view_descs):
                entire_view_desc += f"\n{i+1}. {view_desc}"

        return entire_view_desc


    def is_too_detailed_weakness(self, cwe_id: str) -> bool:
        assert cwe_id in self.cwe_tree

        min_cwe_path = min(self.cwe_tree[cwe_id]["cwe_paths"], key=len)
        if len(min_cwe_path) > self.max_depth:
            return True
        else:
            return False


    def get_depth_k_fathers_of_weakness(self, cwe_id: str, depth: int = 3) -> List[str] | None:
        assert depth > 0

        if cwe_id not in self.cwe_ids:
            return None

        fathers: List[str] = []
        for cwe_path in self.cwe_tree[cwe_id]["cwe_paths"]:
            if depth < len(cwe_path):
                father = cwe_path[depth - 1]
                fathers.append(father)

        fathers = list(set(fathers))

        return fathers


    """CWE MEMORY"""
    @staticmethod
    def trigger_action_def() -> str:
        return "The direct action triggering the vulnerability"


    @staticmethod
    def key_variable_def() -> str:
        return "Important variables that have a direct or indirect relationship with the triggering action"
