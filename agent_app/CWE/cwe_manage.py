import re
import json

from typing import *
from enum import Enum
from dataclasses import dataclass


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
            all_weakness_entry_fpath: str,
            view_cwe_tree_fpaths: List[Tuple[str, str]],
    ):
        self.full_view_id = full_view_id
        self.cwe_entry_fpath = cwe_entry_fpath
        self.cwe_tree_fpath = cwe_tree_fpath
        # NOTE: All CWE entries here refers to 939 weakness CWE entries, i.e. all CWE entries under VIEW-1000.
        self.all_weakness_entry_fpath = all_weakness_entry_fpath
        self.view_cwe_tree_fpaths = view_cwe_tree_fpaths

        self.max_depth = 3
        view_id = self.full_view_id.split('-')[-1]
        if view_id == "1003":
            self.max_depth = 2

        # NOTE: The CWE-IDs / VIEW-IDs following are all brief name, i.e. number only.
        ## Supported / considered CWE ids and tree structures
        self.cwe_ids: List[str] = []         # CWE_ID
        self.cwe_tree: Dict[str, Dict] = {}  # CWE-ID -> CWE tree info

        ## All CWE info
        self.all_category_entries: Dict[str, Dict] = {}  # CWE-ID -> CWE entry info
        self.all_weakness_entries: Dict[str, Dict] = {}  # CWE-ID -> CWE entry info

        ## Useful VIEW info
        # VIEW-ID -> VIEW info
        self.view_cwe_trees: Dict[str, VIEWInfo] = {}

        ## Update
        self.update()


    """UPDATE"""


    def update_all_weakness_entries(self) -> None:
        with open(self.all_weakness_entry_fpath, 'r') as f:
            weakness_entries = json.load(f)

        for entry in weakness_entries:
            self.all_weakness_entries[entry["CWE-ID"]] = entry


    def update_all_category_entries_and_view_cwe_trees(self) -> None:
        for view_id, cwe_tree_fpath in self.view_cwe_tree_fpaths:
            with open(cwe_tree_fpath, 'r') as f:
                cwe_tree = json.load(f)

            if view_id == "699":
                self.view_cwe_trees[view_id] = VIEWInfo("concepts in software development", cwe_tree)
            elif view_id == "888":
                self.view_cwe_trees[view_id] = VIEWInfo("software fault pattern", cwe_tree)
            elif view_id == "1400":
                self.view_cwe_trees[view_id] = VIEWInfo("software assurance trends", cwe_tree)
            else:
                raise RuntimeError(f"Unexpected view_id: {view_id}")


    def update_supported_info(self) -> None:
        """NOTE: Perform this operation after updating all CWE information."""
        # (1) Update supported CWE ids
        with open(self.cwe_entry_fpath, 'r') as f:
            cwe_entries = json.load(f)

        for entry in cwe_entries:
            cwe_id = entry["CWE-ID"]
            if cwe_id in self.all_weakness_entries:
                self.cwe_ids.append(cwe_id)

        # (2) Update supported CWE tree
        with open(self.cwe_tree_fpath, 'r') as f:
            self.cwe_tree = json.load(f)


    def update(self):
        self.update_all_weakness_entries()
        self.update_all_category_entries_and_view_cwe_trees()
        self.update_supported_info()


    """LOOKUP"""


    def get_standard_cwe_id(self, data: str) -> str | None:
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

        view_descs: List[str] = []

        for view_id, view_info in self.view_cwe_trees.items():
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
                view_descs.append(view_desc)

        if view_descs:
            desc = f"CWE-{cwe_id} has the following attributes:"
            for i, view_desc in enumerate(view_descs):
                desc += f"\n{i+1}. {view_desc}"
            return desc
        else:
            return ""


    def is_too_detailed_weakness(self, cwe_id: str) -> bool:
        assert cwe_id in self.cwe_tree

        min_cwe_path = min(self.cwe_tree[cwe_id]["cwe_paths"], key=len)
        if len(min_cwe_path) > self.max_depth:
            return True
        else:
            return False


    def get_fathers_of_weakness(self, cwe_id: str, depth: int = 3) -> List[str] | None:
        assert depth > 0

        if cwe_id not in self.cwe_ids:
            return None

        fathers: List[str] = []
        for cwe_path in self.cwe_tree[cwe_id]["cwe_paths"]:
            if depth < len(cwe_path):
                father = cwe_path[depth - 1]
                fathers.append(father)

        return fathers
