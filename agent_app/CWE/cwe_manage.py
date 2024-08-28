import re
import json

from typing import *


class CWEManager:
    def __init__(self, cwe_entry_fpath: str, cwe_tree_fpath: str):
        self.cwe_entry_fpath = cwe_entry_fpath
        self.cwe_tree_fpath = cwe_tree_fpath

        ## Basic CWE information
        # CWE-ID -> CWE entry info
        self.cwe_entries: Dict[str, Dict] = {}

        ## CWE Tree
        # CWE-ID -> CWE tree info
        self.cwe_tree: Dict[str, Dict] = {}

        ## Update
        self.update()

    """Update"""

    def update_cwe_entries(self) -> None:
        with open(self.cwe_entry_fpath, 'r') as f:
            cwe_items = json.load(f)
        for item in cwe_items:
            self.cwe_entries[item["CWE-ID"]] = item

    def update_cwe_tree(self) -> None:
        with open(self.cwe_tree_fpath, 'r') as f:
            self.cwe_tree = json.load(f)

    def update(self):
        self.update_cwe_entries()
        self.update_cwe_tree()

    """Get CWE item"""

    def all_cwe_ids(self) -> List[str]:
        return list(self.cwe_entries.keys())

    def get_cwe_entry(self, cwe_id: str) -> Dict | None:
        match_1 = re.match(r'CWE-(\d+)', cwe_id)
        match_2 = re.match(r'CWE (\d+)', cwe_id)

        if cwe_id.isdigit():
            # Form like "20"
            pass
        elif match_1:
            # Form like "CWE-20"
            cwe_id = match_1.group(1)
        elif match_2:
            # Form like "CWE 20"
            cwe_id = match_2.group(1)
        else:
            raise RuntimeError

        if cwe_id in self.cwe_entries:
            return self.cwe_entries[cwe_id]
        else:
            return None

    def get_cwe_description(self, cwe_id: str) -> str | None:
        cwe_entry = self.get_cwe_entry(cwe_id)
        return cwe_entry['Description'] if cwe_entry else None


