# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/post_process.py

"""
Post-process the output of the inference workflow.
"""

import os
import json

from typing import *
from enum import Enum


# Track status of silent security patch identification
class ExtractStatus(str, Enum):
    APPLICABLE_PATCH = "APPLICABLE_PATCH"
    MATCHED_BUT_EMPTY_ORIGIN = "MATCHED_BUT_EMPTY_ORIGIN"
    MATCHED_BUT_EMPTY_DIFF = "MATCHED_BUT_EMPTY_DIFF"
    RAW_PATCH_BUT_UNMATCHED = "RAW_PATCH_BUT_UNMATCHED"
    RAW_PATCH_BUT_UNPARSED = "RAW_PATCH_BUT_UNPARSED"
    NO_PATCH = "NO_PATCH"
    IS_VALID_JSON = "IS_VALID_JSON"
    NOT_VALID_JSON = "NOT_VALID_JSON"

    def __lt__(self, other):
        # order from min to max
        order = [
            self.NO_PATCH,
            self.RAW_PATCH_BUT_UNPARSED,
            self.RAW_PATCH_BUT_UNMATCHED,
            self.MATCHED_BUT_EMPTY_DIFF,
            self.MATCHED_BUT_EMPTY_ORIGIN,
            self.APPLICABLE_PATCH,
        ]
        self_index = order.index(self)
        other_index = order.index(other)
        return self_index < other_index

    def __eq__(self, other):
        return self is other

    def __hash__(self):
        return hash(self.value)

    def to_dir_name(self, expr_dir: str):
        return os.path.join(expr_dir, self.value.lower())

    @staticmethod
    def max(statuses):
        return sorted(statuses)[-1]


def is_valid_json(json_str: str) -> Tuple[ExtractStatus, Union[List, Dict, None]]:
    """
    Check whether a json string is valid.

    Args:
        json_str: A string to check if in json format
    Returns:
        ExtractStatus:
        Union[List, Dict, None]: List or Dict if in json format, otherwise None
    """
    try:
        data = json.loads(json_str)
    except json.decoder.JSONDecodeError:
        return ExtractStatus.NOT_VALID_JSON, None
    return ExtractStatus.IS_VALID_JSON, data
