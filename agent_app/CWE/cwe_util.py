import os
import json

from dataclasses import dataclass

from typing import *


@dataclass(frozen=True)
class WeaknessAttrs:
    trigger_action: str
    key_variables: List[str]

    @staticmethod
    def trigger_action_def() -> str:
        return "Direct behaviour leading to vulnerability"

    @staticmethod
    def key_variable_def() -> str:
        return "Conditions, states or parameters directly related to the triggered action"


@dataclass(frozen=True)
class VIEWInfo:
    basis: str
    cwe_tree: Dict[str, Dict]
