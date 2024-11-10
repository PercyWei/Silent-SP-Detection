import json

from typing import *
from enum import Enum
from dataclasses import dataclass, field

from agent_app.flow_control.hypothesis import Hypothesis, VerifiedHypothesis
from agent_app.search.search_util import PySearchResult, JavaSearchResult


"""FLOW STATE"""


class State(str, Enum):
    START_STATE = "start"
    REFLEXION_STATE = "reflexion"
    HYPOTHESIS_CHECK_STATE = "hypothesis_check"
    CONTEXT_RETRIEVAL_STATE = "context_retrieval"
    HYPOTHESIS_VERIFY_STATE = "hypothesis_verify"
    END_STATE = "end"
    POST_PROCESS_STATE = "post_process"

    @staticmethod
    def attributes():
        return [k.value for k in State]


"""PROCESS DATACLASS"""


@dataclass
class ProcOutPaths:
    """For recording all relevant output paths in current process."""
    root: str
    hyp_dpath: str
    proxy_dpath: str
    tool_call_dpath: str


@dataclass
class ProcHypothesis:
    """For recording all relevant info about hypothesis in current process."""
    cur_hyp: Hypothesis | None = None
    unverified: List[Hypothesis] = field(default_factory=list)
    verified: List[VerifiedHypothesis] = field(default_factory=list)
    patch: List[PySearchResult | JavaSearchResult] = field(default_factory=list)
    code_context: List[PySearchResult | JavaSearchResult] = field(default_factory=list)

    """UPDATE"""

    def update_cur_hyp(self) -> None:
        self.sort_unverified()
        self.cur_hyp = self.unverified[0]
        self.unverified.pop(0)

    def add_new_unverified(self, hyp: Hypothesis) -> None:
        if not self.in_verified(hyp):
            self.unverified.append(hyp)

    """SORT"""

    def sort_unverified(self) -> None:
        sorted_hyps = sorted(self.unverified, key=lambda x: x.confidence_score, reverse=True)
        self.unverified = sorted_hyps

    def sort_verified(self) -> None:
        sorted_hyps = sorted(self.verified, key=lambda x: x.confidence_score, reverse=True)
        self.verified = sorted_hyps

    """IDENTIFICATION"""

    def in_unverified(self, hyp: Hypothesis) -> bool:
        for u_hyp in self.unverified:
            if u_hyp.commit_type == hyp.commit_type and u_hyp.vulnerability_type == hyp.vulnerability_type:
                return True
        return False

    def in_verified(self, hyp: Hypothesis) -> bool:
        for v_hyp in self.verified:
            if v_hyp.commit_type == hyp.commit_type and v_hyp.vulnerability_type == hyp.vulnerability_type:
                return True
        return False

    """TO DICT"""

    def hyp_to_dict(self) -> Dict:
        return {
            "unverified": [hyp.to_dict() for hyp in self.unverified],
            "verified": [hyp.to_dict() for hyp in self.verified]
        }

    """TO STRING"""

    def context_to_str(self) -> str:
        code_seq_list = []
        for c in self.code_context:
            code_seq_list.append(c.to_tagged_str())
        return "\n\n".join(code_seq_list)

    def patch_to_str(self) -> str:
        code_seq_list = []
        for c in self.patch:
            code_seq_list.append(c.to_tagged_str())
        return "\n\n".join(code_seq_list)

    """SAVE"""

    def save_hyp_to_file(self, fpath: str) -> None:
        with open(fpath, "w") as f:
            json.dump(self.hyp_to_dict(), f, indent=4)
