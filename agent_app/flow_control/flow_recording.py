import json

from typing import *
from enum import Enum
from dataclasses import dataclass, field

from agent_app.data_structures import SearchStatus
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


@dataclass
class ProcessStatus:

    def to_dict(self):
        return {attr.lstrip('_'): value for attr, value in vars(self).items()}


@dataclass
class ProcActionStatus(ProcessStatus):
    """Dataclass to hold status of some actions during the identification processes."""
    # [success number, failure number]
    _patch_extraction: List[int] = field(default_factory=lambda: [0, 0])
    # [none result number, same result number, unsupported result number, good result number]
    _unsupported_hyp_modification: List[int] = field(default_factory=lambda: [0, 0, 0, 0])
    # modification number
    _too_detailed_hyp_modification: int = 0
    # [success number, failure number]
    _post_process_rank: List[int] = field(default_factory=lambda: [0, 0])
    _finish: bool = False


    def update_patch_extraction_status(self, success_flag: bool):
        if success_flag:
            self._patch_extraction[0] += 1
        else:
            self._patch_extraction[1] += 1


    def add_unsupported_hyp_modification_case(self, none_result: bool, same_result: bool, uns_result: bool, good_result: bool):
        assert none_result + same_result + uns_result + good_result == 1
        if none_result:
            self._unsupported_hyp_modification[0] += 1
        elif same_result:
            self._unsupported_hyp_modification[1] += 1
        elif uns_result:
            self._unsupported_hyp_modification[2] += 1
        else:
            self._unsupported_hyp_modification[3] += 1


    def update_too_detailed_hyp_modification_case(self):
        self._too_detailed_hyp_modification += 1


    def update_post_process_rank_status(self, success_flag: bool):
        if success_flag:
            self._post_process_rank[0] += 1
        else:
            self._post_process_rank[1] += 1


    def update_finish_status(self, success_flag: bool):
        if success_flag:
            self._finish = True
        else:
            self._finish = False


@dataclass
class ProcSearchStatus(ProcessStatus):
    """Dataclass to hold search status of called search APIs during the identification processes."""
    _unknown_search_api_count: int = 0
    _dispatch_error_count: int = 0
    _invalid_argument_count: int = 0
    _non_unique_file_count: int = 0
    _find_none_count: int = 0
    _find_import_count: int = 0
    _find_code_count: int = 0


    def update_by_search_status(self, search_status: SearchStatus):
        attr_name = f"_{search_status}_count"
        count = getattr(self, attr_name, None)
        if count is not None:
            setattr(self, attr_name, count + 1)
        else:
            raise ValueError(f"Unknown attr {attr_name}")

