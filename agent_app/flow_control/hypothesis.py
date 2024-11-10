import re

from typing import *
from dataclasses import dataclass

from agent_app.data_structures import CommitType


"""DATACLASS"""


@dataclass
class Hypothesis:
    """Dataclass to hold the basic hypothesis."""
    commit_type: CommitType
    vulnerability_type: str
    confidence_score: int | float

    def to_dict(self) -> Dict:
        return {
            "commit_type": self.commit_type,
            "vulnerability_type": self.vulnerability_type,
            "confidence_score": self.confidence_score
        }

    def to_str(self) -> str:
        return (f"- commit type: {self.commit_type}"
                f"\n- vulnerability type: {self.vulnerability_type}"
                f"\n- confidence_score: {self.confidence_score}")


@dataclass
class VerifiedHypothesis(Hypothesis):
    """Dataclass to hold the verified hypothesis with its analysis."""
    analysis: str

    def to_dict(self) -> Dict:
        info = super().to_dict()
        info.update({"analysis": self.analysis})
        return info

    def to_str(self) -> str:
        seq = super().to_str()
        seq += f"\n- analysis: {self.analysis}"
        return seq


@dataclass
class FinalHypothesis(Hypothesis):
    """Dataclass to hold the final hypothesis obtained from the results of multiple processes."""
    count: int

    def to_dict(self) -> Dict:
        info = super().to_dict()
        info.update({"count": self.count})
        return info

    def to_str(self) -> str:
        seq = super().to_str()
        seq += f"\n- count: {self.count}"
        return seq


"""UTIL"""


def get_hyp_description(hyp: Hypothesis, with_score: bool = True) -> str:
    """Describe the given hypothesis."""
    if hyp.commit_type == CommitType.NonVulnerabilityPatch:
        desc = f"The given commit does not fix a vulnerability"
    else:
        desc = f"The given commit fixes a vulnerability of type {hyp.vulnerability_type}"

    if with_score:
        desc += f", and the confidence score is {hyp.confidence_score}/10"

    return desc


def build_basic_hyp(commit_type: str, vul_type: str, conf_score: int) -> Hypothesis:
    # (1) Check commit type
    try:
        commit_type = CommitType(commit_type)
    except ValueError:
        raise ValueError(f"CommitType {commit_type} is not valid")

    # (2) Check vulnerability type (CWE-ID)
    if commit_type == CommitType.VulnerabilityPatch:
        assert re.fullmatch(r"CWE-\d+", vul_type)
    else:
        assert vul_type == ""

    # (3) Check confidence score
    assert isinstance(conf_score, int)
    conf_score = min(10, max(1, int(conf_score)))

    return Hypothesis(commit_type, vul_type, conf_score)


def update_hyp_with_analysis(hyp: Hypothesis, analysis: str) -> VerifiedHypothesis:
    ver_hyp = VerifiedHypothesis(
        commit_type=hyp.commit_type,
        vulnerability_type=hyp.vulnerability_type,
        confidence_score=hyp.confidence_score,
        analysis=analysis
    )
    return ver_hyp


def update_hyp_with_count(hyp: Hypothesis, count: int) -> FinalHypothesis:
    final_hyp = FinalHypothesis(
        commit_type=hyp.commit_type,
        vulnerability_type=hyp.vulnerability_type,
        confidence_score=hyp.confidence_score,
        count=count
    )
    return final_hyp