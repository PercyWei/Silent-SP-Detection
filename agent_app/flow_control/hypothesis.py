import re

from typing import *
from dataclasses import dataclass

from agent_app.data_structures import CommitType


"""DATACLASS"""


@dataclass(frozen=True)
class VulAnalysis:
    """For recording analysis of the vulnerability."""
    cwe_id: int
    key_variables: List[Tuple[str, str]]
    trigger_action: str
    fix_method: str
    relationship: str

    def to_dict(self) -> dict:
        return {
            "key_variables": self.key_variables,
            "trigger_action": self.trigger_action,
            "fix_method": self.fix_method,
            "relationship": self.relationship
        }

    def to_str(self) -> str:
        # analysis = f"This commit may be related to the fix for vulnerability CWE-{self.cwe_id}. The analysis is as below.\n\n"
        analysis = ""

        # 1. Key variables
        analysis += "1. Key variables of the vulnerability:"
        for name, desc in self.key_variables:
            analysis += f"\n- {name}: {desc}"

        # 2. Trigger action
        analysis += f"\n2. Trigger action of the vulnerability: {self.trigger_action}"

        # 3. Fix method
        analysis += f"\n3. Fix method: {self.fix_method}"

        # 4. Relationship
        analysis = (f"\n4. Relationship between the fix method, trigger action and key variables: "
                    f"\n{self.relationship}")

        return analysis


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
        return (f"(1) commit type: {self.commit_type}"
                f"\n(2) vulnerability type: {self.vulnerability_type}"
                f"\n(3) confidence_score: {self.confidence_score}")


@dataclass
class VerifiedHypothesis(Hypothesis):
    """Dataclass to hold the verified hypothesis with its analysis."""
    novul_analysis: str | None
    vul_analysis: VulAnalysis | None

    def is_valid(self) -> bool:
        return (self.novul_analysis is not None) ^ (self.vul_analysis is not None)

    def to_dict(self) -> Dict:
        assert self.is_valid()

        hyp_dict = super().to_dict()
        if self.vul_analysis:
            hyp_dict.update({"analysis": self.vul_analysis.to_dict()})
        else:
            hyp_dict.update({"analysis": self.novul_analysis})

        return hyp_dict

    def to_str(self) -> str:
        assert self.is_valid()

        hyp_desc = super().to_str()

        hyp_desc += "\n(4) analysis: "
        if self.vul_analysis:
            for line in self.vul_analysis.to_str().split("\n"):
                hyp_desc += "\n    " + line
        else:
            for line in self.novul_analysis:
                hyp_desc += "\n    " + line

        return hyp_desc


@dataclass
class FinalHypothesis(Hypothesis):
    """Dataclass to hold the final hypothesis obtained from the results of multiple processes."""
    count: int

    def to_dict(self) -> Dict:
        hyp_dict = super().to_dict()
        hyp_dict.update({"count": self.count})
        return hyp_dict

    def to_str(self) -> str:
        hyp_desc = super().to_str()
        hyp_desc += f"\n(4) count: {self.count}"
        return hyp_desc


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


def update_hyp_with_analysis(
        hyp: Hypothesis,
        novul_analysis: str | None,
        vul_analysis: VulAnalysis | None
) -> VerifiedHypothesis:
    assert (novul_analysis is not None) ^ (vul_analysis is not None)

    ver_hyp = VerifiedHypothesis(
        commit_type=hyp.commit_type,
        vulnerability_type=hyp.vulnerability_type,
        confidence_score=hyp.confidence_score,
        novul_analysis=novul_analysis,
        vul_analysis=vul_analysis
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