
from typing import *











def prompt_fill4code_changes(code_changes_info: Dict) ->str:
    # TODO
    code_changes_seq = ""

    return code_changes_seq


def _get_identity_description_seq(iden_type: int = 1) -> str:
    """
        Select identity description sequence.

        :param iden_type: Identity description type.
    """
    if iden_type == 0:
        return ''
    elif iden_type == 1:
        return "You are a senior expert in vulnerability mining and analysis.\n"
    else:
        return "You're a senior security analyst.\n"


def _get_CoT_seq(CoT_type: int = 1) -> str:
    """
       Select CoT instruction sequence.

       :param CoT_type: CoT instruction type.
                        0: No CoT.
                        1: Zero-shot CoT.
                        2: Few-shot CoT (In-context learning).
                        3: Auto CoT (In-context learning).
    """
    if CoT_type == 0:
        return ''
    else:
        return "Let's analyze it step by step.\n"


def _get_few_shot_seq(dataset_retrival: Dict, retrieval_type: int = 0, CoT_type: int = 0) -> str:
    """
        Retrival data examples ([code change, result] pair) from dataset_retrival.
        Retrieval strategy is determined by retrieval_type.
        Form of result sequence is determined by CoT_type.

        :param dataset_retrival:
        :param retrieval_type: Type of retrieval.
                               0: Fixed.
                               1: Random.
                               2:
        :param CoT_type: Type of CoT.
                         0: Result is CWE-ID only.
                         1:
                         2 / 3: Result contain the reasoning process and CWE-ID
    """
    code_examples = _retrival_examples()


def _retrival_examples() -> List[str]:
    pass

def one_time_prompt(prompt_type: int, code_changes_info: Dict) -> str:
    """


    :param prompt_type: Type of prompt for one-time Q&A
                        1: Basic Prompt
                        2: Basic Prompt + Identity
                        3: Basic Prompt + Identity + Instruction
    :param code_changes_info:
    """




    code_section_before_seq = f"```{code_changes_info['language']}\n"
    code_changes_seq = prompt_fill4code_changes(code_changes_info)
    code_section_after_seq = f"```"
    code_section_seq = code_section_before_seq + code_changes_seq + code_section_after_seq

    task_description_seq = ("The above gives the source code changes in a GitHub commit which "
                            "fixes a security vulnerability, please give the type of the vulnerability, "
                            "which is indicated by the CWE ID. The format of the answer is $CWE-ID")
    identity_description_seq = _get_identity_description_seq()
    instruction_seq = ("When you do so, search according to the segmentation guidelines in CWE-1003 "
                       "and try to match the description of each CWE type, "
                       "ultimately giving the CWE-ID with the highest likelihood.\n")


    if prompt_type == 1:
        prompt_seq = code_section_seq + task_description_seq
    elif prompt_type == 2:
        prompt_seq = code_section_seq + identity_description_seq + task_description_seq
    elif prompt_type == 3:
        prompt_seq = code_section_seq + identity_description_seq + task_description_seq + instruction_seq












