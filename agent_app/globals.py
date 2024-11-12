# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/globals.py

"""Values of global configuration variables."""
from typing import *


"""BASIC CONFIG"""


# Project language (Python / Java)
lang: Literal['Python', 'Java'] = 'Python'

# Overall output directory for results
output_dpath: str = ""

# Output directory for current experiment
expr_dpath: str = ""

# Root directory for local repos (cloned from GitHub)
local_repos_dpath: str = ""

# Directory for temp files
temp_dpath: str = ""

# Current experiment for security commit (vul) or other commit (novul)
expr_type: str = ""


"""CWE CONFIG"""


# CWE View (For now, only '1003' and '1000' are supported)
view_id: str = ""

# File storing information about the CWE entries in current VIEW
cwe_entry_file: str = ""

# File storing information about the CWE tree in current VIEW
cwe_tree_file: str = ""

# File storing information about all Weakness CWE entries (VIEW-1000)
all_weakness_entries_file: str = "/root/projects/VDTest/data/CWE/VIEW_1000/CWE_entries.json"

# File storing information about attributes of some weaknesses (depth <= 3)
weakness_attributes_file: str = "/root/projects/VDTest/data/CWE/all_weakness_attrs.json"

## Other VIEWs
# VIEW-ID -> CWE entries file
view_cwe_entries_files: Dict[str, str] = {
    "699": "/root/projects/VDTest/data/CWE/VIEW_699/CWE_entries.json",
    "888": "/root/projects/VDTest/data/CWE/VIEW_888/CWE_entries.json",
    "1400": "/root/projects/VDTest/data/CWE/VIEW_1400/CWE_entries.json"
}

# VIEW-ID -> CWE tree file
view_cwe_tree_files: Dict[str, str] = {
    "699": "/root/projects/VDTest/data/CWE/VIEW_699/CWE_tree.json",
    "888": "/root/projects/VDTest/data/CWE/VIEW_888/CWE_tree.json",
    "1400": "/root/projects/VDTest/data/CWE/VIEW_1400/CWE_tree.json"
}


"""PROCESS CONFIG"""


# Complete process: start state -> ... -> end state
complete_process_limit: int = 3

# Retry
state_retry_limit: int = 3

# Conversation round
state_round_limit: int = 10

# Hypothesis to be verified
hypothesis_limit: int = 3

# Timeout for test cmd execution, currently set to 5 min
test_exec_timeout: int = 300


"""OTHER CONFIG"""


# Task
task_limit: int = 1

java_standard_packages_file: str = "/root/projects/VDTest/data/JavaPKG/java_23_packages.json"
