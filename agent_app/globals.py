# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/globals.py

"""Values of global configuration variables."""
from typing import *


"""BASIC CONFIG"""

# Overall output directory for results
output_dpath: str = ""

# Output directory for current experiment
expr_dpath: str = ""

# Root directory for local repos (cloned from GitHub)
local_repos_dpath: str = ""

# Current experiment for security commit (vul) or other commit (novul)
expr_type: str = ""

"""CWE CONFIG"""

# CWE VIEW (VIEW-1003 / VIEW-1000)
full_view_id: str = ""

# File storing information about all Weakness CWE entries (VIEW-1000)
all_weakness_entry_file: str = ""

# File storing information about the CWE entries in current VIEW
cwe_entry_file: str = ""

# File storing information about the CWE tree in current VIEW
cwe_tree_file: str = ""

# VIEW-ID -> CWE tree
view_cwe_tree_files: List[Tuple[str, str]] = []

"""PROCESS CONFIG"""

# Complete process: start state -> ... -> end state
complete_process_limit: int = 3

# Retry
state_retry_limit: int = 3

# Conversation round
state_round_limit: int = 6

# Hypothesis to be verified
hypothesis_limit: int = 3

# Timeout for test cmd execution, currently set to 5 min
test_exec_timeout: int = 300

"""OTHER CONFIG"""

# Task
task_limit: int = 5
