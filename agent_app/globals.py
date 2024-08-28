# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/globals.py

"""Values of global configuration variables."""

# Overall output directory for results
output_dpath: str = ""

# Output directory for current experiment
expr_dpath: str = ""

# Root directory for local repos (cloned from GitHub)
local_repos_dpath: str = ""

# Current experiment for security commit (vul) or other commit (safe)
expr_type: str = ""

# File storing information about the CWE entries
cwe_entry_file: str = ""

# File storing information about the CWE tree
cwe_tree_file: str = ""

# Task
task_limit: int = 2

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

