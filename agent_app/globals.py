# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/globals.py

"""
Values of global configuration variables.
"""

# Overall output directory for results
output_dpath: str = ""

# Output directory for current experiment
expr_dpath: str = ""

# Root directory for local repos (cloned from GitHub)
local_repos_dpath: str = ""

# Current experiment for security commit (vul) or other commit (safe)
expr_type: str = ""

task_limit: int = 1

# Opper bound of the number of the complete process for silent security patch identification
# Complete process: From start state to end state
complete_process_limit: int = 3

# Retry
state_retry_limit: int = 3

# Conversation round
state_round_limit: int = 6

hypothesis_limit: int = 3

# Timeout for test cmd execution, currently set to 5 min
test_exec_timeout: int = 300

