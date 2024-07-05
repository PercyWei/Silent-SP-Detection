# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/globals.py

"""
Values of global configuration variables.
"""

# Overall output directory for results
output_dir: str = ""

# Opper bound of the number of conversation rounds for the agent
conv_round_limit: int = 15

# Whether to perform layered search
enable_layered: bool = True

# Whether to perform our own validation
enable_validation: bool = False

# Timeout for test cmd execution, currently set to 5 min
test_exec_timeout: int = 300

