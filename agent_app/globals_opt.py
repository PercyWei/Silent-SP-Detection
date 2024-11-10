
## Strategy for building file diff context
# - 1: Only extract diff lines in the file.
# - 2: Except diff lines, also extract:
#      1) for python code: relevant class / function signatures, inclass method signatures, main signatures,
#         the complete statement of each diff line and its nearby code lines;
#      2) for java code: relevant interface / class signatures, inclass interface / class / method signatures,
#         the complete statement of each diff line and its nearby code lines.
opt_to_file_diff_context: int = 2

## Strategy for extracting relevant function / method snippet while building file diff context
# - 1: Extract the entire code snippet of function / method.
# - 2: Only extract the context of diff lines in the function / method and its signature.
opt_to_func_diff_context: int = 2

## Strategy for extracting relevant interface snippet while building file diff context
# NOTE: The same as 'opt_to_func_diff_context'.
opt_to_iface_diff_context: int = 2

# Strategy for init hypothesis making in start state
opt_to_start_state_path: int = 2
