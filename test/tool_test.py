import os
import ast
import json
import subprocess

from typing import *

from utils import run_command


# import unidiff
# diff_text = """--- a/sample.txt
# +++ b/sample.txt
# @@ -1,3 +1,3 @@
# -This is the original text.
# +This is the modified text.
#  With multiple lines.
#  And more content.
# """

# with open("/root/projects/py_commit/1.log") as f:
#     diff_text = f.read()
# #
# patch = unidiff.PatchSet(diff_text)
#
# # 输出diff信息
# for i, patched_file in enumerate(patch):
#     print(f"============ file {i} ============")
#     for j, hunk in enumerate(patched_file):
#         print(f"============ hunk {j} ============")
#         for line in hunk:
#             print(line)


# with open('/root/projects/VDTest/agent_app/inference.py', 'r') as f:
#     c = f.read()
# tree = ast.parse(c)
# print('ok')

