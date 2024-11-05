import ast
import json

from agent_app.commit.commit_util import filter_py_code_content


example_file = "./example1.py"
with open(example_file, "r") as f:
    py_code = f.read()

filtered_py_code, line_id_map = filter_py_code_content(py_code)

print(filtered_py_code)
print("\n\n")
print(json.dumps(line_id_map, indent=4))

# tree = ast.parse(py_code)
# print("\n\n")
# print(ast.dump(tree, indent=4))
