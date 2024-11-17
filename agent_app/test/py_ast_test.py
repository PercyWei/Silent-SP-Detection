import ast


code = """
import a as b, c, d as e
from x.y import z, k as l
from x import *
"""

tree = ast.parse(code)
print(ast.dump(tree))
