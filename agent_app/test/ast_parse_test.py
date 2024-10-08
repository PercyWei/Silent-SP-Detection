import ast


if __name__ == "__main__":
    code = """
import numpy as np
from typing import *
    """

    tree = ast.parse(code)

    print(type(tree.body[0]).__name__)
    print(type(tree.body[1]).__name__)

    print(ast.dump(tree))
