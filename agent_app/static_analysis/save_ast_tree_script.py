import sys
import ast
import dill


def ast_parse_and_save(py_fpath, save_fpath):
    with open(py_fpath, 'r') as f:
        py_code = f.read()

    try:
        tree = ast.parse(py_code)
        with open(save_fpath, 'wb') as f:
            dill.dump(tree, f)
        sys.exit(0)
    except SyntaxError as e:
        sys.exit(1)
    except ValueError as e:
        sys.exit(2)
    except RuntimeError as e:
        sys.exit(3)
    except Exception as e:
        sys.exit(4)


if __name__ == "__main__":
    ast_parse_and_save(sys.argv[1], sys.argv[2])
