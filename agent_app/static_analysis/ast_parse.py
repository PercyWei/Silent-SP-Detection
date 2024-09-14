import os
import sys
import ast
import dill
import subprocess

from typing import *


def ast_parse_in_conda_env(py_fpath: str, save_fpath: str, env_name: str, script_fpath: str) -> Tuple[int, str, str]:
    command = f"conda run -n {env_name} python {script_fpath} {py_fpath} {save_fpath}"

    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    return result.returncode, stdout, stderr


def ast_parse_with_retries(
        py_fpath: str, save_fpath: str, script_fpath: str = "./agent_app/static_analysis/save_ast_tree_script.py"
) -> Tuple[ast.Module | None, str]:
    # TODO-1: We only parse the Python code that failed due to SyntaxError in different versions of Python environment.

    envs = ["py27", "py36", "py37", "py38"]

    with open(py_fpath, "r") as f:
        py_code = f.read()

    # (1) AST parse in current env
    cont_parse = False
    summary = ""
    try:
        tree = ast.parse(py_code)
        return tree, "ok"
    except SyntaxError as e:
        # Ref to TODO-1
        cont_parse = True
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        summary += f"AST parsing failed due to SyntaxError failed in Python {py_version}"
    except ValueError as e:
        summary = str(e)
    except RecursionError as e:
        summary = str(e)
    except Exception as e:
        summary = str(e)

    # (2) AST parse in spare envs
    if cont_parse:
        for env in envs:
            return_code, _, stderr = ast_parse_in_conda_env(py_fpath, save_fpath, env, script_fpath)

            if return_code == 0:
                with open(save_fpath, "rb") as f:
                    tree = dill.load(f)
                os.remove(save_fpath)
                return tree, "ok"
            elif return_code == 1:
                # Ref to TODO-1
                py_version = env[2:]
                py_version = py_version[:1] + "." + py_version[1:]
                summary += f", {py_version}"
                continue
            else:
                summary = stderr
                break

    return None, summary


if __name__ == "__main__":
   pass