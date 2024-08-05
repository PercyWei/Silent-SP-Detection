from __future__ import annotations

import ast
import json
import pathlib

from typing import *
from dataclasses import dataclass
from enum import Enum

from loguru import logger

from utils import LineRange


class LocationType(str, Enum):
    CLASS = "class"
    CLASSOTHER = "classOther"
    CLASSFUNCTION = "classFunction"
    FUNCTION = "function"
    GLOBAL = "global"
    BLANK = "blank"


@dataclass
class Location:
    type: str
    name: str
    start: int
    end: int
    father: Location | None = None


class LocationError(Exception):
    def __init__(self, locations: List[Location]):
        self.locations = locations

    def __str__(self):
        print_msg = ""
        for loc in self.locations:
            print_msg += f"Type: {loc.type}\nName: {loc.name}\nRange: {loc.start} - {loc.end}\n\n"

        return print_msg


def parse_python_file_locations(
        file_content: str
) -> Tuple[Dict, Dict, Dict, List[Location], List[int], ast.Module] | None:
    """

    Args:
        file_content (str): Python file content.

    Returns:
        Dict:                  class name (<original>@<start>) -> class range
        Dict:               function name (<original>@<start>) -> function range
        Dict: async function name (<original>@<start>) -> async function range
        List[Location]: List of Locations
        List[int]: The value of the k-th element is the location index (to Locations) of the k-th code line in the file.
        ast.Module: AST tree.
    """
    try:
        tree = ast.parse(file_content)
    except Exception:
        logger.debug("AST parsing file failed")
        return None

    locations: List[Location] = []

    classes: Dict[str, LineRange] = {}
    class_functions: Dict[str, Dict[str, LineRange]] = {}
    funcs: Dict[str, LineRange] = {}

    for child in ast.iter_child_nodes(tree):
        name = child.name if hasattr(child, 'name') else type(child).__name__
        start_lineno = child.lineno  # 1-based
        end_lineno = child.end_lineno  # 1-based

        if isinstance(child, ast.ClassDef):
            name = name + f"@{start_lineno}"
            assert name not in classes, f"{name} - {start_lineno}"

            classes[name] = LineRange(start_lineno, end_lineno)
            locations.append(Location(LocationType.CLASS, name, start_lineno, end_lineno))

            for c in ast.iter_child_nodes(child):
                if isinstance(c, ast.FunctionDef):

        elif isinstance(child, ast.FunctionDef) or isinstance(child, ast.AsyncFunctionDef):
            name = name + f"@{start_lineno}"
            assert name not in funcs, f"{name} - {start_lineno}"

            funcs[name] = LineRange(start_lineno, end_lineno)
            locations.append(Location(LocationType.FUNCTION, name, start_lineno, end_lineno))

        else:
            locations.append(Location(LocationType.GLOBAL, name, start_lineno, end_lineno))

    # Add BLANK
    updt_locations: List[Location] = []
    for i in range(len(locations)):
        if i == 0:
            if locations[i].start > 1:
                updt_locations.append(Location(LocationType.BLANK, "", 1, locations[i].start - 1))
            updt_locations.append(locations[i])
        else:
            if locations[i].start > locations[i - 1].end + 1:
                updt_locations.append(
                    Location(LocationType.BLANK, "", locations[i - 1].end + 1, locations[i].start - 1))
            updt_locations.append(locations[i])
    if locations[-1].end < len(file_content.splitlines()):
        updt_locations.append(Location(LocationType.BLANK, "", locations[-1].end + 1, len(file_content.splitlines())))

    # Create reference (index of updt_locations) to each file line
    refs = []
    for i, loc in enumerate(updt_locations):
        refs.extend([i] * (loc.end - loc.start + 1))

    assert len(refs) == len(file_content.splitlines()), LocationError(updt_locations)

    return classes, funcs, async_funcs, updt_locations, refs, tree
