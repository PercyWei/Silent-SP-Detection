import ast
import re

from typing import *
from dataclasses import dataclass
from enum import Enum

from loguru import logger

from utils import LineRange


class LocationType(str, Enum):
    # Root
    MODULE = "module"
    # Top level items
    GLOBAL = "global"
    FUNCTION = "function"
    CLASS = "class"
    MAIN = "main"
    # Class children
    CLASS_GLOBAL = "class_global"
    CLASS_FUNCTION = "class_function"
    # Main children
    MAIN_GLOBAL = "main_global"

    @staticmethod
    def attributes():
        return [k.value for k in LocationType]


line_loc_types = [LocationType.GLOBAL, LocationType.FUNCTION,
                  LocationType.CLASS_GLOBAL, LocationType.CLASS_FUNCTION,
                  LocationType.MAIN_GLOBAL]
top_level_loc_types = [LocationType.GLOBAL, LocationType.FUNCTION, LocationType.CLASS, LocationType.MAIN]
no_children_loc_types = [LocationType.GLOBAL, LocationType.FUNCTION,
                         LocationType.CLASS_GLOBAL, LocationType.CLASS_FUNCTION,
                         LocationType.MAIN_GLOBAL]
children_loc_types = [LocationType.CLASS, LocationType.MAIN]
class_child_loc_types = [LocationType.CLASS_GLOBAL, LocationType.CLASS_FUNCTION]
main_child_loc_types = [LocationType.MAIN_GLOBAL]


@dataclass
class Location:
    """For recording different structs in Python code."""
    id: int
    father: int | None
    type: LocationType
    ast: str
    name: str
    range: LineRange

    def get_full_range(self) -> List[int]:
        return list(range(self.range.start, self.range.end + 1))


def _add_class_child_location(
        class_funcs: List[int],
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node (child of class):
    - `locations`: Add CLASSGLOBAL or CLASSFUNCTION location.
    - `line_id2loc_id`: For lines in this node, update look-up dict.
    - `class_funcs`: Record CLASSFUNCTION location id if this node is 'FunctionDef'.
    """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based
    ast_type = type(node).__name__

    # (1) Save location
    if isinstance(node, ast.FunctionDef):
        name = node.name + f"@{start_lineno}"

        class_funcs.append(cur_loc_id)
        class_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS_FUNCTION,
                                   ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    else:
        name = node.name if hasattr(node, 'name') else ""

        class_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS_GLOBAL,
                                   ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))

    locations[cur_loc_id] = class_child_loc
    cur_loc_id += 1

    # (2) Update location look-up dict for line id
    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = class_child_loc.id

    return class_child_loc, cur_loc_id


def _add_class_location(
        classes: List[int],
        classes_funcs: Dict[int, List[int]],
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.ClassDef,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node:
    - `locations`: Add CLASS location.
    - `classes`: Record CLASS location id.

    For children of this Class:
    - `locations`: Add CLASSGLOBAL and CLASSFUNCTION location.
    - `line_id2loc_id`: For lines in class child, update look-up dict.
    - `classes_funcs`: Record CLASSFUNCTION location id.
    """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based
    ast_type = type(node).__name__
    class_name = node.name + f"@{start_lineno}"

    ########### Step I. Save location of CLASS ###########
    classes.append(cur_loc_id)
    class_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS,
                         ast=ast_type, name=class_name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = class_loc
    cur_loc_id += 1

    ########### Step II. Go inside CLASS ###########
    class_funcs: List[int] = []

    ## (1) Add class name
    first_child = node.body[0]
    if start_lineno < first_child.lineno:
        symbol_child_loc = Location(id=cur_loc_id, father=class_loc.id, type=LocationType.CLASS_GLOBAL,
                                    ast="class_name", name="", range=LineRange(start_lineno, first_child.lineno - 1))
        locations[cur_loc_id] = symbol_child_loc
        cur_loc_id += 1

        for line_id in range(start_lineno, first_child.lineno):
            assert line_id not in line_loc_lookup
            line_loc_lookup[line_id] = symbol_child_loc.id

    ## (2) Iterate and add the top level elements of class body
    for child in node.body:
        _, cur_loc_id = _add_class_child_location(
            class_funcs=class_funcs,
            locations=locations,
            line_loc_lookup=line_loc_lookup,
            node=child,
            cur_loc_id=cur_loc_id,
            father_loc_id=class_loc.id
        )

    # Step III. Go out CLASS, save the class functions
    classes_funcs[class_loc.id] = class_funcs

    return class_loc, cur_loc_id


def _add_function_location(
        funcs: List[int],
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.FunctionDef,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node:
    - `locations`: Add FUNCTION location.
    - `line_id2loc_id`: For lines in function, update look-up dict.
    - `funcs`: Record FUNCTION location id.
    """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based
    ast_type = type(node).__name__
    func_name = node.name + f"@{start_lineno}"

    # Step I. Save location of FUNCTION
    funcs.append(cur_loc_id)
    func_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.FUNCTION,
                        ast=ast_type, name=func_name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = func_loc
    cur_loc_id += 1

    # (2) Update location look-up dict for line id
    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = func_loc.id

    return func_loc, cur_loc_id


def _add_global_location(
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node (top level node of root, except class/func):
    - `locations`: Add GLOBAL location.
    - `line_id2loc_id`: For lines in node, update look-up dict.
    """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based
    ast_type = type(node).__name__
    name = node.name if hasattr(node, 'name') else ""

    # (1) Save location of GLOBAL
    global_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.GLOBAL,
                          ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = global_loc
    cur_loc_id += 1

    # (2) Update location look-up dict for line id
    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = global_loc.id

    return global_loc, cur_loc_id


def _is_if_main_line(line: str) -> bool:
    pattern = r'^\s*if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:'
    match = re.search(pattern, line, re.MULTILINE)
    return bool(match)


def _add_if_main_child_location(
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node (child of Main):
    - `locations`: Add MAINGLOBAL location.
    - `line_id2loc_id`: For lines in this node, update look-up dict.
    """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based
    ast_type = type(node).__name__
    name = node.name if hasattr(node, 'name') else ""

    # (1) Save location of MAINGLOBAL
    if_main_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.MAIN_GLOBAL,
                                 ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = if_main_child_loc
    cur_loc_id += 1

    # (2) Update look-up dict for line id
    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = if_main_child_loc.id

    return if_main_child_loc, cur_loc_id


def _add_if_main_location(
        if_mains: List[int],
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        node: ast.If,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
       For AST node of type 'ClassDef':
       - `locations`: Add CLASS location.
       - `line_id2loc_id`: For lines in class, update look-up dict.
       - `classes`: Record CLASS location id.

       For children of class:
       - `locations`: Add CLASSGLOBAL and CLASSFUNCTION location.
       - `line_id2loc_id`: For lines in class child, update look-up dict.
       - `classes_funcs`: Record CLASSFUNCTION location id.

       """
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based
    ast_type = type(node).__name__
    name = "if_main"

    # I. Save location of MAIN
    if_mains.append(cur_loc_id)
    main_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.MAIN,
                        ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = main_loc
    cur_loc_id += 1

    # II. Go inside MAIN, iterate the top level elements of it
    children = [node.test] + node.body + node.orelse

    for child in children:
        _, cur_loc_id = _add_if_main_child_location(
            locations=locations,
            line_loc_lookup=line_id2loc_id,
            node=child,
            cur_loc_id=cur_loc_id,
            father_loc_id=main_loc.id
        )

    return main_loc, cur_loc_id


def parse_python_file_locations(file_content: str) -> Tuple[Dict[int, Location], Dict[int, int], Dict]:
    """
    Parse Python file content and extract the following types of Locations:
    - Top level items:
        - Global
        - Function
        - Class
        - Main (if main)
    - Class child items
        - ClassGlobal
        - ClassFunction
    - Main child items
        - MainGlobal

    Args:
        file_content (str): Python file content.
    Returns:
        Dict[int, Location]: Location id -> Location
        Dict[int, int]: line id -> line location id
        Dict: Info dict containing classes, funcs, class_funcs and if_main.
    """
    try:
        tree = ast.parse(file_content)
    except Exception:
        logger.debug("AST parsing file failed")
        raise RuntimeError("AST parsing file failed")

    file_lines = file_content.splitlines(keepends=False)
    file_len = len(file_lines)

    # location_id -> Location
    locations: Dict[int, Location] = {}
    # line id -> line location info
    line_loc_lookup: Dict[int, int] = {}

    if_mains: List[int] = []
    funcs: List[int] = []
    classes: List[int] = []
    classes_funcs: Dict[int, List[int]] = {}

    ################## Add root Location ##################
    cur_loc_id = 0
    root_loc = Location(id=cur_loc_id, father=None, type=LocationType.MODULE,
                        ast=type(tree).__name__, name="", range=LineRange(start=1, end=file_len))
    locations[cur_loc_id] = root_loc
    cur_loc_id += 1

    ################## Iterate the top level elements of the code ##################
    tree_children = list(ast.iter_child_nodes(tree))
    for i, child in enumerate(tree_children):
        if isinstance(child, ast.ClassDef):
            _, cur_loc_id = _add_class_location(
                classes=classes,
                classes_funcs=classes_funcs,
                locations=locations,
                line_loc_lookup=line_loc_lookup,
                node=child,
                cur_loc_id=cur_loc_id,
                father_loc_id=root_loc.id
            )
        elif isinstance(child, ast.FunctionDef):
            _, cur_loc_id = _add_function_location(
                funcs=funcs,
                locations=locations,
                line_loc_lookup=line_loc_lookup,
                node=child,
                cur_loc_id=cur_loc_id,
                father_loc_id=root_loc.id
            )
        elif isinstance(child, ast.If):
            if_cond_line = file_lines[child.lineno - 1]
            if _is_if_main_line(if_cond_line):
                _, cur_loc_id = _add_if_main_location(
                    if_mains=if_mains,
                    locations=locations,
                    line_id2loc_id=line_loc_lookup,
                    node=child,
                    cur_loc_id=cur_loc_id,
                    father_loc_id=root_loc.id
                )
            else:
                _, cur_loc_id = _add_global_location(
                    locations=locations,
                    line_loc_lookup=line_loc_lookup,
                    node=child,
                    cur_loc_id=cur_loc_id,
                    father_loc_id=root_loc.id
                )
        else:
            _, cur_loc_id = _add_global_location(
                locations=locations,
                line_loc_lookup=line_loc_lookup,
                node=child,
                cur_loc_id=cur_loc_id,
                father_loc_id=root_loc.id
            )

    assert len(if_mains) <= 1

    structs_info = {
        "if_mains": if_mains,
        "funcs": funcs,
        "classes": classes,
        "classes_funcs": classes_funcs
    }

    return locations, line_loc_lookup, structs_info
