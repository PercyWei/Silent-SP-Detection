import ast

from typing import *
from dataclasses import dataclass
from enum import Enum

from loguru import logger

from utils import LineRange


class LocationType(str, Enum):
    MODULE = "module"
    GLOBAL = "global"
    FUNCTION = "function"
    CLASS = "class"
    CLASSGLOBAL = "class_global"
    CLASSFUNCTION = "class_function"
    # BLANK = "blank"
    # CLASSBLANK = "class_blank"

    @staticmethod
    def attributes():
        return [k.value for k in LocationType]


@dataclass
class Location:
    id: int
    father: int | None
    type: LocationType
    name: str
    range: LineRange

    def get_full_range(self) -> List[int]:
        return list(range(self.range.start, self.range.end + 1))


class LocationError(Exception):
    def __init__(self, locations: Dict[int, Location]):
        self.locations = locations

    def __str__(self):
        print_msg = ""
        for _, loc in self.locations.items():
            print_msg += (f"Id: {loc.id}, Father: {loc.father}, Type: {loc.type}, "
                          f"Name: {loc.name}, Range: {loc.range.start}-{loc.range.end}\n")

        return print_msg


def _add_blank_location(
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        blank_type: LocationType,
        cur_loc_id: int,
        cur_loc: Location,
        last_loc: Location | None,
        father_loc: Location,
        add_end: bool = False
) -> int:
    """
    Add a blank location before and after the current location respectively.
    last loc -> <blank loc> -> cur loc ( -> <blank loc> -> end )

    """
    # (1) Add BLANK before the current location
    before_blank_loc = None
    if last_loc is None:
        if cur_loc.range.start > father_loc.range.start:
            before_blank_loc = Location(id=cur_loc_id, father=father_loc.id, type=blank_type,
                                        name="", range=LineRange(father_loc.range.start, cur_loc.range.start - 1))
    else:
        if cur_loc.range.start > last_loc.range.end + 1:
            before_blank_loc = Location(id=cur_loc_id, father=father_loc.id, type=blank_type,
                                        name="", range=LineRange(last_loc.range.end + 1, cur_loc.range.start - 1))

    if before_blank_loc is not None:
        # Save BLANK location before
        locations[cur_loc_id] = before_blank_loc
        cur_loc_id += 1
        # Save loc id of lines in BLANK location before
        for _line_id in range(before_blank_loc.range.start, before_blank_loc.range.end + 1):
            line_id2loc_id[_line_id] = before_blank_loc.id

    # (2) Add BLANK after the current location
    after_blank_loc = None
    if add_end and cur_loc.range.end < father_loc.range.end:
        after_blank_loc = Location(id=cur_loc_id, father=father_loc.id, type=blank_type,
                                   name="", range=LineRange(cur_loc.range.end + 1, father_loc.range.end))

    if after_blank_loc is not None:
        # Save BLANK location after
        locations[cur_loc_id] = after_blank_loc
        cur_loc_id += 1
        # Save loc ids of lines in BLANK location after
        for _line_id in range(after_blank_loc.range.start, after_blank_loc.range.end + 1):
            line_id2loc_id[_line_id] = after_blank_loc.id

    return cur_loc_id


def _add_class_child_location(
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        class_funcs: List[int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For the node of class:
    - `locations`: Add CLASSGLOBAL or CLASSFUNCTION location.
    - `line_id2loc_id`: For lines in this node, update look-up dict.
    - `class_funcs`: Record CLASSFUNCTION location id if this node is 'FunctionDef'.

    """
    name = node.name if hasattr(node, 'name') else type(node).__name__
    start_lineno = node.lineno  # 1-based
    end_lineno = node.end_lineno  # 1-based

    if isinstance(node, ast.FunctionDef):
        name = name + f"@{start_lineno}"

        class_funcs.append(cur_loc_id)
        class_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASSFUNCTION,
                                   name=name, range=LineRange(start_lineno, end_lineno))
    else:
        class_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASSGLOBAL,
                                   name=name, range=LineRange(start_lineno, end_lineno))

    # 1) Save top level element of CLASS
    locations[cur_loc_id] = class_child_loc
    cur_loc_id += 1

    # 2) Save loc ids of lines in CLASS
    for line_id in range(start_lineno, end_lineno + 1):
        line_id2loc_id[line_id] = class_child_loc.id

    return class_child_loc, cur_loc_id


def _add_class_location(
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        classes: List[int],
        classes_funcs: Dict[int, List[int]],
        node: ast.ClassDef,
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
    start_lineno = node.lineno  # 1-based
    end_lineno = node.end_lineno  # 1-based

    name = node.name + f"@{start_lineno}"

    # I. Save the CLASS location
    classes.append(cur_loc_id)
    class_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS,
                         name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = class_loc
    cur_loc_id += 1

    # II. Go inside CLASS, iterate the top level elements of it
    class_funcs: List[int] = []

    children = list(ast.iter_child_nodes(node))
    for j, child in enumerate(children):
        # 1) Save class child information
        cur_child_loc, cur_loc_id = _add_class_child_location(
            locations=locations,
            line_id2loc_id=line_id2loc_id,
            class_funcs=class_funcs,
            node=child,
            cur_loc_id=cur_loc_id,
            father_loc_id=class_loc.id
        )

    # III. Go out CLASS, save the CLASS FUNCTION
    classes_funcs[class_loc.id] = class_funcs

    return class_loc, cur_loc_id


def _add_function_location(
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        funcs: List[int],
        node: ast.FunctionDef,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For AST node of type 'FunctionDef':
    - `locations`: Add FUNCTION location.
    - `line_id2loc_id`: For lines in function, update look-up dict.
    - `funcs`: Record FUNCTION location id.

    """
    start_lineno = node.lineno  # 1-based
    end_lineno = node.end_lineno  # 1-based

    name = node.name + f"@{start_lineno}"

    # I. Save the FUNCTION loc
    funcs.append(cur_loc_id)
    func_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.FUNCTION,
                        name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = func_loc
    cur_loc_id += 1

    # II. Save loc ids of lines in FUNCTION
    for line_id in range(start_lineno, end_lineno + 1):
        line_id2loc_id[line_id] = func_loc.id

    return func_loc, cur_loc_id


def _add_global_location(
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For AST node of type not 'FunctionDef' or 'ClassDef':
    - `locations`: Add GLOBAL location.
    - `line_id2loc_id`: For lines in node, update look-up dict.

    """
    name = node.name if hasattr(node, 'name') else type(node).__name__
    start_lineno = node.lineno  # 1-based
    end_lineno = node.end_lineno  # 1-based

    # I. Save the GLOBAL loc
    global_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.GLOBAL,
                          name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = global_loc
    cur_loc_id += 1

    # II. Save loc ids of lines in GLOBAL
    for line_id in range(start_lineno, end_lineno + 1):
        line_id2loc_id[line_id] = global_loc.id

    return global_loc, cur_loc_id


def parse_python_file_locations(
        file_content: str
) -> Tuple[List[int], List[int], Dict[int, List[int]], Dict[int, Location], List[int]]:
    """

    Args:
        file_content (str): Python file content.

    Returns:
        List[int]: List of CLASS location id
        List[int]: List of FUNCTION location id
        Dict[int, List[int]]: CLASS location id -> List of CLASSFUNCTION location id
        Dict[int, Location]: Location id -> Location
        List[int]: The value of the k-th element is the id of location of the k-th code line in the file.
    """
    try:
        tree = ast.parse(file_content)
    except Exception:
        logger.debug("AST parsing file failed")
        raise RuntimeError("AST parsing file failed")

    # location_id -> Location
    locations: Dict[int, Location] = {}
    # line id -> location id
    line_id2loc_id: Dict[int, int] = {}

    classes: List[int] = []
    funcs: List[int] = []
    classes_funcs: Dict[int, List[int]] = {}

    # Add root Location
    cur_loc_id = 0
    root_loc = Location(id=cur_loc_id, father=None, type=LocationType.MODULE,
                        name="", range=LineRange(start=1, end=len(file_content.splitlines())))
    locations[cur_loc_id] = root_loc
    cur_loc_id += 1

    ################## Iterate the top level elements of the code ##################
    tree_children = list(ast.iter_child_nodes(tree))
    for i, child in enumerate(tree_children):
        if isinstance(child, ast.ClassDef):
            _, cur_loc_id = _add_class_location(
                locations=locations,
                line_id2loc_id=line_id2loc_id,
                classes=classes,
                classes_funcs=classes_funcs,
                node=child,
                cur_loc_id=cur_loc_id,
                father_loc_id=root_loc.id
            )
        elif isinstance(child, ast.FunctionDef):
            _, cur_loc_id = _add_function_location(
                locations=locations,
                line_id2loc_id=line_id2loc_id,
                funcs=funcs,
                node=child,
                cur_loc_id=cur_loc_id,
                father_loc_id=root_loc.id
            )
        else:
            _, cur_loc_id = _add_global_location(
                locations=locations,
                line_id2loc_id=line_id2loc_id,
                node=child,
                cur_loc_id=cur_loc_id,
                father_loc_id=root_loc.id
            )

    assert len(line_id2loc_id) == len(file_content.splitlines()), LocationError(locations)
    line_loc_id = [loc_id for _, loc_id in sorted(line_id2loc_id.items())]

    return classes, funcs, classes_funcs, locations, line_loc_id
