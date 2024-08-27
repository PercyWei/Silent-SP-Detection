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
    UNIT = "unit"
    FUNCTION = "function"
    CLASS = "class"
    MAIN = "main"
    # Class children
    CLASS_UNIT = "class_unit"
    CLASS_FUNCTION = "class_function"
    # Main children
    MAIN_UNIT = "main_unit"

    @staticmethod
    def attributes():
        return [k.value for k in LocationType]


line_loc_types = [LocationType.UNIT, LocationType.FUNCTION,
                  LocationType.CLASS_UNIT, LocationType.CLASS_FUNCTION,
                  LocationType.MAIN_UNIT]
top_level_loc_types = [LocationType.UNIT, LocationType.FUNCTION, LocationType.CLASS, LocationType.MAIN]
no_children_loc_types = [LocationType.UNIT, LocationType.FUNCTION,
                         LocationType.CLASS_UNIT, LocationType.CLASS_FUNCTION,
                         LocationType.MAIN_UNIT]
children_loc_types = [LocationType.CLASS, LocationType.MAIN]
class_child_loc_types = [LocationType.CLASS_UNIT, LocationType.CLASS_FUNCTION]
main_child_loc_types = [LocationType.MAIN_UNIT]


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


"""ADD LOCATION"""


def _cal_class_or_func_def_range(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> Tuple[int, int]:
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based

    # NOTE: For ClassDef / FunctionDef node, `lineno`, `end_lineno` and `decorator_list` are treated separately
    for decorator in node.decorator_list:
        if hasattr(decorator, 'lineno'):
            start_lineno = min(start_lineno, decorator.lineno)
        if hasattr(decorator, 'end_lineno'):
            end_lineno = max(end_lineno, decorator.end_lineno)

    return start_lineno, end_lineno


def _add_class_child_location(
        class_funcs: List[int],
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node:
    - `locations`: Add CLASS_UNIT or CLASS_FUNCTION location.
    - `line_id2loc_id`: For lines in this node, update look-up dict.
    - `class_funcs`: Record CLASS_FUNCTION location id if this node is 'FunctionDef'.
    """
    ast_type = type(node).__name__
    name = node.name if hasattr(node, 'name') else ""

    ###########################################################
    # Step 1. Save the location (CLASS_UNIT / CLASS_FUNCTION) #
    ###########################################################

    if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
        start_lineno, end_lineno = _cal_class_or_func_def_range(node)

        class_funcs.append(cur_loc_id)
        class_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS_FUNCTION,
                                   ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    else:
        start_lineno = node.lineno    # 1-based
        end_lineno = node.end_lineno  # 1-based

        class_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS_UNIT,
                                   ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))

    locations[cur_loc_id] = class_child_loc
    cur_loc_id += 1

    ###################################################
    # Step 2. Update look-up dict (line id -> loc id) #
    ###################################################

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

    For children of it:
    - `locations`: Add CLASS_UNIT and CLASS_FUNCTION location.
    - `line_id2loc_id`: For lines in class child, update look-up dict.
    - `classes_funcs`: Record CLASSFUNCTION location id.
    """
    ast_type = type(node).__name__
    class_name = node.name
    start_lineno, end_lineno = _cal_class_or_func_def_range(node)

    ###################################
    # Step 1. Save the location CLASS #
    ###################################

    classes.append(cur_loc_id)
    class_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.CLASS,
                         ast=ast_type, name=class_name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = class_loc
    cur_loc_id += 1

    ##################################################
    # Step 2. Save the location of children of CLASS #
    ##################################################

    class_funcs: List[int] = []

    ## (1) Add class name (special case)
    first_child = node.body[0]
    if start_lineno < first_child.lineno:
        symbol_child_loc = Location(id=cur_loc_id, father=class_loc.id, type=LocationType.CLASS_UNIT,
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

    ####################################
    # Step 3. Save the class functions #
    ####################################

    classes_funcs[class_loc.id] = class_funcs

    return class_loc, cur_loc_id


def _add_function_location(
        funcs: List[int],
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node:
    - `locations`: Add FUNCTION location.
    - `line_id2loc_id`: For lines in function, update look-up dict.
    - `funcs`: Record FUNCTION location id.
    """
    ast_type = type(node).__name__
    func_name = node.name
    start_lineno, end_lineno = _cal_class_or_func_def_range(node)

    ######################################
    # Step 1: Save the location FUNCTION #
    ######################################

    funcs.append(cur_loc_id)
    func_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.FUNCTION,
                        ast=ast_type, name=func_name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = func_loc
    cur_loc_id += 1

    ###################################################
    # Step 2. Update look-up dict (line id -> loc id) #
    ###################################################

    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = func_loc.id

    return func_loc, cur_loc_id


def _add_unit_location(
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node:
    - `locations`: Add UNIT location.
    - `line_id2loc_id`: For lines in node, update look-up dict.
    """
    ast_type = type(node).__name__
    name = node.name if hasattr(node, 'name') else ""
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based

    ####################################
    # Step 1: Save the location GLOBAL #
    ####################################

    # (1) Save GLOBAL location
    global_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.UNIT,
                          ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = global_loc
    cur_loc_id += 1

    ###################################################
    # Step 2. Update look-up dict (line id -> loc id) #
    ###################################################

    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = global_loc.id

    return global_loc, cur_loc_id


def _is_main_line(line: str) -> bool:
    pattern = r'^\s*if\s+__name__\s*==\s*[\'"]__main__[\'"]\s*:'
    match = re.search(pattern, line, re.MULTILINE)
    return bool(match)


def _add_main_child_location(
        locations: Dict[int, Location],
        line_loc_lookup: Dict[int, int],
        node: ast.AST,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
    For current node:
    - `locations`: Add MAIN_UNIT location.
    - `line_id2loc_id`: For lines in this node, update look-up dict.
    """
    ast_type = type(node).__name__
    name = node.name if hasattr(node, 'name') else ""

    if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
        start_lineno, end_lineno = _cal_class_or_func_def_range(node)
    else:
        start_lineno = node.lineno    # 1-based
        end_lineno = node.end_lineno  # 1-based

    #######################################
    # Step 1: Save the location MAIN_UNIT #
    #######################################

    if_main_child_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.MAIN_UNIT,
                                 ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = if_main_child_loc
    cur_loc_id += 1

    ###################################################
    # Step 2. Update look-up dict (line id -> loc id) #
    ###################################################

    for line_id in range(start_lineno, end_lineno + 1):
        assert line_id not in line_loc_lookup
        line_loc_lookup[line_id] = if_main_child_loc.id

    return if_main_child_loc, cur_loc_id


def _add_main_location(
        locations: Dict[int, Location],
        line_id2loc_id: Dict[int, int],
        node: ast.If,
        cur_loc_id: int,
        father_loc_id: int
) -> Tuple[Location, int]:
    """
   For current node:
   - `locations`: Add MAIN location.
   - `line_id2loc_id`: For lines in main block, update look-up dict.

   For children of it:
   - `locations`: Add MAIN_UNIT location.
   - `line_id2loc_id`: For lines in each child, update look-up dict.
   """
    ast_type = type(node).__name__
    name = "if_main"
    start_lineno = node.lineno    # 1-based
    end_lineno = node.end_lineno  # 1-based

    ##################################
    # Step 1: Save the location MAIN #
    ##################################

    main_loc = Location(id=cur_loc_id, father=father_loc_id, type=LocationType.MAIN,
                        ast=ast_type, name=name, range=LineRange(start_lineno, end_lineno))
    locations[cur_loc_id] = main_loc
    cur_loc_id += 1

    #################################################
    # Step 2. Save the location of children of MAIN #
    #################################################

    children = [node.test] + node.body + node.orelse

    for child in children:
        _, cur_loc_id = _add_main_child_location(
            locations=locations,
            line_loc_lookup=line_id2loc_id,
            node=child,
            cur_loc_id=cur_loc_id,
            father_loc_id=main_loc.id
        )

    return main_loc, cur_loc_id


"""MAIN ENTRY"""


def parse_python_file_locations(file_content: str) -> Tuple[Dict[int, Location], Dict[int, int], Dict]:
    """
    Parse Python file content and extract the following types of Locations:
    - Top level items:
        - Global
        - Function
        - Class
        - Main
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
        Dict: Info dict about structs containing main, classes, funcs and class_funcs.
    """
    file_lines = file_content.splitlines(keepends=False)
    file_len = len(file_lines)

    locations: Dict[int, Location] = {}  # location_id -> Location
    li2loc_lookup: Dict[int, int] = {}   # line_id -> location_id

    main: int | None = None
    funcs: List[int] = []
    classes: List[int] = []
    classes_funcs: Dict[int, List[int]] = {}

    #  ---------------------- Step 1: AST parse ---------------------- #
    try:
        tree = ast.parse(file_content)
    except Exception:
        logger.debug("AST parsing file failed")
        raise RuntimeError("AST parsing file failed")

    # ---------------------- Step 2: Add root location ---------------------- #
    cur_loc_id = 0
    root_loc = Location(id=cur_loc_id, father=None, type=LocationType.MODULE,
                        ast=type(tree).__name__, name="", range=LineRange(start=1, end=file_len))
    locations[cur_loc_id] = root_loc
    cur_loc_id += 1

    # ---------------------- Step 3: Iterate the top level elements of the code ---------------------- #
    tree_children = list(ast.iter_child_nodes(tree))

    for i, child in enumerate(tree_children):
        if isinstance(child, ast.ClassDef):
            _, cur_loc_id = _add_class_location(
                classes, classes_funcs, locations, li2loc_lookup, child, cur_loc_id, root_loc.id)

        elif isinstance(child, ast.FunctionDef) or isinstance(child, ast.AsyncFunctionDef):
            _, cur_loc_id = _add_function_location(funcs, locations, li2loc_lookup, child, cur_loc_id, root_loc.id)

        elif isinstance(child, ast.If) and _is_main_line(file_lines[child.lineno - 1]):
            main_loc, cur_loc_id = _add_main_location(locations, li2loc_lookup, child, cur_loc_id, root_loc.id)
            assert main is None
            main = main_loc.id

        else:
            _, cur_loc_id = _add_unit_location(locations, li2loc_lookup, child, cur_loc_id, root_loc.id)

    #  ---------------------- Step 4: Summary ---------------------- #
    structs_info = {
        "main": main,
        "funcs": funcs,
        "classes": classes,
        "classes_funcs": classes_funcs
    }

    return locations, li2loc_lookup, structs_info
