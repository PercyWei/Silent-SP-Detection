import re
import json
import queue

from typing import *
from tree_sitter import Node as tsNode, Parser

from tools.dependency.util import find_error_nodes
from utils.logging import logger


preprocIf_cmds = ['#if', '#ifdef', '#ifndef', '#else', '#elif', '#elifdef', '#elifndef', '#endif']
preprocIf_cmd_re = re.compile(r'^\s*#\s*(ifdef|ifndef|if|endif|else|elifdef|elifndef|elif)(\s*(.*))$')


class AddIfError(Exception):
    pass


class PreProcessError(Exception):
    def __init__(self, msg: Optional[str] = None):
        if msg is not None:
            logger.error(msg)


def preprocess_v1(root_node: tsNode, source_code: str):
    preproc_if_cmds = ['#if', '#ifdef', '#ifndef', '#else', '#elif', '#elifdef', '#elifndef', '#endif']
    if_re = re.compile(r'#\s*if')
    ifdef_re = re.compile(r'#\s*ifdef')
    ifndef_re = re.compile(r'#\s*ifndef')
    else_re = re.compile(r'#\s*else')
    elif_re = re.compile(r'#\s*elif')
    elifdef_re = re.compile(r'#\s*elifdef')
    elifndef_re = re.compile(r'#\s*elifndef')
    endif_re = re.compile(r'#\s*endif')

    all_preproc_ifs = {}
    all_correct_resolved_if_end_line_id = {}

    def is_preproc_if_node(node: tsNode) -> Tuple[Optional[Tuple], Optional[Dict]]:

        preproc_if_info = {
            'cmd': None,
            'line_id': None,
            'cond': None,
            'has_cond': True,
            'end_line_id': None
        }

        # CORRECTLY RESOLVED PREPROC NODES
        if node.type.startswith('preproc_ifdef'):
            if not (len(node.children) >= 3 and node.field_name_for_child(1) == 'name'):
                print('error')

            # Important info
            ifdef_cmd = '#ifdef' if 'ifdef' in node.children[0].text.decode() else '#ifndef'
            # TODO: Maybe node type is 'preproc_ifdef' but '#ifdef'/'#ifndef' not in it, just like '#endif'
            ifdef_line_id = node.children[0].start_point[0]
            name = node.children[1].text.decode()

            if endif_re.search(node.children[-1].text.decode()):
                endif_line_id = node.children[-1].start_point[0]
            else:
                endif_line_id = None

            preproc_if_info['cmd'] = ifdef_cmd
            preproc_if_info['line_id'] = ifdef_line_id
            preproc_if_info['cond'] = name
            preproc_if_info['end_line_id'] = endif_line_id

            return (2, len(node.children) - 1), preproc_if_info

        elif node.type.startswith('preproc_if'):
            if not (len(node.children) >= 5 and node.field_name_for_child(1) == 'condition'):
                print('error')

            # Important info
            if_cmd = '#if'
            # TODO: Maybe node type is 'preproc_if' but '#if' not in it
            if_line_id = node.children[0].start_point[0]
            cond = node.children[1].text.decode()

            if endif_re.search(node.children[-1].text.decode()):
                endif_line_id = node.children[-1].start_point[0]
            else:
                endif_line_id = None

            preproc_if_info['cmd'] = if_cmd
            preproc_if_info['line_id'] = if_line_id
            preproc_if_info['cond'] = cond
            preproc_if_info['end_line_id'] = endif_line_id

            return (3, len(node.children) - 1), preproc_if_info

        elif node.type.startswith('preproc_else'):
            if not len(node.children) >= 1:
                print('error')

            # Important info
            else_cmd = '#else'
            # TODO: Maybe node type is 'preproc_else' but '#else' not in it
            else_line_id = node.children[0].start_point[0]

            # Visit children excluding preproc_if_cmd nodes
            for i, child in enumerate(node.children):
                if 1 <= i:
                    find_preproc_node(child)

            preproc_if_info['cmd'] = else_cmd
            preproc_if_info['line_id'] = else_line_id
            preproc_if_info['has_cond'] = False

            return (1, len(node.children)), preproc_if_info

        elif node.type.startswith('preproc_elif'):
            if not (len(node.children) >= 4 and node.field_name_for_child(1) == 'condition'):
                print('error')

            # Important info
            elif_cmd = '#elif'
            # TODO: Maybe node type is 'preproc_elif' but '#elif' not in it
            elif_line_id = node.children[0].start_point[0]
            cond = node.children[1].text.decode()

            preproc_if_info['cmd'] = elif_cmd
            preproc_if_info['line_id'] = elif_line_id
            preproc_if_info['cond'] = cond

            return (3, len(node.children)), preproc_if_info

        elif node.type.startswith('preproc_elifdef'):
            if not (len(node.children) >= 3 and node.field_name_for_child(1) == 'name'):
                print('error')

            # Important info
            elifdef_cmd = '#elifdef' if 'elifdef' in node.children[0].text.decode() else '#elifndef'
            # TODO: Maybe node type is 'preproc_elifdef' but 'elifdef'/'#elifndef' not in it
            elifdef_line_id = node.children[0].start_point[0]
            name = node.children[1].text.decode()

            preproc_if_info['cmd'] = elifdef_cmd
            preproc_if_info['line_id'] = elifdef_line_id
            preproc_if_info['cond'] = name

            return (2, len(node.children)), preproc_if_info

        # SPECIAL CASE

        elif node.type.startswith('preproc_call'):
            if not (len(node.children) >= 1 and node.field_name_for_child(0) == 'directive'):
                print('error')

            directive = node.children[0].text.decode()
            for if_cmd in preproc_if_cmds:
                if if_cmd in directive:
                    cmd_line_id = node.children[0].start_point[0]
                    if if_cmd in ('#if', '#ifdef', '#ifndef', '#elif', '#elifdef', '#elifndef'):
                        has_cond = True
                    else:
                        has_cond = False

                    preproc_if_info['cmd'] = if_cmd
                    preproc_if_info['line_id'] = cmd_line_id
                    preproc_if_info['has_cond'] = has_cond

                    children_range = (1, len(node.children)) if len(node.children) > 1 else None

                    return children_range, preproc_if_info

        elif node.type.startswith('preproc_directive'):
            # TODO
            pass

        # INCORRECTLY RESOLVED PREPROC NODES

        else:
            for if_cmd in preproc_if_cmds:
                if node.type == if_cmd:
                    if not len(node.children) == 0:
                        print('error')

                    cmd_line_id = node.start_point[0]
                    if if_cmd in ('#if', '#ifdef', '#ifndef', '#elif', '#elifdef', '#elifndef'):
                        has_cond = True
                    else:
                        has_cond = False

                    preproc_if_info['cmd'] = if_cmd
                    preproc_if_info['line_id'] = cmd_line_id
                    preproc_if_info['has_cond'] = has_cond

                    return None, preproc_if_info

            children_range = (0, len(node.children)) if len(node.children) != 0 else None

            return children_range, None

    def find_preproc_node(node: tsNode):
        visit_child_range, preproc_if_info = is_preproc_if_node(node)

        if preproc_if_info is not None:
            _cmd = preproc_if_info['cmd']
            _line_id = preproc_if_info['line_id']
            _cond = preproc_if_info['cond']
            _has_cond = preproc_if_info['has_cond']
            _if_item = (_cmd, _cond) if _has_cond else (_cmd, '<EMPTY>')
            assert _line_id not in all_preproc_ifs
            all_preproc_ifs[_line_id] = _if_item

            if preproc_if_info['end_line_id'] is not None:
                _endif_line_id = preproc_if_info['end_line_id']
                all_preproc_ifs[_endif_line_id] = ('#endif', '<EMPTY>')
                all_correct_resolved_if_end_line_id[_line_id] = _endif_line_id

        if visit_child_range is not None:
            start = visit_child_range[0]
            end = visit_child_range[1]
            for i, child in enumerate(node.children):
                if start <= i < end:
                    find_preproc_node(child)

    find_preproc_node(root_node)

    all_preproc_ifs = {k: all_preproc_ifs[k] for k in sorted(all_preproc_ifs.keys())}

    current_level = 0
    allow_else = []

    all_endifs = {}

    # Iterate and add hierarchical information
    for line_id, if_item in all_preproc_ifs.items():
        if if_item[0] in ('#if', '#ifdef', '#ifndef'):
            current_level += 1
            allow_else.append(True)

            all_preproc_ifs[line_id] = if_item + (current_level,)
        elif if_item[0] in ('#elif', '#elifdef', '#elifndef'):
            assert allow_else[-1]

            all_preproc_ifs[line_id] = if_item + (current_level,)
        elif if_item[0] == '#else':
            assert allow_else[-1]
            allow_else[-1] = False

            all_preproc_ifs[line_id] = if_item + (current_level,)
        elif if_item[0] == '#endif':
            all_preproc_ifs[line_id] = if_item + (current_level,)
            all_endifs[line_id] = current_level

            current_level -= 1
            allow_else.pop()
        else:
            raise ValueError(f'Unexpected preproc_if: {if_item[0]}')

    if not (current_level == 0 and not allow_else):
        print(json.dumps(all_preproc_ifs, indent=4))
        print('error')

    def find_match_endif_line_id(current_if_line_id: int, current_if_level: int):
        for endif_line_id, endif_level in all_endifs.items():
            if current_if_line_id < endif_line_id and current_if_level == endif_level:
                return endif_line_id

    # Iterate and refine #endif information
    for line_id, if_item in all_preproc_ifs.items():
        if if_item[0] != '#endif':
            match_endif_line_id = find_match_endif_line_id(line_id, if_item[2])

            # If current preproc_if is resolved correctly initially, then compare
            if line_id in all_correct_resolved_if_end_line_id:
                init_end_line_id = all_correct_resolved_if_end_line_id[line_id]
                assert match_endif_line_id == init_end_line_id
            else:
                update_if_item = list(if_item)
                update_if_item[1] = match_endif_line_id
                all_preproc_ifs[line_id] = tuple(update_if_item)

    print(json.dumps(all_preproc_ifs, indent=4))
    print('-' * 100)


def construct_preprocIf_info(cmd: Optional[str] = None,
                             cond: Optional[str] = None,
                             line_range: Optional[Tuple] = None,
                             level: Optional[int] = None,
                             end_line_id: Optional[int] = None) -> Dict:
    return {
        'cmd': cmd,
        'cond': cond,
        'line_range': line_range,
        'level': level,
        'end_line_id': end_line_id
    }


def iterate_to_find_preprocIfs(source_code: List[str]) -> Tuple[Dict, Dict]:
    """
    Iterate the source code and find all preprocIfs and all #endif.

    Args:
        source_code:
    Returns:
        all_preprocIfs:
            key: line id
            value: preprocIf info, details can be found in 'construct_preprocIf_info' function
        all_endifs:
            key: #endif line id
            value: #endif level
    """
    all_preprocIfs = {}
    all_endifs = {}

    current_level = 0
    allow_else = []

    for line_id, line in enumerate(source_code):
        match = preprocIf_cmd_re.match(line)
        cmd = rest = None
        if match:
            cmd = match.group(1)
            rest = match.group(2)
            assert cmd

            cmd = '#' + cmd
            rest = rest.strip()
            if rest == '':
                rest = None

            if cmd in ('#if', '#ifdef', '#ifndef'):
                if rest is None:
                    logger.error(f"Illegal '#if'/'#ifdef'/'#ifndef' usage in line {line_id} - {line}")
                    raise PreProcessError()

                current_level += 1
                allow_else.append(True)
                all_preprocIfs[line_id] = construct_preprocIf_info(cmd=cmd, cond=rest, level=current_level)

            elif cmd in ('#elif', '#elifdef', '#elifndef'):
                if not (allow_else[-1] and rest is not None):
                    logger.error(f"Illegal '#elif'/'#elifdef'/'#elifndef' usage in line {line_id} - {line}")
                    raise PreProcessError()

                all_preprocIfs[line_id] = construct_preprocIf_info(cmd=cmd, cond=rest, level=current_level)

            elif cmd == '#else':
                if not (allow_else[-1] and rest is None):
                    logger.error(f"Illegal '#else' usage in line {line_id} - {line}")
                    raise PreProcessError()

                allow_else[-1] = False
                all_preprocIfs[line_id] = construct_preprocIf_info(cmd=cmd, cond=rest, level=current_level)

            elif cmd == '#endif':
                if rest is not None:
                    logger.error(f"Illegal '#endif' usage in line {line_id} - {line}")
                    raise PreProcessError()

                all_preprocIfs[line_id] = construct_preprocIf_info(cmd=cmd, cond=rest,
                                                                   level=current_level, end_line_id=line_id)
                all_endifs[line_id] = current_level

                current_level -= 1
                allow_else.pop()

            else:
                logger.error(f"Unexpected preproc_if {cmd} in line {line_id} - {line}")
                raise PreProcessError()

    if not (current_level == 0 and not allow_else):
        logger.error(f"Incompletely paired preprocIf!")
        logger.error(f"All preprocIfs: \n{json.dumps(all_preprocIfs, indent=4)}")
        raise PreProcessError()

    return all_preprocIfs, all_endifs


def preprocess(source_code: List[str], verbose: bool = False) -> Tuple[Dict, List]:
    """
    Iterate the source code and find all preprocIfs and group them.

    Args:
        source_code:
        verbose: How the log is recorded
    Returns:
        all_preprocIfs (Dict):
        all_pif_groups (List):
            list_item: A list containing line ids of the preprocIfs in the same group
    """
    all_preprocIfs, all_endifs = iterate_to_find_preprocIfs(source_code)

    def find_match_endif_line_id(current_pif_line_id: int, current_pif_level: int) -> int:
        for endif_line_id, endif_level in all_endifs.items():
            if current_pif_line_id < endif_line_id and current_pif_level == endif_level:
                return endif_line_id

    # Iterate and refine #endif information
    for pif_line_id, pif_info in all_preprocIfs.items():
        if pif_info['cmd'] != '#endif':
            match_endif_line_id = find_match_endif_line_id(pif_line_id, pif_info['level'])
            pif_info['end_line_id'] = match_endif_line_id
            all_preprocIfs[pif_line_id] = pif_info

    all_pif_groups = []

    def fine_range_by_endif():
        for current_endif_line_id, current_endif_level in all_endifs.items():

            current_pif_group = []

            # Start searching from #endif
            current_group_level = current_endif_level

            # For a preprocIf group:
            #     Start cmd: #if or #ifdef or #ifndef
            #      Mid cmds: #elif, #elifdef, #elifndef
            #       End cmd: endif
            start_pif_id = None
            end_pif_id = list(all_preprocIfs.keys()).index(current_endif_line_id)

            # Search forward from current #endif.
            # Add line_id of preprocIf with the same level to the current pif group,
            #     until it meets #if / #ifdef / #ifndef
            for i in range(end_pif_id, -1, -1):
                pif_line_id = list(all_preprocIfs.keys())[i]
                pif_info = all_preprocIfs[pif_line_id]

                assert pif_info['level'] >= current_group_level
                if pif_info['level'] == current_group_level:
                    assert pif_info['end_line_id'] == current_endif_line_id

                    current_pif_group.append(pif_line_id)
                    if pif_info['cmd'] in ('#if', '#ifdef', '#ifndef'):
                        start_pif_id = pif_line_id
                        break

            assert start_pif_id is not None

            current_pif_group = sorted(current_pif_group)
            all_pif_groups.append(current_pif_group)

        if len([len(g) for g in all_pif_groups]) != len(all_pif_groups):
            logger.error(f"Overlap between preprocIf groups!")
            logger.error(f"All preprocIfs: \n{json.dumps(all_preprocIfs, indent=4)}")
            logger.error(f"Groups: \n{json.dumps(all_pif_groups, indent=4)}")
            raise PreProcessError()

    fine_range_by_endif()

    # Iterate all preprocIf groups to find range of preprocIf
    for pif_group in all_pif_groups:
        for i, pif_line_id in enumerate(pif_group):
            pif_info = all_preprocIfs[pif_line_id]
            cmd = pif_info['cmd']

            if i != len(pif_group) - 1:
                assert cmd != '#endif'

                # Find range
                start = pif_line_id + 1
                end = pif_group[i+1]
                assert start <= end
                pif_range = (start, end)

                pif_info['line_range'] = pif_range
                all_preprocIfs[pif_line_id] = pif_info
            else:
                assert cmd == '#endif'

    # Record preprocIf groups
    record = 'Info of preprocIf groups: \n'
    for i, group in enumerate(all_pif_groups):
        start = group[0]
        end = group[-1]

        if end - start > 3 and not verbose:
            # Record simplified preprocIf group information
            snippet_lines = [source_code[start], source_code[start+1], '...', source_code[end-1], source_code[end]]
            snippet = '\n'.join(snippet_lines)
        else:
            # Record detailed preprocIf group information
            snippet = '\n'.join([source_code[line_id] for line_id in range(start, end+1)])
        record += '\n' + '-' * 25 + f' {i} ' + '-' * 25 + f'\n{snippet}\n'
    logger.info(record)

    return all_preprocIfs, all_pif_groups


def parse_preprocIfs(parser: Parser, source_code: List[str], preprocIf_groups: List[List[int]]):
    """
    Parse preprocIf structure using tree-sitter

    Args:
        parser:
        source_code:
        preprocIf_groups:
    """
    for pif_group in preprocIf_groups:

        group_snippet = []

        for i, pif_line_id in enumerate(pif_group):
            pif_line = source_code[pif_line_id]
            pif_line = pif_line.lstrip()

            def filler_stmt(num: int, indent: int = 0) -> str:
                return ' ' * indent + f'int cond = {num};'

            group_snippet.append(pif_line)
            if i != len(pif_group) - 1:
                group_snippet.append(filler_stmt(i))

        print('\n'.join(group_snippet))

        root_node = parser.parse(bytes('\n'.join(group_snippet), encoding='utf-8')).root_node
        # TODO
        pass


def preprocess_error(parser: Parser, root_code: tsNode, source_code: List[str]):
    error_nodes = find_error_nodes(root_code)

    if len(error_nodes) != 0:
        all_preprocIfs, all_pif_groups = preprocess(source_code)

        parse_preprocIfs(parser, source_code, all_pif_groups)

        # TODO: Find preprocIfs in ERROR nodes and process
        # for error_node in error_nodes:
        #
        #     error_start = error_node.start_point[0]
        #     error_end = error_node.end_point[0]
        #
        #     for pif_line_id, pif_info in all_preprocIfs:
        #         if error_start <= pif_line_id <= error_end:
        #             pass
