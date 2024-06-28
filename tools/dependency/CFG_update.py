import sys
import json
import queue
import subprocess

from typing import *
from tree_sitter import Node as tsNode
from tree_sitter_parse_py import _find_import_path_in_import_stat_node


class InternalGraphRepresentation:
    def __init__(self):
        self._graph = {
            '__entry__': {
                'next': set()
            }
        }

        self._file_context = {
            '__entry__': '<ignore>'
        }

        self._alternate_keys = {

        }

    def note_alternate_names(self, type, name, arg_count):
        resolved_node = type + '.' + name + '.' + str(arg_count)

        type_and_name = type + '.' + name
        name_and_arg_count = name + '.' + str(arg_count)

        if name not in self._alternate_keys:
            self._alternate_keys[name] = []

        if type_and_name not in self._alternate_keys:
            self._alternate_keys[type_and_name] = []

        if name_and_arg_count not in self._alternate_keys:
            self._alternate_keys[name_and_arg_count] = []

        self._alternate_keys[name].append(resolved_node)
        self._alternate_keys[type_and_name].append(resolved_node)
        self._alternate_keys[name_and_arg_count].append(resolved_node)

    def add_node_to_graph(self, context: List[str], next_node: str,
                          arg_count: int,
                          type: str = 'unknown', file: str = 'unknown'):
        if len(context) == 0:
            raise ValueError("context should never be empty. \
            Use __entry__ for the root node")

        caller = context[-1]

        if caller not in self._graph:
            raise ValueError("The caller should already exist in the graph")

        resolved_node = type + '.' + next_node + '.' + str(arg_count)

        self._graph[caller]['next'].add(resolved_node)

        if resolved_node not in self._graph:
            self._graph[resolved_node] = {
                'next': set()
            }

            self._file_context[resolved_node] = file
            self.note_alternate_names(type, next_node, arg_count)

    def has_function(self, func_name: str, arg_count: Optional[int], strict: bool = False):
        """
            Check if a function exists

            Args:
                func_name: Function name
                arg_count: Arguments number
                strict: If False, ignores the Class
        """
        if strict and func_name + '.' + str(arg_count) in self._alternate_keys:
            return True

        if not strict:
            if arg_count is None:
                if func_name in self._alternate_keys:
                    return True
            elif func_name + '.' + str(arg_count) in self._alternate_keys:
                return True

        return False




class ControlFlowGraph:
    class ResolveTask:
        def __init__(self, current_node: tsNode, context: List[str], current_file_location: str):
            self.current_node = current_node
            self.context = context
            self.current_file_location = current_file_location

    def __init__(self, ):
        self._graph = InternalGraphRepresentation()
        self._root_node: Optional[tsNode] = None

        self._detected = False

        # Data structure from pydeps
        self._imports: Dict[str, Dict[str, Any]] = {}



    def construct_from_file(self, py_fpath: str, root_node: tsNode, only_file=False):
        """
            Construct a CFG for the given .py file.

            Args:
                py_fpath:
                root_node: Root node of the tree obtained using tree-sitter parsing the given file
                only_file: If True, only builds a CFG contained in a single file.
                           External references are noted as such but not resolved.
        """
        # TODO: Need to rewrite this algorithm as an iterative one rather than a recursive one
        sys.setrecursionlimit(3000)

        assert py_fpath.endswith('.py')

        self._resolve_module_imports(py_fpath)

        assert root_node.type == 'module'
        self._root_node = root_node
        self._parse_and_resolve_tree_sitter(root_node, ['__entry__'], py_fpath)



    def _resolve_module_imports(self, py_fpath: str):
        """

            Args:
                py_fpath:
        """
        # TODO: Need check
        output = subprocess.run(['pydeps', py_fpath, '--show-deps', '--pylib',
                                 '--no-show', '--max-bacon', '0', '--no-dot', '--include-missing'],
                                capture_output=True)

        json_import_tree = json.loads(output.stdout.decode("utf-8"))
        self._imports = json_import_tree


    def _resolve_import_into_callgraph(self, import_stmt_node: tsNode, context: List[str], current_file_location: str,
                                       tasks: queue.SimpleQueue):
        # TODO
        if import_stmt_node.type == 'import_statement':
            pass

        elif import_stmt_node.type == 'import_from_statement':
            pass


    def _parse_and_resolve_tree_sitter(self, init_node: tsNode, init_context: List[str],
                                       init_current_file_location: str):
        tasks = queue.SimpleQueue()
        assert self._root_node is not None
        tasks.put(ControlFlowGraph.ResolveTask(init_node, init_context, init_current_file_location))

        while not tasks.empty():
            current_task = tasks.get()
            current_node = current_task.current_node
            context = current_task.context
            current_file_location = current_task.current_file_location

            if self._detected:
                # We're done early. Stop parsing
                return
            if not current_node.type.is_named:
                # We don't care about anonymous nodes while constructing CFG
                pass

            if current_node.type == 'module':
                for child in current_node.children:
                    tasks.put(ControlFlowGraph.ResolveTask(child, context, current_file_location))

            elif current_node.type == 'import_statement' or current_node.type == 'import_from_statement':
                self._resolve_import_into_callgraph(current_node, context, current_file_location, tasks)

            elif current_node.type == 'expression_statement':
                for child in current_node.children:
                    tasks.put(ControlFlowGraph.ResolveTask(child, context, current_file_location))

            elif current_node.type == 'assignment':
                #TODO
                pass

            elif current_node.type == 'call':
                function = current_node.child_by_field_name('function')

                if function.type == 'identifier':
                    func_name = function.text.decode('utf-8')
                elif function.type == 'subscript':
                    # TODO
                    func_name = None
                else:
                    if function.child_by_field_name('attribute'):
                        func_name = function.child_by_field_name('attribute').text.decode('utf-8')
                    else:
                        func_name = None

                args = current_node.child_by_field_name('arguments')
                arg_count = 0
                for arg in args.children:
                    if arg.is_named:
                        arg_count += 1

                if func_name:
                    if not self.function_exists(func_name, arg_count):
                        self._graph.add_node_to_graph(context, func_name, arg_count, file=current_file_location)

                        # todo

            elif current_node.type == 'list':
                # TODO
                pass

            elif current_node.type == 'block':
                for child in current_node.children:
                    tasks.put(ControlFlowGraph.ResolveTask(child, context, current_file_location))

            elif current_node.type == 'comment':
                pass

            # Compound statement
            elif current_node.type == 'if_statement':
                condition = current_node.child_by_field_name('condition')
                consequence = current_node.child_by_field_name('consequence')
                alternatives = []
                for i, child in enumerate(current_node.children):
                    field_name = current_node.field_name_for_child(i)
                    if field_name == 'alternative':
                        alternatives.append(child)

                tasks.put(ControlFlowGraph.ResolveTask(condition, context, current_file_location))
                tasks.put(ControlFlowGraph.ResolveTask(consequence, context, current_file_location))
                if len(alternatives) > 0:
                    for alternative in alternatives:
                        tasks.put(ControlFlowGraph.ResolveTask(alternative, context, current_file_location))

            elif current_node.type == 'elif_clause':
                condition = current_node.child_by_field_name('condition')
                consequence = current_node.child_by_field_name('consequence')

                tasks.put(ControlFlowGraph.ResolveTask(condition, context, current_file_location))
                tasks.put(ControlFlowGraph.ResolveTask(consequence, context, current_file_location))

            elif current_node.type == 'else_clause':
                body = current_node.child_by_field_name('body')

                tasks.put(ControlFlowGraph.ResolveTask(body, context, current_file_location))




    def function_exists(self, func_name: str, arg_count: Optional[int] = None) -> bool:
        return self._graph.has_function(func_name, arg_count)





cfg = ControlFlowGraph()
cfg._resolve_module_imports(py_fpath='/root/projects/VDTest/tools/dependency/test_data/source_code_data/ansible_ansible/hacking.azp.get_recent_coverage_runs.py/get_recent_coverage_runs.py')
print(json.dumps(cfg._imports, indent=4))
