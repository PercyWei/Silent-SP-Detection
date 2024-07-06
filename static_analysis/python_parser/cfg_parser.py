# This code is modified from https://github.com/coetaur0/staticfg/
# Original file: staticfg/builder.py

"""
Control flow graph builder.
"""
# Aurelien Coet, 2018.
# Modified by Andrei Nacu, 2020

import ast
import sys

from typing import *

import astor
from loguru import logger

from static_analysis.python_parser.cfg_model import Block, Link, CFG


def is_py38_or_higher():
    if sys.version_info.major == 3 and sys.version_info.minor >= 8:
        return True
    return False


NAMECONSTANT_TYPE = ast.Constant if is_py38_or_higher() else ast.NameConstant


def invert(node: ast.expr) -> ast.expr:
    """
    Invert the operation in an ast node object (get its negation).

    Args:
        node: An ast node object.

    Returns:
        An ast node object containing the inverse (negation) of the input node.
    """
    inverse = {ast.Eq: ast.NotEq,
               ast.NotEq: ast.Eq,
               ast.Lt: ast.GtE,
               ast.LtE: ast.Gt,
               ast.Gt: ast.LtE,
               ast.GtE: ast.Lt,
               ast.Is: ast.IsNot,
               ast.IsNot: ast.Is,
               ast.In: ast.NotIn,
               ast.NotIn: ast.In}

    if type(node) == ast.Compare:
        op = type(node.ops[0])
        inverse_node = ast.Compare(left=node.left, ops=[inverse[op]()],
                                   comparators=node.comparators)
    elif isinstance(node, ast.BinOp) and type(node.op) in inverse:
        op = type(node.op)
        inverse_node = ast.BinOp(node.left, inverse[op](), node.right)
    elif type(node) == NAMECONSTANT_TYPE and node.value in [True, False]:
        inverse_node = NAMECONSTANT_TYPE(value=not node.value)
    else:
        inverse_node = ast.UnaryOp(op=ast.Not(), operand=node)

    return inverse_node


def merge_exit_cases(exit1: ast.expr, exit2: ast.expr) -> ast.expr:
    """
    Merge the exit_cases of two Links.

    Args:
        exit1: The exit_case of a Link object.
        exit2: Another exit_case to merge with exit1.

    Returns:
        The merged exit_case.
    """
    if exit1:
        if exit2:
            return ast.BoolOp(ast.And(), values=[exit1, exit2])
        return exit1
    return exit2


class exit_stmt(ast.stmt):
    _fields = ('name',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = '<EXIT>'


class CFGBuilder(ast.NodeVisitor):
    """
    Control flow graph builder.

    A control flow graph builder is an ast.NodeVisitor that can walk through
    a program's AST and iteratively build the corresponding CFG.
    """
    def __init__(self, separate=False):
        super().__init__()
        self.cfg: Optional[CFG] = None
        self.current_id: Optional[int] = None
        self.current_block = None
        self.after_loop_block_stack = []
        self.curr_loop_guard_stack = []
        self.separate_node_blocks = separate

    # ---------- CFG building methods ---------- #
    def build(self, name: str, tree, asynch: bool = False, entry_id: int = 0) -> Optional[CFG]:
        """
        Build a CFG from an AST.

        Args:
            name: The name of the CFG being built.
            tree: The root of the AST from which the CFG must be built.
            asynch: Boolean indicating whether the CFG being built represents an
                    asynchronous function or not. When the CFG of a Python
                    program is being built, it is considered like a synchronous
                    'main' function.
            entry_id: Value for the id of the entry block of the CFG.

        Returns:
            The CFG produced from the AST, None if build fails.
        """
        self.cfg = CFG(name, asynch=asynch)
        # Tracking of the current block while building the CFG.
        self.current_id = entry_id
        self.current_block = self.new_block()
        self.cfg.entry_block = self.current_block
        # Actual building of the CFG is done here.
        self.visit(tree)
        self.clean_cfg(self.cfg.entry_block)
        return self.cfg

    def build_from_src(self, name: str, src_code: str) -> Optional[CFG]:
        """
        Build a CFG from some Python source code.

        Args:
            name: The name of the CFG being built.
            src_code: A string containing the source code to build the CFG from.

        Returns:
            The CFG produced from the source code, None if build fails.
        """
        try:
            compile(src_code, '', 'exec')
        except:
            logger.error('CFG Build Failure > Source code has error')
            return None
        tree = ast.parse(src_code, mode='exec')
        return self.build(name, tree)

    def build_from_file(self, name: str, fpath: str) -> Optional[CFG]:
        """
        Build a CFG from some Python source file.

        Args:
            name: The name of the CFG being built.
            fpath: The path to the file containing the Python source code
                      to build the CFG from.

        Returns:
            The CFG produced from the source file, None if build fails.
        """
        try:
            with open(fpath, 'r') as src_file:
                src_code = src_file.read()
                return self.build_from_src(name, src_code)
        except FileNotFoundError:
            logger.error(f"CFG Build Failure > Source code file not found: {fpath}")
        except UnicodeDecodeError:
            logger.error(f"CFG Build Failure > source code file encoding error: {fpath}")
        return None

    # ---------- Graph management methods ---------- #
    def new_block(self) -> Block:
        """
        Create a new block with a new id.

        Returns:
            A Block object with a new unique id.
        """
        self.current_id += 1
        return Block(self.current_id)

    def add_statement(self, block: Block, statement: ast.stmt):
        """
        Add a statement to a block.

        Args:
            block: A Block object to which a statement must be added.
            statement: An AST node representing the statement that must be added to the current block.
        """
        block.statements.append(statement)

    def add_exit(self, prev_block: Block, next_block: Block, exit_case: Optional[ast.expr] = None):
        """
        Add a new exit to a block.

        Args:
            prev_block: A block to which an exit must be added.
            next_block: The block to which control jumps from the new exit.
            exit_case: An AST node representing the 'case' (or condition)
                       leading to the exit from the block in the program.
        """
        new_link = Link(prev_block, next_block, exit_case)
        prev_block.exits.append(new_link)
        next_block.predecessors.append(new_link)

    def new_loop_guard(self) -> Block:
        """
        Create a new block for a loop's guard if the current block is not empty.
        Links the current block to the new loop guard.

        Returns:
            The block to be used as new loop guard.
        """
        if self.current_block.is_empty() and len(self.current_block.exits) == 0:
            # If the current block is empty and has no exits, it is used as
            # entry block (condition test) for the loop.
            loop_guard = self.current_block
        else:
            # Jump to a new block for the loop's guard if the current block isn't empty or has exits.
            loop_guard = self.new_block()
            self.add_exit(self.current_block, loop_guard)
        return loop_guard

    def new_functionCFG(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], asynch: bool = False):
        """
        Create a new sub-CFG for a function definition and add it to the
        function CFGs of the CFG being built.

        Args:
            node: FunctionDef / AsyncFunctionDef type AST node.
            asynch: Boolean indicating whether the function for which the CFG is
                    being built is asynchronous or not.
        """
        self.current_id += 1
        # A new sub-CFG is created for the body of the function definition and
        # added to the function CFGs of the current CFG.
        func_name = node.name
        func_body = ast.Module(body=node.body)
        func_builder = CFGBuilder()
        self.cfg.function_cfgs[func_name] = func_builder.build(name=func_name,
                                                               tree=func_body,
                                                               asynch=asynch,
                                                               entry_id=self.current_id)
        self.current_id = func_builder.current_id + 1

    def new_classCFG(self, node: ast.ClassDef):
        """
        Create CFGs for each function in the class and the class backbone

        Args:
            node: ClassDef type AST node.
        """
        class_name = node.name
        # New item in class_cfgs for saving function definitions in this class
        assert class_name not in self.cfg.class_def_cfgs
        self.cfg.class_def_cfgs[class_name] = {}

        # Create a block for the code in the class definition
        class_body_block = self.new_block()
        self.current_block = class_body_block
        for child in node.body:
            # Simply add statements one by one to class_body_block
            # TODO: Need consider more complex conditions
            self.add_statement(self.current_block, child)

            # Create sub-CFG of func def in class and save it in class_cfgs specified item
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.current_id += 1
                func_name = child.name
                func_body = ast.Module(body=child.body)
                func_builder = CFGBuilder()
                asynch = True if isinstance(child, ast.AsyncFunctionDef) else False
                assert func_name not in self.cfg.class_def_cfgs[class_name]
                self.cfg.class_def_cfgs[class_name][func_name] = func_builder.build(name=class_name + '.' + func_name,
                                                                                    tree=func_body,
                                                                                    asynch=asynch,
                                                                                    entry_id=self.current_id)
                self.current_id = func_builder.current_id + 1

        # TODO
        assert class_name not in self.cfg.class_cfgs

    def clean_cfg(self, block: Block, visited: Optional[List[Block]] = None) -> None:
        """
        Remove the useless (empty) blocks from a CFG.

        Args:
            block: The block from which to start traversing the CFG to clean it.
            visited: A list of blocks that already have been visited by clean_cfg (recursive function).
        """
        if visited is None:
            visited = []

        # Don't visit blocks twice.
        if block in visited:
            return
        visited.append(block)

        # Empty blocks are removed from the CFG.
        if block.is_empty():
            for pred_link in block.predecessors:
                pred_block = pred_link.source
                for exit_link in block.exits:
                    next_block = exit_link.target
                    # Directly connect the pred_block and next_block of the current empty block
                    self.add_exit(pred_block, next_block, merge_exit_cases(pred_link.exit_case, exit_link.exit_case))

                    # Current exit_link is useless for next_block, remove it from its predecessors
                    if exit_link in next_block.predecessors:
                        next_block.predecessors.remove(exit_link)
                # Current pred_link is useless for pred_block, remove it from its exits
                if pred_link in pred_block.exits:
                    pred_block.exits.remove(pred_link)

            block.predecessors = []
            # As the exits may be modified during the recursive call, it is unsafe to iterate on block.exits
            # Created a copy of block.exits before calling clean cfg , and iterate over it instead.
            block_exits_copy = list(block.exits)
            for exit_link in block_exits_copy:
                self.clean_cfg(exit_link.target, visited)
            block.exits = []
        else:
            block_exits_copy = list(block.exits)
            for exit_link in block_exits_copy:
                self.clean_cfg(exit_link.target, visited)

    # ---------- AST Node visitor methods ---------- #
    def goto_new_block(self, node: ast.stmt):
        if self.separate_node_blocks:
            new_block = self.new_block()
            self.add_exit(self.current_block, new_block)
            self.current_block = new_block
        self.generic_visit(node)

    """Call"""

    def visit_Call(self, node: ast.Call):
        def visit_func(_node):
            if isinstance(_node, ast.Name):
                return _node.id
            elif isinstance(_node, ast.Attribute):
                # Recursion on series of calls to attributes.
                _func_name = visit_func(_node.value)
                _func_name += "." + _node.attr
                return _func_name
            elif isinstance(_node, ast.Str):
                return _node.s
            elif isinstance(_node, ast.Subscript):
                return _node.value.id
            else:
                return type(_node).__name__

        func = node.func
        func_name = visit_func(func)
        self.current_block.func_calls.append(func_name)

    """Expression"""

    def visit_Expr(self, node: ast.Expr):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)

    """Statement"""

    def visit_Assign(self, node: ast.Assign):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)

    def visit_Raise(self, node: ast.Raise):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)
        self.cfg.final_blocks.append(self.current_block)
        self.current_block = self.new_block()

    def visit_Assert(self, node: ast.Assert):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)
        # New block for the case in which the assertion 'fails'.
        fail_block = self.new_block()
        # TODO: Since fail_block is empty, it will be removed at last, consider to preserve it
        self.add_exit(self.current_block, fail_block, invert(node.test))
        # If the assertion fails, the current flow ends, so the fail block is a final block of the CFG.
        self.cfg.final_blocks.append(fail_block)
        # If the assertion is True, continue the flow of the program.
        success_block = self.new_block()
        self.add_exit(self.current_block, success_block, node.test)
        self.current_block = success_block

    def visit_Delete(self, node: ast.Delete):
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)

    def visit_Pass(self, node: ast.Pass):
        self.add_statement(self.current_block, node)

    """Import"""

    def visit_Import(self, node: ast.Import):
        self.add_statement(self.current_block, node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.add_statement(self.current_block, node)

    """Control Flow"""

    def visit_If(self, node: ast.If):
        # Add the If statement at the end of the current block.
        self.add_statement(self.current_block, node)

        # Create a new block for code in if_body.
        if_body_block = self.new_block()
        self.add_exit(self.current_block, if_body_block, node.test)

        # Create a block for the code after the if-else.
        after_if_block = self.new_block()

        # New block for the body of the else if there is an else clause.
        if len(node.orelse) != 0:
            else_block = self.new_block()
            self.add_exit(self.current_block, else_block, invert(node.test))
            self.current_block = else_block
            # Visit the children in the body of the else to populate the block.
            for child in node.orelse:
                self.visit(child)
            # If no break is encountered while through the else_block, add after_if_block as the next block of it
            if not self.current_block.exits:
                self.add_exit(self.current_block, after_if_block)
        else:
            self.add_exit(self.current_block, after_if_block, invert(node.test))

        # Visit children to populate the if block.
        self.current_block = if_body_block
        for child in node.body:
            self.visit(child)
        # If no break is encountered while through the if_body_block, add after_if_block as the next block of it
        if not self.current_block.exits:
            self.add_exit(self.current_block, after_if_block)

        # Continue building the CFG in the after-if block.
        self.current_block = after_if_block

    def visit_For(self, node: ast.For):
        loop_guard = self.new_loop_guard()
        self.current_block = loop_guard
        self.add_statement(self.current_block, node)
        self.curr_loop_guard_stack.append(loop_guard)
        # New block for the body of the for-loop.
        for_block = self.new_block()
        self.add_exit(self.current_block, for_block, node.iter)

        # Block of code after the for loop.
        after_for_block = self.new_block()
        self.add_exit(self.current_block, after_for_block)
        self.after_loop_block_stack.append(after_for_block)
        self.current_block = for_block

        # Populate the body of the for loop.
        for child in node.body:
            self.visit(child)
        if not self.current_block.exits:
            # Did not encounter a break
            self.add_exit(self.current_block, loop_guard)

        # Continue building the CFG in the after-for block.
        self.current_block = after_for_block
        # Popping the current after loop stack,taking care of errors in case of nested for loops
        self.after_loop_block_stack.pop()
        self.curr_loop_guard_stack.pop()

    def visit_While(self, node: ast.While):
        loop_guard = self.new_loop_guard()
        self.current_block = loop_guard
        self.add_statement(self.current_block, node)
        self.curr_loop_guard_stack.append(loop_guard)
        # New block for the case where the test in the while is True.
        while_body_block = self.new_block()
        self.add_exit(self.current_block, while_body_block, node.test)

        # TODO: Condition while ... else ...
        # if len(node.orelse) != 0:
        #     else_block = self.new_block()
        #     self.add_exit(self.current_block, else_block, invert(node.test))

        # New block for the case where the test in the while is False.
        after_while_block = self.new_block()
        self.after_loop_block_stack.append(after_while_block)
        inverted_test = invert(node.test)
        # Skip shortcut loop edge if while True:
        if not (isinstance(inverted_test, NAMECONSTANT_TYPE) and inverted_test.value is False):
            self.add_exit(self.current_block, after_while_block, inverted_test)

        # Populate the while body block.
        self.current_block = while_body_block
        for child in node.body:
            self.visit(child)
        if not self.current_block.exits:
            # Did not encounter a break statement, loop back
            self.add_exit(self.current_block, loop_guard)

        # Continue building the CFG in the after-while block.
        self.current_block = after_while_block
        self.after_loop_block_stack.pop()
        self.curr_loop_guard_stack.pop()

    def visit_Continue(self, node: ast.Continue):
        assert len(self.curr_loop_guard_stack), "Found continue outside loop"
        self.add_exit(self.current_block, self.curr_loop_guard_stack[-1])
        self.current_block = self.new_block()

    def visit_Break(self, node: ast.Break):
        assert len(self.after_loop_block_stack), "Found break not inside loop"
        self.add_exit(self.current_block, self.after_loop_block_stack[-1])
        self.current_block = self.new_block()

    def visit_Try(self, node: ast.Try):
        # TODO: Since exactly where the except is triggered is unknown, we can only add the edge from body -> except
        # TODO: Combining 'raise' with 'try ... except' maybe a good idea
        try_body_block = self.new_block()
        self.add_exit(self.current_block, try_body_block)

        after_try_block = self.new_block()

        if len(node.finalbody) != 0:
            finally_block = self.new_block()
            self.current_block = finally_block
            for child in node.finalbody:
                self.visit(child)
            self.add_exit(self.current_block, after_try_block)
        else:
            finally_block = None

        # Visit children to populate try_body_block first
        self.current_block = try_body_block
        for child in node.body:
            self.visit(child)
        if finally_block is not None:
            self.add_exit(self.current_block, finally_block)
        else:
            self.add_exit(self.current_block, after_try_block)

        for handler in node.handlers:
            assert isinstance(handler, ast.ExceptHandler)
            current_handler_block = self.new_block()
            self.current_block = current_handler_block
            self.add_exit(try_body_block, self.current_block, handler.type)
            # Then visit children to populate each handler_block one by one
            for child in handler.body:
                self.visit(child)
            if finally_block is not None:
                self.add_exit(self.current_block, finally_block)
            else:
                self.add_exit(self.current_block, after_try_block)

        self.current_block = after_try_block

    def visit_TryStar(self, node):
        # TODO: TryStar statement is available fot python >= 3.11, so consider refining it later
        pass

    def visit_With(self, node: ast.With):
        # TODO: We simply consider it as a sequential execution here, maybe update it later
        # TODO: We add the full with statement here because 'with xx:' is not a full statement,
        #       and we visit its children in body later, which needs attention!
        self.add_statement(self.current_block, node)
        self.goto_new_block(node)

    """Function and Class Def"""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.add_statement(self.current_block, node)
        self.new_functionCFG(node, asynch=False)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.add_statement(self.current_block, node)
        self.new_classCFG(node)

    def visit_Return(self, node: ast.Return):
        self.add_statement(self.current_block, node)
        # The final_blocks of function CFG contains return statement or end line of it
        self.cfg.final_blocks.append(self.current_block)
        # Continue in a new block but without any jump to it, thus all code after
        # the return statement will not be included in the CFG.
        self.current_block = self.new_block()

    def visit_Yield(self, node: ast.Yield):
        # TODO: Why?
        self.cfg.asynch = True
        after_yield_block = self.new_block()
        self.add_exit(self.current_block, after_yield_block)
        self.current_block = after_yield_block

    def visit_Global(self, node: ast.Global):
        self.add_statement(self.current_block, node)

    def visit_Nonlocal(self, node: ast.Nonlocal):
        self.add_statement(self.current_block, node)

    """Async"""
    # TODO: Check if 'Async' is common in real world

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.add_statement(self.current_block, node)
        self.new_functionCFG(node, asynch=True)

    def visit_Await(self, node: ast.Await):
        after_await_block = self.new_block()
        self.add_exit(self.current_block, after_await_block)
        self.goto_new_block(node)
        self.current_block = after_await_block

    def visit_AsyncFor(self, node):
        # TODO
        pass

    def visit_TypeAlias(self, node):
        # TODO
        pass

    def visit_AsyncWith(self, node):
        # TODO
        pass


class ASTParser:
    def __init__(self):
        self.ast = None

    def generate_tree_from_file(self, fpath: str):
        """
        Generates AST tree from file

        Args:
            fpath: Path to py source code file
        Returns:
            AST tree, None if generating failed
        """
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                source_code = f.read()

            return self.generate_tree_from_code(source_code)
        except UnicodeDecodeError:
            return None
        except Exception as e:
            return None

    def generate_tree_from_code(self, source_code: str):
        """
        Generates AST tree from source code

        Args:
            source_code: Source code
        Returns:
            AST tree, None if generating failed
        """
        try:
            tree = ast.parse(source_code, mode='exec')
            self.ast = tree
            return tree
        except Exception as e:
            return None


# src_code_fpath = "/root/projects/VDTest/tools/dependency/test_data/source_code_data/ansible_ansible/hacking.azp.get_recent_coverage_runs.py/get_recent_coverage_runs.py"
# cfg = CFGBuilder().build_from_file('get_recent_coverage_runs.py', src_code_fpath)
# cfg.build_visual('exampleCFG', 'pdf')

if __name__ == '__main__':
    src = (
        "aa = 1\n"
        "class A:\n"
        "   a = 1\n"
        "   def foo(self):\n"
        "       print(1)\n"
        "   def foo2(self):\n"
        "       print(2)\n"
        "def func(a, b):\n"
        "   if a > 1:\n"
        "       b = 1\n"
        "       while b < 10:\n"
        "           a += 2\n"
        "           if a > 9:\n"
        "               for j in range(1, 11):\n"
        "                   if a > j:\n"
        "                       a -= 1\n"
        "                       continue\n"
        "                       a += 1\n"
        "                   elif 0 < a < j:\n"
        "                       a -= 2\n"
        "                       break\n"
        "                       a += 2\n"
        "                   a = 1\n"
        "               a = 9\n"
        "               break\n"
        "       print(b)\n"
        "   elif a == 1:\n"
        "       b = 0\n"
        "       global aa\n"
        "       b = a if a > 1 else 1\n"
        "       return\n"
        "       b = 3\n"
        "   elif a > -1:\n"
        "       b = -1\n"
        "   else:\n"
        "       b = -2\n"
        "   pass\n"
        "   def inter(num):\n"
        "       print(num)\n"
        "if __name__ == '__main__':\n"
        "   func(1, 2)\n"
        "   s = 1\n"
        "   try:\n"
        "       s += 1\n"
        "   except E:\n"
        "       s += 2\n"
        "   except oE as o:\n"
        "       s += 3\n"
        "   finally:\n"
        "       s += 4\n"
        "       if s > 2:\n"
        "           assert isTrue(s)\n"
        "       else:\n"
        "           raise ValueError(s)\n"
        "   s += 5\n"
        "   with open(file) as f:\n"
        "       f = f.read()\n"
    )

    # n = ast.parse(src)
    # print(astor.to_source(n.body[0].orelse[0]))

    print(src)
    cfg = CFGBuilder().build_from_src('test.py', src)
    cfg.build_visual('testCFG', '.', 'pdf')
