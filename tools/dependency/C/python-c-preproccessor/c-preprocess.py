# This code is copied from https://github.com/hrehfeld/python-c-preproccessor
# Original file: c-preprocess.py
# Original author: hrehfeld

import json
import sys
from pathlib import Path
from pprint import pprint
import re
import os


identifier = r'\w+'
value = r'\S+'
function_names = 'defined'
function = function_names + r'\(' + identifier + r'\)'
expr = '(?:' + value + '|' + function + ')'

function_re = re.compile('(' + function_names + ')' + r'\((' + identifier + r')\)')

include_re = re.compile(r'\s+("[^"]*"|\<[^>]*>)')
ifdef_re = re.compile(r'\s+(' + identifier + r')')
define_re = re.compile(r'\s+(' + identifier + r')(\s+(' + value + '))?')
undef_re = re.compile(r'\s+(' + identifier + r')')
if_re = re.compile(r'\s+(' + expr + ')')
pragma_re = re.compile(r'\s+(once)')

command_re_str = r'\s*\#(include|ifdef|ifndef|define|if|endif|else|elif|undef|pragma)(\s*(.*))'
command_re = re.compile(command_re_str)


class Options:
    def __init__(self):
        self.passthrough_defines = False
        self.verbose = False
        self.quiet = False


def process_file(options, fp, includes, parent_defines, included_filepaths=None, indent=0):
    if included_filepaths is None:
        included_filepaths = set()
    with fp.open('r') as f:
        src = f.readlines()

    prefix = '#'

    defines = dict(parent_defines)


    ifs = []
    allow_else = []

    def is_valid():
        return not ifs or ifs[-1]

    def add_if(cond):
        if is_valid():
            ifs.append(cond)
            allow_else.append(not cond)
        else:
            ifs.append(False)
            allow_else.append(False)


    def log(*args):
        if options.verbose:
            print((indent + len(ifs)) * '  ', *args)

    def line_str(iline, fp):
        return f'//{fp}\n#line {iline}\n'

    res = []
    iline = 0
    last_iline = -1
    def set_iline():
        nonlocal last_iline
        last_iline = iline
    def emit(s):
        set_iline()
    for iline, line in enumerate(src):
        #log(line)
        m = command_re.match(line)
        cmd = rest = None
        if m:
            cmd = m.group(1)
            assert cmd, line
            rest = m.group(2)
            log('cmd', cmd, rest)

        if cmd == 'endif':
            log(cmd, ifs)
            assert ifs, ''.join([f'{i}	{line}' for i, line in enumerate(src)]) + f'\nERROR: {fp}:{iline}: '
            ifs.pop()
            allow_else.pop()
        elif cmd == 'else':
            assert ifs
            if allow_else[-1]:
                ifs[-1] = True
                allow_else[-1] = False
        elif cmd in ('ifdef', 'ifndef'):
            m = ifdef_re.match(rest)
            var = m.group(1)
            cond = var in defines
            if cmd == 'ifndef':
                cond = not cond
            log(cmd, var, cond)
            add_if(cond)
        elif cmd in ('elif', 'if'):
            if cmd == 'elif' and not allow_else[-1]:
                continue
            m = if_re.match(rest)
            assert m, line
            cond_str = m.group(1)
            m = function_re.match(cond_str)
            cond = False
            if m:
                function = m.group(1)
                arg = m.group(2)
                log('FUNCTION', cmd, function, arg)

                if function == 'defined':
                    cond = arg in defines
                else:
                    assert False, line
            else:
                log(line, function_re)
                assert False, line
            log(cmd, cond_str, cond)

            if cmd == 'if':
                add_if(cond)
            elif cond:
                ifs[-1] = True
                allow_else[-1] = False
        elif is_valid():
            if cmd:
                log('--- valid ---', ifs, cmd, rest)
            if cmd == 'include':
                m = include_re.match(rest)
                path = m.group(1)
                is_system = path[0] == '<'
                path = path[1:-1]
                log(path, is_system)

                these_includes = [fp.parent, *includes] if not is_system else includes

                for include_dir in these_includes:
                    sub_fp = include_dir / path
                    if sub_fp.exists():
                        log(sub_fp)
                        sub_src = process_file(options, sub_fp, includes, defines, included_filepaths, indent + 1)
                        # just don't emit empty files
                        log('sub_src', repr(sub_src[:10]), repr(sub_src.strip()[:10]))
                        if sub_src.strip():
                            res.append(line_str(0, sub_fp))
                            res.append(sub_src)
                            res.append(line_str(iline, fp))
                            set_iline()
                        break
                else:
                    raise Exception(f'{path} not found!')
            elif cmd == 'define':
                m = define_re.match(rest)
                assert m, line
                k = m.group(1)
                v = m.group(3)
                log(cmd, k, v)
                defines[k] = v
                if options.passthrough_defines:
                    emit(line)
            elif cmd == 'undef':
                m = undef_re.match(rest)
                assert m, line
                var = m.group(1)
                del defines[var]
            elif cmd == 'pragma':
                m = pragma_re.match(rest)
                assert m, line
                assert m.group(1) == 'once', line
                if fp in included_filepaths:
                    log('skipping')
                    return ''
                included_filepaths.add(fp)
            else:
                assert cmd == None, cmd
                if not ifs or ifs[-1]:
                    emit(line)

    return ''.join(res)





def main():
    options = Options()

    def log(*args, **kwargs):
        if options.verbose:
            print(*args, **kwargs)

    args = list(sys.argv[1:])

    options_params = {
        '--verbose': 'verbose',
        '--passthrough-defines': 'passthrough_defines',
        '-q': 'quiet',
    }

    while args:
        arg = args.pop(0)
        for arg_str, arg_attr in options_params.items():
            if arg == arg_str:
                setattr(options, arg_attr, True)
                log('option found')
                break
        else:
            args.insert(0, arg)
            break


    base_path = Path(os.getcwd()).absolute()

    filepaths = args

    filepaths = [Path(fp).absolute() for fp in filepaths]

    compile_commands_filepath = filepaths.pop(0)
    similar_filepath = filepaths.pop(0)
    process_filepath = filepaths.pop(0)


    with compile_commands_filepath.open('r') as fp:
        compile_commands = json.load(fp)

    def make_relative(fp):
        fp = fp.absolute()
        if fp.is_relative_to(base_path):
            return fp.relative_to(base_path)
        return fp
    compile_commands = dict([((Path(e['file']).absolute()), e['command']) for e in compile_commands])

    compile_commands = compile_commands[similar_filepath]

    compile_commands = compile_commands.strip().split()

    includes = []
    defines = []
    include_switch = '-I'
    define_switch = '-D'
    for arg in compile_commands:
        for switch, ls in ((include_switch, includes), (define_switch, defines)):
            if arg.startswith(switch):
                arg = arg.lstrip(switch)
                ls.append(arg)

    def parse_define(s):
        s = s.split('=')
        assert len(s) <= 2, s
        if len(s) == 1:
            return s[0], None
        return tuple(*s)

    includes = [Path(p) for p in includes]
    defines = [parse_define(e) for e in defines]
    defines = dict(defines)

    src = process_file(options, process_filepath.absolute(), includes, defines)
    if not options.quiet:
        print(src)

main()