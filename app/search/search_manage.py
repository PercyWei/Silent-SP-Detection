# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: app/search/search_manage.py


from typing import *
from collections import defaultdict, namedtuple
from collections.abc import MutableMapping


LineRange = namedtuple("LineRange", ["start", "end"])

ClassIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]
ClassFuncIndexType = MutableMapping[str, MutableMapping[str, List[Tuple[str, LineRange]]]]
FuncIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]


class SearchManager:
    def __init__(self, local_repo_dpath: str):
        self.local_repo_dpath = local_repo_dpath
        # List of all files ending with .py, which are likely not test files
        # These are all ABSOLUTE paths.
        self.parsed_files: List[str] = []

        # for file name in the indexes, assume they are absolute path
        # class name -> [(file_name, line_range)]
        self.class_index: ClassIndexType = {}

        # {class_name -> {func_name -> [(file_name, line_range)]}}
        # inner dict is a list, since we can have (1) overloading func names,
        # and (2) multiple classes with the same name, having the same method
        self.class_func_index: ClassFuncIndexType = {}

        # function name -> [(file_name, line_range)]
        self.function_index: FuncIndexType = {}
        self._build_index()


    def _build_index(self):
        """
        With all source code of the project, build two indexes:
            1. From class name to (source file, start line, end line)
            2. From function name to (source file, start line, end line)
        Since there can be two classes/functions with the same name, the mapping
        value is a list of tuples.
        This is for fast lookup whenever we receive a query.
        """
        self._update_indices(*self._build_python_index())

    def _update_indices(
        self,
        class_index: ClassIndexType,
        class_func_index: ClassFuncIndexType,
        function_index: FuncIndexType,
        parsed_files: List[str],
    ) -> None:
        self.class_index.update(class_index)
        self.class_func_index.update(class_func_index)
        self.function_index.update(function_index)
        self.parsed_files.extend(parsed_files)

    def _build_python_index(self) -> Tuple[ClassIndexType, ClassFuncIndexType, FuncIndexType, List[str]]:
        class_index: ClassIndexType = defaultdict(list)
        class_func_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))
        function_index: FuncIndexType = defaultdict(list)

        py_files = search_utils.find_python_files(self.project_path)
        # holds the parsable subset of all py files
        parsed_py_files = []
        for py_file in py_files:
            file_info = search_utils.parse_python_file(py_file)
            if file_info is None:
                # parsing of this file failed
                continue
            parsed_py_files.append(py_file)
            # extract from file info, and form search index
            classes, class_to_funcs, top_level_funcs = file_info

            # (1) build class index
            for c, start, end in classes:
                class_index[c].append((py_file, LineRange(start, end)))

            # (2) build class-function index
            for c, class_funcs in class_to_funcs.items():
                for f, start, end in class_funcs:
                    class_func_index[c][f].append((py_file, LineRange(start, end)))

            # (3) build (top-level) function index
            for f, start, end in top_level_funcs:
                function_index[f].append((py_file, LineRange(start, end)))

        return class_index, class_func_index, function_index, parsed_py_files



