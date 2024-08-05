# This code is modified from https://github.com/nus-apr/auto-code-rover
# Original file: agent_app/search/search_manage.py


from typing import *
from collections import defaultdict
from collections.abc import MutableMapping

from agent_app.search import search_util
from agent_app.search.search_util import SearchResult
from utils import LineRange


ClassIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]
ClassFuncIndexType = MutableMapping[str, MutableMapping[str, List[Tuple[str, LineRange]]]]
FuncIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]

FileClassIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]
FileFuncIndexType = MutableMapping[str, List[Tuple[str, LineRange]]]

RESULT_SHOW_LIMIT = 3


class SearchManager:
    def __init__(self, local_repo_dpath: str, commit_mod_files: Dict[str, str]):
        ## Basic information
        self.local_repo_dpath = local_repo_dpath

        ## Files in the repo (after applying the commit)
        # List of all files ending with .py, which are likely not test files
        # These are all ABSOLUTE paths.
        self.parsed_files: List[str] = []
        self.parsed_failed_files: List[str] = []

        # For file name in the indexes, assume they are absolute path
        # class name -> [(file_name, line_range)]
        self.class_index: ClassIndexType = {}

        # class_name -> {func_name -> [(file_name, line_range)]}
        # Inner dict is a list, since we can have
        # (1) overloading func names, and
        # (2) multiple classes with the same name, having the same method
        self.class_func_index: ClassFuncIndexType = {}

        # func_name -> [(file_name, line_range)]
        self.func_index: FuncIndexType = {}

        # file_name -> [(class_name, line_range)]
        self.file_class_index: FileClassIndexType = {}

        # file_name -> [(func_name, line_range)]
        self.file_func_index: FileFuncIndexType = {}

        # Build index
        self._build_index()

        ## Modified files involved in the commit
        # file after commit -> file before commit
        self.commit_mod_files: Dict[str, str] = commit_mod_files

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
            parsed_files: List[str],
            parsed_failed_files: List[str],
            class_index: ClassIndexType,
            class_func_index: ClassFuncIndexType,
            func_index: FuncIndexType,
            file_class_index: FileClassIndexType,
            file_func_index: FileFuncIndexType,
    ) -> None:
        self.parsed_files.extend(parsed_files)
        self.parsed_failed_files.extend(parsed_failed_files)
        self.class_index.update(class_index)
        self.class_func_index.update(class_func_index)
        self.func_index.update(func_index)
        self.file_class_index.update(file_class_index)
        self.file_func_index.update(file_func_index)

    def _build_python_index(
            self
    ) -> Tuple[List[str], List[str], ClassIndexType, ClassFuncIndexType, FuncIndexType, FileClassIndexType, FileFuncIndexType]:
        class_index: ClassIndexType = defaultdict(list)
        class_func_index: ClassFuncIndexType = defaultdict(lambda: defaultdict(list))
        func_index: FuncIndexType = defaultdict(list)

        file_class_index: FileClassIndexType = defaultdict(list)
        file_func_index: FileFuncIndexType = defaultdict(list)

        py_files = search_util.find_python_files(self.local_repo_dpath)
        # Holds the parsable subset of all py files
        parsed_py_files = []
        parsed_failed_py_files = []
        for py_file in py_files:
            file_info = search_util.parse_python_file(py_file)
            if file_info is None:
                # AST parsing failed
                parsed_failed_py_files.append(py_file)
                continue

            parsed_py_files.append(py_file)
            # Extract from file info, and form search index
            classes, class_to_funcs, top_level_funcs = file_info

            # (1) Build class index and file class index
            for c, start, end in classes:
                class_index[c].append((py_file, LineRange(start, end)))
                file_class_index[py_file].append((c, LineRange(start, end)))

            # (2) Build class-function index
            for c, class_funcs in class_to_funcs.items():
                for f, start, end in class_funcs:
                    class_func_index[c][f].append((py_file, LineRange(start, end)))

            # (3) Build (top-level) function index and file function index
            for f, start, end in top_level_funcs:
                func_index[f].append((py_file, LineRange(start, end)))
                file_func_index[py_file].append((f, LineRange(start, end)))

        return (parsed_py_files, parsed_failed_py_files,
                class_index, class_func_index, func_index,
                file_class_index, file_func_index)

    """Search Functions"""

    def _search_func_in_class_in_file(self, function_name: str, class_name: str, file_name: str) -> List[SearchResult]:
        """
        Search for the function name in the class in the file.

        Args:
            function_name (str): Name of the function.
            class_name (str): Name of the class.
            file_name (str): Name of the file.
        Returns:
            The list of code snippets searched.
        """
        result: List[SearchResult] = []
        if class_name not in self.class_func_index:
            return result
        if function_name not in self.class_func_index[class_name]:
            return result
        for fname, (func_start, func_end) in self.class_func_index[class_name][function_name]:
            if fname == file_name:
                func_code = search_util.get_code_snippets(fname, func_start, func_end)
                res = SearchResult(fname, class_name, function_name, func_code)
                result.append(res)
        return result

    def _search_func_in_class(self, function_name: str, class_name: str) -> List[SearchResult]:
        """
        Search for the function name in the class.

        Args:
            function_name (str): Name of the function.
            class_name (str): Name of the class.
        Returns:
            The list of code snippets searched.
        """
        result: List[SearchResult] = []
        if class_name not in self.class_func_index:
            return result
        if function_name not in self.class_func_index[class_name]:
            return result
        for fname, (func_start, func_end) in self.class_func_index[class_name][function_name]:
            func_code = search_util.get_code_snippets(fname, func_start, func_end)
            res = SearchResult(fname, class_name, function_name, func_code)
            result.append(res)
        return result

    def _search_func_in_all_classes(self, function_name: str) -> list[SearchResult]:
        """
        Search for the function name in all classes.
        Args:
            function_name (str): Name of the function.
        Returns:
            The list of code snippets searched.
        """
        result: list[SearchResult] = []
        for class_name in self.class_index:
            res = self._search_func_in_class(function_name, class_name)
            result.extend(res)
        return result

    def _search_top_level_func(self, function_name: str) -> List[SearchResult]:
        """
        Search for top-level function name in the entire project.

        Args:
            function_name (str): Name of the function.
        Returns:
            List: The list of code snippets searched.
        """
        result: List[SearchResult] = []
        if function_name not in self.func_index:
            return result

        for fname, (func_start, func_end) in self.func_index[function_name]:
            func_code = search_util.get_code_snippets(fname, func_start, func_end)
            res = SearchResult(fname, None, function_name, func_code)
            result.append(res)
        return result

    def _search_func_in_repo(self, function_name: str) -> list[SearchResult]:
        """
        Search for this function, from both top-level and all class definitions.
        """
        result: list[SearchResult] = []  # list of (file_name, func_code)
        # (1) search in top level
        top_level_res = self._search_top_level_func(function_name)
        class_res = self._search_func_in_all_classes(function_name)
        result.extend(top_level_res)
        result.extend(class_res)
        return result

    """Interfaces"""

    def search_class(self, class_name: str) -> Tuple[str, str, bool]:
        """
        NOTE: Search for class in entire repo.
        """
        # (1) Check whether we can get the class
        if class_name not in self.class_index:
            tool_output = summary = f"Could not find class {class_name} in the repo."
            return tool_output, summary, False

        # (2) There are some classes; we return their signatures
        search_res: List[SearchResult] = []
        for fname, _ in self.class_index[class_name]:
            code = search_util.get_class_signature(fname, class_name)
            res = SearchResult(fname, class_name, None, code)
            search_res.append(res)

        # For all the searched result, append them and form the final result
        tool_output = summary = f"Found {len(search_res)} classes with name {class_name} in the repo:\n\n"
        if len(search_res) > RESULT_SHOW_LIMIT:
            # Too much classes, simplified representation
            tool_output += "They appeared in the following files:\n"
            tool_output += SearchResult.collapse_to_file_level(search_res, self.local_repo_dpath)
        else:
            # Several classes, verbose representation
            for idx, res in enumerate(search_res):
                res_str = res.to_tagged_str(self.local_repo_dpath)
                tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, summary, True


    def search_class_in_file(self, class_name, file_name: str) -> Tuple[str, str, bool]:
        """
        NOTE: Search for class in specified file.
        """
        # (1) Check whether we can get the file
        candidate_py_abs_paths = [f for f in self.parsed_files if f.endswith(file_name)]
        if not candidate_py_abs_paths:
            tool_output = summary = f"Could not find file {file_name} in the repo."
            return tool_output, summary, False

        # (2) Search for this class in the entire repo (we do filtering later)
        if class_name not in self.class_index:
            tool_output = summary = f"Could not find class {class_name} in the repo."
            return tool_output, summary, False

        # (3) Class is there, check whether it exists in the file specified.
        search_res: List[SearchResult] = []
        for fname, (class_start_line, class_end_line) in self.class_index[class_name]:
            if fname in candidate_py_abs_paths:
                class_code = search_util.get_code_snippets(fname, class_start_line, class_end_line)
                res = SearchResult(fname, class_name, None, class_code)
                search_res.append(res)

        if not search_res:
            tool_output = summary = f"Could not find class {class_name} in file {file_name}."
            return tool_output, summary, False

        # We have result, now just form a response
        tool_output = summary = f"Found {len(search_res)} classes with name {class_name} in file {file_name}:\n\n"
        for idx, res in enumerate(search_res):
            res_str = res.to_tagged_str(self.local_repo_dpath)
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, summary, True


    def search_method_in_file(self, method_name: str, file_name: str) -> Tuple[str, str, bool]:
        """
        NOTE: Search for (top level) function in specified file.
        """
        # (1) Check whether we can get the file
        candidate_py_abs_paths = [f for f in self.parsed_files if f.endswith(file_name)]
        if not candidate_py_abs_paths:
            tool_output = summary = f"Could not find file {file_name} in the repo."
            return tool_output, summary, False

        # (2) Search for this method in the entire repo (we do filtering later)
        search_res: List[SearchResult] = self._search_func_in_repo(method_name)
        if not search_res:
            tool_output = summary = f"The method {method_name} does not appear in the repo."
            return tool_output, summary, False

        # (3) Filter the search result => they need to be in one of the candidate files!
        filtered_res: List[SearchResult] = [res for res in search_res if res.file_path in candidate_py_abs_paths]

        # (4) Done with search, now prepare result
        if not filtered_res:
            tool_output = summary = f"There is no method with name `{method_name}` in file {file_name}."
            return tool_output, summary, False

        tool_output = summary = f"Found {len(filtered_res)} methods with name `{method_name}` in file {file_name}:\n\n"

        # When searching for a method in one file, it's rare that there are
        # many candidates, so we do not trim the result
        for idx, res in enumerate(filtered_res):
            res_str = res.to_tagged_str(self.local_repo_dpath)
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, summary, True


    def search_method_in_class(self, method_name: str, class_name: str) -> Tuple[str, str, bool]:
        """
        NOTE: Search for class function in specified class.
        """
        # (1) Check whether we can get the class
        if class_name not in self.class_index:
            tool_output = summary = f"Could not find class {class_name} in the repo."
            return tool_output, summary, False

        # (2) Class exists, check whether it has the method
        search_res: List[SearchResult] = self._search_func_in_class(method_name, class_name)
        if not search_res:
            tool_output = summary = f"Could not find method {method_name} in class {class_name}`."
            return tool_output, summary, False

        # (3) Found some methods, prepare the result
        tool_output = summary = f"Found {len(search_res)} methods with name {method_name} in class {class_name}:\n\n"

        # There can be multiple classes defined in multiple files, which contain the same method
        # still trim the result, just in case
        if len(search_res) > RESULT_SHOW_LIMIT:
            tool_output += f"Too many results, showing full code for {RESULT_SHOW_LIMIT} of them, and the rest just file names:\n"
        first_five = search_res[:RESULT_SHOW_LIMIT]
        for idx, res in enumerate(first_five):
            res_str = res.to_tagged_str(self.local_repo_dpath)
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        # For the rest, collect the file names into a set
        if rest := search_res[RESULT_SHOW_LIMIT:]:
            tool_output += "Other results are in these files:\n"
            tool_output += SearchResult.collapse_to_file_level(rest, self.local_repo_dpath)
        return tool_output, summary, True


    def search_method_in_class_in_file(self, method_name: str, class_name: str, file_name: str) -> Tuple[str, str, bool]:
        """
        NOTE: Search for class function in specified class and file.
        """
        # (1) Check whether we can get the file
        candidate_py_abs_paths = [f for f in self.parsed_files if f.endswith(file_name)]
        if not candidate_py_abs_paths:
            tool_output = summary = f"Could not find file {file_name} in the repo."
            return tool_output, summary, False

        # (2) Search for this class in the entire repo (we do filtering later)
        if class_name not in self.class_index:
            tool_output = summary = f"Could not find class {class_name} in the repo."
            return tool_output, summary, False

        # (3) Class is there, check whether it exists in the file specified.
        search_res: List[SearchResult] = []
        for fname, _ in self.class_index[class_name]:
            if fname in candidate_py_abs_paths:
                res = SearchResult(fname, class_name, None, "")
                search_res.append(res)

        if not search_res:
            tool_output = summary = f"Could not find class {class_name} in file {file_name}."
            return tool_output, summary, False

        # (4) Search for this method in the class and file specified
        final_search_res: List[SearchResult] = []
        for res in search_res:
            final_search_res.extend(self._search_func_in_class_in_file(method_name, class_name, res.file_path))

        if not search_res:
            tool_output = summary = f"Could not find method {method_name} in class {class_name} in file {file_name}."
            return tool_output, summary, False

        # We have result, now just form a response
        tool_output = summary = f"Found {len(search_res)} methods with name {method_name} in class {class_name} in file {file_name}:\n\n"
        for idx, res in enumerate(search_res):
            res_str = res.to_tagged_str(self.local_repo_dpath)
            tool_output += f"- Search result {idx + 1}:\n```\n{res_str}\n```\n"
        return tool_output, summary, True
