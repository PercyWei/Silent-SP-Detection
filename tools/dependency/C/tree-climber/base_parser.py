# This code is copied from https://github.com/bstee615/tree-climber
# Original file: tree_climber/base_parser.py
# Original author: bstee615

import abc


class BaseParser(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    def parse(data, *args, **kwargs):
        pass
