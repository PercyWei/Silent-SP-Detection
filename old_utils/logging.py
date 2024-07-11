import os
import sys
import logging
import time
import datetime

from os import get_terminal_size
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel


def get_timestamp() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')


def _create_logger_fpath(log_dpath='./logs', log_fname=None):
    if log_fname is None:
        log_fname = get_timestamp() + '.log'
    else:
        log_fname = log_fname + '.log'

    if not os.path.exists(log_dpath):
        os.mkdir(log_dpath)
    log_fpath = os.path.join(log_dpath, log_fname)

    return log_fpath


def get_logger(name, level=logging.DEBUG, log_dpath='./logs', log_fname=None, log_format=None, mode='w'):
    _logger = logging.getLogger(name)

    if log_format is None:
        log_format = '%(levelname)s - %(message)s'

    formatter = logging.Formatter(log_format)

    log_fpath = _create_logger_fpath(log_dpath, log_fname)

    file_handler = logging.FileHandler(log_fpath, mode=mode)
    file_handler.setFormatter(formatter)

    _logger.addHandler(file_handler)
    _logger.setLevel(level)

    return _logger


def start_with_logger(name, level=logging.DEBUG, log_dpath='./logs', log_fname=None, log_format=None, mode='w'):

    _logger = get_logger(name, level, log_dpath, log_fname, log_format, mode)

    # Add command and execution time
    command_line = ' '.join(sys.argv)
    start_time = time.time()
    start_time_formatted = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))

    _logger.info('+' * 50)
    _logger.info(f"Command: {command_line}")
    _logger.info(f"Start time: {start_time_formatted}")
    _logger.info('+' * 50)

    return _logger


def get_global_logger():

    timestamp = get_timestamp()
    if '__main__' in sys.modules:
        main_script = sys.modules['__main__'].__file__
        file_name = os.path.basename(main_script)
        log_fname = f"{os.path.splitext(file_name)[0]}-{timestamp}"
    else:
        log_fname = timestamp

    _logger = start_with_logger(__name__, log_fname=log_fname)

    return _logger


def log_debug(_logger, msg: str):
    _logger.debug("=" * 100)
    _logger.debug(msg)
    _logger.debug("=" * 100)


logger = get_global_logger()
