
from typing import *

from loguru import logger

from logs import base_log_and_cprint



def default_add_logger(log_fpath: str):
    logger.remove()
    logger.add(
        log_fpath,
        level="DEBUG",
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    )


def log_banner(msg: str):
    logger.debug('=' * 100)
    logger.debug(msg)
    logger.debug('=' * 100)


def log_and_print(msg):
    base_log_and_cprint(msg)


def log_and_cprint(msg, **kwargs):
    base_log_and_cprint(msg, print_log=True, print_stdout=True, **kwargs)


def cprint(msg, **kwargs) -> None:
    base_log_and_cprint(msg, print_log=False, print_stdout=True, **kwargs)

