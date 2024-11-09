import os
import subprocess

from typing import *
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

from logs import base_log_and_cprint


def make_hie_dirs(root: str, *dirs: str) -> str:
    """Make hierarchical directories recursively."""
    new_dpath = os.path.join(root, *dirs)
    if not os.path.exists(new_dpath):
        os.makedirs(new_dpath, exist_ok=True)

    return new_dpath


def run_command(
        command: List[str],
        print_log: bool = True,
        print_stdout: bool = True,
        raise_error: bool = True,
        **run_params
) -> Tuple[Optional[subprocess.CompletedProcess], Optional[str]]:
    """
    Run a command in the shell.

    Args:
        command (List(str)): The command to run.
        print_log (bool): If True, print details to the log.
        print_stdout (bool): If True, print details to the stdout.
        raise_error (bool): If Ture, raise error when command failed.
        run_params: Params to pass to the `subprocess.run`.
    Returns:
        subprocess.CompletedProcess | None: Result of running the command, or None if the run failed.
        str | None: Error message, or None if the run succeed.
    """
    try:
        result = subprocess.run(command, check=True, **run_params)
        return result, None

    except subprocess.CalledProcessError as e:
        error_msg = f"Error running command: {' '.join(command)}\nError msg: {e}"
        base_log_and_cprint(error_msg, print_log=print_log, print_stdout=print_stdout)
        if raise_error:
            raise e
        return None, str(e)

    except Exception as e:
        error_msg = f"Error running command: {' '.join(command)}\nError msg: {e}"
        base_log_and_cprint(error_msg, print_log=print_log, print_stdout=print_stdout)
        if raise_error:
            raise e
        return None, str(e)


"""CRAWLER"""


def selenium_driver_setup(driver_type='chrome') -> webdriver.Remote | None:
    driver = None

    if driver_type == 'chrome':
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    else:
        print("Driver type not supported")

    return driver


def selenium_driver_close(driver):
    driver.quit()


"""UTILS"""


def insert_key_value(d: Dict, key: Any, value: Any, index: int = 0) -> Dict:
    d_list = list(d.items())
    d_list.insert(index, (key, value))
    return dict(d_list)
