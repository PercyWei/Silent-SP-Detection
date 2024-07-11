import json
import os
from typing import *
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from old_utils.crawler import selenium_driver_setup, selenium_driver_close
from old_utils.logging import start_with_logger


def filter_duplicate_cwe_items(cweTree: Dict) -> Dict:
    logger.info("Filtering duplicate cwe items in CWE tree, i.e. nodes with duplicate fathers.")

    cwe_simple_item_dict = {}

    for father, child_list in cweTree.items():
        cwe_item = {
            "CWE-ID": father,
            "VIEW-" + view_id:
                {
                    "father": [],
                    "children": child_list
                }
        }
        cwe_simple_item_dict[father] = cwe_item

        for child in child_list:
            if child in cwe_simple_item_dict:
                cwe_simple_item_dict[child]["VIEW-" + view_id]["father"].append(father)
                logger.info(f"CWE-{child} already added before (has multiple fathers).")
            else:
                cwe_item = {
                    "CWE-ID": child,
                    "VIEW-" + view_id:
                        {
                            "father": [father],
                            "children": []
                        }
                }

                cwe_simple_item_dict[child] = cwe_item

    return cwe_simple_item_dict


def craw_view_rels(view_id: str, view_url: str, save_dpath: str):
    logger.info(f"Crawling view {view_id} from {view_url}.")

    driver = selenium_driver_setup()

    driver.get(view_url)

    cweTree = {}
    cwe_simple_item_dict = {}

    try:
        expand_button = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//a[@href="javascript:toggleAll(\'expand\');"]'))
        )
        expand_button.click()
        driver.maximize_window()

        xpath_selector = f"//div[contains(@class, 'group') and starts-with(@id, '{int(view_id)}')]"

        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, xpath_selector))
        )

        elements = driver.find_elements_by_xpath(xpath_selector)
        logger.info(f"Successfully crawled {len(elements)} qualified items.")

        father_id = None
        children_id_list = []

        for element in elements:
            cwe_id_path = element.get_attribute('id')
            if father_id is None:
                father_id = cwe_id_path[len(view_id):]
                children_id_list = []

                assert int(father_id) <= 1362
                continue

            if cwe_id_path.startswith(view_id + father_id):
                child_id = cwe_id_path[len(view_id + father_id):]
                children_id_list.append(child_id)
            else:
                assert father_id not in cweTree
                cweTree[father_id] = children_id_list

                father_id = cwe_id_path[len(view_id):]
                children_id_list = []

                assert int(father_id) <= 1362

        cweTree[father_id] = children_id_list

        # Filter
        cwe_simple_item_dict = filter_duplicate_cwe_items(cweTree)

        # Save
        if not os.path.exists(save_dpath):
            os.makedirs(save_dpath, exist_ok=True)

        cwe_simple_items_fpath = os.path.join(save_dpath, 'VIEW-' + view_id + '_CWESimpleItems' + '.json')

        with open(cwe_simple_items_fpath, "w") as f:
            f.write(json.dumps(cwe_simple_item_dict, indent=4))

        logger.info(f"Successfully crawled {len(cwe_simple_item_dict)} CWE items.")
        logger.info(f"Detailed information save in {cwe_simple_items_fpath}.")

    finally:
        selenium_driver_close(driver)


if __name__ == '__main__':
    logger = start_with_logger(__name__)

    view_id = '699'
    cwe699_url = 'https://cwe.mitre.org/data/definitions/699.html'
    # view_id = '1003'
    # cwe1003_url = 'https://cwe.mitre.org/data/definitions/1003.html'

    save_dpath = './data/crawler'

    craw_view_rels(view_id, cwe699_url, save_dpath)
