import os
import json

from typing import *
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from utils import selenium_driver_setup, selenium_driver_close


def crawl_java_standard_packages_from_oracle(output_dpath: str, java_version: int = 23):

    driver = selenium_driver_setup()

    java_packages: List[str] = []

    try:
        url = f"https://docs.oracle.com/en/java/javase/{java_version}/docs/api/allpackages-index.html"

        driver.get(url)

        wait = WebDriverWait(driver, 10)
        div_elements = wait.until(
            EC.presence_of_all_elements_located(
                (By.XPATH,
                 "/html/body/div[1]/main/div[3]/div[@class='col-first even-row-color' or @class='col-first odd-row-color']"
                 )
            )
        )
        for div in div_elements:
            a_element = div.find_element(By.TAG_NAME, 'a')
            if a_element:
                java_packages.append(a_element.text)

    finally:
        selenium_driver_close(driver)

    save_fpath = os.path.join(output_dpath, f'java_{java_version}_packages.json')
    with open(save_fpath, 'w') as f:
        json.dump(java_packages, f, indent=4)


if __name__ == '__main__':
    output_dir = "/root/projects/VDTest/data/JavaPKG"
    crawl_java_standard_packages_from_oracle(output_dpath=output_dir, java_version=23)
