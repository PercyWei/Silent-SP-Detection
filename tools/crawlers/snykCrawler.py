from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
import os
import time

from old_utils import selenium_driver_setup, selenium_driver_close


if __name__ == '__main__':

    driver = selenium_driver_setup()

    snyk_vulDB_url = 'https://security.snyk.io/vuln/unmanaged/'
    driver.get(snyk_vulDB_url)

    vul_urls = []
    page = 1

    vul_item_css_selector = 'table#sortable-table.vulns-table__table tbody.vue--table__tbody tr.vue--table__row td a.vue--anchor'
    next_button_css_selector = 'footer div.pagination a.vue--anchor.next.vue--anchor--plain'

    try:
        while True:
            print(f'Searching in page {page} ...')
            WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CSS_SELECTOR, vul_item_css_selector)))

            vul_links = driver.find_elements_by_css_selector(vul_item_css_selector)
            vul_urls = vul_urls + [link.get_attribute('href') for link in vul_links]

            try:
                next_button = driver.find_element_by_css_selector(next_button_css_selector)
                if next_button.is_enabled() and next_button.is_displayed():
                    next_button.click()
                    page += 1
                else:
                    break
            except NoSuchElementException:
                break

        # for vulnerability_url in vulnerability_urls:
        #     driver.get(vulnerability_url)
        #     WebDriverWait(driver, 10).until(
        #         EC.presence_of_element_located((By.CSS_SELECTOR, "selector_for_github_commit_link")))
        #     commit_link = driver.find_element_by_css_selector('your_commit_link_selector').get_attribute('href')
        #
        #     # 访问Commit链接
        #     driver.get(commit_link)
        #     WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "selector_for_version")))
        #     version_link = driver.find_element_by_css_selector('your_version_link_selector').get_attribute('href')
        #
        #     # 访问版本页面并下载文件
        #     driver.get(version_link)
        #     download_links = driver.find_elements_by_css_selector('your_download_links_selector')
        #     for download_link in download_links:
        #         download_url = download_link.get_attribute('href')
        #         # 以文件名命名目录并下载文件
        #         file_name = download_url.split('/')[-1]
        #         local_path = os.path.join('path_to_save', file_name)
        #         with open(local_path, 'wb') as file:
        #             file.write(driver.get(download_url).content)

        for url in vul_urls:
            driver.get(url)
            print(f'Processing vul: {driver.name}')

            try:
                fix_heading = WebDriverWait(driver, 10).until(
                    EC.visibility_of_element_located((By.XPATH, "//h2[contains(text(), 'How to fix?')]"))
                )

                p_elements = fix_heading.find_elements_by_xpath("following-sibling::*//p")

                assert len(p_elements) == 1
                fix_description = p_elements[0].text
                print(fix_description)

            except NoSuchElementException:
                print("No 'How to fix?' item found.")


    except TimeoutException:
        print("A timeout occurred while waiting for the page elements.")
        print("Current URL:", driver.current_url)

    finally:
        selenium_driver_close(driver)
