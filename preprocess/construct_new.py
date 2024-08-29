import re
import json

from typing import *
from tqdm import tqdm

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def search_nvd_and_extract_cwe(driver, cve_id):
    nvd_url = 'https://nvd.nist.gov/vuln/search'
    driver.get(nvd_url)

    wait = WebDriverWait(driver, 10)
    search_box = wait.until(EC.presence_of_element_located((By.ID, 'Keywords')))
    search_box.clear()
    search_box.send_keys(cve_id)

    search_button = driver.find_element(By.ID, 'vuln-search-submit')
    search_button.click()

    try:
        result_xpath = f"//a[contains(@href, '/vuln/detail/{cve_id}')]"
        result_link = wait.until(EC.presence_of_element_located((By.XPATH, result_xpath)))
        result_link.click()
    except Exception as e:
        return None

    cve_detail = wait.until(EC.presence_of_element_located((By.ID, 'vulnTechnicalDetailsDiv')))
    cwe_xpath = "//div[@id='vulnTechnicalDetailsDiv']//a[contains(@href, 'cwe.mitre.org') and contains(text(), 'CWE-')]"
    cwe_elements = wait.until(EC.presence_of_all_elements_located((By.XPATH, cwe_xpath)))

    # 提取所有CWE-ID并输出
    cwe_ids = [element.text for element in cwe_elements]

    driver.back()

    return cwe_ids


def find_github_relevant_ref(refs: List[Dict]) -> List[str]:
    """Only check if there is a github url in the ref."""
    github_urls = []
    for ref in refs:
        url = ref['url']
        if "https://github.com/" in url:
            github_urls.append(url)
    return github_urls


def build_new_dataset():
    nvdcve_file = "/root/projects/VDTest/NVD/raw/nvdcve-1.1-2022.json"
    with open(nvdcve_file, 'r') as f:
        content = json.load(f)

    cve_items = content["CVE_Items"]

    dateset_items = []

    with tqdm(total=len(cve_items)) as pb:
        for item in cve_items:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]

            # Find GitHub reference of CVE
            refs = item["cve"]["references"]["reference_data"]
            github_urls = find_github_relevant_ref(refs)

            if github_urls:
                # Get CWE-IDs of CVE
                cwe_list = []
                for cwe in item["cve"]["problemtype"]["problemtype_data"][0]["description"]:
                    cwe_id = cwe["value"]
                    if re.match(r"^CWE-\d+$", cwe_id):
                        cwe_list.append(cwe_id)

                if len(cwe_list) > 0:
                    sim_item = {"cve_id": cve_id, "cwe_list": cwe_list, "urls": github_urls}
                    dateset_items.append(sim_item)

            pb.update(1)

    dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve_2022_v1.json"
    with open(dataset_fpath, 'w') as f:
        json.dump(dateset_items, f, indent=4)


def filter_dataset():
    dataset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve_2022_v1.json"
    with open(dataset_fpath, 'r') as f:
        dateset_items = json.load(f)

    blob_pattern = r"^https://github\.com/([\w-]+/[\w-]+)/blob/([^/]+)/(.*?)(?:#L\d+)?$"

    for item in dateset_items:
        urls = item["urls"]

        for url in urls:



    filtered_dateset_fpath = "/root/projects/VDTest/NVD/filter/nvdcve_2022_v2.json"



build_new_dataset()
