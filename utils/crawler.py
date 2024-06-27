from selenium import webdriver
from selenium.webdriver.chrome.options import Options


def selenium_driver_setup(driver_type='chrome', driver_path='/usr/local/bin/chromedriver'):
    driver = None

    if driver_type == 'chrome':
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(executable_path=driver_path, options=chrome_options)
    else:
        print("Driver type not supported")

    return driver


def selenium_driver_close(driver):
    driver.quit()
