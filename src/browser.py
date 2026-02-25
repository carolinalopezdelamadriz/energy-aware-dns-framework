from selenium import webdriver
import time

def open_website(url, duration=10):
    driver = webdriver.Chrome()
    driver.get(url)
    time.sleep(duration)
    driver.quit()