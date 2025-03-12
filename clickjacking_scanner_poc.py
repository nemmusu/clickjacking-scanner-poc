#!/usr/bin/env python3
import argparse
import os
import time
import configparser
import sys
import uuid
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import requests
import concurrent.futures

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import (
    WebDriverException,
    NoSuchFrameException,
    TimeoutException
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from tqdm import tqdm

POC_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking POC</title>
    <style>
        body {{
            background-color: #f0f0f0;
            font-family: Arial, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }}
        .description {{
            text-align: center;
            margin-bottom: 20px;
            color: #333;
        }}
        h2 {{
            color: #000;
        }}
        p {{
            color: rgb(146, 83, 83);
            font-weight: bold;
        }}
        .container {{
            position: relative;
            width: 80%;
            max-width: 900px;
            height: 600px;
            border: 2px solid #ccc;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            background-color: #fff;
        }}
        .container iframe {{
            width: 100%;
            height: 100%;
            border: none;
            display: block;
        }}
        .overlay-button {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            padding: 20px 40px;
            font-size: 20px;
            font-weight: bold;
            color: #fff;
            background-color: #ff5722;
            border: none;
            cursor: pointer;
            opacity: 1;
            z-index: 10;
            border-radius: 5px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        .overlay-button:hover {{
            background-color: #e64a19;
        }}
    </style>
</head>
<body>
    <div class="description">
        <h2>Clickjacking Vulnerability POC</h2>
        <p>This vulnerability presents a security risk, allowing for potential manipulation<br> of user interactions and unauthorized data access without user consent.</p>
    </div>
    <div class="container">
        <iframe src="{victim_url}"></iframe>
        <button class="overlay-button">Click here</button>
    </div>
</body>
</html>
"""

def read_config():
    config = configparser.ConfigParser()
    config.read("config.ini")
    webdriver_path = config.get("settings", "webdriver_path", fallback="chromedriver")
    return webdriver_path

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Clickjacking POC Tester"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-u", "--url",
        help="Specifies a single URL to test."
    )
    group.add_argument(
        "-f", "--file-list",
        help="Specifies a file containing a list of URLs (one per line)."
    )
    parser.add_argument(
        "-o", "--output",
        default="output/",
        help="Output directory (default: output/)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed output."
    )
    parser.add_argument(
        "-d", "--driver-path",
        help="Path to the ChromeDriver binary (overrides config.ini)."
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=1,
        help="Number of threads to use (default=1)."
    )
    return parser.parse_args()

def get_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def generate_poc(victim_url):
    return POC_TEMPLATE.format(victim_url=victim_url)

def save_poc(html_content, output_dir, domain):
    domain_dir = Path(output_dir) / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    poc_path = domain_dir / f"poc_{domain}.html"
    with open(poc_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return poc_path

def check_headers_for_protection(headers):
    xfo = headers.get("X-Frame-Options", "").lower()
    csp = headers.get("Content-Security-Policy", "").lower()
    if "deny" in xfo or "sameorigin" in xfo:
        return True
    if "frame-ancestors" in csp and ("'none'" in csp or "none" in csp):
        return True
    return False

def is_framable(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        if r.status_code == 200 and not check_headers_for_protection(r.headers):
            return True
    except requests.RequestException:
        pass
    return False

def load_poc_and_check_iframe(poc_path, driver_path, victim_url):
    caps = DesiredCapabilities.CHROME.copy()
    caps["goog:loggingPrefs"] = {"performance": "ALL"}
    caps["acceptInsecureCerts"] = True
    
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--ignore-certificate-errors")

    random_uid = str(uuid.uuid4())[:8]
    user_data_path = f"/tmp/chrome_data_{random_uid}"
    chrome_options.add_argument(f"--user-data-dir={user_data_path}")

    for k, v in caps.items():
        chrome_options.set_capability(k, v)

    try:
        service = ChromeService(executable_path=driver_path)
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.execute_cdp_cmd("Network.enable", {})

        driver.get(f"file://{os.path.abspath(poc_path)}")
        time.sleep(2)

        if not is_framable(victim_url):
            driver.quit()
            return False

        try:
            iframe_elem = driver.find_element(By.TAG_NAME, "iframe")
            driver.switch_to.frame(iframe_elem)
        except (NoSuchFrameException, WebDriverException):
            driver.quit()
            return False

        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except TimeoutException:
            driver.quit()
            return False

        time.sleep(3)

        try:
            driver.find_element(By.TAG_NAME, "body")
            can_switch = True
        except WebDriverException:
            can_switch = False

        driver.quit()
        return can_switch

    except WebDriverException as e:
        print(f"WebDriver Error: {e}")
        sys.exit(1)

def process_single_url(url, output_dir, verbose, driver_path):
    domain = get_domain(url)
    poc_html = generate_poc(url)

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as tmpfile:
        tmpfile_name = tmpfile.name
        tmpfile.write(poc_html)

    is_vuln = load_poc_and_check_iframe(tmpfile_name, driver_path, url)

    try:
        os.unlink(tmpfile_name)
    except OSError:
        pass

    if is_vuln:
        save_poc(poc_html, output_dir, domain)
        status = "[VULNERABLE]"
    else:
        status = "[NOT VULNERABLE]"

    result_str = f"{status} {url}"
    if verbose:
        return result_str
    if is_vuln:
        return result_str
    return None

def process_url_list(file_path, output_dir, verbose, driver_path, threads):
    try:
        with open(file_path, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: file '{file_path}' not found.")
        sys.exit(1)

    total = len(urls)
    if total == 0:
        print("Error: the file list is empty.")
        return

    print(f"Total sites to test: {total}")
    vulnerable_count = 0

    if threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(process_single_url, u, output_dir, verbose, driver_path) for u in urls]
            with tqdm(total=total, desc="Processing", unit="site") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    pbar.update(1)
                    res = future.result()
                    if res:
                        tqdm.write(res)
                        if "[VULNERABLE]" in res:
                            vulnerable_count += 1
    else:
        with tqdm(total=total, desc="Processing", unit="site") as pbar:
            for url in urls:
                res = process_single_url(url, output_dir, verbose, driver_path)
                pbar.update(1)
                if res:
                    tqdm.write(res)
                    if "[VULNERABLE]" in res:
                        vulnerable_count += 1

    if vulnerable_count == 0:
        print("No vulnerable sites found.")

def main():
    args = parse_arguments()
    config_driver_path = read_config()
    driver_path = args.driver_path if args.driver_path else config_driver_path
    output_dir = args.output
    verbose = args.verbose
    threads = args.threads

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    if args.url:
        print("Total sites to test: 1")
        res = process_single_url(args.url, output_dir, verbose, driver_path)
        if res:
            print(res)
            if "[VULNERABLE]" not in res:
                print("No vulnerable sites found.")
        else:
            print("No vulnerable sites found.")
    elif args.file_list:
        process_url_list(args.file_list, output_dir, verbose, driver_path, threads)

if __name__ == "__main__":
    main()