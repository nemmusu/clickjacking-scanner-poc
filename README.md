# Clickjacking Scanner and POC

This Python script now provides **enhanced testing for Clickjacking vulnerabilities** on one or more websites. It can also capture **automatic screenshots** of the generated POC, highlighting the URL bar with a red box and partially censoring it (leaving only the final segments). The script uses **Chrome** (headless or otherwise) via **Selenium**, plus a **progress bar** (`tqdm`) to show status.

---

## Features

- **HTTP Header Analysis**: Checks if a site uses `X-Frame-Options`, `Content-Security-Policy`, or other relevant mechanisms (including certain JavaScript frame-busting methods) to prevent embedding.
- **POC Generation**: Creates an HTML file for each vulnerable site to demonstrate the Clickjacking attack. The file is based on a customizable `template.html`; just insert `{victim_url}` wherever you want the target URL to appear.
- **Automatic Screenshot Option (`-s`)**: Captures screenshots of the generated POC, draws a red rectangle around the URL bar, and **partially blurs** the address. Only the last two path segments remain visible.
- **OCR‑Based Editing**: Uses Tesseract to dynamically locate and censor the URL bar in the screenshot.
- **Progress Bar**: Provides real-time feedback on the scanning progress. (via `tqdm`).
- **Multithreading**: Optionally run tests in parallel (though `-s` can’t be used with multi-threading).

---

## Installation

### Prerequisites

- **Python 3.7+**
- **Google Chrome/Chromium**
- **ChromeDriver** matching your Chrome version
- **Tesseract** OCR installed on your system (e.g., `sudo apt-get install tesseract-ocr`)

### Install Python Dependencies

1. **Clone** this repository (or download it). Then:
   ```bash
   pip install -r requirements.txt
   ```
   The `requirements.txt` should contain:
   ```
   selenium
   requests
   tqdm
   configparser
   pillow
   pytesseract
   ```
2. **Set up ChromeDriver**
   - Edit `config.ini` under `[settings] webdriver_path = /path/to/chromedriver`.
   - Or pass `--driver-path /path/to/chromedriver`.

---

## Usage

### Single URL
```bash
python clickjacking_scanner_poc.py --url https://example.com
```

### Multiple URLs
```bash
python clickjacking_scanner_poc.py --file-list urls.txt
```

### Output to a Specific Folder
```bash
python clickjacking_scanner_poc.py --file-list urls.txt --output results/
```

### Verbose Mode
```bash
python clickjacking_scanner_poc.py --url https://example.com --verbose
```

### Multithreading
```bash
python clickjacking_scanner_poc.py --file-list urls.txt --threads 5
```
(`-s` cannot be used with `--threads > 1`)

### Screenshots with Partial Censorship
```bash
python clickjacking_scanner_poc.py --file-list urls.txt --screenshot
```
If vulnerable, the script generates a POC HTML and **captures a screenshot** of it. Tesseract is used to detect and blur the URL bar, highlighting it with a red rectangle but leaving the last two path segments in clear text.

---

## Example Output

```bash
python clickjacking_scanner_poc.py --file-list urls.txt --screenshot
```

- If a site is vulnerable:
  ```
  [VULNERABLE] https://vulnerable-example.com
  Screenshot saved: output/vulnerable-example.com__root/screenshot_vulnerable-example.com__root.png
  Scanning URLs: 100%|███████████████| 3/3 [00:15<00:00,  5.00s/url]
  ```

- If no vulnerable site is found:
  ```
  No vulnerable sites found.
  ```

---

## Template Customization

- The default template is `template.html`. Inside it, place `{victim_url}` where you want the target site to appear.
- You can customize styles or text, as long as `{victim_url}` remains to let the script inject the site.

---

## Notes

- **ChromeDriver** must match your **Chrome**/Chromium version.
- **Tesseract** must be installed for the partial censorship screenshot feature.
- By default, results and POC files go into `output/`.
- If you do not pass `--screenshot`, the script only performs the vulnerability tests and prints the results, without capturing screenshots.
- `-s` is incompatible with `--threads > 1`.

