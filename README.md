# Clickjacking Scanner and POC 

This Python script provides **advanced testing for Clickjacking vulnerabilities** on one or more websites. It also detects JavaScript-based frame-busting. The script uses **Chrome in headless mode**, **Selenium**, and a **progress bar** (`tqdm`) to display the testing status in real-time.

---

## Features

- **HTTP Header Analysis**: Checks if the site uses headers like `X-Frame-Options` or `Content-Security-Policy` to block embedding.
- **JavaScript Frame-Busting Detection**: Identifies if JavaScript attempts to break or redirect the iframe after it loads.
- **POC Generation**: Creates an HTML file for each vulnerable site to demonstrate the Clickjacking attack.
- **Multithreading**: Tests multiple sites concurrently to speed up the process.
- **Progress Bar**: Provides real-time feedback with `tqdm`.
- **Detailed Output**: Displays vulnerable and non-vulnerable results. Shows “No vulnerable sites found.” if none are vulnerable.

---

## Installation

### Prerequisites

- Python 3.7+
- Google Chrome/Chromium
- ChromeDriver matching your Chrome/Chromium version

### Install Dependencies

1. **Clone this repository**:
   ```bash
   git clone https://github.com/nemmusu/clickjacking-scanner-poc.git
   cd clickjacking-scanner-poc
   ```

2. **Install required Python libraries**:
   ```bash
   pip install -r requirements.txt
   ```

3. **ChromeDriver path**:
   - You can specify it in **`config.ini`**, under `[settings] webdriver_path`.
   - Or pass it directly to the script via the `--driver-path` option.
   - If neither is set, the script defaults to `chromedriver`.

---

## Usage

### Basic Commands

- **Single URL Test**:
  ```bash
  python clickjacking_scanner.py --url https://example.com
  ```
  If you have `webdriver_path` in `config.ini`, no additional arguments are needed. Otherwise, pass `--driver-path /path/to/chromedriver`.
  
- **Multiple URLs from a File**:
  ```bash
  python clickjacking_scanner.py --file-list urls.txt
  ```

- **Output Results to a Specific Folder**:
  ```bash
  python clickjacking_scanner.py --file-list urls.txt --output results/
  ```

- **Enable Verbose Mode**:
  ```bash
  python clickjacking_scanner.py --url https://example.com --verbose
  ```

- **Multithreaded Testing**:
  ```bash
  python clickjacking_scanner.py --file-list urls.txt --threads 5
  ```

### Config File Example

Edit the config file `config.ini` in the same directory with:
```
[settings]
webdriver_path = /path/to/chromedriver
```
When you run the script, it will read `webdriver_path` from `config.ini` if no `--driver-path` is provided. If both are missing, the script attempts to call `chromedriver` directly.

---

## Example Output

### Command (verbose output):
```bash
python clickjacking_scanner.py --file-list urls.txt --threads 5 --verbose
```
(assuming `webdriver_path` is set in `config.ini`)

### Output:
```
Total sites to test: 3
[NOT VULNERABLE] https://www.google.com
[NOT VULNERABLE] https://example.com
[VULNERABLE] https://vulnerable-site.com
Processing: 100%|████████████████████████████████████████████████| 3/3 [00:15<00:00,  5.00s/site]
```

If no sites are found vulnerable:
```
Total sites to test: 3
[NOT VULNERABLE] https://www.google.com
[NOT VULNERABLE] https://example.com
[NOT VULNERABLE] https://safe-site.com
Processing: 100%|████████████████████████████████████████████████| 3/3 [00:15<00:00,  5.00s/site]
No vulnerable sites found.
```

### Command (minimal output):
```bash
python clickjacking_scanner.py --file-list urls.txt --threads 5 
```
(assuming `webdriver_path` is set in `config.ini`)

### Output:
```
Total sites to test: 3
[VULNERABLE] https://vulnerable-site.com
Processing: 100%|████████████████████████████████████████████████| 3/3 [00:15<00:00,  5.00s/site]
```

If no sites are found vulnerable:
```
Total sites to test: 3
Processing: 100%|████████████████████████████████████████████████| 3/3 [00:15<00:00,  5.00s/site]
No vulnerable sites found.
```

---

## Notes

- Ensure that **ChromeDriver** matches your installed **Google Chrome/Chromium** version.
- You can download the matching ChromeDriver from the [official site](https://chromedriver.storage.googleapis.com/index.html).
- The script saves **Proof-of-Concept HTML files** in the output folder (default `output/`) for any vulnerable site.

---

