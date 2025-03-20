#!/usr/bin/env python3
import argparse
import os
import sys
import time
import configparser
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException, NoSuchFrameException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image, ImageDraw, ImageFilter, ImageGrab
import pytesseract
from pytesseract import Output
from tqdm import tqdm

TEMPLATE_PATH = Path("template") / "template.html"

def read_template(v: str) -> str:
    t = TEMPLATE_PATH.read_text(encoding="utf-8")
    return t.replace("{victim_url}", v)

def read_config():
    c = configparser.ConfigParser()
    c.read("config.ini")
    return c.get("settings","webdriver_path",fallback="chromedriver")

def parse_arguments():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u","--url")
    g.add_argument("-f","--file-list")
    p.add_argument("-o","--output",default="output/")
    p.add_argument("-v","--verbose",action="store_true")
    p.add_argument("-d","--driver-path")
    p.add_argument("-s","--screenshot",action="store_true")
    p.add_argument("-t","--threads",type=int,default=1)
    return p.parse_args()

def resolve_redirect(u: str) -> str:
    try:
        r = requests.head(u, allow_redirects=True, timeout=10)
        if r.url.rstrip("/") != u.rstrip("/"):
            return r.url
    except:
        pass
    return u

def is_framable(u: str) -> bool:
    try:
        r = requests.get(u, timeout=10, allow_redirects=False)
        if 300<=r.status_code<400:
            return False
        xfo = r.headers.get("X-Frame-Options","").lower()
        csp = r.headers.get("Content-Security-Policy","").lower()
        if "deny" in xfo or "sameorigin" in xfo or "frame-ancestors" in csp:
            return False
        return True
    except:
        return False

def sanitize_for_folder(u: str) -> str:
    p = urlparse(u)
    d = p.netloc.replace("www.","")
    pa = p.path.strip("/")
    if not pa:
        pa = "root"
    else:
        pa = pa.replace("/", "_")
    folder_name = f"{d}__{pa}"
    max_len = 100
    if len(folder_name) > max_len:
        folder_name = folder_name[:max_len]
    return folder_name

def generate_and_save_poc(d:str, o:str, outd:str):
    f = sanitize_for_folder(d)
    html_content = read_template(d)
    pp= Path(outd)/f
    pp.mkdir(parents=True, exist_ok=True)
    prefix = "poc_redirect_" if o.rstrip("/") != d.rstrip("/") else "poc_"
    poc_file = pp / f"{prefix}{f}.html"
    poc_file.write_text(html_content, encoding="utf-8")
    return poc_file

def partial_blur_segment(img:Image.Image, x1,y1,x2,y2,r=6):
    c = img.crop((x1,y1,x2,y2))
    b = c.filter(ImageFilter.GaussianBlur(r))
    img.paste(b,(int(x1),int(y1)))

def partial_blur_token(img:Image.Image, t:str, gx:float, gy:float, w:float, h:float):
    sc = t.count("/")
    if sc == 0:
        return
    ln = len(t)
    if ln<1:
        return
    cw = w / ln
    cdt = t
    if cdt.startswith("/"):
        cdt = cdt[1:]
    segs = cdt.split("/")
    ts = len(segs)
    x1g = gx
    y1g = gy
    cs = 0
    ss = [0]*ts
    se = [0]*ts
    ss[0] = x1g
    cx = x1g
    for ch in t:
        if cs>=ts:
            break
        if ch=="/":
            se[cs] = cx
            cs += 1
            if cs<ts:
                ss[cs] = cx
        cx += cw
    if cs<ts:
        se[cs] = x1g + w
    for i in range(ts):
        sx1 = ss[i]
        sx2 = se[i]
        if sx2<=sx1:
            continue
        if i>=1 and i<(ts-2):
            partial_blur_segment(img, sx1,y1g,sx2,y1g+h,r=6)

def obscure_url_in_image(img: Image.Image) -> Image.Image:
    rb = (120, 40, 990, 40)
    rx, ry, rw, rh = rb
    rl = rx
    rt = ry
    rr = rx + rw
    rbm = ry + rh
    d = ImageDraw.Draw(img)
    d.rectangle((rl, rt, rr, rbm), outline="red", width=2)

    ob = (200, 35, 980, 40)
    ox, oy, ow, oh = ob
    ol = ox
    ot = oy
    or_ = ox + ow
    obm = oy + oh
    bar = img.crop((ol, ot, or_, obm))
    cf = "--psm 7 --oem 3 -c tessedit_char_whitelist=/.:?=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    dt = pytesseract.image_to_data(bar, output_type=Output.DICT, config=cf)
    tk = []
    for i in range(len(dt["text"])):
        txt = dt["text"][i].strip()
        if not txt:
            continue
        x = dt["left"][i]
        y = dt["top"][i]
        w = dt["width"][i]
        h = dt["height"][i]
        tk.append((txt, x, y, w, h))
    if not tk:
        b = bar.filter(ImageFilter.GaussianBlur(10))
        img.paste(b, (ol, ot))
        return img
    alls = sum(txt_.count("/") for (txt_, *_) in tk)
    if alls == 0:
        bb = bar.filter(ImageFilter.GaussianBlur(10))
        img.paste(bb, (ol, ot))
        return img
    sf = 0
    for (tt, xx, yy, ww, hh) in tk:
        sc = tt.count("/")
        gx1 = ol + xx
        gy1 = ot + yy
        if sc <= 1:
            gx2 = gx1 + ww
            gy2 = gy1 + hh
            if sf < (alls - 2) and sf >= 1:
                region = img.crop((gx1, gy1, gx2, gy2))
                blurred = region.filter(ImageFilter.GaussianBlur(6))
                img.paste(blurred, (int(gx1), int(gy1)))
            sf += sc
        else:
            partial_blur_token(img, tt, gx1, gy1, ww, hh)
            sf += sc
    return img

def capture_screenshot(d_url:str,o_url:str,outd:str,drv:str):
    f = sanitize_for_folder(d_url)
    prefix = "poc_redirect_" if o_url.rstrip("/") != d_url.rstrip("/") else "poc_"
    poc = Path(outd)/f/f"{prefix}{f}.html"
    oo = Options()
    oo.add_argument("--no-sandbox")
    oo.add_argument("--ignore-certificate-errors")
    oo.add_experimental_option("excludeSwitches",["enable-automation"])
    oo.add_experimental_option("useAutomationExtension",False)
    oo.add_argument("--disable-infobars")
    c = DesiredCapabilities.CHROME.copy()
    c["acceptInsecureCerts"] = True
    for k,v in c.items():
        oo.set_capability(k,v)
    dr = webdriver.Chrome(service=ChromeService(executable_path=drv), options=oo)
    try:
        dr.set_window_position(0,0)
        dr.set_window_size(1280,900)
        dr.get(f"file://{poc.resolve()}")
        WebDriverWait(dr,5).until(EC.presence_of_element_located((By.TAG_NAME,"iframe")))
        time.sleep(0.5)
        full = ImageGrab.grab()
        out = obscure_url_in_image(full)
        w,h = out.size
        left = 20
        top = 0
        right = w-40
        bottom = h-50
        right = max(left+1, right)
        bottom = max(top+1, bottom)
        final = out.crop((left, top, right, bottom))
        sc= f"screenshot_{f}.png"
        pa= Path(outd)/f/sc
        final.save(pa)
        tqdm.write(f"Screenshot saved: {pa}")
    finally:
        dr.quit()

def test_clickjacking(u:str,dp:str,vt=None)->bool:
    if vt is None:
        vt=set()
    if u in vt or len(vt)>=3 or not is_framable(u):
        return False
    vt.add(u)
    oo = Options()
    oo.add_argument("--headless=new")
    oo.add_argument("--ignore-certificate-errors")
    c = DesiredCapabilities.CHROME.copy()
    c["acceptInsecureCerts"] = True
    for k,v in c.items():
        oo.set_capability(k,v)
    dr = webdriver.Chrome(service=ChromeService(executable_path=dp), options=oo)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".html", delete=False)
    try:
        tmp.write(read_template(u))  # <--- sostituzione manuale {victim_url}
        tmp.close()
        dr.get(f"file://{tmp.name}")
        f=WebDriverWait(dr,5).until(EC.presence_of_element_located((By.TAG_NAME,"iframe")))
        dr.switch_to.frame(f)
        end = time.time() + 5
        while time.time() < end:
            curr = dr.execute_script("return window.location.href")
            if curr.rstrip("/") != u.rstrip("/"):
                dr.quit()
                return test_clickjacking(curr, dp, vt)
            time.sleep(0.2)
        return True
    finally:
        dr.quit()
        try:
            os.unlink(tmp.name)
        except:
            pass

def process_url(u:str,outd:str,dp:str,ver:bool,shot:bool)->bool:
    orig = u
    dest = resolve_redirect(u)
    if test_clickjacking(dest, dp):
        if orig.rstrip("/") != dest.rstrip("/"):
            tqdm.write(f"[VULNERABLE] {dest} [redirected from] {orig}")
        else:
            tqdm.write(f"[VULNERABLE] {dest}")
        generate_and_save_poc(dest, orig, outd)
        if shot:
            capture_screenshot(dest, orig, outd, dp)
        return True
    return False

def main():
    args = parse_arguments()
    if args.screenshot and args.threads > 1:
        print("[ERROR] Screenshot can't be used with multi-threading. Exiting.")
        sys.exit(1)
    dp = args.driver_path or read_config()
    Path(args.output).mkdir(parents=True, exist_ok=True)
    if args.url:
        targets = [args.url]
    else:
        targets = Path(args.file_list).read_text().splitlines()
    found_any = False
    with tqdm(total=len(targets),desc="Scanning URLs",unit="url") as pbar:
        for link in targets:
            link = link.strip()
            if not link:
                pbar.update(1)
                continue
            if process_url(link,args.output,dp,args.verbose,args.screenshot):
                found_any = True
            pbar.update(1)
    if not found_any:
        print("No vulnerable sites found.")

if __name__=="__main__":
    main()
