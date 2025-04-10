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
        if r.url.rstrip("/")!=u.rstrip("/"):
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

def sanitize_for_folder(u:str)->str:
    p = urlparse(u)
    d = p.netloc.replace("www.","")
    pa = p.path.strip("/")
    if not pa:
        pa = "root"
    else:
        pa = pa.replace("/", "_")
    return f"{d}__{pa}"

def generate_and_save_poc(d:str, o:str, outd:str):
    f = sanitize_for_folder(d)
    h = read_template(d)
    pp= Path(outd)/f
    pp.mkdir(parents=True, exist_ok=True)
    pre= "poc_redirect_" if o.rstrip("/")!=d.rstrip("/") else "poc_"
    poc= pp/f"{pre}{f}.html"
    poc.write_text(h,encoding="utf-8")
    return poc

def partial_blur_segment(img: Image.Image, x1, y1, x2, y2, r=6):
    c = img.crop((x1, y1, x2, y2))
    b = c.filter(ImageFilter.GaussianBlur(r))
    img.paste(b, (int(x1), int(y1)))

def partial_blur_token_precise(img: Image.Image, t: str, gx: float, gy: float, w: float, h: float):
    if not t.startswith("/"):
        return
    segs = t.strip("/").split("/")
    if len(segs) < 3:
        return
    ln = len(t)
    cw = w / ln
    cx = gx
    current_segment = ""
    seg_idx = -1
    start_pos = gx
    positions = []
    for ch in t:
        if ch == "/":
            if current_segment:
                positions.append((seg_idx, start_pos, cx))
            seg_idx += 1
            current_segment = ""
            start_pos = cx
        else:
            current_segment += ch
        cx += cw
    if current_segment:
        positions.append((seg_idx, start_pos, cx))
    for idx, sx1, sx2 in positions:
        if idx <= 0 or idx >= (len(segs) - 1):
            continue
        partial_blur_segment(img, sx1, gy, sx2, gy + h, 6)

def obscure_url_in_image(img: Image.Image) -> Image.Image:
    rb = (120, 40, 945, 40)
    rx, ry, rw, rh = rb
    rl = rx
    rt = ry
    rr = rx + rw
    rbm = ry + rh
    ob = (200, 35, 980, 40)
    ox, oy, ow, oh = ob
    ol = ox
    ot = oy
    or_ = ox + ow
    obm = oy + oh
    bar = img.crop((ol, ot, or_, obm))
    cf = (
        "--psm 7 "
        "--oem 3 "
        "-c tessedit_char_whitelist=/.:?=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    )
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
        ImageDraw.Draw(img).rectangle((rl, rt, rr, rbm), outline="red", width=2)
        return img
    alls = sum(t.count("/") for (t, _, _, _, _) in tk)
    if alls == 0:
        bb = bar.filter(ImageFilter.GaussianBlur(10))
        img.paste(bb, (ol, ot))
        ImageDraw.Draw(img).rectangle((rl, rt, rr, rbm), outline="red", width=2)
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
            segs = tt.split("/")
            ln = len(tt)
            if ln < 1:
                continue
            cw = ww / ln
            ss = []
            cx = gx1
            for ch in tt:
                if ch == "/":
                    ss.append(cx)
                cx += cw
            ss.append(gx1 + ww)
            for i in range(0, len(ss) - 2):  # ← FIX: inizia da 0
                x1 = ss[i]
                x2 = ss[i+1]
                if x2 > x1:
                    partial_blur_segment(img, x1, gy1, x2, gy1 + hh, 6)
            sf += sc
    ImageDraw.Draw(img).rectangle((rl, rt, rr, rbm), outline="red", width=2)
    return img




def capture_screenshot(d_url:str,o_url:str,outd:str,drv:str):
    f= sanitize_for_folder(d_url)
    pr= "poc_redirect_" if o_url.rstrip("/")!=d_url.rstrip("/") else "poc_"
    poc= Path(outd)/f/f"{pr}{f}.html"
    oo= Options()
    oo.add_argument("--no-sandbox")
    oo.add_argument("--ignore-certificate-errors")
    oo.add_experimental_option("excludeSwitches",["enable-automation"])
    oo.add_experimental_option("useAutomationExtension",False)
    oo.add_argument("--disable-infobars")
    cc= DesiredCapabilities.CHROME.copy()
    cc["acceptInsecureCerts"]=True
    for k,v in cc.items():
        oo.set_capability(k,v)
    dr= webdriver.Chrome(service=ChromeService(executable_path=drv),options=oo)
    try:
        dr.set_window_position(0, 0)
        dr.maximize_window()
        time.sleep(1)
        dr.get(f"file://{poc.resolve()}")
        WebDriverWait(dr,5).until(EC.presence_of_element_located((By.TAG_NAME,"iframe")))
        time.sleep(0.5)
        full= ImageGrab.grab()
        out= obscure_url_in_image(full)
        w,h= out.size
        left=20
        top=0
        right= w-40
        bottom= h-50
        right= max(left+1,right)
        bottom= max(top+1,bottom)
        final= out.crop((left,top,right,bottom))
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
    oo=Options()
    oo.add_argument("--headless=new")
    oo.add_argument("--ignore-certificate-errors")
    c=DesiredCapabilities.CHROME.copy()
    c["acceptInsecureCerts"]=True
    for k,v in c.items():
        oo.set_capability(k,v)
    dr=webdriver.Chrome(service=ChromeService(executable_path=dp),options=oo)
    tmp=tempfile.NamedTemporaryFile("w",suffix=".html",delete=False)
    try:
        tmp.write(read_template(u))
        tmp.close()
        dr.get(f"file://{tmp.name}")
        f=WebDriverWait(dr,5).until(EC.presence_of_element_located((By.TAG_NAME,"iframe")))
        dr.switch_to.frame(f)
        e=time.time()+5
        while time.time()<e:
            cu=dr.execute_script("return window.location.href")
            if cu.rstrip("/")!= u.rstrip("/"):
                dr.quit()
                return test_clickjacking(cu,dp,vt)
            time.sleep(0.2)
        return True
    finally:
        dr.quit()
        try:os.unlink(tmp.name)
        except:pass

def process_url(u:str,outd:str,dp:str,ver:bool,shot:bool)->bool:
    o=u
    d=resolve_redirect(o)
    if test_clickjacking(d,dp):
        if o.rstrip("/")!=d.rstrip("/"):
            tqdm.write(f"[VULNERABLE] {d} [redirected from] {o}")
        else:
            tqdm.write(f"[VULNERABLE] {d}")
        generate_and_save_poc(d,o,outd)
        if shot:
            capture_screenshot(d,o,outd,dp)
        return True
    return False

def main():
    a=parse_arguments()
    if a.screenshot and a.threads>1:
        print("[ERROR] Screenshot can't be used with multi-threading. Exiting.")
        sys.exit(1)
    dp=a.driver_path or read_config()
    Path(a.output).mkdir(parents=True,exist_ok=True)
    if a.url:
        tg=[a.url]
    else:
        tg=Path(a.file_list).read_text().splitlines()
    fd=False
    with tqdm(total=len(tg),desc="Scanning URLs",unit="url") as pbar:
        for l in tg:
            ll=l.strip()
            if not ll:
                pbar.update(1)
                continue
            if process_url(ll,a.output,dp,a.verbose,a.screenshot):
                fd=True
            pbar.update(1)
    if not fd:
        print("No vulnerable sites found.")

if __name__=="__main__":
    main()
