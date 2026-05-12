#!/usr/bin/env python3

import os
import sys
import time
import random
import subprocess
import threading
import signal
from datetime import datetime
from collections import defaultdict

# --- CONFIGURATION ---
DL_CLIENTS = 30
UL_CLIENTS = 50
DURATION_MINS = 3000

G1_QUIC = ["https://www.google.com", "https://www.facebook.com", "https://chatgpt.com", "https://www.tiktok.com"]
G2_HTTPS = ["https://www.wikipedia.org", "https://www.reddit.com", "https://www.amazon.com", "https://www.github.com", "https://www.apple.com", "https://www.nytimes.com", "https://www.ebay.com"]
G3_HTTP = ["http://www.msn.com", "http://www.yahoo.com", "http://www.cnn.com", "http://www.bing.com", "http://www.bbc.com"]
G4_FILES = ["http://ipv4.download.thinkbroadband.com/100MB.zip", "http://ipv4.download.thinkbroadband.com/512MB.zip", "https://speed.hetzner.de/100MB.bin", "https://mirror.leaseweb.com/speedtest/100mb.bin"]
G5_UPLOADS = ["https://httpbin.org/post", "http://httpbin.org/post"]

stats = defaultdict(lambda: {'success': 0, 'fail': 0, 'dl_bytes': 0, 'ul_bytes': 0, 'sock_opened': 0, 'sock_closed': 0, 'sock_reset': 0})
stats_lock = threading.Lock()
running = True

def check_h3_support():
    try:
        res = subprocess.run(['curl', '--version'], capture_output=True, text=True)
        return any(x in res.stdout for x in ['HTTP3', 'quic', 'ngtcp2', 'quiche'])
    except:
        return False

CURL_H3_SUPPORT = check_h3_support()

def run_downloader(worker_id):
    global running
    while running:
        g_pick = random.randint(1, 4)
        if g_pick == 1:
            req_type = "QUIC "
            url_list = G1_QUIC
        elif g_pick == 2:
            req_type = "HTTPS"
            url_list = G2_HTTPS
        elif g_pick == 3:
            req_type = "HTTP "
            url_list = G3_HTTP
        else:
            req_type = "FILE "
            url_list = G4_FILES

        url = random.choice(url_list)
        ts = datetime.now().strftime("%H:%M:%S")

        print(f"[{ts}] [DL-Thread #{worker_id}] -> STARTING [{req_type}] | {url}")

        cmd = ['curl', '-L', '-s', '-v', '--limit-rate', '5M', '--max-time', '300', '--user-agent', 'Mozilla/5.0', '-o', '/dev/null', '-w', '%{size_download} %{size_upload} %{http_code}', url]
        if req_type == "QUIC " and CURL_H3_SUPPORT:
            cmd.insert(1, '--http3')

        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            dl_b, ul_b, code = res.stdout.strip().split()
            http_code = int(code)
            dl_bytes, ul_bytes = int(dl_b), int(ul_b)
            success = 1 if 200 <= http_code < 400 and res.returncode == 0 else 0
            
            stderr = res.stderr.lower()
            sock_opened = stderr.count("connected to")
            sock_closed = stderr.count("closing connection") + stderr.count("left intact")
            sock_reset = stderr.count("reset by peer") + stderr.count("empty reply")
            if sock_reset == 0 and res.returncode in (52, 56):
                sock_reset += 1
                if sock_opened == 0: sock_opened += 1
                
        except Exception:
            dl_bytes, ul_bytes, success = 0, 0, 0
            sock_opened, sock_closed, sock_reset = 0, 0, 0

        if running:
            with stats_lock:
                key = f"{worker_id}_DL"
                if success:
                    stats[key]['success'] += 1
                else:
                    stats[key]['fail'] += 1
                stats[key]['dl_bytes'] += dl_bytes
                stats[key]['ul_bytes'] += ul_bytes
                stats[key]['sock_opened'] += sock_opened
                stats[key]['sock_closed'] += sock_closed
                stats[key]['sock_reset'] += sock_reset

        print(f"[{datetime.now().strftime('%H:%M:%S')}] [DL-Thread #{worker_id}] <- FINISHED")
        
        sleep_time = random.randint(1, 4)
        for _ in range(sleep_time * 10):
            if not running: break
            time.sleep(0.1)

def run_uploader(worker_id):
    global running
    while running:
        url = random.choice(G5_UPLOADS)
        size_mb = random.randint(10, 49) # 10 to 49 MB
        ts = datetime.now().strftime("%H:%M:%S")

        print(f"[{ts}] [UL-Thread #{worker_id}] -> UPLOADING {size_mb}MB to {url}")
        
        dd_cmd = ['dd', 'if=/dev/zero', 'bs=1M', f'count={size_mb}']
        curl_cmd = ['curl', '-s', '-v', '-X', 'POST', '--data-binary', '@-', '--limit-rate', '3M', '--max-time', '300', '-o', '/dev/null', '-w', '%{size_download} %{size_upload} %{http_code}', url]

        try:
            p1 = subprocess.Popen(dd_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p2 = subprocess.Popen(curl_cmd, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            p1.stdout.close() 
            out, err = p2.communicate()
            returncode = p2.returncode
            
            try:
                dl_b, ul_b, code = out.strip().split()
                http_code = int(code)
                dl_bytes, ul_bytes = int(dl_b), int(ul_b)
                success = 1 if 200 <= http_code < 400 and returncode == 0 else 0
            except ValueError:
                dl_bytes, ul_bytes, success = 0, 0, 0
                
            stderr = err.lower()
            sock_opened = stderr.count("connected to")
            sock_closed = stderr.count("closing connection") + stderr.count("left intact")
            sock_reset = stderr.count("reset by peer") + stderr.count("empty reply")
            if sock_reset == 0 and returncode in (52, 56):
                sock_reset += 1
                if sock_opened == 0: sock_opened += 1
                
        except Exception:
            dl_bytes, ul_bytes, success = 0, 0, 0
            sock_opened, sock_closed, sock_reset = 0, 0, 0

        if running:
            with stats_lock:
                key = f"{worker_id}_UL"
                if success:
                    stats[key]['success'] += 1
                else:
                    stats[key]['fail'] += 1
                stats[key]['dl_bytes'] += dl_bytes
                stats[key]['ul_bytes'] += ul_bytes
                stats[key]['sock_opened'] += sock_opened
                stats[key]['sock_closed'] += sock_closed
                stats[key]['sock_reset'] += sock_reset
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [UL-Thread #{worker_id}] <- FINISHED UPLOAD")
        
        sleep_time = random.randint(2, 6)
        for _ in range(sleep_time * 10):
            if not running: break
            time.sleep(0.1)

def generate_report():
    print("\n==========================================================================")
    print("                     TRAFFIC SIMULATION REPORT")
    print("==========================================================================")
    
    if not stats:
        print("No data recorded.")
        return

    print(f"{'CLIENT':<8} {'ROLE':<5} {'SUCC':<5} {'FAIL':<5} {'OPEN':<5} {'CLOS':<5} {'RST':<5} {'DATA_TRANSFERRED':<20}")
    print("-" * 74)
    
    tot_succ, tot_fail, tot_dl, tot_ul = 0, 0, 0, 0
    tot_open, tot_clos, tot_rst = 0, 0, 0
    
    # Sort by client ID and then DL first
    for key in sorted(stats.keys(), key=lambda x: (int(x.split('_')[0]), 0 if x.split('_')[1] == 'DL' else 1)):
        client_id, role = key.split('_')
        succ = stats[key]['success']
        fail = stats[key]['fail']
        dl = stats[key]['dl_bytes']
        ul = stats[key]['ul_bytes']
        opened = stats[key]['sock_opened']
        closed = stats[key]['sock_closed']
        rst = stats[key]['sock_reset']
        
        tot_succ += succ
        tot_fail += fail
        tot_dl += dl
        tot_ul += ul
        tot_open += opened
        tot_clos += closed
        tot_rst += rst
        
        data_mb = dl / 1048576 if role == "DL" else ul / 1048576
        
        print(f"{client_id:<8} {role:<5} {succ:<5} {fail:<5} {opened:<5} {closed:<5} {rst:<5} {data_mb:.2f} MB")

    print("-" * 74)
    print(f"{'TOTAL':<14} {tot_succ:<5} {tot_fail:<5} {tot_open:<5} {tot_clos:<5} {tot_rst:<5} DL: {tot_dl / 1048576:.2f} MB / UL: {tot_ul / 1048576:.2f} MB")

def signal_handler(sig, frame):
    global running
    if running:
        running = False
        print("\n[!] Shutting down workers... waiting for clean exit.")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        os.nice(19)
    except:
        pass

    print("=====================================================")
    print(f"   DUAL-ROLE TRAFFIC ENGINE: {DL_CLIENTS} DL | {UL_CLIENTS} UL")
    print("   ALL DATA DISCARDED TO /dev/null")
    print("=====================================================")

    threads = []
    for i in range(1, DL_CLIENTS + 1):
        t = threading.Thread(target=run_downloader, args=(i,), daemon=True)
        t.start()
        threads.append(t)

    for i in range(1, UL_CLIENTS + 1):
        t = threading.Thread(target=run_uploader, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        
    start_time = time.time()
    
    try:
        while running:
            if DURATION_MINS > 0 and (time.time() - start_time) > DURATION_MINS * 60:
                running = False
            else:
                time.sleep(0.5)
    except KeyboardInterrupt:
        running = False
        print("\n[!] Shutting down workers... waiting for clean exit.")
        
    # Flush output buffers by waiting briefly
    for t in threads:
        t.join(timeout=0.5)
    
    time.sleep(0.5)
    generate_report()

