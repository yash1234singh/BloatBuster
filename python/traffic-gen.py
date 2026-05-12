#!/usr/bin/env python3
"""
traffic-gen.py — Standalone user-browsing traffic simulator for network stress testing.
Simulates concurrent HTTP/HTTPS/QUIC downloads and uploads to generate realistic traffic.

Usage:
    python3 traffic-gen.py [options]

Options:
    -d, --dl-clients N    Parallel download threads (default: 30)
    -u, --ul-clients N    Parallel upload threads   (default: 50)
    -t, --duration MINS   Run time in minutes, 0=unlimited (default: 3000)
    -l, --log FILE        Save final report to CSV file (optional)
    -p, --progress SECS   Periodic summary interval in seconds (default: 60, 0=off)
"""

import argparse
import csv
import os
import shutil
import signal
import subprocess
import sys
import time
import random
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# --- CONFIGURATION DEFAULTS (edit here, or override with CLI flags) ---
DL_CLIENTS    = 30
UL_CLIENTS    = 50
DURATION_MINS = 3000
PROGRESS_SECS = 60
LOG_FILE      = None
STATS_FILE    = None   # real-time byte-counter file (used by userbufferTest.py)

# --- URL GROUPS ---
G1_QUIC = [
    "https://www.google.com", "https://www.facebook.com",
    "https://chatgpt.com",    "https://www.tiktok.com",
]
G2_HTTPS = [
    "https://www.wikipedia.org", "https://www.reddit.com",
    "https://www.amazon.com",    "https://www.github.com",
    "https://www.apple.com",     "https://www.nytimes.com",
    "https://www.ebay.com",
]
G3_HTTP = [
    "http://www.msn.com",  "http://www.yahoo.com",
    "http://www.cnn.com",  "http://www.bing.com",
    "http://www.bbc.com",
]
G4_FILES = [
    "http://ipv4.download.thinkbroadband.com/100MB.zip",
    "http://ipv4.download.thinkbroadband.com/512MB.zip",
    "https://speed.hetzner.de/100MB.bin",
    "https://mirror.leaseweb.com/speedtest/100mb.bin",
]
G5_UPLOADS = ["https://httpbin.org/post", "http://httpbin.org/post"]

_GROUP_MAP = {
    1: ("QUIC ", G1_QUIC),
    2: ("HTTPS", G2_HTTPS),
    3: ("HTTP ", G3_HTTP),
    4: ("FILE ", G4_FILES),
}

stats      = defaultdict(lambda: {
    'success': 0, 'fail': 0,
    'dl_bytes': 0, 'ul_bytes': 0,
    'sock_opened': 0, 'sock_closed': 0, 'sock_reset': 0,
})
stats_lock = threading.Lock()
running    = True
_report_log_file = None   # set from CLI args; used by signal handler


# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------

def check_dependencies():
    """Verify required external tools are present; exit with a clear error if not."""
    missing = [tool for tool in ('curl', 'dd') if shutil.which(tool) is None]
    if missing:
        print(f"[ERROR] Missing required tool(s): {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def check_h3_support():
    """Return True if the installed curl supports HTTP/3 (QUIC)."""
    try:
        res = subprocess.run(['curl', '--version'], capture_output=True, text=True, check=False)
        return any(x in res.stdout for x in ('HTTP3', 'quic', 'ngtcp2', 'quiche'))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Shared helpers (reduce duplication between DL and UL workers)
# ---------------------------------------------------------------------------

def _parse_curl_output(raw):
    """Parse curl -w '%{size_download} %{size_upload} %{http_code}' output.

    Returns (dl_bytes, ul_bytes, http_code).
    Raises ValueError on unexpected output so callers can handle it uniformly.
    """
    parts = raw.strip().split()
    if len(parts) < 3:
        raise ValueError(f"Unexpected curl output: {raw!r}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def _parse_socket_events(stderr_text):
    """Count TCP socket lifecycle events from curl verbose (-v) stderr."""
    s = stderr_text.lower()
    opened = s.count("connected to")
    closed = s.count("closing connection") + s.count("left intact")
    reset  = s.count("reset by peer")      + s.count("empty reply")
    return opened, closed, reset


def _record_stats(key, success, dl_bytes, ul_bytes,
                  sock_opened, sock_closed, sock_reset, returncode):
    """Thread-safe update of the global stats dict."""
    if sock_reset == 0 and returncode in (52, 56):
        sock_reset  += 1
        sock_opened += (1 if sock_opened == 0 else 0)

    with stats_lock:
        s = stats[key]
        s['success']     += success
        s['fail']        += (1 - success)
        s['dl_bytes']    += dl_bytes
        s['ul_bytes']    += ul_bytes
        s['sock_opened'] += sock_opened
        s['sock_closed'] += sock_closed
        s['sock_reset']  += sock_reset


def _now():
    return datetime.now().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Worker functions
# ---------------------------------------------------------------------------

def run_downloader(worker_id, curl_h3_enabled):
    """Download worker: repeatedly fetches random URLs while running is True."""
    while running:
        req_type, url_list = _GROUP_MAP[random.randint(1, 4)]
        url = random.choice(url_list)
        print(f"[{_now()}] [DL-Thread #{worker_id:>3}] -> STARTING [{req_type}] | {url}")

        cmd = [
            'curl', '-L', '-s', '-v',
            '--limit-rate', '5M', '--max-time', '300',
            '--user-agent', 'Mozilla/5.0',
            '-o', '/dev/null',
            '-w', '%{size_download} %{size_upload} %{http_code}',
            url,
        ]
        if req_type == "QUIC " and curl_h3_enabled:
            cmd.insert(1, '--http3')

        dl_bytes = ul_bytes = success = sock_opened = sock_closed = sock_reset = 0
        returncode = -1
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            returncode = res.returncode
            dl_bytes, ul_bytes, http_code = _parse_curl_output(res.stdout)
            success = 1 if 200 <= http_code < 400 and returncode == 0 else 0
            sock_opened, sock_closed, sock_reset = _parse_socket_events(res.stderr)
        except Exception as exc:
            print(f"[{_now()}] [DL-Thread #{worker_id:>3}] ERROR: {exc}")

        if running:
            _record_stats(f"{worker_id}_DL", success, dl_bytes, ul_bytes,
                          sock_opened, sock_closed, sock_reset, returncode)
        print(f"[{_now()}] [DL-Thread #{worker_id:>3}] <- FINISHED")

        for _ in range(random.randint(1, 4) * 10):
            if not running:
                break
            time.sleep(0.1)


def run_uploader(worker_id):
    """Upload worker: repeatedly POSTs random-sized blobs while running is True."""
    while running:
        url     = random.choice(G5_UPLOADS)
        size_mb = random.randint(10, 49)
        print(f"[{_now()}] [UL-Thread #{worker_id:>3}] -> UPLOADING {size_mb}MB to {url}")

        dd_cmd   = ['dd', 'if=/dev/zero', 'bs=1M', f'count={size_mb}']
        curl_cmd = [
            'curl', '-s', '-v', '-X', 'POST', '--data-binary', '@-',
            '--limit-rate', '3M', '--max-time', '300',
            '-o', '/dev/null',
            '-w', '%{size_download} %{size_upload} %{http_code}',
            url,
        ]

        dl_bytes = ul_bytes = success = sock_opened = sock_closed = sock_reset = 0
        returncode = -1
        try:
            p1 = subprocess.Popen(dd_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p2 = subprocess.Popen(curl_cmd, stdin=p1.stdout,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if p1.stdout:
                p1.stdout.close()
            out, err = p2.communicate()
            returncode = p2.returncode
            dl_bytes, ul_bytes, http_code = _parse_curl_output(out)
            success = 1 if 200 <= http_code < 400 and returncode == 0 else 0
            sock_opened, sock_closed, sock_reset = _parse_socket_events(err)
        except Exception as exc:
            print(f"[{_now()}] [UL-Thread #{worker_id:>3}] ERROR: {exc}")

        if running:
            _record_stats(f"{worker_id}_UL", success, dl_bytes, ul_bytes,
                          sock_opened, sock_closed, sock_reset, returncode)
        print(f"[{_now()}] [UL-Thread #{worker_id:>3}] <- FINISHED UPLOAD")

        for _ in range(random.randint(2, 6) * 10):
            if not running:
                break
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def periodic_summary(interval_secs, run_start_time):
    """Print a running-totals summary every interval_secs seconds until stopped."""
    while running:
        for _ in range(interval_secs * 2):
            if not running:
                return
            time.sleep(0.5)
        if not running:
            return
        elapsed = time.time() - run_start_time
        with stats_lock:
            tot_succ = sum(v['success']  for v in stats.values())
            tot_fail = sum(v['fail']     for v in stats.values())
            tot_dl   = sum(v['dl_bytes'] for v in stats.values()) / 1048576
            tot_ul   = sum(v['ul_bytes'] for v in stats.values()) / 1048576
        print(f"\n[{_now()}] --- PROGRESS ({elapsed / 60:.1f} min elapsed) ---")
        print(f"    Requests : {tot_succ} ok  /  {tot_fail} fail")
        print(f"    Data     : DL {tot_dl:.1f} MB  |  UL {tot_ul:.1f} MB\n")


def stats_writer(stats_file_path, run_start_time):
    """Write cumulative byte counters to a file every second.

    Format per line: <timestamp> <elapsed_sec> <dl_bytes> <ul_bytes>
    The file is atomically overwritten each second so the reader always
    gets a consistent snapshot.  A growing append log (.log suffix) is
    also maintained for post-hoc analysis.
    """
    log_path = stats_file_path + ".log"
    try:
        with open(log_path, 'w', encoding='utf-8') as lf:
            lf.write("timestamp elapsed_sec dl_bytes ul_bytes\n")
    except OSError:
        pass

    while running:
        time.sleep(1)
        if not running:
            return
        elapsed = time.time() - run_start_time
        with stats_lock:
            tot_dl = sum(v['dl_bytes'] for v in stats.values())
            tot_ul = sum(v['ul_bytes'] for v in stats.values())
        ts = _now()
        line = f"{ts} {elapsed:.1f} {tot_dl} {tot_ul}\n"
        # Atomic-ish overwrite of snapshot file
        try:
            tmp = stats_file_path + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(line)
            os.replace(tmp, stats_file_path)
        except OSError:
            pass
        # Append to log
        try:
            with open(log_path, 'a', encoding='utf-8') as lf:
                lf.write(line)
        except OSError:
            pass


def generate_report(log_file=None):
    """Print the final per-client statistics table.
    Optionally save results to a CSV file when log_file is given.
    """
    print("\n==========================================================================")
    print("                     TRAFFIC SIMULATION REPORT")
    print("==========================================================================")

    if not stats:
        print("No data recorded.")
        return

    print(f"{'CLIENT':<8} {'ROLE':<5} {'SUCC':<5} {'FAIL':<5} "
          f"{'OPEN':<5} {'CLOS':<5} {'RST':<5} {'DATA_TRANSFERRED':<20}")
    print("-" * 74)

    rows = []
    tot_succ = tot_fail = tot_dl = tot_ul = 0
    tot_open = tot_clos = tot_rst = 0

    for key in sorted(stats.keys(),
                      key=lambda x: (int(x.split('_')[0]),
                                     0 if x.split('_')[1] == 'DL' else 1)):
        client_id, role = key.split('_')
        s      = stats[key]
        succ   = s['success'];    fail   = s['fail']
        dl     = s['dl_bytes'];   ul     = s['ul_bytes']
        opened = s['sock_opened']; closed = s['sock_closed']; rst = s['sock_reset']

        tot_succ += succ;   tot_fail += fail
        tot_dl   += dl;     tot_ul   += ul
        tot_open += opened; tot_clos += closed; tot_rst += rst

        data_mb = (dl if role == "DL" else ul) / 1048576
        print(f"{client_id:<8} {role:<5} {succ:<5} {fail:<5} "
              f"{opened:<5} {closed:<5} {rst:<5} {data_mb:.2f} MB")
        rows.append([client_id, role, succ, fail, opened, closed, rst, f"{data_mb:.2f}"])

    print("-" * 74)
    print(f"{'TOTAL':<14} {tot_succ:<5} {tot_fail:<5} {tot_open:<5} {tot_clos:<5} {tot_rst:<5} "
          f"DL: {tot_dl / 1048576:.2f} MB / UL: {tot_ul / 1048576:.2f} MB")

    if log_file:
        try:
            with open(log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['client', 'role', 'success', 'fail',
                                 'sock_opened', 'sock_closed', 'sock_reset', 'data_MB'])
                writer.writerows(rows)
                writer.writerow(['TOTAL', '',
                                 tot_succ, tot_fail, tot_open, tot_clos, tot_rst,
                                 f"DL:{tot_dl / 1048576:.2f} UL:{tot_ul / 1048576:.2f}"])
            print(f"\nReport saved to: {log_file}")
        except OSError as exc:
            print(f"[WARN] Could not write log file: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI and entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Simulate concurrent user browsing traffic for network stress testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('-d', '--dl-clients', type=int,   default=DL_CLIENTS,
                   help="Number of parallel download threads")
    p.add_argument('-u', '--ul-clients', type=int,   default=UL_CLIENTS,
                   help="Number of parallel upload threads")
    p.add_argument('-t', '--duration',   type=float, default=DURATION_MINS,
                   help="Run duration in minutes (0 = unlimited)")
    p.add_argument('-l', '--log',        type=str,   default=LOG_FILE,
                   help="Save final report to this CSV file")
    p.add_argument('-p', '--progress',   type=int,   default=PROGRESS_SECS,
                   help="Periodic progress summary interval in seconds (0 = off)")
    p.add_argument('-S', '--stats-file',  type=str,   default=STATS_FILE,
                   help="Write cumulative byte counters to this file every second (for external readers)")
    return p.parse_args()


def signal_handler(_sig, _frame):
    global running  # noqa: PLW0603 — assignment required here
    if running:
        running = False
        print("\n[!] Shutting down workers... waiting for clean exit.")
        # Write report immediately so data is saved even if the process is
        # killed (e.g. by userbufferTest.py) before ThreadPoolExecutor exits.
        generate_report(log_file=_report_log_file)


if __name__ == "__main__":
    args = parse_args()
    _report_log_file = args.log

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    check_dependencies()

    _nice = getattr(os, 'nice', None)  # Unix-only; no-op on Windows
    if _nice:
        try:
            _nice(19)
        except OSError:
            pass

    h3_available = check_h3_support()

    print("=====================================================")
    print(f"   DUAL-ROLE TRAFFIC ENGINE: {args.dl_clients} DL | {args.ul_clients} UL")
    print(f"   Duration : {'unlimited' if args.duration == 0 else f'{args.duration:.0f} min'}")
    print(f"   HTTP/3   : {'available' if h3_available else 'not available (falling back to HTTPS)'}") 
    print("   ALL DATA DISCARDED TO /dev/null")
    print("=====================================================")

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.dl_clients + args.ul_clients + 2) as executor:
        # Stagger launches to avoid a thundering-herd at startup
        for i in range(1, args.dl_clients + 1):
            executor.submit(run_downloader, i, h3_available)
            time.sleep(0.05)
        for i in range(1, args.ul_clients + 1):
            executor.submit(run_uploader, i)
            time.sleep(0.05)
        if args.progress > 0:
            executor.submit(periodic_summary, args.progress, start_time)  # start_time defined above
        if args.stats_file:
            executor.submit(stats_writer, args.stats_file, start_time)

        try:
            while running:
                if args.duration > 0 and (time.time() - start_time) > args.duration * 60:
                    running = False
                    print(f"\n[!] Duration limit reached ({args.duration:.0f} min). Stopping.")
                else:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            running = False
            print("\n[!] Shutting down workers... waiting for clean exit.")
        # ThreadPoolExecutor.__exit__ waits for all submitted futures to complete

    generate_report(log_file=args.log)

