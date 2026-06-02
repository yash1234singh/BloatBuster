#!/usr/bin/env python3
"""
userbufferTest.py — Bufferbloat measurement using real user-browsing traffic as stress.

Two-phase test (same methodology as bufferTest.sh):
  Phase 1: BASELINE — traceroute per-hop latency under idle conditions
  Phase 2: STRESS   — traceroute per-hop latency while traffic-gen.py generates load

Optionally measures per-direction One-Way Delay (OWD) in parallel using the TCP
Timestamp IPDV technique (tcp_owd.py).  Use --owd to enable; requires root + scapy.

Analysis Output:
  1. Per-Segment Bloat Table    — incremental delay per hop pair
  2. Ranked Bloat Summary       — worst links sorted by severity
  3. ASCII Network Diagram      — visual path with per-link bloat
  4. Overall Latency Summary    — RTT avg/P95/max/loss%; plus FwdOWD†/BwdOWD†
                                   rows in same format when --owd is used;
                                   FwdOWD‡/BwdOWD‡ rows when --twamp is used
  5. One-Way Delay Analysis     — [--owd] BASELINE vs STRESS IPDV comparison table
  5b. TWAMP OWD Analysis        — [--twamp] BASELINE vs STRESS TWAMP-Light table
  6. Throughput Summary         — DL/UL mean, max, median, P10, P90
  7. Time-Series Table          — 1-second RTT + throughput data
  8. ASCII Chart                — dual-axis: ▓DL ░UL throughput + ○● RTT;
                                   ▲FwdOWD†(upload) ▽BwdOWD†(download) overlay when --owd;
                                   ◆FwdOWD‡(upload) ◇BwdOWD‡(download) overlay when --twamp
  9. Traffic Summary            — per-client success/fail/socket stats

Usage:
    python3 userbufferTest.py -T <target> [options]

Key Options:
    -T, --target       Target host/IP (required)
    -b, --baseline     Baseline phase duration in seconds  (default: 30)
    -s, --stress       Stress phase duration in seconds    (default: 120)
    -d, --dl-clients   Download threads for traffic-gen    (default: 30)
    -u, --ul-clients   Upload threads for traffic-gen      (default: 50)
    -o, --output       Save results to CSV file
    --owd              Enable TCP Timestamp OWD measurement (requires root + scapy)
    --owd-port         TCP port for OWD probe connection   (default: 80)
    --owd-interval     Seconds between OWD keep-alive probes (default: 0.2)
    --owd-timeout      Drain-window: wait after last probe before declaring drops (default: 2.0)
    -m, --rate-method  Throughput method: auto|procnetdev|statsfile|ss
    -I, --interface    Network interface for procnetdev
    -W, --chart-width  ASCII chart width  (default: 80)
    -H, --chart-height ASCII chart height (default: 20)

Examples:
    python3 userbufferTest.py -T 8.8.8.8
    python3 userbufferTest.py -T 10.1.2.1 -b 20 -s 60 -d 15 -u 25
    python3 userbufferTest.py -T 1.1.1.1 -o results.csv
    sudo python3 userbufferTest.py -T 1.1.1.1 --owd
    sudo python3 userbufferTest.py -T 1.1.1.1 --owd --owd-port 443 --owd-interval 0.2 -b 30 -s 120
    python3 userbufferTest.py -T 8.8.8.8 --twamp
    python3 userbufferTest.py -T 8.8.8.8 --twamp --twamp-server 34.209.241.130 --twamp-port 4200
    sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp -b 30 -s 120
"""

import argparse
import csv
import math
import os
import re
import signal
import statistics
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Configuration defaults (override via CLI)
# ---------------------------------------------------------------------------
DEFAULT_BASELINE_SEC  = 30
DEFAULT_STRESS_SEC    = 120
DEFAULT_POLL_INTERVAL = 1
DEFAULT_TIMEOUT       = 2
DEFAULT_DL_CLIENTS    = 30
DEFAULT_UL_CLIENTS    = 50
DEFAULT_CHART_WIDTH   = 80
DEFAULT_CHART_HEIGHT  = 20
# Rate measurement method — three options:
#   'statsfile'  — reads traffic-gen.py's own byte counters (app-level).
#                  Only counts curl bytes, unaffected by other LAN traffic.
#                  Rate = (cumulative_bytes_now - cumulative_bytes_prev) * 8
#                         / elapsed_seconds_between_stats_file_writes / 1_000_000
#                  Units: Mbps.  Can appear bursty as curl threads finish in bursts.
#   'procnetdev' — reads /proc/net/dev RX/TX counters for the WAN interface
#                  (interface auto-detected via 'ip route get <target>').
#                  Rate = (NIC_counter_now - NIC_counter_prev) * 8
#                         / wall_clock_dt / 1_000_000
#                  Units: Mbps.  Wire-level, smooth, but counts ALL traffic on
#                  that interface (not just the test), so may be inflated on a
#                  router or shared LAN machine.
#   'ss'         — hybrid: DL from NIC RX (/proc/net/dev, monotonic — avoids the
#                  non-monotonic ss bytes_received problem when DL connections close),
#                  UL from ss bytes_acked (excludes retransmissions).  Requires an
#                  interface to be detected for accurate DL; falls back to bytes_received
#                  otherwise.  Still affected by TCP slow-start on hotspot topologies.
#   'auto'       — selects 'statsfile' unconditionally (safe default); use
#                  '-m procnetdev -I <iface>' or '-m ss' explicitly for wire-level readings.
DEFAULT_RATE_METHOD   = 'auto'
MAX_RTT_ALLOWED       = 5     # seconds — hard wall-clock limit for one traceroute subprocess

# OWD probe defaults
DEFAULT_OWD_PORT         = 80
DEFAULT_OWD_INTERVAL     = 0.2    # seconds between keep-alive probes
DEFAULT_OWD_TIMEOUT      = 2.0    # per-probe reply timeout; matches standalone tcp_owd.py default.
                                  # Must be >1.5s to capture queue-full probes (600–1900ms RTT)
                                  # that create meaningful IPDV swings under drop-tail congestion.
                                  # At 1.0s those probes time out and only drain-gap survivors remain,
                                  # producing artificially small (~21ms) jitter regardless of congestion.

# TWAMP-Light probe defaults
DEFAULT_TWAMP_SERVER     = '34.209.241.130'
DEFAULT_TWAMP_PORT       = 4200
DEFAULT_TWAMP_INTERVAL   = 0.2    # seconds between UDP test packets
DEFAULT_TWAMP_TIMEOUT    = 2.0    # per-probe receive timeout (seconds)
DEFAULT_TWAMP_PADDING    = 27     # padding bytes; sender pkt = 14+27 = 41 bytes total (Nokia default)
DEFAULT_TWAMP_BACKEND    = 'native'  # 'native' or 'nokia'

# Analysis thresholds
BLOAT_THRESHOLD_MS       = 1.0    # minimum per-hop bloat considered significant (ms)
OWD_DIAGNOSIS_THRESHOLD  = 2.0    # ms avg OWD increase needed to flag a direction as degraded
OWD_SYMMETRIC_THRESHOLD  = 5.0    # ms; if |fwd_delta - bwd_delta| < this → symmetric congestion

# Reporting percentiles
PERCENTILE_P95           = 95
PERCENTILE_P10           = 10
PERCENTILE_P90           = 90

# Chart / display
CHART_AXIS_PADDING       = 1.1    # scale multiplier so top of chart has headroom
SEPARATOR_WIDTH          = 72     # width of == and -- separator lines

# Conversion factors
BYTES_PER_MB             = 1_048_576
BITS_PER_MBPS            = 1_000_000

# Subprocess management
TRAFFIC_GEN_TERM_TIMEOUT = 15     # seconds to wait for SIGTERM before SIGKILL
TRAFFIC_GEN_KILL_TIMEOUT = 5      # seconds to wait after SIGKILL
TRAFFIC_GEN_RAMP_SECS    = 5      # sleep after starting traffic-gen before stress phase
MIN_DT_VALID             = 0.1    # minimum elapsed-time delta for rate calculation (s)


# ---------------------------------------------------------------------------
# Traceroute parsing
# ---------------------------------------------------------------------------

def run_traceroute(target, timeout=2, max_rtt=MAX_RTT_ALLOWED):
    """Run a single traceroute and return list of (hop_num, ip, rtt_ms) tuples.

    Returns None entries for hops that timed out (* * *).
    max_rtt: hard wall-clock limit for the entire subprocess (kills it if exceeded).
    """
    cmd = ['traceroute', '-I', '-n', '-w', str(timeout), '-q', '1', target]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             check=False, timeout=max_rtt)
        hops = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith('traceroute'):
                continue
            m = re.match(r'^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+([\d.]+)\s+ms', line)
            if m:
                hops.append((int(m.group(1)), m.group(2), float(m.group(3))))
            else:
                m2 = re.match(r'^\s*(\d+)\s+\*', line)
                if m2:
                    hops.append((int(m2.group(1)), None, None))
        return hops
    except (subprocess.TimeoutExpired, OSError):
        return []


# ---------------------------------------------------------------------------
# Data collection — time-series aware
# ---------------------------------------------------------------------------

def read_throughput_snapshot(stats_file):
    """Read the current cumulative byte counters from traffic-gen's stats file.

    Returns (elapsed_sec, dl_bytes, ul_bytes) or None if not available.
    """
    if not stats_file or not os.path.exists(stats_file):
        return None
    try:
        with open(stats_file, 'r', encoding='utf-8') as f:
            line = f.read().strip()
        if not line:
            return None
        parts = line.split()
        if len(parts) >= 4:
            return float(parts[1]), int(parts[2]), int(parts[3])
    except (OSError, ValueError):
        pass
    return None


def read_ss_bytes():
    """Sum bytes_received (DL) and bytes_acked (UL) across all TCP connections via ss -i.

    Returns (rx_bytes, tx_bytes) or None if ss is unavailable.
    bytes_received = payload bytes received by local TCP stack (DL proxy, no header overhead)
    bytes_acked    = payload bytes sent and ACKed by peer (UL proxy, excludes retransmits)
    """
    try:
        result = subprocess.run(
            ['ss', '-i', '-t', '-n'],
            capture_output=True, text=True, timeout=2
        )
        rx_total = tx_total = 0
        for line in result.stdout.splitlines():
            m = re.search(r'bytes_received:(\d+)', line)
            if m:
                rx_total += int(m.group(1))
            m = re.search(r'bytes_acked:(\d+)', line)
            if m:
                tx_total += int(m.group(1))
        if rx_total > 0 or tx_total > 0:
            return rx_total, tx_total
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def read_ss_hybrid(interface):
    """DL from NIC RX (monotonic, accurate), UL from ss bytes_acked (no retransmit overhead).

    ss bytes_received is non-monotonic — it drops when DL connections close, causing
    the cumulative sum to decrease between samples (DL shows 0 Mbps).  Using NIC RX
    from /proc/net/dev instead gives a strictly monotonic DL counter.

    Falls back to ss bytes_received for DL only if interface is unavailable.
    Returns (rx_bytes, tx_bytes) or None.
    """
    try:
        result = subprocess.run(
            ['ss', '-i', '-t', '-n'],
            capture_output=True, text=True, timeout=2
        )
        rx_ss = tx_total = 0
        for line in result.stdout.splitlines():
            m = re.search(r'bytes_received:(\d+)', line)
            if m:
                rx_ss += int(m.group(1))
            m = re.search(r'bytes_acked:(\d+)', line)
            if m:
                tx_total += int(m.group(1))
        # Prefer NIC RX (strictly monotonic) for DL; fall back to ss bytes_received
        if interface:
            nd = read_procnetdev(interface)
            rx_bytes = nd[0] if nd else rx_ss
        else:
            rx_bytes = rx_ss
        if rx_bytes > 0 or tx_total > 0:
            return rx_bytes, tx_total
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def read_procnetdev(interface):
    """Read RX/TX byte counters from /proc/net/dev for the given interface.

    Returns (rx_bytes, tx_bytes) or None if unavailable.
    """
    try:
        with open('/proc/net/dev', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith(interface + ':'):
                    parts = line.split()
                    # Format: iface: rx_bytes rx_packets ... tx_bytes tx_packets ...
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    return rx_bytes, tx_bytes
    except (OSError, ValueError, IndexError):
        pass
    return None


def detect_default_interface():
    """Detect the default network interface from /proc/net/route.

    Returns the interface name or None.
    """
    try:
        with open('/proc/net/route', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split()
                # Default route has destination 00000000
                if len(parts) >= 2 and parts[1] == '00000000':
                    return parts[0]
    except (OSError, IndexError):
        pass
    return None


def detect_interface_for_target(target):
    """Return the outgoing network interface used to reach *target*.

    Uses ``ip route get <target>`` which correctly resolves policy routing
    and returns the WAN/cellular interface rather than always returning the
    default-route interface.  Falls back to detect_default_interface() if
    the command is unavailable.
    """
    try:
        res = subprocess.run(
            ['ip', 'route', 'get', target],
            capture_output=True, text=True, check=False, timeout=3
        )
        m = re.search(r'\bdev\s+(\S+)', res.stdout)
        if m:
            return m.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return detect_default_interface()


def collect_latency_samples(target, duration_sec, interval_sec, timeout,
                            phase_name="PHASE", stats_file=None,
                            rate_method='statsfile', interface=None,
                            min_probe_depth=0, max_rtt=MAX_RTT_ALLOWED):
    """Collect traceroute samples for the given duration.

    Args:
        rate_method: 'procnetdev' to read /proc/net/dev (wire-level, smooth),
                     'statsfile'  to read traffic-gen's stats file (app-level, bursty).
        interface:   Network interface name for procnetdev method.

    Returns:
        hop_data:     dict[hop_num] -> list of (ip, rtt_ms)
        total_probes: int
        lost_probes:  int
        time_series:  list of {ts, elapsed, e2e_rtt, dl_bytes, ul_bytes,
                               dl_rate_mbps, ul_rate_mbps}
    """
    hop_data = defaultdict(list)
    total_probes = 0
    lost_probes = 0
    time_series = []
    start_time = time.time()
    end_time = start_time + duration_sec
    sample_count = 0
    prev_dl = prev_ul = 0
    start_dl = start_ul = 0
    prev_time = start_time
    prev_sample_elapsed = None
    rate_mode = rate_method if rate_method != 'auto' else 'statsfile'

    # Take initial snapshot for delta calculation
    if rate_mode == 'procnetdev' and interface:
        snap0 = read_procnetdev(interface)
        if snap0:
            prev_dl, prev_ul = snap0  # rx_bytes = DL, tx_bytes = UL
            start_dl, start_ul = snap0
    elif rate_mode == 'ss':
        snap0 = read_ss_hybrid(interface)
        if snap0:
            prev_dl, prev_ul = snap0
            start_dl, start_ul = snap0
    elif stats_file:
        snap0 = read_throughput_snapshot(stats_file)
        if snap0:
            prev_sample_elapsed, prev_dl, prev_ul = snap0
            start_dl, start_ul = prev_dl, prev_ul

    print(f"\n{'='*72}")
    if rate_mode == 'procnetdev' and interface:
        method_label = f"/proc/net/dev ({interface})"
    elif rate_mode == 'ss':
        method_label = f"ss-hybrid (NIC-RX/{interface or 'fallback'} + bytes-acked)"
    else:
        method_label = "stats-file"
    print(f"  {phase_name}: Collecting traceroute samples for {duration_sec}s "
          f"(interval={interval_sec}s, rate={method_label})")
    print(f"{'='*72}")

    while time.time() < end_time:
        now = time.time()
        sample_count += 1
        ts = datetime.now().strftime("%H:%M:%S")
        hops = run_traceroute(target, timeout, max_rtt)
        total_probes += 1

        e2e_rtt = None
        if not hops:
            lost_probes += 1
            rtt_str = "TIMEOUT"
        else:
            # Find last responding hop for end-to-end RTT
            last_hop_num = 0
            for hop_num, _, h_rtt in reversed(hops):
                if h_rtt is not None:
                    if e2e_rtt is None:
                        e2e_rtt = h_rtt
                        last_hop_num = hop_num
            # Shallow probe: probe didn't reach expected network depth under congestion
            # (e.g. only hop 1 at 0.1ms responded — not a valid e2e measurement)
            if min_probe_depth > 0 and last_hop_num < min_probe_depth:
                e2e_rtt = None
                lost_probes += 1
                rtt_str = f"SHALLOW ({last_hop_num}/{min_probe_depth} hops)"
            else:
                rtt_str = f"{e2e_rtt:.1f}ms" if e2e_rtt else "*"
            for hop_num, ip, rtt in hops:
                hop_data[hop_num].append((ip, rtt))

        # Read throughput snapshot
        dl_bytes = ul_bytes = 0
        dl_rate = ul_rate = 0.0
        snap = None

        if rate_mode == 'procnetdev' and interface:
            snap = read_procnetdev(interface)
            if snap:
                t_snap = time.time()
                raw_dl_bytes, raw_ul_bytes = snap  # rx = DL, tx = UL
                dt = t_snap - prev_time
                if dt > MIN_DT_VALID:
                    dl_rate = (raw_dl_bytes - prev_dl) * 8 / dt / BITS_PER_MBPS
                    ul_rate = (raw_ul_bytes - prev_ul) * 8 / dt / BITS_PER_MBPS
                    prev_dl, prev_ul = raw_dl_bytes, raw_ul_bytes
                    prev_time = t_snap
                dl_bytes = max(0, raw_dl_bytes - start_dl)
                ul_bytes = max(0, raw_ul_bytes - start_ul)
        elif rate_mode == 'ss':
            snap = read_ss_hybrid(interface)
            if snap:
                t_snap = time.time()
                raw_dl_bytes, raw_ul_bytes = snap
                dt = t_snap - prev_time
                if dt > MIN_DT_VALID:
                    dl_rate = (raw_dl_bytes - prev_dl) * 8 / dt / BITS_PER_MBPS
                    ul_rate = (raw_ul_bytes - prev_ul) * 8 / dt / BITS_PER_MBPS
                    prev_dl, prev_ul = raw_dl_bytes, raw_ul_bytes
                    prev_time = t_snap
                dl_bytes = max(0, raw_dl_bytes - start_dl)
                ul_bytes = max(0, raw_ul_bytes - start_ul)
        elif stats_file:
            snap = read_throughput_snapshot(stats_file)
            if snap:
                sample_elapsed, raw_dl_bytes, raw_ul_bytes = snap
                if prev_sample_elapsed is None:
                    prev_sample_elapsed = sample_elapsed
                    prev_dl, prev_ul = raw_dl_bytes, raw_ul_bytes
                    start_dl, start_ul = raw_dl_bytes, raw_ul_bytes
                dt = sample_elapsed - prev_sample_elapsed
                if dt >= DEFAULT_OWD_INTERVAL:
                    # Simple per-interval delta rate.  traffic-gen.py now
                    # reports bytes progressively (counted as they flow
                    # through the pipe), so the counter increments smoothly
                    # every second instead of jumping on curl completion.
                    dl_rate = (raw_dl_bytes - prev_dl) * 8 / dt / BITS_PER_MBPS
                    ul_rate = (raw_ul_bytes - prev_ul) * 8 / dt / BITS_PER_MBPS
                    prev_dl, prev_ul = raw_dl_bytes, raw_ul_bytes
                    prev_sample_elapsed = sample_elapsed
                else:
                    # Stale snapshot — file hasn't been updated yet
                    snap = None
                dl_bytes = max(0, raw_dl_bytes - start_dl)
                ul_bytes = max(0, raw_ul_bytes - start_ul)

        elapsed = time.time() - start_time
        time_series.append({
            'ts': ts,
            'elapsed': elapsed,
            'e2e_rtt': e2e_rtt,
            'dl_bytes': dl_bytes,
            'ul_bytes': ul_bytes,
            'dl_rate_mbps': max(0, dl_rate),
            'ul_rate_mbps': max(0, ul_rate),
        })

        if snap:
            print(f"  [{ts}] #{sample_count:>4} RTT: {rtt_str:>10}  "
                  f"DL: {dl_rate:5.1f} Mbps  UL: {ul_rate:5.1f} Mbps")
        else:
            print(f"  [{ts}] #{sample_count:>4} RTT: {rtt_str:>10}")

        # Sleep remainder of interval
        next_sample = now + interval_sec
        sleep_left = next_sample - time.time()
        if sleep_left > 0 and time.time() < end_time:
            time.sleep(min(sleep_left, end_time - time.time()))

    print(f"  Collected {sample_count} samples ({lost_probes} lost)")
    return hop_data, total_probes, lost_probes, time_series


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def percentile(values, pct):
    """Return the pct-th percentile of a sorted list of values."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = (pct / 100.0) * (len(sorted_v) - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_v[lo]
    frac = idx - lo
    return sorted_v[lo] * (1 - frac) + sorted_v[hi] * frac


def compute_hop_stats(hop_data):
    """Compute per-hop statistics from collected data."""
    result = {}
    for hop_num in sorted(hop_data.keys()):
        measurements = hop_data[hop_num]
        ips = [ip for ip, _ in measurements if ip is not None]
        rtts = [rtt for _, rtt in measurements if rtt is not None]
        losses = sum(1 for _, rtt in measurements if rtt is None)

        ip_counts = defaultdict(int)
        for ip in ips:
            ip_counts[ip] += 1
        primary_ip = max(ip_counts, key=ip_counts.get) if ip_counts else "*"

        if rtts:
            result[hop_num] = {
                'ip': primary_ip,
                'avg': sum(rtts) / len(rtts),
                'p95': percentile(rtts, PERCENTILE_P95),
                'max': max(rtts),
                'min': min(rtts),
                'samples': len(measurements),
                'losses': losses,
                'rtts': rtts,
            }
        else:
            result[hop_num] = {
                'ip': primary_ip,
                'avg': 0, 'p95': 0, 'max': 0, 'min': 0,
                'samples': len(measurements),
                'losses': losses,
                'rtts': [],
            }
    return result


# ---------------------------------------------------------------------------
# Reporting (matches bufferTest.sh output style)
# ---------------------------------------------------------------------------

def print_segment_bloat_table(baseline_stats, stress_stats):
    """Per-segment incremental delay analysis.

    Each row shows the latency added by that single link segment (incremental),
    not the cumulative RTT to that hop.  Segment bloat values sum to the
    end-to-end bloat; no intermediate hop can exceed the final hop.

    A hop that responded in baseline but not during stress is ICMP-silent:
    core/MPLS routers commonly deprioritise or drop ICMP TTL-exceeded
    messages under load.  These hops are shown with 'N/A' bloat so they
    do not produce spurious negative values; their bloat is already
    captured by the first hop that DID respond under stress.
    """
    print(f"\n{'='*72}")
    print(f"{'PER-SEGMENT BLOAT ANALYSIS (Incremental Delay)':^72}")
    print(f"{'='*72}")
    print(f"{'Hop':<5}{'Segment':<38}{'Link Base':<12}{'Link P95':<12}{'Bloat':<10}")
    print("-" * 77)

    all_hops = sorted(set(baseline_stats.keys()) | set(stress_stats.keys()))
    segments = []

    prev_ip = "(source)"
    prev_base_cum   = 0.0
    prev_stress_cum = 0.0

    for hop in all_hops:
        b = baseline_stats.get(hop, {})
        s = stress_stats.get(hop, {})
        curr_ip = s.get('ip', b.get('ip', '*'))

        cum_base       = b.get('avg', 0.0)
        cum_stress_p95 = s.get('p95', 0.0)

        # Skip hops where BOTH phases have no data (pure wildcard hops)
        if curr_ip == '*' and cum_base == 0.0 and cum_stress_p95 == 0.0:
            continue

        # Hop has a real IP in baseline but no/few RTTs during stress
        # → ICMP TTL-exceeded dropped under load; bloat is N/A for this segment.
        # Also treat hops with very few stress RTTs (<3) as unreliable.
        stress_rtts = s.get('rtts', [])
        is_icmp_silent = (curr_ip != '*') and (len(stress_rtts) < 3)

        # Skip same-IP consecutive hops (MPLS / non-decrementing TTL)
        # These always have 0ms segment delay and duplicate nodes in the diagram.
        if curr_ip == prev_ip and prev_ip != '(source)':
            continue

        segment_label = f"{prev_ip} -> {curr_ip}"

        link_base = max(0.0, cum_base - prev_base_cum)

        if is_icmp_silent:
            print(f"{hop:<5}{segment_label:<38}{link_base:<12.2f}{'N/A':<12}"
                  f"N/A  (ICMP silent under load)")
            segments.append((hop, curr_ip, link_base, None, None, True))
        else:
            link_stress_p95 = max(0.0, cum_stress_p95 - prev_stress_cum)
            segment_bloat   = max(0.0, link_stress_p95 - link_base)
            marker = "  <<<" if segment_bloat > 50 else ""
            print(f"{hop:<5}{segment_label:<38}{link_base:<12.2f}"
                  f"{link_stress_p95:<12.2f}{segment_bloat:<10.2f}{marker}")
            segments.append((hop, curr_ip, link_base, link_stress_p95, segment_bloat, False))
            if cum_stress_p95 > 0.0:
                prev_stress_cum = cum_stress_p95

        if cum_base > 0.0:
            prev_base_cum = cum_base
        prev_ip = curr_ip

    return segments


def print_ranked_bloat(segments):
    """Ranked bloat summary — worst links first (ICMP-silent hops excluded)."""
    print(f"\n{'='*72}")
    print(f"{'LINK SEGMENTS RANKED BY BLOAT (Worst First)':^72}")
    print(f"{'='*72}")
    print(f"{'IP Address':<20}{'Bloat (ms)':<15}")
    print("-" * 72)

    # Only include hops with at least 1ms of bloat (sub-ms values are floating-point noise)
    ranked = sorted(
        [seg for seg in segments if not seg[5] and seg[4] is not None and seg[4] >= 1.0],
        key=lambda x: x[4], reverse=True,
    )
    for _, ip, _, _, bloat, _ in ranked:
        print(f"{ip:<20}{bloat:<15.2f}ms")


def print_network_diagram(segments):
    """ASCII network path diagram."""
    print(f"\n{'='*72}")
    print(f"{'NETWORK PATH DIAGRAM (Baseline / Stress)':^72}")
    print(f"{'='*72}")

    print(f"\n+{'─'*15}+")
    print(f"|  {'(source)':<12}|")
    print(f"+{'─'*15}+")

    for _, ip, base_avg, stress_p95, bloat, is_silent in segments:
        print(f"    |  Base:  {base_avg:.2f} ms")
        if is_silent:
            print("    |  P95:  N/A (ICMP silent under load)")
            print("    |  Bloat: N/A")
        else:
            marker = "  <<<" if bloat > 50 else ""
            print(f"    |  P95:  {stress_p95:.2f} ms")
            print(f"    |  Bloat: {bloat:.2f} ms{marker}")
        print("    v")
        print(f"+{'─'*15}+")
        print(f"| {ip:<14}|")
        print(f"+{'─'*15}+")


def _owd_diagnosis(b, s):
    """Human-readable congestion direction verdict from BASELINE/STRESS stats dicts."""
    fwd_d_avg = s['fwd_avg'] - b['fwd_avg']
    bwd_d_avg = s['bwd_avg'] - b['bwd_avg']
    fwd_d_p95 = s['fwd_p95'] - b['fwd_p95']
    bwd_d_p95 = s['bwd_p95'] - b['bwd_p95']

    fwd_worse = fwd_d_avg > OWD_DIAGNOSIS_THRESHOLD
    bwd_worse = bwd_d_avg > OWD_DIAGNOSIS_THRESHOLD

    # fwd = upload (client→server); bwd = download (server→client)
    if fwd_worse and bwd_worse:
        if abs(fwd_d_avg - bwd_d_avg) < OWD_SYMMETRIC_THRESHOLD:
            direction = "Both directions degraded symmetrically (mid-path / end-to-end congestion)"
        elif fwd_d_avg > bwd_d_avg:
            direction = "OUTBOUND (upload) path is the primary bottleneck"
        else:
            direction = "INBOUND (download) path is the primary bottleneck"
    elif fwd_worse:
        direction = "OUTBOUND (upload) path degraded \u2014 inbound (download) was stable"
    elif bwd_worse:
        direction = "INBOUND (download) path degraded \u2014 outbound (upload) was stable"
    else:
        direction = "No significant OWD increase detected under stress"

    return (
        f"  Diagnosis  : {direction}\n"
        f"               FwdOWD\u2020 (upload)   \u0394avg={fwd_d_avg:>+7.1f}ms  \u0394p95={fwd_d_p95:>+7.1f}ms\n"
        f"               BwdOWD\u2020 (download) \u0394avg={bwd_d_avg:>+7.1f}ms  \u0394p95={bwd_d_p95:>+7.1f}ms"
    )


def print_overall_summary(baseline_ts, stress_ts,
                          baseline_probes, baseline_lost,
                          stress_probes, stress_lost,
                          owd_results=None, target='',
                          owd_attempt_stats=None,
                          h2_results=None,
                          twamp_results=None,
                          twamp_attempt_stats=None):
    """End-to-end latency summary.

    RTT values are taken from the time-series e2e_rtt field (the RTT to the
    last responding hop in each traceroute probe) rather than from hop_data,
    which can have very few entries for the last-numbered hop under stress
    because high-numbered hops are often ICMP-silent.

    If owd_results is provided, FwdOWD† and BwdOWD† rows are appended in the
    same Phase/Samples/Avg/P95/Max column format.
    """
    print(f"\n{'='*72}")
    print(f"{'OVERALL LATENCY SUMMARY (End-to-End)':^72}")
    print(f"{'='*72}")
    print(f"{'Phase':<12}{'Samples':<9}{'Loss %':<9}{'Avg (ms)':<11}"
          f"{'P95 (ms)':<11}{'Max (ms)':<11}")
    print("-" * 72)

    base_rtts   = [e['e2e_rtt'] for e in baseline_ts if e['e2e_rtt'] is not None]
    stress_rtts = [e['e2e_rtt'] for e in stress_ts   if e['e2e_rtt'] is not None]

    base_loss_pct   = (baseline_lost / baseline_probes * 100) if baseline_probes else 0
    stress_loss_pct = (stress_lost   / stress_probes   * 100) if stress_probes   else 0

    if base_rtts:
        print(f"{'BASELINE':<12}{len(base_rtts):<9}{base_loss_pct:<9.1f}"
              f"{sum(base_rtts)/len(base_rtts):<11.2f}"
              f"{percentile(base_rtts, PERCENTILE_P95):<11.2f}{max(base_rtts):<11.2f}")
    else:
        print(f"{'BASELINE':<12}{'0':<9}{base_loss_pct:<9.1f}{'—':<11}{'—':<11}{'—':<11}")

    if stress_rtts:
        print(f"{'STRESS':<12}{len(stress_rtts):<9}{stress_loss_pct:<9.1f}"
              f"{sum(stress_rtts)/len(stress_rtts):<11.2f}"
              f"{percentile(stress_rtts, PERCENTILE_P95):<11.2f}{max(stress_rtts):<11.2f}")
    else:
        print(f"{'STRESS':<12}{'0':<9}{stress_loss_pct:<9.1f}{'—':<11}{'—':<11}{'—':<11}")

    if base_rtts or stress_rtts:
        bj = (max(base_rtts)   - min(base_rtts))   if len(base_rtts)   > 1 else 0.0
        sj = (max(stress_rtts) - min(stress_rtts)) if len(stress_rtts) > 1 else 0.0
        print(f"  RTT jitter (range):  BASELINE {bj:.0f}ms  \u2192  STRESS {sj:.0f}ms")

    if owd_results:
        scope = f" (end-to-end to {target})" if target else " (end-to-end)"
        for label, key in [("FwdOWD\u2020 (upload)" + scope, "fwd_owd_ms"),
                           ("BwdOWD\u2020 (download)" + scope, "bwd_owd_ms")]:
            print(f"\n  \u2014 {label} \u2014")
            print(f"{'Phase':<12}{'Samples':<9}{'Loss %':<9}{'Avg (ms)':<11}"
                  f"{'P95 (ms)':<11}{'Max (ms)':<11}")
            print("-" * 72)
            for phase_tag in ("BASELINE", "STRESS"):
                vals = [r[key] for r in owd_results
                        if r.get('phase') == phase_tag and r.get(key) is not None]
                s = owd_attempt_stats.get(phase_tag) if owd_attempt_stats else None
                loss_str = f"{100*(1 - s['valid']/s['total']):.1f}" if s and s['total'] else '—'
                if vals:
                    print(f"{phase_tag:<12}{len(vals):<9}{loss_str:<9}"
                          f"{sum(vals)/len(vals):<11.2f}"
                          f"{percentile(vals, PERCENTILE_P95):<11.2f}{max(vals):<11.2f}")
                else:
                    print(f"{phase_tag:<12}{'0':<9}{loss_str:<9}{'—':<11}{'—':<11}{'—':<11}")
        # Compute OWD probe loss per phase — needed by IPDV table, diagnosis, and guards.
        def _owd_loss_pct(phase_tag):
            if not owd_attempt_stats:
                return 0.0
            s = owd_attempt_stats.get(phase_tag, {})
            return (1 - s['valid'] / s['total']) * 100 if s.get('total') else 0.0

        _base_owd_loss   = _owd_loss_pct('BASELINE')
        _stress_owd_loss = _owd_loss_pct('STRESS')

        # OWD probe jitter — RTT range (total path) + per-direction IPDV ranges.
        # Async probing records true RTT for high-latency bufferbloat probes;
        # truly dropped probes are excluded (shown in Loss% above).
        _jitter = {}
        print(f"\n  \u2014 OWD probe jitter \u2014")
        print(f"{'Phase':<12}{'Samples':<9}{'RTTJitter(ms)':<15}{'FwdIPDV(ms)':<14}{'BwdIPDV(ms)':<14}")
        print("-" * 64)
        for phase_tag in ('BASELINE', 'STRESS'):
            recv_rtts = [r['rtt_ms'] for r in owd_results
                         if r.get('phase') == phase_tag and not r.get('timed_out')]
            fipdv = [r['fwd_ipdv_ms'] for r in owd_results
                     if r.get('phase') == phase_tag and r.get('fwd_ipdv_ms') is not None]
            bipd  = [r['bwd_ipdv_ms'] for r in owd_results
                     if r.get('phase') == phase_tag and r.get('bwd_ipdv_ms') is not None]
            if len(recv_rtts) > 1:
                rj = max(recv_rtts) - min(recv_rtts)
                fj = (max(fipdv) - min(fipdv)) if len(fipdv) > 1 else 0.0
                bj = (max(bipd)  - min(bipd))  if len(bipd)  > 1 else 0.0
                _jitter[phase_tag] = {'fwd': fj, 'bwd': bj}
                print(f"{phase_tag:<12}{len(recv_rtts):<9}{rj:<15.2f}{fj:<14.2f}{bj:<14.2f}")
            else:
                print(f"{phase_tag:<12}{len(recv_rtts):<9}{'—':<15}{'—':<14}{'—':<14}")

        # Diagnosis: which direction degraded and by how much
        _diag = {}
        for phase_tag in ('BASELINE', 'STRESS'):
            fwds = [r['fwd_owd_ms'] for r in owd_results
                    if r.get('phase') == phase_tag and r.get('fwd_owd_ms') is not None]
            bwds = [r['bwd_owd_ms'] for r in owd_results
                    if r.get('phase') == phase_tag and r.get('bwd_owd_ms') is not None]
            if fwds and bwds:
                _diag[phase_tag] = {
                    'fwd_avg': sum(fwds) / len(fwds),
                    'fwd_p95': percentile(fwds, PERCENTILE_P95),
                    'bwd_avg': sum(bwds) / len(bwds),
                    'bwd_p95': percentile(bwds, PERCENTILE_P95),
                }
        _cal_shift = max((r.get('cal_shift_ms', 0.0) for r in owd_results), default=0.0)

        if 'BASELINE' in _diag and 'STRESS' in _diag:
            print()
            if _stress_owd_loss > 50:
                print(f"  Diagnosis  : \u26a0 Suppressed \u2014 {_stress_owd_loss:.0f}% STRESS probe loss (survivorship bias).")
                print(f"               Surviving probes hit queue-drain gaps; FwdOWD/BwdOWD split reflects")
                print(f"               fast survivors, not the congested path \u2014 direction verdict is unreliable.")
                print(f"               \u2192 Use RTT jitter and per-hop bloat table for congestion direction.")
            elif _cal_shift > 5:
                print(f"  Diagnosis  : \u26a0 Low-confidence \u2014 calibration shift +{_cal_shift:.1f}ms (anchor error >5ms).")
                print(f"               OWD direction split unreliable at this shift magnitude.")
                print(f"               \u2192 Use RTT jitter and per-hop bloat table for congestion direction.")
            else:
                print(_owd_diagnosis(_diag['BASELINE'], _diag['STRESS']))

        # Jitter asymmetry diagnosis (C3)
        if 'STRESS' in _jitter and 'BASELINE' in _jitter:
            sfj = _jitter['STRESS']['fwd']
            sbj = _jitter['STRESS']['bwd']
            if sfj > 2 * sbj and sfj > 10:
                print(f"  \u26a0 IPDV jitter asymmetry: FwdJitter {sfj:.0f}ms >> BwdJitter {sbj:.0f}ms")
                print(f"       Strong evidence of OUTBOUND (upload) path congestion.")
        # Show probe drop rate increase if significant (drop-tail congestion indicator)
        delta_pp = _stress_owd_loss - _base_owd_loss
        if delta_pp >= 20:
            print(f"  \u26a0  Upload packet drop: BASELINE {_base_owd_loss:.0f}% \u2192 STRESS "
                  f"{_stress_owd_loss:.0f}% (+{delta_pp:.0f}pp)")
            print(f"       Severe drop-tail congestion — probe packets dropped before queuing.")
            print(f"       Surviving probes hit queue-drain gaps; probe loss % is the congestion indicator.")
            print(f"       Consider enabling AQM (fq_codel / CAKE) on the upload interface.")
        print(f"\n  \u2020 End-to-end OWD only — per-hop RTT breakdown is in the segment table above.")
        print(f"    Direct TSval-clock OWD; anchor = handshake RTT/2. Each probe independent. No NTP required.")

        # 3-method comparison (M1 RTT/2, M2 TSval-dir, M3 H2 PING)
        if owd_results or h2_results:
            print(f"\n  \u2014 OWD Method Comparison \u2014")
            print(f"  {'Method':<26}  {'Port':>4}  {'Phase':<8}  "
                  f"{'RTT avg':>8}  {'FwdOWD avg':>10}  {'BwdOWD avg':>10}  {'Probes':>8}")
            print(f"  {'-'*73}")
            for phase_tag in ('BASELINE', 'STRESS'):
                # M1 + M2: from HTTP HEAD probes
                if owd_results:
                    ph_http = [r for r in owd_results
                               if r.get('phase') == phase_tag and not r.get('timed_out')]
                    if ph_http:
                        rtts = [r['rtt_ms'] for r in ph_http]
                        fwds = [r['fwd_owd_ms'] for r in ph_http if r.get('fwd_owd_ms') is not None]
                        bwds = [r['bwd_owd_ms'] for r in ph_http if r.get('bwd_owd_ms') is not None]
                        avg_rtt = sum(rtts) / len(rtts)
                        tot_http = sum(1 for r in owd_results if r.get('phase') == phase_tag)
                        # M1: RTT/2
                        print(f"  {'M1: RTT/2 (symmetric)':<26}  {'80':>4}  {phase_tag:<8}  "
                              f"{avg_rtt:>7.2f}ms  {avg_rtt/2:>9.2f}ms  {avg_rtt/2:>9.2f}ms  "
                              f"{len(ph_http):>4}/{tot_http}")
                        # M2: TSval-dir
                        if fwds and bwds:
                            print(f"  {'M2: TSval-dir (server clk)':<26}  {'80':>4}  {phase_tag:<8}  "
                                  f"{avg_rtt:>7.2f}ms  {sum(fwds)/len(fwds):>9.2f}ms  "
                                  f"{sum(bwds)/len(bwds):>9.2f}ms  {len(ph_http):>4}/{tot_http}")
                    else:
                        tot_http = sum(1 for r in owd_results if r.get('phase') == phase_tag)
                        if tot_http:
                            print(f"  {'M1: RTT/2 (symmetric)':<26}  {'80':>4}  {phase_tag:<8}  "
                                  f"{'N/A':>8}  {'N/A':>10}  {'N/A':>10}  {'0':>4}/{tot_http}")
                            print(f"  {'M2: TSval-dir (server clk)':<26}  {'80':>4}  {phase_tag:<8}  "
                                  f"{'N/A':>8}  {'N/A':>10}  {'N/A':>10}  {'0':>4}/{tot_http}")
                # M3: H2 PING probes
                if h2_results:
                    ph_h2 = [r for r in h2_results
                             if r.get('phase') == phase_tag and not r.get('timed_out')]
                    tot_h2 = sum(1 for r in h2_results if r.get('phase') == phase_tag)
                    if ph_h2:
                        rtts_h2 = [r['rtt_ms'] for r in ph_h2]
                        fwds_h2 = [r['fwd_owd_ms'] for r in ph_h2 if r.get('fwd_owd_ms') is not None]
                        bwds_h2 = [r['bwd_owd_ms'] for r in ph_h2 if r.get('bwd_owd_ms') is not None]
                        avg_h2  = sum(rtts_h2) / len(rtts_h2)
                        fwd_h2  = sum(fwds_h2) / len(fwds_h2) if fwds_h2 else avg_h2 / 2
                        bwd_h2  = sum(bwds_h2) / len(bwds_h2) if bwds_h2 else avg_h2 / 2
                        print(f"  {'M3: H2 PING (TLS port 443)':<26}  {'443':>4}  {phase_tag:<8}  "
                              f"{avg_h2:>7.2f}ms  {fwd_h2:>9.2f}ms  {bwd_h2:>9.2f}ms  "
                              f"{len(ph_h2):>4}/{tot_h2}")
                    else:
                        print(f"  {'M3: H2 PING (TLS port 443)':<26}  {'443':>4}  {phase_tag:<8}  "
                              f"{'N/A':>8}  {'N/A':>10}  {'N/A':>10}  {'0':>4}/{tot_h2}")
            print(f"  {'-'*73}")
            print(f"  M1/M2: HTTP HEAD probe data — M1 assumes symmetric, M2 uses server TSval clock.")
            print(f"  M3: H2 PING — kernel-level ACK (no server HTTP processing delay).")

    # --- TWAMP summary block ---
    if twamp_results:
        scope = f" (end-to-end to {target})" if target else " (end-to-end)"
        for label, key in [("FwdOWD\u2021 (upload)" + scope, "fwd_owd_ms"),
                           ("BwdOWD\u2021 (download)" + scope, "bwd_owd_ms")]:
            print(f"\n  \u2014 {label} [TWAMP-Light] \u2014")
            print(f"{'Phase':<12}{'Samples':<9}{'Loss %':<9}{'Avg (ms)':<11}"
                  f"{'P95 (ms)':<11}{'Max (ms)':<11}")
            print("-" * 72)
            for phase_tag in ("BASELINE", "STRESS"):
                vals = [r[key] for r in twamp_results
                        if r.get('phase') == phase_tag and r.get(key) is not None]
                s = twamp_attempt_stats.get(phase_tag) if twamp_attempt_stats else None
                loss_str = f"{100*(1 - s['valid']/s['total']):.1f}" if s and s['total'] else '—'
                if vals:
                    print(f"{phase_tag:<12}{len(vals):<9}{loss_str:<9}"
                          f"{sum(vals)/len(vals):<11.2f}"
                          f"{percentile(vals, PERCENTILE_P95):<11.2f}{max(vals):<11.2f}")
                else:
                    print(f"{phase_tag:<12}{'0':<9}{loss_str:<9}{'—':<11}{'—':<11}{'—':<11}")
        # TWAMP IPDV jitter table
        print(f"\n  \u2014 TWAMP probe jitter \u2014")
        print(f"{'Phase':<12}{'Samples':<9}{'RTTJitter(ms)':<15}{'FwdIPDV(ms)':<14}{'BwdIPDV(ms)':<14}")
        print("-" * 64)
        for phase_tag in ('BASELINE', 'STRESS'):
            recv_rtts = [r['rtt_ms'] for r in twamp_results
                         if r.get('phase') == phase_tag and not r.get('timed_out')]
            fipdv = [r['fwd_ipdv_ms'] for r in twamp_results
                     if r.get('phase') == phase_tag and r.get('fwd_ipdv_ms') is not None]
            bipd  = [r['bwd_ipdv_ms'] for r in twamp_results
                     if r.get('phase') == phase_tag and r.get('bwd_ipdv_ms') is not None]
            if len(recv_rtts) > 1:
                rj = max(recv_rtts) - min(recv_rtts)
                fj = (max(fipdv) - min(fipdv)) if len(fipdv) > 1 else 0.0
                bj = (max(bipd)  - min(bipd))  if len(bipd)  > 1 else 0.0
                print(f"{phase_tag:<12}{len(recv_rtts):<9}{rj:<15.2f}{fj:<14.2f}{bj:<14.2f}")
            else:
                print(f"{phase_tag:<12}{len(recv_rtts):<9}{'—':<15}{'—':<14}{'—':<14}")
        print(f"\n  \u2021 TWAMP-Light UDP end-to-end OWD. FwdOWD\u2021/BwdOWD\u2021 are accurate only with")
        print(f"    NTP-synchronised clocks; without sync they reflect RTT/2 (symmetric assumption).")
        print(f"    IPDV/jitter values are always accurate regardless of clock sync.")


# ---------------------------------------------------------------------------
# Time-series table and ASCII charts
# ---------------------------------------------------------------------------

def print_time_series_table(baseline_ts, stress_ts):
    """Print a time-aligned table of RTT and throughput for both phases.

    Columns:
      DL Δ(MB) / UL Δ(MB) — bytes transferred in this 1-second interval
                             (delta of cumulative counters).  This is the
                             raw source used to derive the Mbps rate.
      DL Total / UL Total  — cumulative bytes since stress phase started.
    """
    W = 96
    print(f"\n{'='*W}")
    print(f"{'TIME-SERIES DATA (1-second intervals)':^{W}}")
    print(f"{'='*W}")
    print(f"{'Time':<10}│{'Phase':<10}│{'RTT ms':>8} │"
          f"{'DL Mbps':>9} {'UL Mbps':>9} │"
          f"{'DL Δ(MB)':>9} {'UL Δ(MB)':>9} │"
          f"{'DL Total':>10} {'UL Total':>10}")
    sep = f"{'─'*10}┼{'─'*10}┼{'─'*9}┼{'─'*20}┼{'─'*20}┼{'─'*21}"
    print(sep)

    for entry in baseline_ts:
        rtt_s = f"{entry['e2e_rtt']:.1f}" if entry['e2e_rtt'] else "-"
        print(f"{entry['ts']:<10}│{'BASE':<10}│{rtt_s:>8} │"
              f"{'':>9} {'':>9} │{'':>9} {'':>9} │{'':>10} {'':>10}")

    prev_dl = prev_ul = 0
    for entry in stress_ts:
        rtt_s = f"{entry['e2e_rtt']:.1f}" if entry['e2e_rtt'] else "-"
        dl_r  = f"{entry['dl_rate_mbps']:.1f}" if entry['dl_rate_mbps'] > 0 else "0.0"
        ul_r  = f"{entry['ul_rate_mbps']:.1f}" if entry['ul_rate_mbps'] > 0 else "0.0"

        # Per-interval deltas (bytes → MB)
        dl_delta = (entry['dl_bytes'] - prev_dl) / BYTES_PER_MB
        ul_delta = (entry['ul_bytes'] - prev_ul) / BYTES_PER_MB
        dl_d_s = f"{dl_delta:.2f}" if dl_delta > 0 else "0.00"
        ul_d_s = f"{ul_delta:.2f}" if ul_delta > 0 else "0.00"

        dl_tot = f"{entry['dl_bytes']/BYTES_PER_MB:.1f}MB" if entry['dl_bytes'] > 0 else "-"
        ul_tot = f"{entry['ul_bytes']/BYTES_PER_MB:.1f}MB" if entry['ul_bytes'] > 0 else "-"

        print(f"{entry['ts']:<10}│{'STRESS':<10}│{rtt_s:>8} │"
              f"{dl_r:>9} {ul_r:>9} │"
              f"{dl_d_s:>9} {ul_d_s:>9} │"
              f"{dl_tot:>10} {ul_tot:>10}")
        prev_dl = entry['dl_bytes']
        prev_ul = entry['ul_bytes']


def print_ascii_chart(baseline_ts, stress_ts, width=80, height=20,
                      owd_results=None, twamp_results=None):
    """Render a dual-axis ASCII chart: throughput (left) + RTT (right).

    DL throughput = ▓, UL throughput = ░, RTT = ● / ○
    OWD overlay (when owd_results provided): ▲ FwdOWD† upload, ▽ BwdOWD† download.
    TWAMP overlay (when twamp_results provided): ◆ FwdOWD‡ upload, ◇ BwdOWD‡ download.
    """
    # Combine all time-series entries in order
    all_entries = []
    for e in baseline_ts:
        all_entries.append({**e, 'phase': 'BASE'})
    for e in stress_ts:
        all_entries.append({**e, 'phase': 'STRESS'})

    if not all_entries:
        return

    # Collect data ranges
    rtt_values = [e['e2e_rtt'] for e in all_entries if e['e2e_rtt'] is not None]
    dl_rates = [e['dl_rate_mbps'] for e in all_entries if e['dl_rate_mbps'] > 0]
    ul_rates = [e['ul_rate_mbps'] for e in all_entries if e['ul_rate_mbps'] > 0]
    all_rates = dl_rates + ul_rates

    # Extend RTT axis to cover OWD and IPDV values if they're larger
    if owd_results:
        for key in ('fwd_owd_ms', 'bwd_owd_ms'):
            rtt_values += [r[key] for r in owd_results if r.get(key) is not None]
        rtt_values += [abs(r['fwd_ipdv_ms']) for r in owd_results
                       if r.get('fwd_ipdv_ms') is not None]
        # High-RTT received probes (bufferbloat) also included via fwd/bwd_owd_ms above
    if twamp_results:
        for key in ('fwd_owd_ms', 'bwd_owd_ms'):
            rtt_values += [r[key] for r in twamp_results if r.get(key) is not None]

    if not rtt_values and not all_rates:
        return

    max_rtt = max(rtt_values) * CHART_AXIS_PADDING if rtt_values else 100
    max_rate = max(all_rates) * CHART_AXIS_PADDING if all_rates else 10
    if max_rtt < 1:
        max_rtt = 1
    if max_rate < 0.1:
        max_rate = 1

    # Determine how many data points to show
    n_base   = len(baseline_ts)
    n_stress = len(stress_ts)
    n_entries = len(all_entries)
    chart_w = min(width - 18, n_entries)  # leave room for y-axes
    if chart_w < 10:
        chart_w = min(n_entries, 60)

    # Resample if more data points than chart columns
    if n_entries > chart_w:
        step = n_entries / chart_w
        sampled = []
        for i in range(chart_w):
            idx = int(i * step)
            sampled.append(all_entries[min(idx, n_entries - 1)])
        entries = sampled
    else:
        entries = all_entries
        chart_w = len(entries)

    has_owd   = bool(owd_results)
    has_twamp = bool(twamp_results)
    if has_owd and has_twamp:
        title = 'ASCII CHART: Throughput (\u2593DL \u2591UL) + RTT (\u25cf) + OWD (\u25b2\u25bd) + TWAMP (\u25c6\u25c7)'
    elif has_owd:
        title = 'ASCII CHART: Throughput (\u2593DL \u2591UL) + RTT (\u25cf) + OWD (\u25b2\u25bd)'
    elif has_twamp:
        title = 'ASCII CHART: Throughput (\u2593DL \u2591UL) + RTT (\u25cf) + TWAMP (\u25c6\u25c7)'
    else:
        title = 'ASCII CHART: Throughput (DL \u2593, UL \u2591) + RTT (\u25cf)'
    print(f"\n{'='*80}")
    print(f"{title:^80}")
    print(f"{'='*80}")
    if has_owd or has_twamp:
        rtt_label = "RTT+OWD"
    else:
        rtt_label = "RTT"
    print(f"  Y-axis left: Throughput (0-{max_rate:.0f} Mbps)   "
          f"Y-axis right: {rtt_label} (0-{max_rtt:.0f} ms)\n")

    # Build the chart grid
    grid = [[' ' for _ in range(chart_w)] for _ in range(height)]

    for col, e in enumerate(entries):
        # DL throughput bar
        if e['dl_rate_mbps'] > 0:
            bar_h = int(e['dl_rate_mbps'] / max_rate * (height - 1))
            bar_h = min(bar_h, height - 1)
            for row in range(bar_h + 1):
                grid[height - 1 - row][col] = '▓'

        # UL throughput bar (overlay, use ░ where no DL)
        if e['ul_rate_mbps'] > 0:
            bar_h = int(e['ul_rate_mbps'] / max_rate * (height - 1))
            bar_h = min(bar_h, height - 1)
            for row in range(bar_h + 1):
                r = height - 1 - row
                if grid[r][col] == ' ':
                    grid[r][col] = '░'

        # RTT dot
        if e['e2e_rtt'] is not None:
            rtt_row = int(e['e2e_rtt'] / max_rtt * (height - 1))
            rtt_row = min(rtt_row, height - 1)
            r = height - 1 - rtt_row
            ch = '○' if e['phase'] == 'BASE' else '●'
            grid[r][col] = ch

    # OWD overlay — map each probe to a chart column by wall-clock elapsed time
    if has_owd and n_entries >= 2:
        base_dur   = baseline_ts[-1]['elapsed'] if baseline_ts else 0
        stress_dur = stress_ts[-1]['elapsed']   if stress_ts   else 0

        base_probes   = [r for r in owd_results if r.get('phase') == 'BASELINE']
        stress_probes = [r for r in owd_results if r.get('phase') == 'STRESS']

        owd_base_t0   = (min(r['t_send_ns'] for r in base_probes)   / 1e9
                         if base_probes else None)
        owd_stress_t0 = (min(r['t_send_ns'] for r in stress_probes) / 1e9
                         if stress_probes else None)

        def _owd_col(probe):
            """Return chart column index for an OWD probe, or None if unmappable."""
            phase = probe.get('phase')
            if phase == 'BASELINE' and owd_base_t0 and base_dur > 0:
                elapsed = probe['t_send_ns'] / 1e9 - owd_base_t0
                raw_pos = elapsed / base_dur * max(n_base - 1, 1)
            elif phase == 'STRESS' and owd_stress_t0 and stress_dur > 0:
                elapsed = probe['t_send_ns'] / 1e9 - owd_stress_t0
                raw_pos = n_base + elapsed / stress_dur * max(n_stress - 1, 1)
            else:
                return None
            col = round(raw_pos * chart_w / n_entries)
            return max(0, min(col, chart_w - 1))

        # RTT dot characters — we don't overwrite these
        _rtt_chars = {'●', '○'}

        for probe in owd_results:
            col = _owd_col(probe)
            if col is None:
                continue
            # Dropped (truly unresponsive) probe → X at top of chart
            if probe.get('timed_out'):
                if grid[0][col] == ' ':
                    grid[0][col] = 'X'
                continue
            # FwdOWD† upload → ▲
            fwd = probe.get('fwd_owd_ms')
            if fwd is not None:
                owd_row = max(0, min(int(fwd / max_rtt * (height - 1)), height - 1))
                r = height - 1 - owd_row
                if grid[r][col] not in _rtt_chars:
                    grid[r][col] = '▲'
            # BwdOWD† download → ▽
            bwd = probe.get('bwd_owd_ms')
            if bwd is not None:
                owd_row = max(0, min(int(bwd / max_rtt * (height - 1)), height - 1))
                r = height - 1 - owd_row
                if grid[r][col] not in _rtt_chars:
                    grid[r][col] = '▽'
            # |FwdIPDV| upload jitter magnitude → x
            fipd = probe.get('fwd_ipdv_ms')
            if fipd is not None:
                ipdv_row = max(0, min(int(abs(fipd) / max_rtt * (height - 1)), height - 1))
                r = height - 1 - ipdv_row
                if grid[r][col] == ' ':
                    grid[r][col] = 'x'

    # TWAMP overlay — map each probe to chart column by wall-clock elapsed time
    # TWAMP probes store t1_posix (float seconds) rather than t_send_ns
    if has_twamp and n_entries >= 2:
        base_dur_tw   = baseline_ts[-1]['elapsed'] if baseline_ts else 0
        stress_dur_tw = stress_ts[-1]['elapsed']   if stress_ts   else 0

        tw_base   = [r for r in twamp_results if r.get('phase') == 'BASELINE']
        tw_stress = [r for r in twamp_results if r.get('phase') == 'STRESS']

        tw_base_t0   = (min(r['t1_posix'] for r in tw_base   if r.get('t1_posix'))
                        if tw_base   else None)
        tw_stress_t0 = (min(r['t1_posix'] for r in tw_stress if r.get('t1_posix'))
                        if tw_stress else None)

        def _twamp_col(probe):
            phase = probe.get('phase')
            t1 = probe.get('t1_posix')
            if t1 is None:
                return None
            if phase == 'BASELINE' and tw_base_t0 and base_dur_tw > 0:
                elapsed = t1 - tw_base_t0
                raw_pos = elapsed / base_dur_tw * max(n_base - 1, 1)
            elif phase == 'STRESS' and tw_stress_t0 and stress_dur_tw > 0:
                elapsed = t1 - tw_stress_t0
                raw_pos = n_base + elapsed / stress_dur_tw * max(n_stress - 1, 1)
            else:
                return None
            col = round(raw_pos * chart_w / n_entries)
            return max(0, min(col, chart_w - 1))

        _protected = {'●', '○', '▲', '▽'}
        for probe in twamp_results:
            col = _twamp_col(probe)
            if col is None:
                continue
            if probe.get('timed_out'):
                if grid[0][col] == ' ':
                    grid[0][col] = 'T'   # TWAMP timeout marker
                continue
            # FwdOWD‡ upload → ◆
            fwd = probe.get('fwd_owd_ms')
            if fwd is not None:
                owd_row = max(0, min(int(fwd / max_rtt * (height - 1)), height - 1))
                r = height - 1 - owd_row
                if grid[r][col] not in _protected:
                    grid[r][col] = '\u25c6'
            # BwdOWD‡ download → ◇
            bwd = probe.get('bwd_owd_ms')
            if bwd is not None:
                owd_row = max(0, min(int(bwd / max_rtt * (height - 1)), height - 1))
                r = height - 1 - owd_row
                if grid[r][col] not in _protected and grid[r][col] != '\u25c6':
                    grid[r][col] = '\u25c7'

    # Render
    for row in range(height):
        rate_val = max_rate * (height - 1 - row) / (height - 1)
        rtt_val = max_rtt * (height - 1 - row) / (height - 1)
        line = ''.join(grid[row])
        print(f"  {rate_val:5.1f}│{line}│{rtt_val:>6.0f}")

    print(f"       └{'─' * chart_w}┘")

    # Time labels
    label_line = "        "
    if len(entries) >= 3:
        first_ts = entries[0]['ts']
        mid_ts = entries[len(entries) // 2]['ts']
        last_ts = entries[-1]['ts']
        gap1 = chart_w // 2 - len(first_ts)
        gap2 = chart_w - chart_w // 2 - len(mid_ts)
        label_line += f"{first_ts}{' ' * max(1, gap1)}{mid_ts}{' ' * max(1, gap2)}{last_ts}"
    print(label_line)

    legend = "\n  Legend: \u2593 DL Mbps   \u2591 UL Mbps   \u25cb Base RTT   \u25cf Stress RTT"
    if has_owd:
        legend += "   \u25b2 FwdOWD\u2020(UL)   \u25bd BwdOWD\u2020(DL)   x |FwdIPDV|   X OWD-timeout"
    if has_twamp:
        legend += "   \u25c6 FwdOWD\u2021(UL)   \u25c7 BwdOWD\u2021(DL)   T TWAMP-timeout"
    if not has_owd and not has_twamp:
        legend = "\n  Legend: \u2593 DL Mbps   \u2591 UL Mbps   \u25cb Baseline RTT (ms)   \u25cf Stress RTT (ms)"
    print(legend)


def print_throughput_summary(stress_ts):
    """Print aggregate throughput statistics from the stress phase."""
    dl_rates = [e['dl_rate_mbps'] for e in stress_ts if e['dl_rate_mbps'] > 0]
    ul_rates = [e['ul_rate_mbps'] for e in stress_ts if e['ul_rate_mbps'] > 0]

    if not dl_rates and not ul_rates:
        return

    print(f"\n{'='*72}")
    print(f"{'THROUGHPUT SUMMARY (Browsing Traffic)':^72}")
    print(f"{'='*72}")
    print(f"{'Direction':<12}{'Mean Mbps':>10}{'Max':>8}{'Median':>8}"
          f"{'P10':>8}{'P90':>8}{'Samples':>8}")
    print("-" * 72)

    for label, rates in [('download', dl_rates), ('upload', ul_rates)]:
        if rates:
            avg = sum(rates) / len(rates)
            print(f"{label:<12}{avg:>10.2f}{max(rates):>8.2f}"
                  f"{percentile(rates, 50):>8.2f}{percentile(rates, PERCENTILE_P10):>8.2f}"
                  f"{percentile(rates, PERCENTILE_P90):>8.2f}{len(rates):>8}")
        else:
            print(f"{label:<12}{'—':>10}{'—':>8}{'—':>8}{'—':>8}{'—':>8}{'0':>8}")

    # Total data transferred
    if stress_ts:
        last = stress_ts[-1]
        dl_mb = last['dl_bytes'] / BYTES_PER_MB
        ul_mb = last['ul_bytes'] / BYTES_PER_MB
        print(f"\n  Total data transferred: DL {dl_mb:.1f} MB  |  UL {ul_mb:.1f} MB")


def print_traffic_summary(traffic_log_file):
    """Print traffic-gen.py results from its CSV log."""
    print(f"\n{'='*72}")
    print(f"{'TRAFFIC GENERATION SUMMARY (from traffic-gen.py)':^72}")
    print(f"{'='*72}")

    if not traffic_log_file or not os.path.exists(traffic_log_file):
        print("  (No traffic log available)")
        return

    try:
        with open(traffic_log_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)

        if len(rows) < 2:
            print("  (Empty traffic log)")
            return

        total_row = rows[-1]
        if total_row[0] == 'TOTAL':
            succ = total_row[2]
            fail = total_row[3]
            opened = total_row[4]
            closed = total_row[5]
            rst = total_row[6]
            data = total_row[7]
            print(f"  Requests  : {succ} success / {fail} failed")
            print(f"  Sockets   : {opened} opened / {closed} closed / {rst} reset")
            print(f"  Data      : {data}")
        else:
            print("  (Could not parse traffic log TOTAL row)")

    except (OSError, csv.Error) as exc:
        print(f"  (Error reading traffic log: {exc})")


def save_results_csv(output_file, baseline_stats, stress_stats, segments,
                     baseline_ts, stress_ts, twamp_results=None):
    """Save detailed results to CSV."""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Section 1: Per-hop bloat
            writer.writerow(['# PER-HOP BLOAT'])
            writer.writerow(['hop', 'ip', 'baseline_avg_ms', 'baseline_p95_ms',
                             'stress_avg_ms', 'stress_p95_ms', 'bloat_ms'])
            for hop_num, ip, base_avg, stress_p95, bloat, is_silent in segments:
                b = baseline_stats.get(hop_num, {})
                s = stress_stats.get(hop_num, {})
                writer.writerow([
                    hop_num, ip,
                    f"{base_avg:.2f}",
                    f"{b.get('p95', 0):.2f}",
                    f"{s.get('avg', 0):.2f}",
                    f"{stress_p95:.2f}" if not is_silent else "N/A",
                    f"{bloat:.2f}"     if not is_silent else "N/A",
                ])

            # Section 2: Time-series
            writer.writerow([])
            writer.writerow(['# TIME-SERIES'])
            writer.writerow(['timestamp', 'phase', 'elapsed_sec', 'e2e_rtt_ms',
                             'dl_rate_mbps', 'ul_rate_mbps',
                             'dl_bytes_total', 'ul_bytes_total'])
            for e in baseline_ts:
                writer.writerow([
                    e['ts'], 'BASELINE', f"{e['elapsed']:.1f}",
                    f"{e['e2e_rtt']:.2f}" if e['e2e_rtt'] else '',
                    '', '', '', '',
                ])
            for e in stress_ts:
                writer.writerow([
                    e['ts'], 'STRESS', f"{e['elapsed']:.1f}",
                    f"{e['e2e_rtt']:.2f}" if e['e2e_rtt'] else '',
                    f"{e['dl_rate_mbps']:.2f}",
                    f"{e['ul_rate_mbps']:.2f}",
                    e['dl_bytes'], e['ul_bytes'],
                ])

            # Section 3: TWAMP probe data (optional)
            if twamp_results:
                writer.writerow([])
                writer.writerow(['# TWAMP-LIGHT PROBES'])
                writer.writerow(['probe', 'phase', 'seq', 'rtt_ms', 'fwd_owd_ms',
                                 'bwd_owd_ms', 'fwd_ipdv_ms', 'bwd_ipdv_ms', 'timed_out'])
                for r in twamp_results:
                    writer.writerow([
                        r.get('probe', ''),
                        r.get('phase', ''),
                        r.get('seq', ''),
                        f"{r['rtt_ms']:.3f}"       if r.get('rtt_ms')       is not None else '',
                        f"{r['fwd_owd_ms']:.3f}"   if r.get('fwd_owd_ms')   is not None else '',
                        f"{r['bwd_owd_ms']:.3f}"   if r.get('bwd_owd_ms')   is not None else '',
                        f"{r['fwd_ipdv_ms']:.3f}"  if r.get('fwd_ipdv_ms')  is not None else '',
                        f"{r['bwd_ipdv_ms']:.3f}"  if r.get('bwd_ipdv_ms')  is not None else '',
                        int(r.get('timed_out', False)),
                    ])

        print(f"\nResults saved to: {output_file}")
    except OSError as exc:
        print(f"[WARN] Could not write output file: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# One-Way Delay (OWD) helpers — tcp_owd.py integration
# ---------------------------------------------------------------------------

def _load_tcp_owd():
    """Import tcp_owd from the same directory. Returns the module or None."""
    try:
        import importlib.util
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tcp_owd.py')
        _spec = importlib.util.spec_from_file_location('tcp_owd', _path)
        _mod  = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        return _mod
    except Exception as exc:
        print(f"[WARN] Could not load tcp_owd.py: {exc}", file=sys.stderr)
        return None


def _owd_worker(tcp_owd, target, port, conn, phase, duration_secs, interval,
                results_list, probe_timeout=10.0, attempt_stats=None,
                h2_results_list=None):
    """Background thread: run OWD probes for duration_secs, tag with phase.

    Runs HTTP HEAD probes (port 80) and HTTP/2 PING probes (port 443) in
    parallel sub-threads so both methods measure the same network conditions.
    h2_results_list: if provided, H2 PING results are appended here.
    """
    h2_buf = []

    def _run_http():
        phase_results = tcp_owd.run_probes_kernel_http(
            target, port, conn,
            count=0, interval=interval, verbose=False,
            phase=phase, duration_secs=duration_secs,
            drain_timeout=probe_timeout,
        )
        results_list.extend(phase_results)
        if attempt_stats is not None:
            attempt_stats[phase] = {
                'total': len(phase_results),
                'valid': sum(1 for r in phase_results if not r.get('timed_out')),
            }

    def _run_h2():
        h2_res, conn_h2 = tcp_owd.run_h2_ping_probes(
            target,
            count=0,
            interval=interval,
            verbose=False,
            phase=phase,
            duration_secs=duration_secs,
            drain_timeout=probe_timeout,
        )
        if conn_h2 and h2_res:
            tcp_owd.compute_owd(h2_res, conn_h2)
        h2_buf.extend(h2_res)

    t_http = threading.Thread(target=_run_http, daemon=True)
    t_h2   = threading.Thread(target=_run_h2,   daemon=True)
    t_http.start()
    t_h2.start()
    t_http.join()
    t_h2.join()

    if h2_results_list is not None:
        h2_results_list.extend(h2_buf)


def print_owd_section(tcp_owd, owd_results, owd_attempt_stats=None):
    """Print the OWD BASELINE vs STRESS comparison table."""
    print(f"\n{'='*72}")
    print(f"{'ONE-WAY DELAY ANALYSIS (TCP Timestamp OWD†)':^72}")
    print(f"{'='*72}")
    print(f"  Note: OWD is end-to-end only (single TCP connection to target).")
    print(f"        Per-hop RTT breakdown is in the segment bloat table above.")
    def _loss_pct(phase_tag):
        if not owd_attempt_stats:
            return 0.0
        s = owd_attempt_stats.get(phase_tag, {})
        return (1 - s['valid'] / s['total']) * 100 if s.get('total') else 0.0
    phase_loss = {'BASELINE': _loss_pct('BASELINE'), 'STRESS': _loss_pct('STRESS')}
    # print_phase_summary computes FwdJitter/BwdJitter from fwd_ipdv_ms/bwd_ipdv_ms
    # ranges internally — no override needed.
    tcp_owd.print_phase_summary(owd_results, phase_loss=phase_loss)


# ---------------------------------------------------------------------------
# TWAMP-Light helpers — twamp_owd.py integration
# ---------------------------------------------------------------------------

def _load_twamp_owd():
    """Import twamp_owd from the same directory. Returns the module or None."""
    try:
        import importlib.util
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'twamp_owd.py')
        _spec = importlib.util.spec_from_file_location('twamp_owd', _path)
        _mod  = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        return _mod
    except Exception as exc:
        print(f"[WARN] Could not load twamp_owd.py: {exc}", file=sys.stderr)
        return None


def _twamp_worker(twamp_mod, server, port, phase, duration_secs, interval,
                  results_list, timeout, padding, attempt_stats=None,
                  backend='native'):
    """Background thread: run TWAMP-Light UDP probes for duration_secs, tag with phase."""
    if backend == 'nokia':
        phase_results = twamp_mod.run_twamp_probes_nokia(
            server, port,
            duration_secs=duration_secs, interval=interval,
            phase=phase, timeout=timeout, padding=padding, verbose=False,
        )
        if phase_results is None:
            print(
                f"[ERROR] --twamp-backend nokia: Nokia twampy is not installed.\n"
                f"        Install it with:  pip install twampy\n"
                f"        Or use the built-in backend: --twamp-backend native",
                file=sys.stderr,
            )
            phase_results = []
    else:
        phase_results = twamp_mod.run_twamp_probes(
            server, port,
            count=0, interval=interval,
            phase=phase, duration_secs=duration_secs,
            timeout=timeout, padding=padding, verbose=False,
        )
    results_list.extend(phase_results)
    if attempt_stats is not None:
        attempt_stats[phase] = {
            'total': len(phase_results),
            'valid': sum(1 for r in phase_results if not r.get('timed_out')),
        }


def print_twamp_section(twamp_mod, twamp_results, twamp_attempt_stats=None):
    """Print the TWAMP BASELINE vs STRESS comparison table."""
    print(f"\n{'='*72}")
    print(f"{'ONE-WAY DELAY ANALYSIS (TWAMP-Light UDP‡)':^72}")
    print(f"{'='*72}")
    print(f"  Note: OWD is end-to-end only (UDP probes to TWAMP reflector).")
    print(f"        FwdOWD‡/BwdOWD‡ are accurate only with NTP-synced clocks;")
    print(f"        without sync they equal RTT/2. IPDV/jitter is always accurate.")

    def _loss_pct(phase_tag):
        if not twamp_attempt_stats:
            return 0.0
        s = twamp_attempt_stats.get(phase_tag, {})
        return (1 - s['valid'] / s['total']) * 100 if s.get('total') else 0.0

    phase_loss = {'BASELINE': _loss_pct('BASELINE'), 'STRESS': _loss_pct('STRESS')}
    twamp_mod.print_phase_summary(twamp_results, phase_loss=phase_loss)


# ---------------------------------------------------------------------------
# Traffic-gen subprocess management
# ---------------------------------------------------------------------------

def start_traffic_gen(dl_clients, ul_clients, duration_secs, log_file, stats_file):
    """Spawn traffic-gen.py as a subprocess. Returns the Popen object."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    traffic_gen = os.path.join(script_dir, 'traffic-gen.py')

    if not os.path.exists(traffic_gen):
        print(f"[ERROR] Cannot find traffic-gen.py at: {traffic_gen}", file=sys.stderr)
        sys.exit(1)

    duration_mins = max(1, int(math.ceil(duration_secs / 60.0)))

    cmd = [
        sys.executable, traffic_gen,
        '-d', str(dl_clients),
        '-u', str(ul_clients),
        '-t', str(duration_mins),
        '-p', '0',
        '-S', stats_file,
        '--stats-interval', '1',
    ]
    if log_file:
        cmd.extend(['-l', log_file])

    print(f"\n  Starting traffic-gen.py: {dl_clients} DL / {ul_clients} UL threads")
    print(f"  Command: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc


def stop_traffic_gen(proc):
    """Gracefully stop traffic-gen.py subprocess."""
    if proc and proc.poll() is None:
        print("\n  Stopping traffic-gen.py...")
        proc.send_signal(signal.SIGTERM if os.name != 'nt' else signal.CTRL_C_EVENT)
        try:
            proc.wait(timeout=TRAFFIC_GEN_TERM_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=TRAFFIC_GEN_KILL_TIMEOUT)
        print("  traffic-gen.py stopped.")


# ---------------------------------------------------------------------------
# CLI and entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Bufferbloat measurement using real browsing traffic (traffic-gen.py) as stress.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('-T', '--target', type=str, required=True,
                   help="Traceroute target host/IP")
    p.add_argument('-b', '--baseline', type=int, default=DEFAULT_BASELINE_SEC,
                   help="Baseline phase duration in seconds")
    p.add_argument('-s', '--stress', type=int, default=DEFAULT_STRESS_SEC,
                   help="Stress phase duration in seconds")
    p.add_argument('-i', '--interval', type=int, default=DEFAULT_POLL_INTERVAL,
                   help="Traceroute poll interval in seconds")
    p.add_argument('-w', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                   help="Traceroute wait timeout per hop in seconds")
    p.add_argument('--max-rtt', type=int, default=MAX_RTT_ALLOWED,
                   help="Hard wall-clock limit for one traceroute call (seconds); "
                        "probe killed and counted as lost if exceeded")
    p.add_argument('-d', '--dl-clients', type=int, default=DEFAULT_DL_CLIENTS,
                   help="Download threads for traffic-gen.py")
    p.add_argument('-u', '--ul-clients', type=int, default=DEFAULT_UL_CLIENTS,
                   help="Upload threads for traffic-gen.py")
    p.add_argument('-o', '--output', type=str, default=None,
                   help="Save results to CSV file")
    p.add_argument('-W', '--chart-width', type=int, default=DEFAULT_CHART_WIDTH,
                   help="ASCII chart width in columns")
    p.add_argument('-H', '--chart-height', type=int, default=DEFAULT_CHART_HEIGHT,
                   help="ASCII chart height in rows")
    p.add_argument('-m', '--rate-method', type=str, default=DEFAULT_RATE_METHOD,
                   choices=['auto', 'procnetdev', 'statsfile', 'ss'],
                   help="Throughput measurement method: "
                        "'procnetdev' reads /proc/net/dev on the WAN interface (wire-level, "
                        "auto-detected via 'ip route get <target>'), "
                        "'ss' runs 'ss -i -t -n' and sums bytes_acked (UL) and "
                        "bytes_received (DL) across all TCP sockets (no interface needed), "
                        "'statsfile' reads traffic-gen.py's app-level byte counters, "
                        "'auto' defaults to statsfile (default)")
    p.add_argument('-I', '--interface', type=str, default=None,
                   help="Network interface for /proc/net/dev measurement "
                        "(auto-detected from default route if omitted)")

    owd = p.add_argument_group(
        'One-Way Delay (OWD) measurement',
        'Runs TCP Timestamp keep-alive probes in parallel with traceroute '
        '(requires root + scapy). Reports per-direction FwdOWD†/BwdOWD† '
        'BASELINE vs STRESS comparison.')
    owd.add_argument('--owd', action='store_true',
                     help='Enable OWD measurement alongside traceroute')
    owd.add_argument('--owd-port', type=int, default=DEFAULT_OWD_PORT, metavar='PORT',
                     help=f'TCP port for OWD probe connection (default: {DEFAULT_OWD_PORT})')
    owd.add_argument('--owd-interval', type=float, default=DEFAULT_OWD_INTERVAL, metavar='SECS',
                     help=f'Seconds between OWD keep-alive probes (default: {DEFAULT_OWD_INTERVAL})')
    owd.add_argument('--owd-timeout', type=float, default=DEFAULT_OWD_TIMEOUT, metavar='SECS',
                     help=f'Per-probe reply timeout for OWD keepalives (default: {DEFAULT_OWD_TIMEOUT}). '
                          'Increase if probes time out under heavy bufferbloat.')

    twamp = p.add_argument_group(
        'TWAMP-Light OWD measurement',
        'UDP TWAMP-Light (RFC 5357) probes to a reflector. No root required. '
        'Reports per-direction FwdOWD‡/BwdOWD‡ BASELINE vs STRESS comparison. '
        f'Default server: {DEFAULT_TWAMP_SERVER}:{DEFAULT_TWAMP_PORT}.')
    twamp.add_argument('--twamp', action='store_true',
                       help='Enable TWAMP-Light OWD measurement alongside traceroute')
    twamp.add_argument('--twamp-server', type=str, default=DEFAULT_TWAMP_SERVER, metavar='HOST',
                       help=f'TWAMP reflector IP or hostname (default: {DEFAULT_TWAMP_SERVER})')
    twamp.add_argument('--twamp-port', type=int, default=DEFAULT_TWAMP_PORT, metavar='PORT',
                       help=f'TWAMP reflector UDP port (default: {DEFAULT_TWAMP_PORT})')
    twamp.add_argument('--twamp-interval', type=float, default=DEFAULT_TWAMP_INTERVAL, metavar='SECS',
                       help=f'Seconds between TWAMP probe packets (default: {DEFAULT_TWAMP_INTERVAL})')
    twamp.add_argument('--twamp-timeout', type=float, default=DEFAULT_TWAMP_TIMEOUT, metavar='SECS',
                       help=f'Per-probe receive timeout for TWAMP (default: {DEFAULT_TWAMP_TIMEOUT})')
    twamp.add_argument('--twamp-padding', type=int, default=DEFAULT_TWAMP_PADDING, metavar='BYTES',
                       help=f'Padding bytes appended to each sender packet (default: {DEFAULT_TWAMP_PADDING})')
    twamp.add_argument('--twamp-backend', type=str, default=DEFAULT_TWAMP_BACKEND,
                       choices=['native', 'nokia'],
                       help="TWAMP sender backend: 'native' uses built-in RFC 5357 UDP client "
                            "(per-probe data, full chart overlay); 'nokia' uses Nokia twampy "
                            "subprocess (requires pip install twampy, summary stats only). "
                            f"Default: {DEFAULT_TWAMP_BACKEND}")
    return p.parse_args()


def check_traceroute():
    """Verify traceroute is available."""
    try:
        subprocess.run(['traceroute', '--version'], capture_output=True,
                       text=True, check=False)
    except FileNotFoundError:
        print("[ERROR] 'traceroute' not found. Install it: apt install traceroute",
              file=sys.stderr)
        sys.exit(1)


def main():
    args = parse_args()

    check_traceroute()

    # Resolve throughput measurement method
    rate_method = args.rate_method
    interface = args.interface
    if rate_method == 'auto':
        # Default to statsfile: counts only traffic-gen.py's own curl bytes,
        # so it is unaffected by other hosts on the LAN or router forwarding
        # traffic on the outgoing interface.  Use '-m procnetdev -I <iface>'
        # explicitly if you want raw NIC counters on a known WAN interface.
        rate_method = 'statsfile'

    if rate_method == 'procnetdev':
        if not os.path.exists('/proc/net/dev'):
            print("[WARN] /proc/net/dev not available, falling back to statsfile method.",
                  file=sys.stderr)
            rate_method = 'statsfile'
        elif not interface:
            # Use the interface that actually routes packets to the test target
            # (e.g. the cellular/WAN port), not necessarily the default-route iface.
            interface = detect_interface_for_target(args.target)
            if not interface:
                print("[WARN] Could not detect outgoing interface, falling back to statsfile.",
                      file=sys.stderr)
                rate_method = 'statsfile'

    # --- procnetdev pre-test sanity check ---
    # Measure a 2-second idle rate on the detected interface BEFORE any traffic
    # starts.  This lets the user verify they are reading the right interface
    # and catches the common misconfiguration where a LAN/bridge interface is
    # auto-detected instead of the WAN port.
    if rate_method == 'procnetdev' and interface:
        print(f"\n[INFO] procnetdev: checking interface '{interface}' ...")
        try:
            res = subprocess.run(['ip', 'route', 'get', args.target],
                                 capture_output=True, text=True, check=False, timeout=3)
            print(f"[INFO] ip route get {args.target}  →  {res.stdout.strip()}")
        except (OSError, subprocess.TimeoutExpired):
            pass
        snap_a = read_procnetdev(interface)
        time.sleep(2)
        snap_b = read_procnetdev(interface)
        if snap_a and snap_b:
            idle_dl = (snap_b[0] - snap_a[0]) * 8 / 2 / BITS_PER_MBPS
            idle_ul = (snap_b[1] - snap_a[1]) * 8 / 2 / BITS_PER_MBPS
            print(f"[INFO] '{interface}' idle rate (2s sample): "
                  f"DL {idle_dl:.1f} Mbps  UL {idle_ul:.1f} Mbps")
            if idle_dl > 20 or idle_ul > 20:
                print(f"[WARN] *** Idle rate is unexpectedly high for a 10 Mbps WAN! ***",
                      file=sys.stderr)
                print(f"[WARN] '{interface}' is likely a LAN/bridge interface that sees all",
                      file=sys.stderr)
                print(f"[WARN] forwarded traffic — reported rates will be inflated.",
                      file=sys.stderr)
                print(f"[WARN] Recommendation: use '-m statsfile' (measures only test traffic),",
                      file=sys.stderr)
                print(f"[WARN] or specify your actual WAN interface with '-I <iface>'.",
                      file=sys.stderr)
                # List available interfaces to help the user pick the right one
                print(f"[WARN] Available interfaces in /proc/net/dev:", file=sys.stderr)
                try:
                    with open('/proc/net/dev', 'r', encoding='utf-8') as _f:
                        for _line in _f:
                            if ':' in _line:
                                _iface = _line.split(':')[0].strip()
                                if _iface and _iface != 'lo':
                                    _snap = read_procnetdev(_iface)
                                    _rx = f"{_snap[0]/1073741824:.2f} GB RX" if _snap else ""
                                    print(f"[WARN]   {_iface:15s} {_rx}", file=sys.stderr)
                except OSError:
                    pass

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    traffic_log = f"traffic_gen_{timestamp}.csv"
    stats_file = f".traffic_stats_{timestamp}.dat"

    print("=" * 72)
    print(f"{'USER BROWSING BUFFERBLOAT TEST':^72}")
    print("=" * 72)
    print(f"  Target       : {args.target}")
    print(f"  Baseline     : {args.baseline}s")
    print(f"  Stress       : {args.stress}s")
    print(f"  Poll interval: {args.interval}s")
    print(f"  DL clients   : {args.dl_clients}")
    print(f"  UL clients   : {args.ul_clients}")
    print(f"  Rate method  : {rate_method}"
          + (f" ({interface})" if rate_method == 'procnetdev' else ""))
    print(f"  Traffic log  : {traffic_log}")
    if args.owd:
        print(f"  OWD          : enabled (port={args.owd_port}  interval={args.owd_interval}s  "
              f"timeout={args.owd_timeout}s)")
    if args.twamp:
        print(f"  TWAMP        : enabled (server={args.twamp_server}:{args.twamp_port}  "
              f"interval={args.twamp_interval}s  padding={args.twamp_padding}B)")
    print("=" * 72)

    # Discover route depth before baseline — used to filter shallow probes in BOTH phases
    print("  Discovering route depth...")
    _disc = run_traceroute(args.target, args.timeout, args.max_rtt)
    discovery_max_hop = max((h for h, _, r in _disc if r is not None), default=0)
    min_probe_depth = max(3, discovery_max_hop - 5)
    print(f"  Discovery: {discovery_max_hop} hops → min_probe_depth={min_probe_depth} "
          f"(probes reaching fewer hops treated as lost)")
    print(f"  MAX_RTT_ALLOWED: {args.max_rtt}s (traceroute subprocess killed if it exceeds this)")

    # --- OWD setup ---
    tcp_owd      = None
    owd_enabled  = False
    owd_conn     = None
    owd_results  = []
    h2_results   = []

    if args.owd:
        if os.geteuid() != 0:
            print("[WARN] --owd requires root (CAP_NET_RAW for Scapy sniffer); OWD disabled.",
                  file=sys.stderr)
        else:
            tcp_owd = _load_tcp_owd()
            if tcp_owd is not None:
                try:
                    owd_conn = tcp_owd.connect_kernel_http(
                        args.target, args.owd_port, verbose=True)
                    owd_enabled = True
                except Exception as exc:
                    print(f"[WARN] OWD setup failed: {exc}; OWD disabled.", file=sys.stderr)
                    owd_conn = None

    owd_attempt_stats = {}

    # --- TWAMP setup ---
    twamp_mod      = None
    twamp_enabled  = False
    twamp_results  = []

    if args.twamp:
        twamp_mod = _load_twamp_owd()
        if twamp_mod is not None:
            twamp_enabled = True
            print(f"[TWAMP] Reflector: {args.twamp_server}:{args.twamp_port}  "
                  f"interval={args.twamp_interval}s  padding={args.twamp_padding}B")
        else:
            print("[WARN] --twamp requested but twamp_owd.py could not be loaded; TWAMP disabled.",
                  file=sys.stderr)

    twamp_attempt_stats = {}

    # --- Phase 1: Baseline ---
    if owd_enabled:
        _owd_t = threading.Thread(
            target=_owd_worker,
            args=(tcp_owd, args.target, args.owd_port, owd_conn,
                  'BASELINE', args.baseline, args.owd_interval, owd_results,
                  args.owd_timeout, owd_attempt_stats, h2_results),
            daemon=True,
        )
        _owd_t.start()

    if twamp_enabled:
        _twamp_t = threading.Thread(
            target=_twamp_worker,
            args=(twamp_mod, args.twamp_server, args.twamp_port,
                  'BASELINE', args.baseline, args.twamp_interval,
                  twamp_results, args.twamp_timeout, args.twamp_padding,
                  twamp_attempt_stats),
            kwargs={'backend': args.twamp_backend},
            daemon=True,
        )
        _twamp_t.start()

    baseline_data, baseline_probes, baseline_lost, baseline_ts = \
        collect_latency_samples(
            target=args.target,
            duration_sec=args.baseline,
            interval_sec=args.interval,
            timeout=args.timeout,
            phase_name="PHASE 1: BASELINE (no load)",
            min_probe_depth=min_probe_depth,
            max_rtt=args.max_rtt,
        )

    if owd_enabled:
        _owd_t.join()
    if twamp_enabled:
        _twamp_t.join()

    # --- Phase 2: Stress ---
    traffic_proc = start_traffic_gen(
        dl_clients=args.dl_clients,
        ul_clients=args.ul_clients,
        duration_secs=args.stress + 30,
        log_file=traffic_log,
        stats_file=stats_file,
    )

    # Give traffic-gen a few seconds to ramp up
    print(f"  Waiting {TRAFFIC_GEN_RAMP_SECS}s for traffic to ramp up...")
    time.sleep(TRAFFIC_GEN_RAMP_SECS)

    if owd_enabled:
        _owd_t = threading.Thread(
            target=_owd_worker,
            args=(tcp_owd, args.target, args.owd_port, owd_conn,
                  'STRESS', args.stress, args.owd_interval, owd_results,
                  args.owd_timeout, owd_attempt_stats, h2_results),
            daemon=True,
        )
        _owd_t.start()

    if twamp_enabled:
        _twamp_t = threading.Thread(
            target=_twamp_worker,
            args=(twamp_mod, args.twamp_server, args.twamp_port,
                  'STRESS', args.stress, args.twamp_interval,
                  twamp_results, args.twamp_timeout, args.twamp_padding,
                  twamp_attempt_stats),
            kwargs={'backend': args.twamp_backend},
            daemon=True,
        )
        _twamp_t.start()

    try:
        stress_data, stress_probes, stress_lost, stress_ts = \
            collect_latency_samples(
                target=args.target,
                duration_sec=args.stress,
                interval_sec=args.interval,
                timeout=args.timeout,
                phase_name="PHASE 2: STRESS (browsing traffic load)",
                stats_file=stats_file,
                rate_method=rate_method,
                interface=interface,
                min_probe_depth=min_probe_depth,
                max_rtt=args.max_rtt,
            )
    finally:
        stop_traffic_gen(traffic_proc)
        if owd_enabled:
            _owd_t.join()
        if twamp_enabled:
            _twamp_t.join()

    # --- OWD post-processing ---
    if owd_enabled:
        tcp_owd.compute_owd(owd_results, owd_conn)   # HTTP HEAD (port 80) OWD
        # H2 PING OWD already computed per-phase inside _owd_worker
        try:
            owd_conn['sock'].close()
        except Exception:
            pass

    # --- TWAMP post-processing ---
    if twamp_enabled and twamp_results:
        twamp_mod.compute_twamp_owd(twamp_results)

    # --- Analysis ---
    baseline_stats = compute_hop_stats(baseline_data)
    stress_stats = compute_hop_stats(stress_data)

    segments = print_segment_bloat_table(baseline_stats, stress_stats)
    print_ranked_bloat(segments)
    print_network_diagram(segments)
    print_overall_summary(baseline_ts, stress_ts,
                          baseline_probes, baseline_lost,
                          stress_probes, stress_lost,
                          owd_results=owd_results if owd_enabled else None,
                          target=args.target,
                          owd_attempt_stats=owd_attempt_stats if owd_enabled else None,
                          h2_results=h2_results if owd_enabled and h2_results else None,
                          twamp_results=twamp_results if twamp_enabled else None,
                          twamp_attempt_stats=twamp_attempt_stats if twamp_enabled else None)
    if owd_enabled and owd_results:
        print_owd_section(tcp_owd, owd_results,
                          owd_attempt_stats=owd_attempt_stats if owd_enabled else None)
    if twamp_enabled and twamp_results:
        print_twamp_section(twamp_mod, twamp_results,
                            twamp_attempt_stats=twamp_attempt_stats if twamp_enabled else None)
    print_throughput_summary(stress_ts)
    print_time_series_table(baseline_ts, stress_ts)
    print_ascii_chart(baseline_ts, stress_ts,
                      width=args.chart_width, height=args.chart_height,
                      owd_results=owd_results if owd_enabled else None,
                      twamp_results=twamp_results if twamp_enabled else None)
    print_traffic_summary(traffic_log)

    # --- Save results ---
    if args.output:
        save_results_csv(args.output, baseline_stats, stress_stats, segments,
                         baseline_ts, stress_ts,
                         twamp_results=twamp_results if twamp_enabled else None)

    # Cleanup temp stats file
    for f in (stats_file, stats_file + ".tmp", stats_file + ".log"):
        try:
            os.remove(f)
        except OSError:
            pass

    print(f"\n{'='*72}")
    print(f"{'TEST COMPLETE':^72}")
    print(f"{'='*72}")


if __name__ == "__main__":
    main()
