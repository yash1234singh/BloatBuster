#!/usr/bin/env python3
"""
userbufferTest.py — Bufferbloat measurement using real user-browsing traffic as stress.

Two-phase test (same methodology as bufferTest.sh):
  Phase 1: BASELINE — traceroute per-hop latency under idle conditions
  Phase 2: STRESS   — traceroute per-hop latency while traffic-gen.py generates load

Reports per-hop bloat analysis, ranked worst links, ASCII network diagram,
overall latency summary, and time-series ASCII charts showing RTT + data rate.

Usage:
    python3 userbufferTest.py -T <target> [options]

Examples:
    python3 userbufferTest.py -T 8.8.8.8
    python3 userbufferTest.py -T 10.1.2.1 -b 20 -s 60 -d 15 -u 25
    python3 userbufferTest.py -T 1.1.1.1 -o results.csv
"""

import argparse
import csv
import math
import os
import re
import signal
import subprocess
import sys
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
DEFAULT_RATE_METHOD   = 'auto'   # 'auto', 'procnetdev', or 'statsfile'


# ---------------------------------------------------------------------------
# Traceroute parsing
# ---------------------------------------------------------------------------

def run_traceroute(target, timeout=2):
    """Run a single traceroute and return list of (hop_num, ip, rtt_ms) tuples.

    Returns None entries for hops that timed out (* * *).
    """
    cmd = ['traceroute', '-I', '-n', '-w', str(timeout), '-q', '1', target]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True,
                             check=False, timeout=timeout + 10)
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

    Returns (dl_bytes, ul_bytes) or None if not available.
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
            return int(parts[2]), int(parts[3])
    except (OSError, ValueError):
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


def collect_latency_samples(target, duration_sec, interval_sec, timeout,
                            phase_name="PHASE", stats_file=None,
                            rate_method='statsfile', interface=None):
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
    prev_time = start_time
    use_procnetdev = (rate_method == 'procnetdev' and interface)

    # Take initial /proc/net/dev snapshot for delta calculation
    if use_procnetdev:
        snap0 = read_procnetdev(interface)
        if snap0:
            prev_dl, prev_ul = snap0  # rx_bytes = DL, tx_bytes = UL

    print(f"\n{'='*72}")
    method_label = f"/proc/net/dev ({interface})" if use_procnetdev else "stats-file"
    print(f"  {phase_name}: Collecting traceroute samples for {duration_sec}s "
          f"(interval={interval_sec}s, rate={method_label})")
    print(f"{'='*72}")

    while time.time() < end_time:
        now = time.time()
        sample_count += 1
        ts = datetime.now().strftime("%H:%M:%S")
        hops = run_traceroute(target, timeout)
        total_probes += 1

        e2e_rtt = None
        if not hops:
            lost_probes += 1
            rtt_str = "TIMEOUT"
        else:
            # Find last responding hop for end-to-end RTT
            for _, _, h_rtt in reversed(hops):
                if h_rtt is not None:
                    e2e_rtt = h_rtt
                    break
            rtt_str = f"{e2e_rtt:.1f}ms" if e2e_rtt else "*"
            for hop_num, ip, rtt in hops:
                hop_data[hop_num].append((ip, rtt))

        # Read throughput snapshot
        dl_bytes = ul_bytes = 0
        dl_rate = ul_rate = 0.0
        snap = None

        if use_procnetdev:
            snap = read_procnetdev(interface)
            if snap:
                dl_bytes, ul_bytes = snap  # rx = DL, tx = UL
                dt = time.time() - prev_time
                if dt > 0.1:
                    dl_rate = (dl_bytes - prev_dl) * 8 / dt / 1_000_000
                    ul_rate = (ul_bytes - prev_ul) * 8 / dt / 1_000_000
                    prev_dl, prev_ul = dl_bytes, ul_bytes
                    prev_time = time.time()
        elif stats_file:
            snap = read_throughput_snapshot(stats_file)
            if snap:
                dl_bytes, ul_bytes = snap
                dt = time.time() - prev_time
                if dt > 0.1:
                    dl_rate = (dl_bytes - prev_dl) * 8 / dt / 1_000_000
                    ul_rate = (ul_bytes - prev_ul) * 8 / dt / 1_000_000
                    prev_dl, prev_ul = dl_bytes, ul_bytes
                    prev_time = time.time()

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
                'p95': percentile(rtts, 95),
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
    """Per-segment incremental delay analysis."""
    print(f"\n{'='*72}")
    print(f"{'PER-SEGMENT BLOAT ANALYSIS (Incremental Delay)':^72}")
    print(f"{'='*72}")
    print(f"{'Hop':<5}{'Segment':<35}{'Link Base':<12}{'Link P95':<12}{'Bloat':<10}")
    print("-" * 72)

    all_hops = sorted(set(baseline_stats.keys()) | set(stress_stats.keys()))
    segments = []

    prev_ip = "(source)"
    for hop in all_hops:
        b = baseline_stats.get(hop, {})
        s = stress_stats.get(hop, {})
        curr_ip = s.get('ip', b.get('ip', '*'))

        base_avg = b.get('avg', 0)
        stress_p95 = s.get('p95', 0)
        bloat = stress_p95 - base_avg

        segment_label = f"{prev_ip} -> {curr_ip}"
        marker = "  <<<" if bloat > 50 else ""

        print(f"{hop:<5}{segment_label:<35}{base_avg:<12.2f}{stress_p95:<12.2f}"
              f"{bloat:<10.2f}{marker}")
        segments.append((hop, curr_ip, base_avg, stress_p95, bloat))
        prev_ip = curr_ip

    return segments


def print_ranked_bloat(segments):
    """Ranked bloat summary — worst links first."""
    print(f"\n{'='*72}")
    print(f"{'LINK SEGMENTS RANKED BY BLOAT (Worst First)':^72}")
    print(f"{'='*72}")
    print(f"{'IP Address':<20}{'Bloat (ms)':<15}")
    print("-" * 72)

    ranked = sorted(segments, key=lambda x: x[4], reverse=True)
    for _, ip, _, _, bloat in ranked:
        if bloat > 0:
            print(f"{ip:<20}{bloat:<15.2f}ms")


def print_network_diagram(segments):
    """ASCII network path diagram."""
    print(f"\n{'='*72}")
    print(f"{'NETWORK PATH DIAGRAM (Baseline / Stress)':^72}")
    print(f"{'='*72}")

    print(f"\n+{'─'*15}+")
    print(f"|  {'(source)':<12}|")
    print(f"+{'─'*15}+")

    for _, ip, base_avg, stress_p95, bloat in segments:
        marker = "  <<<" if bloat > 50 else ""
        print(f"    |  Base:  {base_avg:.2f} ms")
        print(f"    |  P95:  {stress_p95:.2f} ms")
        print(f"    |  Bloat: {bloat:.2f} ms{marker}")
        print("    v")
        print(f"+{'─'*15}+")
        print(f"| {ip:<14}|")
        print(f"+{'─'*15}+")


def print_overall_summary(baseline_stats, stress_stats,
                          baseline_probes, baseline_lost,
                          stress_probes, stress_lost):
    """End-to-end latency summary."""
    print(f"\n{'='*72}")
    print(f"{'OVERALL LATENCY SUMMARY (End-to-End)':^72}")
    print(f"{'='*72}")
    print(f"{'Phase':<12}{'Samples':<9}{'Loss %':<9}{'Avg (ms)':<11}"
          f"{'P95 (ms)':<11}{'Max (ms)':<11}")
    print("-" * 72)

    def get_e2e(stats):
        if not stats:
            return []
        last_hop = max(stats.keys())
        return stats[last_hop].get('rtts', [])

    base_rtts = get_e2e(baseline_stats)
    stress_rtts = get_e2e(stress_stats)

    base_loss_pct = (baseline_lost / baseline_probes * 100) if baseline_probes else 0
    stress_loss_pct = (stress_lost / stress_probes * 100) if stress_probes else 0

    if base_rtts:
        print(f"{'BASELINE':<12}{len(base_rtts):<9}{base_loss_pct:<9.1f}"
              f"{sum(base_rtts)/len(base_rtts):<11.2f}"
              f"{percentile(base_rtts, 95):<11.2f}{max(base_rtts):<11.2f}")
    else:
        print(f"{'BASELINE':<12}{'0':<9}{base_loss_pct:<9.1f}{'—':<11}{'—':<11}{'—':<11}")

    if stress_rtts:
        print(f"{'STRESS':<12}{len(stress_rtts):<9}{stress_loss_pct:<9.1f}"
              f"{sum(stress_rtts)/len(stress_rtts):<11.2f}"
              f"{percentile(stress_rtts, 95):<11.2f}{max(stress_rtts):<11.2f}")
    else:
        print(f"{'STRESS':<12}{'0':<9}{stress_loss_pct:<9.1f}{'—':<11}{'—':<11}{'—':<11}")


# ---------------------------------------------------------------------------
# Time-series table and ASCII charts
# ---------------------------------------------------------------------------

def print_time_series_table(baseline_ts, stress_ts):
    """Print a time-aligned table of RTT and throughput for both phases."""
    print(f"\n{'='*80}")
    print(f"{'TIME-SERIES DATA (1-second intervals)':^80}")
    print(f"{'='*80}")
    print(f"{'Time':<10}│{'Phase':<10}│{'RTT ms':>8} │{'DL Mbps':>9} {'UL Mbps':>9} │"
          f"{'DL Total':>10} {'UL Total':>10}")
    print(f"{'─'*10}┼{'─'*10}┼{'─'*9}┼{'─'*20}┼{'─'*21}")

    for entry in baseline_ts:
        rtt_s = f"{entry['e2e_rtt']:.1f}" if entry['e2e_rtt'] else "-"
        print(f"{entry['ts']:<10}│{'BASE':<10}│{rtt_s:>8} │"
              f"{'':>9} {'':>9} │{'':>10} {'':>10}")

    for entry in stress_ts:
        rtt_s = f"{entry['e2e_rtt']:.1f}" if entry['e2e_rtt'] else "-"
        dl_r = f"{entry['dl_rate_mbps']:.1f}" if entry['dl_rate_mbps'] > 0 else "-"
        ul_r = f"{entry['ul_rate_mbps']:.1f}" if entry['ul_rate_mbps'] > 0 else "-"
        dl_mb = f"{entry['dl_bytes']/1048576:.1f}MB" if entry['dl_bytes'] > 0 else "-"
        ul_mb = f"{entry['ul_bytes']/1048576:.1f}MB" if entry['ul_bytes'] > 0 else "-"
        print(f"{entry['ts']:<10}│{'STRESS':<10}│{rtt_s:>8} │"
              f"{dl_r:>9} {ul_r:>9} │{dl_mb:>10} {ul_mb:>10}")


def print_ascii_chart(baseline_ts, stress_ts, width=80, height=20):
    """Render a dual-axis ASCII chart: throughput (left) + RTT (right).

    DL throughput = ▓, UL throughput = ░, RTT = ●
    Baseline RTT shown as ○ for comparison.
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

    if not rtt_values and not all_rates:
        return

    max_rtt = max(rtt_values) * 1.1 if rtt_values else 100
    max_rate = max(all_rates) * 1.1 if all_rates else 10
    if max_rtt < 1:
        max_rtt = 1
    if max_rate < 0.1:
        max_rate = 1

    # Determine how many data points to show
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

    print(f"\n{'='*80}")
    print(f"{'ASCII CHART: Throughput (DL ▓, UL ░) + RTT (●)':^80}")
    print(f"{'='*80}")
    print(f"  Y-axis left: Throughput (0-{max_rate:.0f} Mbps)   "
          f"Y-axis right: RTT (0-{max_rtt:.0f} ms)\n")

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

    print("\n  Legend: ▓ DL Mbps   ░ UL Mbps   ○ Baseline RTT (ms)   ● Stress RTT (ms)")


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
                  f"{percentile(rates, 50):>8.2f}{percentile(rates, 10):>8.2f}"
                  f"{percentile(rates, 90):>8.2f}{len(rates):>8}")
        else:
            print(f"{label:<12}{'—':>10}{'—':>8}{'—':>8}{'—':>8}{'—':>8}{'0':>8}")

    # Total data transferred
    if stress_ts:
        last = stress_ts[-1]
        dl_mb = last['dl_bytes'] / 1048576
        ul_mb = last['ul_bytes'] / 1048576
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
                     baseline_ts, stress_ts):
    """Save detailed results to CSV."""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Section 1: Per-hop bloat
            writer.writerow(['# PER-HOP BLOAT'])
            writer.writerow(['hop', 'ip', 'baseline_avg_ms', 'baseline_p95_ms',
                             'stress_avg_ms', 'stress_p95_ms', 'bloat_ms'])
            for hop_num, ip, base_avg, stress_p95, bloat in segments:
                b = baseline_stats.get(hop_num, {})
                s = stress_stats.get(hop_num, {})
                writer.writerow([
                    hop_num, ip,
                    f"{base_avg:.2f}",
                    f"{b.get('p95', 0):.2f}",
                    f"{s.get('avg', 0):.2f}",
                    f"{stress_p95:.2f}",
                    f"{bloat:.2f}",
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

        print(f"\nResults saved to: {output_file}")
    except OSError as exc:
        print(f"[WARN] Could not write output file: {exc}", file=sys.stderr)


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
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
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
                   help="Traceroute wait timeout in seconds")
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
                   choices=['auto', 'procnetdev', 'statsfile'],
                   help="Throughput measurement method: "
                        "'procnetdev' reads /proc/net/dev (wire-level, smooth — Linux only), "
                        "'statsfile' reads traffic-gen.py's stats file (app-level, bursty), "
                        "'auto' uses procnetdev on Linux, statsfile otherwise")
    p.add_argument('-I', '--interface', type=str, default=None,
                   help="Network interface for /proc/net/dev measurement "
                        "(auto-detected from default route if omitted)")
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
        if os.path.exists('/proc/net/dev'):
            rate_method = 'procnetdev'
        else:
            rate_method = 'statsfile'

    if rate_method == 'procnetdev':
        if not os.path.exists('/proc/net/dev'):
            print("[WARN] /proc/net/dev not available, falling back to statsfile method.",
                  file=sys.stderr)
            rate_method = 'statsfile'
        elif not interface:
            interface = detect_default_interface()
            if not interface:
                print("[WARN] Could not detect default interface, falling back to statsfile.",
                      file=sys.stderr)
                rate_method = 'statsfile'

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
    print("=" * 72)

    # --- Phase 1: Baseline ---
    baseline_data, baseline_probes, baseline_lost, baseline_ts = \
        collect_latency_samples(
            target=args.target,
            duration_sec=args.baseline,
            interval_sec=args.interval,
            timeout=args.timeout,
            phase_name="PHASE 1: BASELINE (no load)",
        )

    # --- Phase 2: Stress ---
    traffic_proc = start_traffic_gen(
        dl_clients=args.dl_clients,
        ul_clients=args.ul_clients,
        duration_secs=args.stress + 30,
        log_file=traffic_log,
        stats_file=stats_file,
    )

    # Give traffic-gen a few seconds to ramp up
    print("  Waiting 5s for traffic to ramp up...")
    time.sleep(5)

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
            )
    finally:
        stop_traffic_gen(traffic_proc)

    # --- Analysis ---
    baseline_stats = compute_hop_stats(baseline_data)
    stress_stats = compute_hop_stats(stress_data)

    segments = print_segment_bloat_table(baseline_stats, stress_stats)
    print_ranked_bloat(segments)
    print_network_diagram(segments)
    print_overall_summary(baseline_stats, stress_stats,
                          baseline_probes, baseline_lost,
                          stress_probes, stress_lost)
    print_throughput_summary(stress_ts)
    print_time_series_table(baseline_ts, stress_ts)
    print_ascii_chart(baseline_ts, stress_ts,
                      width=args.chart_width, height=args.chart_height)
    print_traffic_summary(traffic_log)

    # --- Save results ---
    if args.output:
        save_results_csv(args.output, baseline_stats, stress_stats, segments,
                         baseline_ts, stress_ts)

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
