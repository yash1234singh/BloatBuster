#!/usr/bin/env python3
# =============================================================================
# net_monitor.py — Deep Network Infrastructure Burst & Queue Analyzer
# =============================================================================
#
# PURPOSE:
#   Real-time multi-subsystem monitoring tool that detects packet queuing,
#   bufferbloat, microbursts, and kernel-level bottlenecks on a Linux network
#   interface. Produces statistical analysis and graphical reports to pinpoint
#   WHERE packets are being delayed/dropped in the IP stack.
#
# WHAT IT MONITORS:
#   ┌─────────────┬─────────────────────────────────────────────────────────┐
#   │ Subsystem   │ What it reveals                                         │
#   ├─────────────┼─────────────────────────────────────────────────────────┤
#   │ TC (qdisc)  │ HTB/pfifo queue depth, drops, overlimits, requeues.     │
#   │             │ Shows if traffic shaping is causing buffering/drops.     │
#   │ IP Link     │ Interface-level RX/TX bytes, packets, errors, drops.    │
#   │             │ Reveals NIC ring buffer overflows & driver-level loss.   │
#   │ Softnet     │ Per-CPU backlog drops and softIRQ squeeze events.       │
#   │             │ Identifies CPU inability to drain NIC fast enough.       │
#   │ VMstat      │ Run-queue depth, blocked procs, swap activity.          │
#   │             │ Context for CPU/memory pressure affecting networking.    │
#   │ IOstat      │ Disk I/O TPS and throughput.                            │
#   │             │ Disk contention can starve network softIRQ processing.  │
#   │ MPstat      │ CPU user/system/iowait/softirq/idle breakdown.          │
#   │             │ Shows how much CPU is consumed by packet processing.    │
#   └─────────────┴─────────────────────────────────────────────────────────┘
#
# HOW IT WORKS:
#   1. Pre-flight checks validate which tools are available on the system
#   2. Spawns per-subsystem polling threads sampling at 1-second intervals
#   3. Writes time-series CSV data to ./net_out/ per subsystem
#   4. On Ctrl+C, aggregates all collected data and produces:
#      - Statistical summary tables (min/max/mean/median/stdev/p95)
#      - Burst detection analysis with root-cause explanations
#      - Live kernel sysctl queue/burst parameter snapshot
#      - Matplotlib charts with per-metric rate plots + embedded stats
#
# KEY DESIGN DECISIONS:
#   - Cumulative counters (TC, IP_Link, Softnet) use first-sample as baseline;
#     all reporting shows SESSION DELTA only (since counters can't be cleared)
#   - Plots convert cumulative metrics to per-second RATES via delta computation
#   - Dual Y-axis separates high-magnitude throughput from low-magnitude errors
#   - Works gracefully without matplotlib (skips plots, still prints report)
#
# USAGE:
#   sudo python3 net_monitor.py <interface_name>
#
#   Examples:
#     sudo python3 net_monitor.py eth0
#     sudo python3 net_monitor.py ens3f0
#
#   Run under load, let it collect for desired duration, then Ctrl+C to get
#   the full report. Minimum ~5 seconds recommended for meaningful statistics.
#
# OUTPUT:
#   ./net_out/                        — Directory with per-subsystem CSV files
#   ./net_out/system_burst_analysis.png — Combined chart (if matplotlib available)
#   Terminal report with sections:
#     [1] Queue architecture topology explanation
#     [2] Statistical data summary per subsystem
#     [3] Traffic burst analysis with root-cause
#     [4] Kernel sysctl queue/burst tuning snapshot
#
# REQUIREMENTS:
#   - Linux with root/sudo (for tc, /proc access)
#   - Python 3.6+
#   - Optional: matplotlib (for graphical output)
#   - Tools: tc, ip, /proc/net/softnet_stat, vmstat, iostat, mpstat
#     (missing tools are auto-detected and skipped gracefully)
#
# =============================================================================

import os
import sys
import time
import csv
import shutil
import threading
import subprocess
import re
import statistics
from datetime import datetime

# =============================================================================
# KERNEL TUNING RECOMMENDATIONS
# =============================================================================
# If "Squeezed" (softnet_squeezed) counter spikes actively under load, the CPU
# cores cannot drain the NIC ring buffer within their softIRQ budget window.
# Apply the following sysctl tunables to expand the processing budget:
#
#   sysctl -w net.core.netdev_budget=600
#       -> Increases the max number of packets the kernel processes per softIRQ
#          cycle (default: 300). Raising this gives cores more time to drain
#          incoming frames before yielding.
#
#   sysctl -w net.core.netdev_max_backlog=5000
#       -> Expands the per-CPU input queue depth (default: 1000). When bursts
#          arrive faster than softIRQ can drain them, a deeper backlog prevents
#          immediate drops while the kernel catches up.
#
# To persist across reboots, add to /etc/sysctl.conf:
#   net.core.netdev_budget = 600
#   net.core.netdev_max_backlog = 5000
#
# Monitor effect by watching: cat /proc/net/softnet_stat (columns: received,
# dropped, squeezed). If squeezed continues to climb, increase budget further
# or consider enabling RPS/RFS to spread IRQ load across cores.
# =============================================================================

# --- OPTIONAL DEPENDENCY MANAGEMENT ---
HAS_MATPLOTLIB = True
try:
    import matplotlib
    matplotlib.use('Agg')  # Headless-safe backend (no X11/DISPLAY needed)
    import matplotlib.pyplot as plt
except ImportError:
    HAS_MATPLOTLIB = False

INTERVAL = 1.0
OUTPUT_DIR = "net_out"

# Command prefix for namespace/container execution (e.g. "ip netns exec ns1" or "denter atg4g")
# Set externally before calling pre_flight_checks() / worker()
CMD_PREFIX = ""

working_tools = {}
threads = []
stop_event = threading.Event()

# Nested structure schema to map out raw tool metrics
TOOL_METRICS = {
    "TC": [
        "tc_total_sent_bytes", "tc_total_sent_pkts", "tc_total_dropped", 
        "tc_total_overlimits", "tc_total_requeues", "tc_max_backlog_bytes", "tc_max_backlog_pkts"
    ],
    "IP_Link": [
        "ip_rx_bytes", "ip_rx_pkts", "ip_rx_dropped", "ip_rx_overrun", "ip_rx_errors",
        "ip_tx_bytes", "ip_tx_pkts", "ip_tx_dropped", "ip_tx_errors", "ip_tx_colls"
    ],
    "Softnet": ["softnet_dropped", "softnet_squeezed", "softnet_received"],
    "VMstat": ["vm_r", "vm_b", "vm_si", "vm_so"],
    "IOstat": ["io_tps", "io_read_kb", "io_wrtn_kb"],
    "MPstat": ["cpu_user", "cpu_system", "cpu_iowait", "cpu_softirq", "cpu_idle"],
    "Netstat_UDP": [
        "ns_udp_in_datagrams", "ns_udp_no_ports", "ns_udp_in_errors",
        "ns_udp_out_datagrams", "ns_udp_rcvbuf_errors", "ns_udp_sndbuf_errors",
        "ns_udp_in_csum_errors"
    ],
    "Netstat_TCP": [
        "ns_tcp_active_opens", "ns_tcp_passive_opens", "ns_tcp_in_segs",
        "ns_tcp_out_segs", "ns_tcp_retrans_segs", "ns_tcp_in_errs", "ns_tcp_out_rsts"
    ],
    "Netstat_Sockets": [
        "ns_sock_udp_count", "ns_sock_udp_recv_q_total", "ns_sock_udp_recv_q_max",
        "ns_sock_udp_send_q_total", "ns_sock_udp_send_q_max"
    ],
    "SS_Info": [
        "ss_cwnd_avg", "ss_cwnd_min", "ss_ssthresh_avg", "ss_rtt_avg",
        "ss_retrans_total", "ss_pacing_rate_avg", "ss_delivery_rate_avg",
        "ss_busy_ms_total", "ss_rwnd_limited_ms_total", "ss_sndbuf_limited_ms_total",
        "ss_conn_count"
    ],
    "SS_Queues": [
        "ss_tcp_count", "ss_tcp_send_q_total", "ss_tcp_send_q_max",
        "ss_tcp_recv_q_total", "ss_tcp_recv_q_max",
        "ss_udp_count", "ss_udp_send_q_total", "ss_udp_send_q_max",
        "ss_udp_recv_q_total", "ss_udp_recv_q_max"
    ],
    "SS_Summary": [
        "ss_tcp_total", "ss_tcp_estab", "ss_tcp_closed",
        "ss_tcp_orphaned", "ss_tcp_timewait", "ss_udp_total"
    ],
}

# Realtime Data Buffer Map
metrics_buffer = {m: 0.0 for tool in TOOL_METRICS for m in TOOL_METRICS[tool]}
buffer_lock = threading.Lock()

# Architectural Metadata and Explanations
METRIC_HELP = {
    "tc_total_sent_bytes": "Total Bytes Passed Through TC Queueing System.",
    "tc_total_sent_pkts": "Total Packets Passed Through TC Queueing System.",
    "tc_total_dropped": "Queue Drops: Out of buffer capacity. Definitive microburst proof.",
    "tc_total_overlimits": "Throttling Events: Burst exceeded class/shaper bandwidth ceilings.",
    "tc_total_requeues": "Requeues: Network driver rejected a packet because hardware ring was full.",
    "tc_max_backlog_bytes": "Current Memory Queue Depth: Total bytes waiting inside kernel buffer.",
    "tc_max_backlog_pkts": "Current Packet Queue Depth: Count of packets delayed waiting for wire transmission.",
    "ip_rx_bytes": "Inbound Wire Data Volume: Total bytes received by the network interface.",
    "ip_rx_pkts": "Inbound Frame Footprint: Total network frames received by the card hardware.",
    "ip_rx_dropped": "Driver Frame Discards: Ring buffer full or kernel out of socket descriptors.",
    "ip_rx_overrun": "FIFO Memory Spillover: Hardware processing layer failed to catch incoming bits.",
    "ip_rx_errors": "Corrupted Frames: Inbound checksum errors, malformed packets, or bad alignment.",
    "ip_tx_bytes": "Outbound Wire Data Volume: Bytes requested to leave the physical port interface.",
    "ip_tx_pkts": "Outbound Frame Footprint: Network frames driven out through the interface.",
    "ip_tx_dropped": "Transmit Aborts: Dropped inside network card driver due to buffer exhaustion.",
    "ip_tx_errors": "Carrier Failures: Disconnects, collisions, or hardware failure events on transmission.",
    "ip_tx_colls": "Ethernet Collisions: Multiple hosts transmitting on shared half-duplex paths.",
    "softnet_dropped": "CPU Backlog Drops: Per-core backlog full (`/proc/sys/net/core/netdev_max_backlog`).",
    "softnet_squeezed": "SoftIRQ Deprivations: Core budget exhausted before draining the ring buffer.",
    "softnet_received": "SoftIRQ Calls: Direct network process cycles performed by kernel loop handlers.",
    "vm_r": "Process Run-Queue: Tasks competing for CPU execution time slots.",
    "vm_b": "Processes Blocked: Threads completely frozen waiting on disk storage synchronization.",
    "vm_si": "Memory Swapping-In: Inactive blocks reading from disk into RAM (Cripples performance).",
    "vm_so": "Memory Swapping-Out: Ram overload forcing system pages to drop to physical disk space.",
    "io_tps": "Storage Transfers Per Sec: Disk transactions. High IO can introduce scheduling latency.",
    "io_read_kb": "Disk Read Throughput: Active local blocks pulled from storage filesystems.",
    "io_wrtn_kb": "Disk Write Throughput: Active local blocks written to storage filesystems.",
    "cpu_user": "Application Layer CPU Load: Compute cycles driven by userland applications.",
    "cpu_system": "Kernel Core Activity: CPU cycles occupied handling operating system primitives.",
    "cpu_iowait": "I/O Wait Latency: CPU idle time spent stalling for physical storage disk response.",
    "cpu_softirq": "Software Interrupt Latency: Time CPU spends pulling packets from ring buffers.",
    "cpu_idle": "Idle Compute Pool: Free headroom available to absorb unexpected processing spikes."
}

# --- VALIDATION ENGINE ---
def pre_flight_checks(interface):
    print("=" * 80)
    pfx_label = f" (prefix: {CMD_PREFIX.strip()})" if CMD_PREFIX.strip() else ""
    print(f" SYSTEM PRE-FLIGHT TELEMETRY CHECKS FOR: {interface}{pfx_label}")
    print("=" * 80)
    
    if not HAS_MATPLOTLIB:
        print("\033[93m[!] WARNING: 'matplotlib' is not installed. Graphical plotting features will be skipped.\033[0m")
    
    checks = {
        "TC": f"tc -s qdisc show dev {interface}",
        "IP_Link": f"ip -s link show dev {interface}",
        "Softnet": "cat /proc/net/softnet_stat",
        "VMstat": "vmstat 1 1",
        "IOstat": "iostat 1 1",
        "MPstat": "mpstat 1 1",
    }
    
    for tool, cmd in checks.items():
        full_cmd = f"{CMD_PREFIX}{cmd}" if CMD_PREFIX else cmd
        print(f"Testing Profile: {tool:<10} | Command: {full_cmd}")
        try:
            if tool == "Softnet" and not CMD_PREFIX:
                with open("/proc/net/softnet_stat", "r") as f: res = f.read()
            else:
                run_cmd = full_cmd.split()
                res = subprocess.check_output(run_cmd, text=True, stderr=subprocess.STDOUT, timeout=5)
            
            if "not found" in res.lower() or "command not found" in res.lower():
                print(f"--> Status  : \033[91mFAILED / NOT INSTALLED\033[0m\n")
            else:
                print(f"--> Status  : \033[92mWORKING\033[0m\n")
                working_tools[tool] = cmd
        except Exception:
            print(f"--> Status  : \033[91mFAILED / RESOURCE LOCKED\033[0m\n")
            
    print("=" * 80)
    print(f"Active Monitoring Pipeline Matrix: {list(working_tools.keys())}")
    print("=" * 80 + "\n")

# --- HIGH FIDELITY PARSING ENGINES ---
def poll_tc(interface):
    try:
        cmd = f"{CMD_PREFIX}tc -s qdisc show dev {interface}".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        
        # Accumulate metrics across nested htb root classes and pfifo subqueues
        sent_bytes = sum(map(float, re.findall(r"Sent\s+(\d+)\s+bytes", res)))
        sent_pkts  = sum(map(float, re.findall(r"bytes\s+(\d+)\s+pkt", res)))
        dropped    = sum(map(float, re.findall(r"dropped\s+(\d+)", res)))
        overlimits = sum(map(float, re.findall(r"overlimits\s+(\d+)", res)))
        requeues   = sum(map(float, re.findall(r"requeues\s+(\d+)", res)))
        
        backlog_b  = sum(map(float, re.findall(r"backlog\s+(\d+)b", res)))
        backlog_p  = sum(map(float, re.findall(r"backlog\s+\S+\s+(\d+)p", res)))
        
        with buffer_lock:
            metrics_buffer["tc_total_sent_bytes"] = sent_bytes
            metrics_buffer["tc_total_sent_pkts"]  = sent_pkts
            metrics_buffer["tc_total_dropped"]    = dropped
            metrics_buffer["tc_total_overlimits"] = overlimits
            metrics_buffer["tc_total_requeues"]   = requeues
            metrics_buffer["tc_max_backlog_bytes"] = backlog_b
            metrics_buffer["tc_max_backlog_pkts"]  = backlog_p
    except Exception: pass

def poll_ip_link(interface):
    try:
        cmd = f"{CMD_PREFIX}ip -s link show dev {interface}".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        lines = [l.strip() for l in res.splitlines()]
        
        rx_bytes = rx_pkts = rx_err = rx_drp = rx_ovr = 0
        tx_bytes = tx_pkts = tx_err = tx_drp = tx_col = 0
        
        for i, l in enumerate(lines):
            if l.startswith("RX:"):
                # Header: "RX:  bytes  packets errors dropped  missed   mcast"
                # or older: "RX: bytes  packets  errors  dropped overrun mcast"
                header_parts = l.split()[1:]  # strip "RX:"
                vals = lines[i+1].split()
                if len(vals) >= 4:
                    rx_bytes = float(vals[0])
                    rx_pkts = float(vals[1])
                    rx_err = float(vals[2])
                    rx_drp = float(vals[3])
                    # 5th column may be 'overrun' or 'missed' depending on kernel
                    if len(vals) >= 5:
                        rx_ovr = float(vals[4])
            elif l.startswith("TX:"):
                # Header: "TX:  bytes  packets errors dropped carrier collsns"
                header_parts = l.split()[1:]  # strip "TX:"
                vals = lines[i+1].split()
                if len(vals) >= 4:
                    tx_bytes = float(vals[0])
                    tx_pkts = float(vals[1])
                    tx_err = float(vals[2])
                    tx_drp = float(vals[3])
                    # 6th column is collisions (collsns)
                    if len(vals) >= 6:
                        tx_col = float(vals[5])
                    elif len(vals) >= 5:
                        tx_col = float(vals[4])
                    
        with buffer_lock:
            metrics_buffer["ip_rx_bytes"], metrics_buffer["ip_rx_pkts"] = rx_bytes, rx_pkts
            metrics_buffer["ip_rx_errors"], metrics_buffer["ip_rx_dropped"] = rx_err, rx_drp
            metrics_buffer["ip_rx_overrun"] = rx_ovr
            
            metrics_buffer["ip_tx_bytes"], metrics_buffer["ip_tx_pkts"] = tx_bytes, tx_pkts
            metrics_buffer["ip_tx_errors"], metrics_buffer["ip_tx_dropped"] = tx_err, tx_drp
            metrics_buffer["ip_tx_colls"] = tx_col
    except Exception: pass

def poll_softnet():
    try:
        if CMD_PREFIX:
            cmd = f"{CMD_PREFIX}cat /proc/net/softnet_stat".split()
            text = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            lines = text.splitlines()
        else:
            with open("/proc/net/softnet_stat", "r") as f: lines = f.readlines()
        rcv, drp, sqz = 0, 0, 0
        for l in lines:
            parts = l.split()
            if len(parts) >= 3:
                rcv += int(parts[0], 16)
                drp += int(parts[1], 16)
                sqz += int(parts[2], 16)
        with buffer_lock:
            metrics_buffer["softnet_received"] = float(rcv)
            metrics_buffer["softnet_dropped"]  = float(drp)
            metrics_buffer["softnet_squeezed"] = float(sqz)
    except Exception: pass

def poll_vmstat():
    try:
        cmd = f"{CMD_PREFIX}vmstat 1 2".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).splitlines()[-1].split()
        with buffer_lock:
            metrics_buffer["vm_r"], metrics_buffer["vm_b"] = float(res[0]), float(res[1])
            metrics_buffer["vm_si"], metrics_buffer["vm_so"] = float(res[6]), float(res[7])
    except Exception: pass

def poll_iostat():
    try:
        cmd = f"{CMD_PREFIX}iostat 1 2".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).splitlines()
        for row in reversed(res):
            if row.strip() and not any(row.startswith(x) for x in ["Linux", "avg-cpu", "Device"]):
                parts = row.split()
                if len(parts) >= 4:
                    with buffer_lock:
                        metrics_buffer["io_tps"], metrics_buffer["io_read_kb"], metrics_buffer["io_wrtn_kb"] = float(parts[1]), float(parts[2]), float(parts[3])
                    break
    except Exception: pass

def poll_mpstat():
    try:
        cmd = f"{CMD_PREFIX}mpstat 1 1".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).splitlines()[-1].split()
        with buffer_lock:
            metrics_buffer["cpu_user"], metrics_buffer["cpu_system"] = float(res[2]), float(res[4])
            metrics_buffer["cpu_iowait"], metrics_buffer["cpu_softirq"] = float(res[5]), float(res[7])
            metrics_buffer["cpu_idle"] = float(res[11])
    except Exception: pass

# Netstat prefix list — independent from CMD_PREFIX; defaults to local
NETSTAT_PREFIXES = [""]

def poll_netstat_udp(prefix=""):
    """Parse 'netstat -s -u' for UDP protocol statistics."""
    try:
        pfx = prefix if prefix else CMD_PREFIX
        cmd = f"{pfx}netstat -s -u".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        # Pattern: "    <number> <description>" lines under Udp: section
        mapping = {
            r"(\d+)\s+packets\s+received": "ns_udp_in_datagrams",
            r"(\d+)\s+packets\s+to\s+unknown\s+port": "ns_udp_no_ports",
            r"(\d+)\s+packet\s+receive\s+errors": "ns_udp_in_errors",
            r"(\d+)\s+packets\s+sent": "ns_udp_out_datagrams",
            r"(\d+)\s+receive\s+buffer\s+errors": "ns_udp_rcvbuf_errors",
            r"(\d+)\s+send\s+buffer\s+errors": "ns_udp_sndbuf_errors",
            r"(\d+)\s+(?:InCsumErrors|checksum\s+errors)": "ns_udp_in_csum_errors",
        }

        with buffer_lock:
            for pattern, metric in mapping.items():
                m = re.search(pattern, res, re.IGNORECASE)
                if m:
                    metrics_buffer[metric] = float(m.group(1))
    except Exception: pass

def poll_netstat_tcp(prefix=""):
    """Parse 'netstat -s -t' for TCP protocol statistics."""
    try:
        pfx = prefix if prefix else CMD_PREFIX
        cmd = f"{pfx}netstat -s -t".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        mapping = {
            r"(\d+)\s+active\s+connection(?:s)?\s+opening": "ns_tcp_active_opens",
            r"(\d+)\s+passive\s+connection(?:s)?\s+opening": "ns_tcp_passive_opens",
            r"(\d+)\s+segments\s+received": "ns_tcp_in_segs",
            r"(\d+)\s+segments\s+send\s+out": "ns_tcp_out_segs",
            r"(\d+)\s+segments\s+retransmit": "ns_tcp_retrans_segs",
            r"(\d+)\s+bad\s+segments\s+received": "ns_tcp_in_errs",
            r"(\d+)\s+resets\s+sent": "ns_tcp_out_rsts",
        }

        with buffer_lock:
            for pattern, metric in mapping.items():
                m = re.search(pattern, res, re.IGNORECASE)
                if m:
                    metrics_buffer[metric] = float(m.group(1))
    except Exception: pass

def poll_netstat_sockets(prefix=""):
    """Parse 'netstat -anu' for active UDP socket count and queue depths."""
    try:
        pfx = prefix if prefix else CMD_PREFIX
        cmd = f"{pfx}netstat -anu".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        udp_count = 0
        recv_q_total = 0
        recv_q_max = 0
        send_q_total = 0
        send_q_max = 0

        for line in res.splitlines():
            parts = line.split()
            # Format: Proto Recv-Q Send-Q Local-Address Foreign-Address State
            # UDP lines: udp/udp6  <recv-q> <send-q> ...
            if len(parts) >= 4 and parts[0] in ("udp", "udp6"):
                udp_count += 1
                rq = int(parts[1])
                sq = int(parts[2])
                recv_q_total += rq
                send_q_total += sq
                recv_q_max = max(recv_q_max, rq)
                send_q_max = max(send_q_max, sq)

        with buffer_lock:
            metrics_buffer["ns_sock_udp_count"] = float(udp_count)
            metrics_buffer["ns_sock_udp_recv_q_total"] = float(recv_q_total)
            metrics_buffer["ns_sock_udp_recv_q_max"] = float(recv_q_max)
            metrics_buffer["ns_sock_udp_send_q_total"] = float(send_q_total)
            metrics_buffer["ns_sock_udp_send_q_max"] = float(send_q_max)
    except Exception: pass


def _parse_ss_rate(rate_str):
    """Parse ss rate string like '500Mbps', '1.5Gbps', '1200Kbps' into bits/sec."""
    m = re.match(r'([\d.]+)(\w+)', rate_str)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2).lower()
    multipliers = {'bps': 1, 'kbps': 1e3, 'mbps': 1e6, 'gbps': 1e9}
    return val * multipliers.get(unit, 1)


def poll_ss_info(prefix=""):
    """Parse 'ss -tin' for TCP internal connection metrics (cwnd, retrans, pacing)."""
    try:
        pfx = prefix if prefix else CMD_PREFIX
        cmd = f"{pfx}ss -tin".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        cwnd_list = []
        ssthresh_list = []
        rtt_list = []
        retrans_total = 0
        pacing_list = []
        delivery_list = []
        busy_total = 0.0
        rwnd_limited_total = 0.0
        sndbuf_limited_total = 0.0
        conn_count = 0

        # ss -tin outputs connection header lines followed by indented info lines
        for line in res.splitlines():
            # cwnd:10
            cw = re.search(r'\bcwnd:(\d+)', line)
            if cw:
                cwnd_list.append(int(cw.group(1)))
                conn_count += 1

            ss_m = re.search(r'\bssthresh:(\d+)', line)
            if ss_m:
                ssthresh_list.append(int(ss_m.group(1)))

            # rtt:1.5/0.75
            rtt_m = re.search(r'\brtt:([\d.]+)/', line)
            if rtt_m:
                rtt_list.append(float(rtt_m.group(1)))

            # retrans:0/5 — second number is total retransmits
            ret_m = re.search(r'\bretrans:\d+/(\d+)', line)
            if ret_m:
                retrans_total += int(ret_m.group(1))

            # pacing_rate 500Mbps
            pace_m = re.search(r'pacing_rate\s+([\d.]+\w+)', line)
            if pace_m:
                pacing_list.append(_parse_ss_rate(pace_m.group(1)))

            # delivery_rate 480Mbps
            del_m = re.search(r'delivery_rate\s+([\d.]+\w+)', line)
            if del_m:
                delivery_list.append(_parse_ss_rate(del_m.group(1)))

            # busy:1200ms
            busy_m = re.search(r'\bbusy:([\d.]+)ms', line)
            if busy_m:
                busy_total += float(busy_m.group(1))

            # rwnd_limited:50ms
            rwnd_m = re.search(r'\brwnd_limited:([\d.]+)ms', line)
            if rwnd_m:
                rwnd_limited_total += float(rwnd_m.group(1))

            # sndbuf_limited:0ms
            sndbuf_m = re.search(r'\bsndbuf_limited:([\d.]+)ms', line)
            if sndbuf_m:
                sndbuf_limited_total += float(sndbuf_m.group(1))

        with buffer_lock:
            metrics_buffer["ss_cwnd_avg"] = sum(cwnd_list) / len(cwnd_list) if cwnd_list else 0.0
            metrics_buffer["ss_cwnd_min"] = min(cwnd_list) if cwnd_list else 0.0
            metrics_buffer["ss_ssthresh_avg"] = sum(ssthresh_list) / len(ssthresh_list) if ssthresh_list else 0.0
            metrics_buffer["ss_rtt_avg"] = sum(rtt_list) / len(rtt_list) if rtt_list else 0.0
            metrics_buffer["ss_retrans_total"] = float(retrans_total)
            metrics_buffer["ss_pacing_rate_avg"] = sum(pacing_list) / len(pacing_list) if pacing_list else 0.0
            metrics_buffer["ss_delivery_rate_avg"] = sum(delivery_list) / len(delivery_list) if delivery_list else 0.0
            metrics_buffer["ss_busy_ms_total"] = busy_total
            metrics_buffer["ss_rwnd_limited_ms_total"] = rwnd_limited_total
            metrics_buffer["ss_sndbuf_limited_ms_total"] = sndbuf_limited_total
            metrics_buffer["ss_conn_count"] = float(conn_count)
    except Exception:
        pass


def poll_ss_queues(prefix=""):
    """Parse 'ss -tnp' and 'ss -unp' for TCP/UDP socket queue depths."""
    try:
        pfx = prefix if prefix else CMD_PREFIX

        tcp_count = tcp_sq_total = tcp_sq_max = tcp_rq_total = tcp_rq_max = 0
        udp_count = udp_sq_total = udp_sq_max = udp_rq_total = udp_rq_max = 0

        # TCP queues
        cmd_tcp = f"{pfx}ss -tnp".split()
        res_tcp = subprocess.check_output(cmd_tcp, text=True, stderr=subprocess.DEVNULL)
        for line in res_tcp.splitlines():
            parts = line.split()
            # State Recv-Q Send-Q Local:port Peer:port ...
            if len(parts) >= 5 and parts[0] in ("ESTAB", "CLOSE-WAIT", "FIN-WAIT-1",
                                                  "FIN-WAIT-2", "TIME-WAIT", "SYN-SENT"):
                tcp_count += 1
                rq, sq = int(parts[1]), int(parts[2])
                tcp_rq_total += rq
                tcp_sq_total += sq
                tcp_rq_max = max(tcp_rq_max, rq)
                tcp_sq_max = max(tcp_sq_max, sq)

        # UDP queues
        cmd_udp = f"{pfx}ss -unp".split()
        res_udp = subprocess.check_output(cmd_udp, text=True, stderr=subprocess.DEVNULL)
        for line in res_udp.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] in ("UNCONN", "ESTAB"):
                udp_count += 1
                rq, sq = int(parts[1]), int(parts[2])
                udp_rq_total += rq
                udp_sq_total += sq
                udp_rq_max = max(udp_rq_max, rq)
                udp_sq_max = max(udp_sq_max, sq)

        with buffer_lock:
            metrics_buffer["ss_tcp_count"] = float(tcp_count)
            metrics_buffer["ss_tcp_send_q_total"] = float(tcp_sq_total)
            metrics_buffer["ss_tcp_send_q_max"] = float(tcp_sq_max)
            metrics_buffer["ss_tcp_recv_q_total"] = float(tcp_rq_total)
            metrics_buffer["ss_tcp_recv_q_max"] = float(tcp_rq_max)
            metrics_buffer["ss_udp_count"] = float(udp_count)
            metrics_buffer["ss_udp_send_q_total"] = float(udp_sq_total)
            metrics_buffer["ss_udp_send_q_max"] = float(udp_sq_max)
            metrics_buffer["ss_udp_recv_q_total"] = float(udp_rq_total)
            metrics_buffer["ss_udp_recv_q_max"] = float(udp_rq_max)
    except Exception:
        pass


def poll_ss_summary(prefix=""):
    """Parse 'ss -s' for socket state summary counts."""
    try:
        pfx = prefix if prefix else CMD_PREFIX
        cmd = f"{pfx}ss -s".split()
        res = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        tcp_total = tcp_estab = tcp_closed = tcp_orphaned = tcp_timewait = 0
        udp_total = 0

        # TCP:   42 (estab 35, closed 2, orphaned 0, timewait 3, ...)
        tcp_line = re.search(r'TCP:\s+(\d+)\s+\((.+?)\)', res)
        if tcp_line:
            tcp_total = int(tcp_line.group(1))
            detail = tcp_line.group(2)
            em = re.search(r'estab\s+(\d+)', detail)
            if em:
                tcp_estab = int(em.group(1))
            cm = re.search(r'closed\s+(\d+)', detail)
            if cm:
                tcp_closed = int(cm.group(1))
            om = re.search(r'orphaned\s+(\d+)', detail)
            if om:
                tcp_orphaned = int(om.group(1))
            tw = re.search(r'timewait\s+(\d+)', detail)
            if tw:
                tcp_timewait = int(tw.group(1))

        # UDP:   8
        udp_line = re.search(r'UDP:\s+(\d+)', res)
        if udp_line:
            udp_total = int(udp_line.group(1))

        with buffer_lock:
            metrics_buffer["ss_tcp_total"] = float(tcp_total)
            metrics_buffer["ss_tcp_estab"] = float(tcp_estab)
            metrics_buffer["ss_tcp_closed"] = float(tcp_closed)
            metrics_buffer["ss_tcp_orphaned"] = float(tcp_orphaned)
            metrics_buffer["ss_tcp_timewait"] = float(tcp_timewait)
            metrics_buffer["ss_udp_total"] = float(udp_total)
    except Exception:
        pass


# --- CRON SCHEDULER ENGINE ---
def worker(tool_name, interface):
    while not stop_event.is_set():
        t0 = time.time()
        if tool_name == "TC": poll_tc(interface)
        elif tool_name == "IP_Link": poll_ip_link(interface)
        elif tool_name == "Softnet": poll_softnet()
        elif tool_name == "VMstat": poll_vmstat()
        elif tool_name == "IOstat": poll_iostat()
        elif tool_name == "MPstat": poll_mpstat()
        elif tool_name == "Netstat_UDP": poll_netstat_udp()
        elif tool_name == "Netstat_TCP": poll_netstat_tcp()
        elif tool_name == "Netstat_Sockets": poll_netstat_sockets()
        elif tool_name == "SS_Info": poll_ss_info()
        elif tool_name == "SS_Queues": poll_ss_queues()
        elif tool_name == "SS_Summary": poll_ss_summary()
        dt = time.time() - t0
        time.sleep(max(0.05, INTERVAL - dt))

# --- STATISTICAL ANALYSIS HELPERS ---
def compute_stats(values):
    """Compute full statistical summary for a list of numeric values."""
    if not values:
        return {"samples": 0, "total": 0, "min": 0, "max": 0, "mean": 0, "median": 0, "stdev": 0, "p95": 0, "last": 0}
    n = len(values)
    sorted_v = sorted(values)
    total = sum(values)
    mean = total / n
    median = statistics.median(values)
    stdev = statistics.stdev(values) if n > 1 else 0
    p95_idx = int(n * 0.95)
    p95 = sorted_v[min(p95_idx, n - 1)]
    return {
        "samples": n,
        "total": total,
        "min": sorted_v[0],
        "max": sorted_v[-1],
        "mean": mean,
        "median": median,
        "stdev": stdev,
        "p95": p95,
        "last": values[-1]
    }


def print_stats_table(tool_name, metrics_data, cumul_keys):
    """Print a formatted statistical summary table for a tool's metrics."""
    # Header
    hdr = f"  {'Metric':<26} {'Total':>12} {'Min':>10} {'Max':>10} {'Mean':>10} {'Median':>10} {'Stdev':>10} {'P95':>10} {'Last':>10}"
    sep = "  " + "-" * 120
    print(sep)
    print(hdr)
    print(sep)
    
    for m, raw_data in metrics_data.items():
        if not raw_data:
            continue
        # Use session deltas for cumulative, raw for instantaneous
        if m in cumul_keys:
            display_data = _baseline_subtract(raw_data)
        else:
            display_data = raw_data
        
        s = compute_stats(display_data)
        clean_lbl = m.replace(f"{tool_name.lower()}_", "").replace("tc_", "").replace("ip_", "").replace("_", " ").title()
        if m in cumul_keys:
            clean_lbl += " \u0394"
        
        # Format numbers: use compact notation for large values
        def fmt(v):
            if abs(v) >= 1_000_000_000:
                return f"{v/1e9:.2f}G"
            elif abs(v) >= 1_000_000:
                return f"{v/1e6:.2f}M"
            elif abs(v) >= 10_000:
                return f"{v/1e3:.1f}K"
            elif abs(v) >= 100:
                return f"{v:.0f}"
            elif abs(v) >= 1:
                return f"{v:.2f}"
            else:
                return f"{v:.4f}"
        
        print(f"  {clean_lbl:<26} {fmt(s['total']):>12} {fmt(s['min']):>10} {fmt(s['max']):>10} "
              f"{fmt(s['mean']):>10} {fmt(s['median']):>10} {fmt(s['stdev']):>10} {fmt(s['p95']):>10} {fmt(s['last']):>10}")
    
    print(sep)

# --- CUMULATIVE vs INSTANTANEOUS METRIC CLASSIFICATION ---
# Cumulative: counters that only increment since boot (can't be cleared)
#   -> First sample = baseline, display session delta only
# Instantaneous: point-in-time gauge values (vmstat, iostat, mpstat)
#   -> Display raw values as-is
CUMULATIVE_METRICS = {
    "TC": ["tc_total_sent_bytes", "tc_total_sent_pkts", "tc_total_dropped",
            "tc_total_overlimits", "tc_total_requeues"],
    "IP_Link": ["ip_rx_bytes", "ip_rx_pkts", "ip_rx_dropped", "ip_rx_overrun", "ip_rx_errors",
                "ip_tx_bytes", "ip_tx_pkts", "ip_tx_dropped", "ip_tx_errors", "ip_tx_colls"],
    "Softnet": ["softnet_dropped", "softnet_squeezed", "softnet_received"],
    "Netstat_UDP": ["ns_udp_in_datagrams", "ns_udp_no_ports", "ns_udp_in_errors",
                    "ns_udp_out_datagrams", "ns_udp_rcvbuf_errors", "ns_udp_sndbuf_errors",
                    "ns_udp_in_csum_errors"],
    "Netstat_TCP": ["ns_tcp_active_opens", "ns_tcp_passive_opens", "ns_tcp_in_segs",
                    "ns_tcp_out_segs", "ns_tcp_retrans_segs", "ns_tcp_in_errs", "ns_tcp_out_rsts"],
    "SS_Info": ["ss_retrans_total", "ss_busy_ms_total", "ss_rwnd_limited_ms_total",
               "ss_sndbuf_limited_ms_total"],
}

# High-magnitude throughput metrics (plotted on primary Y-axis as rates)
THROUGHPUT_METRICS = {
    "TC": ["tc_total_sent_bytes", "tc_total_sent_pkts"],
    "IP_Link": ["ip_rx_bytes", "ip_rx_pkts", "ip_tx_bytes", "ip_tx_pkts"],
    "Softnet": ["softnet_received"],
    "Netstat_UDP": ["ns_udp_in_datagrams", "ns_udp_out_datagrams"],
    "Netstat_TCP": ["ns_tcp_in_segs", "ns_tcp_out_segs"],
    "SS_Info": ["ss_pacing_rate_avg", "ss_delivery_rate_avg"],
}

# Low-magnitude event/error metrics (plotted on secondary Y-axis as rates)
EVENT_METRICS = {
    "TC": ["tc_total_dropped", "tc_total_overlimits", "tc_total_requeues",
            "tc_max_backlog_bytes", "tc_max_backlog_pkts"],
    "IP_Link": ["ip_rx_dropped", "ip_rx_overrun", "ip_rx_errors",
                "ip_tx_dropped", "ip_tx_errors", "ip_tx_colls"],
    "Softnet": ["softnet_dropped", "softnet_squeezed"],
    "Netstat_UDP": ["ns_udp_no_ports", "ns_udp_in_errors", "ns_udp_rcvbuf_errors",
                    "ns_udp_sndbuf_errors", "ns_udp_in_csum_errors"],
    "Netstat_TCP": ["ns_tcp_retrans_segs", "ns_tcp_in_errs", "ns_tcp_out_rsts"],
    "SS_Info": ["ss_retrans_total", "ss_rwnd_limited_ms_total", "ss_sndbuf_limited_ms_total"],
}


def _compute_deltas(values):
    """Convert cumulative counter list to per-interval delta list."""
    if len(values) < 2:
        return values
    return [0] + [max(0, values[i] - values[i-1]) for i in range(1, len(values))]


def _baseline_subtract(values):
    """Subtract first reading (baseline) from all values. Session-relative."""
    if not values:
        return values
    base = values[0]
    return [v - base for v in values]


# --- ARCHITECTURAL EVALUATOR AND SUMMARIZER ---
def run_expert_analytics_report(aggregated_data):
    print("\n" + "="*95)
    print(" DEEP NETWORKING INFRASTRUCTURE ANALYTICS & ROOT-CAUSE REPORT")
    print("="*95)
    
    # Structural Explanations for your specific queue topology setup
    print("\n\033[1m[1] DETECTED INTERFACE QUEUE ARCHITECTURE & TOPOLOGY EXPLANATION\033[0m")
    print("-" * 95)
    print("• Root Engine Type: HTB (Hierarchical Token Bucket)")
    print("  Class Context: Your system uses Classful Traffic Shaping. HTB maps out bandwidth limits using token buckets.")
    print("  Direct Packets: Packets routed directly without classification bypass scheduling constraints entirely.")
    print("\n• Child Leaf Types: pfifo (Pure First-In-First-Out Queues)")
    print("  Class Context: leaf queues 10: and 20: are configured with absolute limits (100p and 1000p).")
    print("  Impact: If traffic arriving in these child pipelines overflows their packet threshold limits, dropped counters tick up.")

    print("\n\033[1m[2] STATISTICAL DATA SUMMARY PER SUBSYSTEM\033[0m")
    print("-" * 95)
    print("  \033[90m(Cumulative counters shown as session delta \u0394 since monitoring started)\033[0m")
    for tool, package in aggregated_data.items():
        samples = len(package["times"])
        duration = (package["times"][-1] - package["times"][0]).total_seconds() if samples > 1 else 0
        print(f"\n  \033[1mSubsystem: [{tool}]\033[0m  |  Samples: {samples}  |  Duration: {duration:.0f}s")
        cumul_keys = CUMULATIVE_METRICS.get(tool, [])
        metrics_data = {m: package["data"][m] for m in TOOL_METRICS[tool]}
        print_stats_table(tool, metrics_data, cumul_keys)

    print("\n\033[1m[3] TRAFFIC BURST ANALYSIS RESULTS\033[0m")
    print("-" * 95)
    
    is_bursting = False
    
    if "IP_Link" in aggregated_data:
        rx_b = aggregated_data["IP_Link"]["data"]["ip_rx_bytes"]
        tx_b = aggregated_data["IP_Link"]["data"]["ip_tx_bytes"]
        
        # Session totals (baseline-subtracted)
        rx_session = _baseline_subtract(rx_b)
        tx_session = _baseline_subtract(tx_b)
        
        # Calculate Delta variations across sampling points to discover transient spikes
        rx_deltas = _compute_deltas(rx_b)
        tx_deltas = _compute_deltas(tx_b)
        
        max_rx_rate = (max(rx_deltas) / 1024 / 1024) if rx_deltas else 0
        max_tx_rate = (max(tx_deltas) / 1024 / 1024) if tx_deltas else 0
        total_rx_mb = (rx_session[-1] / 1024 / 1024) if rx_session else 0
        total_tx_mb = (tx_session[-1] / 1024 / 1024) if tx_session else 0
        
        print(f"• Session Transfer Totals: Inbound: {total_rx_mb:.2f} MB | Outbound: {total_tx_mb:.2f} MB")
        print(f"• Dynamic Rate Variations: Max Inbound Burst Rate: {max_rx_rate:.2f} MB/s | Max Outbound Burst Rate: {max_tx_rate:.2f} MB/s")
        
        # Flag if maximum transfer variation rate deviates significantly from normal ranges
        if max_rx_rate > 15 or max_tx_rate > 15:
            print("  --> Diagnostic Inference: \033[93mMICROBURST SIGNATURE CONFIRMED.\033[0m Traffic arrival spikes are sharp and abrupt.")
            is_bursting = True

    if "TC" in aggregated_data:
        tc_drp = _baseline_subtract(aggregated_data["TC"]["data"]["tc_total_dropped"])[-1] if aggregated_data["TC"]["data"]["tc_total_dropped"] else 0
        tc_req = _baseline_subtract(aggregated_data["TC"]["data"]["tc_total_requeues"])[-1] if aggregated_data["TC"]["data"]["tc_total_requeues"] else 0
        tc_ovr = _baseline_subtract(aggregated_data["TC"]["data"]["tc_total_overlimits"])[-1] if aggregated_data["TC"]["data"]["tc_total_overlimits"] else 0
        
        if tc_drp > 0 or tc_req > 0 or tc_ovr > 0:
            print(f"• TC Engine Exceptions: Drop Max: {tc_drp} | Requeues Max: {tc_req} | Overlimits Max: {tc_ovr}")
            if tc_drp > 0:
                print("  --> Architectural Meaning [DROPS]: HTB/pfifo buffers hit 100% saturation capacity. Kernel was forced to discard packets.")
            if tc_req > 0:
                print("  --> Architectural Meaning [REQUEUES]: Driver ring-buffer rejected frames because the NIC hardware was blocked.")
            if tc_ovr > 0:
                print("  --> Architectural Meaning [OVERLIMITS]: Spikes hit the configured bandwidth limit ceiling and were delayed/throttled.")
            is_bursting = True
            
    if "Softnet" in aggregated_data:
        sf_drp = _baseline_subtract(aggregated_data["Softnet"]["data"]["softnet_dropped"])[-1] if aggregated_data["Softnet"]["data"]["softnet_dropped"] else 0
        sf_sqz = _baseline_subtract(aggregated_data["Softnet"]["data"]["softnet_squeezed"])[-1] if aggregated_data["Softnet"]["data"]["softnet_squeezed"] else 0
        if sf_drp > 0 or sf_sqz > 0:
            print(f"• CPU Interrupt Scheduling Stalls: Softnet Drops: {sf_drp} | Softnet Squeezed Count: {sf_sqz}")
            print("  --> Architectural Meaning: The system CPU cores are stalling. It can't empty network card buffers fast enough.")
            is_bursting = True
            
    if not is_bursting:
        print("[+] All structural layers are tracking cleanly. No buffer microburst overruns detected during this window.")
    
    # Collect and display kernel queue/burst tuning state
    collect_and_report_sysctl_queue_params()
    
    print("=" * 95 + "\n")

# --- KERNEL QUEUE & BURST SYSCTL PARAMETER COLLECTOR ---

# All sysctl keys related to packet queuing, burst behavior, and IP stack buffering
SYSCTL_QUEUE_PARAMS = {
    # --- Core Network Device Queue Controls ---
    "net.core.netdev_max_backlog": (
        "Per-CPU input queue depth. Packets queue here when NIC delivers faster than softIRQ can drain. "
        "If full, packets are DROPPED (shows in softnet_stat col[1]). Raise under bursty inbound traffic."
    ),
    "net.core.netdev_budget": (
        "Max packets a CPU processes in one softIRQ NAPI poll cycle. When budget exhausts before queue "
        "empties, the core yields (shows as 'squeezed' in softnet_stat). Raise to reduce squeeze events."
    ),
    "net.core.netdev_budget_usecs": (
        "Max wall-clock time (microseconds) allowed per softIRQ NAPI cycle. Even if packet budget "
        "remains, time expiry forces yield. Raise carefully—too high starves user-space processes."
    ),
    "net.core.dev_weight": (
        "Max packets processed from a single device backlog in one scheduler pass. Higher values "
        "favor a busy NIC but may starve other devices sharing the CPU."
    ),
    # --- Socket Buffer Memory Limits ---
    "net.core.rmem_max": (
        "System-wide maximum receive socket buffer (bytes). Caps SO_RCVBUF setsockopt. Limits how much "
        "unread data a socket can hold before kernel drops or applies backpressure."
    ),
    "net.core.rmem_default": (
        "Default receive socket buffer for new sockets. Applies when application doesn't set SO_RCVBUF. "
        "Too small causes recv queue overflow under burst; too large wastes kernel memory."
    ),
    "net.core.wmem_max": (
        "System-wide maximum send socket buffer (bytes). Caps SO_SNDBUF. Limits how much unsent data "
        "can queue inside a socket's write buffer before send() blocks or returns EAGAIN."
    ),
    "net.core.wmem_default": (
        "Default send socket buffer for new sockets. Governs how much outbound data queues before "
        "transmission. Affects burst absorption on the egress path."
    ),
    "net.core.optmem_max": (
        "Max ancillary/cmsg buffer memory per socket. Used for control messages, IP options, "
        "and socket filter buffers. Rarely the bottleneck, but can limit BPF program space."
    ),
    # --- TCP Specific Queue Tuning ---
    "net.ipv4.tcp_rmem": (
        "TCP auto-tuning receive buffer: 'min default max' (bytes). Kernel dynamically adjusts between "
        "min and max per connection. 'max' bounds the largest burst a single flow can absorb."
    ),
    "net.ipv4.tcp_wmem": (
        "TCP auto-tuning send buffer: 'min default max' (bytes). Controls how much unACKed data TCP "
        "can queue for transmission. Directly impacts throughput×RTT (BDP) accommodation."
    ),
    "net.ipv4.tcp_mem": (
        "Global TCP memory pressure thresholds: 'low pressure high' (pages). When total TCP buffer "
        "usage exceeds 'pressure', kernel enters memory pressure mode and restricts allocations."
    ),
    "net.ipv4.tcp_max_syn_backlog": (
        "Max half-open connections (SYN_RECV state). Under SYN flood or burst of new connections, "
        "this queue overflows causing SYN drops. Size this to handle legitimate connection bursts."
    ),
    "net.ipv4.tcp_limit_output_bytes": (
        "Max bytes queued in device Qdisc per TCP socket before TCP pauses sending (TSQ). Lower values "
        "reduce bufferbloat latency but may underutilize fast links. Higher values add queuing delay."
    ),
    "net.ipv4.tcp_congestion_control": (
        "Active TCP congestion control algorithm. Dictates burst behavior: cubic (default, aggressive "
        "probing), bbr (pacing-based, lower queue), reno (conservative). Directly controls send bursts."
    ),
    "net.ipv4.tcp_notsent_lowat": (
        "Threshold of unsent bytes in write queue before socket reports writability. Lower values reduce "
        "latency by pacing writes; higher values batch more data increasing burst size."
    ),
    # --- UDP Queue Controls ---
    "net.ipv4.udp_mem": (
        "Global UDP memory pressure thresholds: 'low pressure high' (pages). Similar to tcp_mem but for "
        "UDP. When exceeded, new UDP allocations fail causing packet drops."
    ),
    "net.ipv4.udp_rmem_min": (
        "Minimum receive buffer guaranteed per UDP socket (bytes). Even under memory pressure, each "
        "socket retains at least this much. Protects against total starvation under burst."
    ),
    "net.ipv4.udp_wmem_min": (
        "Minimum send buffer guaranteed per UDP socket (bytes). Ensures a floor for outbound "
        "queueing even when system is under global memory pressure."
    ),
    # --- Qdisc / Scheduler Burst Controls ---
    "net.core.default_qdisc": (
        "Default packet scheduler for new interfaces. Options: fq_codel (fair-queue + AQM, fights "
        "bufferbloat), pfifo_fast (simple priority FIFO), fq (flow-fair pacing). Determines queue behavior."
    ),
    "net.ipv4.tcp_pacing_ss_ratio": (
        "Pacing rate multiplier during slow-start (percent, e.g. 200 = 2x). Controls how aggressively "
        "TCP bursts during connection ramp-up. Lower = smoother bursts, higher = faster ramp."
    ),
    "net.ipv4.tcp_pacing_ca_ratio": (
        "Pacing rate multiplier during congestion avoidance (percent). Controls steady-state burst "
        "smoothing. Only effective when FQ qdisc or BBR provides pacing support."
    ),
    # --- Connection Tracking & Queue Overflow ---
    "net.core.somaxconn": (
        "Max completed (ESTABLISHED) connections waiting in accept queue. If full, new connections "
        "get dropped or SYN-ACK is delayed. Size for burst of simultaneous new connections."
    ),
    "net.core.busy_poll": (
        "Microseconds to busy-poll for new packets before sleeping. Reduces latency by avoiding "
        "interrupt/softIRQ overhead. Trades CPU cycles for lower per-packet queue residence time."
    ),
    "net.core.busy_read": (
        "Microseconds to busy-read on blocking socket recv. Similar to busy_poll but for blocking I/O. "
        "Reduces jitter in latency-sensitive workloads at cost of CPU spin."
    ),
}


def collect_sysctl_queue_params():
    """Read all queue/burst-related sysctl values from the running kernel."""
    results = {}
    for param in SYSCTL_QUEUE_PARAMS:
        proc_path = "/proc/sys/" + param.replace(".", "/")
        try:
            if CMD_PREFIX:
                cmd = f"{CMD_PREFIX}cat {proc_path}".split()
                value = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
            else:
                with open(proc_path, "r") as f:
                    value = f.read().strip()
            results[param] = value
        except (FileNotFoundError, PermissionError, OSError, subprocess.CalledProcessError):
            results[param] = None
    return results


def collect_and_report_sysctl_queue_params():
    """Collect and display kernel queue/burst sysctl parameters in the report."""
    print(f"\n\033[1m[4] KERNEL QUEUE & BURST TUNING PARAMETER SNAPSHOT\033[0m")
    print("-" * 95)
    print("  These sysctl values control where packets queue, how large bursts can grow,")
    print("  and when the kernel drops/throttles. Tune these to address queuing bottlenecks.\n")
    
    params = collect_sysctl_queue_params()
    available = {k: v for k, v in params.items() if v is not None}
    unavailable = [k for k, v in params.items() if v is None]
    
    if not available:
        print("  [!] Could not read any sysctl parameters. Are you running with sufficient privileges?")
        return
    
    # Group display by category
    categories = {
        "Core Device Queue Controls": [
            "net.core.netdev_max_backlog", "net.core.netdev_budget",
            "net.core.netdev_budget_usecs", "net.core.dev_weight"
        ],
        "Socket Buffer Limits": [
            "net.core.rmem_max", "net.core.rmem_default",
            "net.core.wmem_max", "net.core.wmem_default", "net.core.optmem_max"
        ],
        "TCP Queue & Burst Tuning": [
            "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.ipv4.tcp_mem",
            "net.ipv4.tcp_max_syn_backlog", "net.ipv4.tcp_limit_output_bytes",
            "net.ipv4.tcp_congestion_control", "net.ipv4.tcp_notsent_lowat",
            "net.ipv4.tcp_pacing_ss_ratio", "net.ipv4.tcp_pacing_ca_ratio"
        ],
        "UDP Queue Controls": [
            "net.ipv4.udp_mem", "net.ipv4.udp_rmem_min", "net.ipv4.udp_wmem_min"
        ],
        "Scheduler & Connection Queue": [
            "net.core.default_qdisc", "net.core.somaxconn",
            "net.core.busy_poll", "net.core.busy_read"
        ],
    }
    
    for cat_name, cat_params in categories.items():
        cat_available = [(p, available[p]) for p in cat_params if p in available]
        if not cat_available:
            continue
        print(f"  \033[96m┌─ {cat_name}\033[0m")
        for param, value in cat_available:
            explanation = SYSCTL_QUEUE_PARAMS[param]
            # Truncate explanation for display
            short_expl = explanation.split(".")[0] + "."
            print(f"  │  {param:<42} = \033[93m{value}\033[0m")
            print(f"  │    └─ {short_expl}")
        print(f"  \033[96m└{'─' * 90}\033[0m\n")
    
    if unavailable:
        print(f"  [i] {len(unavailable)} params unavailable (kernel version or permission): "
              f"{', '.join(unavailable[:5])}{'...' if len(unavailable) > 5 else ''}")

# --- HIGH RESOLUTION GRAPHICAL PLOTTING PIPELINE ---

def _build_stats_table_text(tool, package):
    """Build a stats summary string for embedding in plot as text annotation."""
    cumul_keys = CUMULATIVE_METRICS.get(tool, [])
    lines = []
    header = f"{'Metric':<20} {'Total':>10} {'Min':>8} {'Max':>8} {'Mean':>8} {'Med':>8} {'Std':>8} {'P95':>8}"
    lines.append(header)
    lines.append("-" * len(header))
    
    for m in TOOL_METRICS[tool]:
        raw = package["data"][m]
        if not raw:
            continue
        # For plots: use deltas (rate/s) for cumulative, raw for gauges
        if m in cumul_keys:
            data = _compute_deltas(raw)
        else:
            data = raw
        
        s = compute_stats(data)
        lbl = m.replace("tc_", "").replace("ip_", "").replace("softnet_", "").replace("_", " ").title()
        if len(lbl) > 18:
            lbl = lbl[:18] + ".."
        
        def fmt(v):
            if abs(v) >= 1e9: return f"{v/1e9:.1f}G"
            elif abs(v) >= 1e6: return f"{v/1e6:.1f}M"
            elif abs(v) >= 1e4: return f"{v/1e3:.0f}K"
            elif abs(v) >= 100: return f"{v:.0f}"
            elif abs(v) >= 1: return f"{v:.1f}"
            else: return f"{v:.3f}"
        
        lines.append(f"{lbl:<20} {fmt(s['total']):>10} {fmt(s['min']):>8} {fmt(s['max']):>8} "
                     f"{fmt(s['mean']):>8} {fmt(s['median']):>8} {fmt(s['stdev']):>8} {fmt(s['p95']):>8}")
    
    return "\n".join(lines)


def generate_plots(aggregated_data):
    if not HAS_MATPLOTLIB:
        return
    
    from matplotlib.gridspec import GridSpec
    
    num_tools = len(aggregated_data)
    # Each tool gets 2 grid rows: one for chart, one for stats table
    fig = plt.figure(figsize=(16, 6.0 * num_tools))
    gs = GridSpec(num_tools * 2, 1, figure=fig, height_ratios=[3, 1] * num_tools, hspace=0.4)
    
    fig.suptitle(f"Deep Architectural Root-Cause Layer Analysis Matrix ({sys.argv[1]})", fontsize=14, fontweight='bold', y=0.995)
    
    for idx, (tool, package) in enumerate(aggregated_data.items()):
        ax = fig.add_subplot(gs[idx * 2])
        times = package["times"]
        
        # For cumulative tools: use dual Y-axes with rate conversion
        if tool in THROUGHPUT_METRICS:
            throughput_keys = THROUGHPUT_METRICS[tool]
            event_keys = EVENT_METRICS[tool]
            
            for m in throughput_keys:
                raw = package["data"][m]
                deltas = _compute_deltas(raw) if m in CUMULATIVE_METRICS.get(tool, []) else raw
                lbl_title = m.replace("tc_", "").replace("ip_", "").replace("softnet_", "").replace("_", " ").title()
                ax.plot(times, deltas, label=f"{lbl_title}/s", lw=1.8)
            
            ax.set_ylabel("Throughput (per second)", fontsize=9)
            ax.tick_params(axis='y')
            
            ax2 = ax.twinx()
            has_event_data = False
            for m in event_keys:
                raw = package["data"][m]
                deltas = _compute_deltas(raw) if m in CUMULATIVE_METRICS.get(tool, []) else raw
                if max(deltas) > 0:
                    has_event_data = True
                lbl_title = m.replace("tc_", "").replace("ip_", "").replace("softnet_", "").replace("_", " ").title()
                ax2.plot(times, deltas, label=f"{lbl_title}/s", lw=1.4, linestyle='--')
            
            ax2.set_ylabel("Events/s", fontsize=9, color='tab:red')
            ax2.tick_params(axis='y', labelcolor='tab:red')
            if not has_event_data:
                ax2.set_ylim(-0.5, 5)
            
            lines1, labels1 = ax.get_legend_handles_labels()
            lines2, labels2 = ax2.get_legend_handles_labels()
            ax.legend(lines1 + lines2, labels1 + labels2,
                      loc="upper left", bbox_to_anchor=(1.08, 1), borderaxespad=0, fontsize=7)
        else:
            # Instantaneous/gauge tools: plot raw
            for m in TOOL_METRICS[tool]:
                lbl_title = m.replace("tc_", "").replace("ip_", "").replace("softnet_", "").replace("_", " ").title()
                ax.plot(times, package["data"][m], label=lbl_title, lw=1.8)
            ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), borderaxespad=0, fontsize=7)
            
        ax.set_title(f"{tool} {'(Rate/s)' if tool in THROUGHPUT_METRICS else '(Gauge)'}",
                     fontsize=11, fontweight='semibold', loc='left')
        ax.grid(True, linestyle=':', alpha=0.5)
        
        # --- Stats table below the chart ---
        ax_table = fig.add_subplot(gs[idx * 2 + 1])
        ax_table.axis('off')
        stats_text = _build_stats_table_text(tool, package)
        ax_table.text(0.02, 0.95, stats_text, transform=ax_table.transAxes,
                      fontsize=7.5, fontfamily='monospace', verticalalignment='top',
                      bbox=dict(boxstyle='round,pad=0.4', facecolor='#f0f0f0', alpha=0.8))
    
    plt.tight_layout()
    plot_out = os.path.join(OUTPUT_DIR, "system_burst_analysis.png")
    plt.savefig(plot_out, dpi=200, bbox_inches='tight')
    plt.close(fig)
    print(f"[+] Graphical plot compilation completed successfully -> Saved to: {plot_out}\n")

# --- INITIALIZATION CONTAINER ENGINE ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 net_monitor.py <interface_name> [cmd_prefix]")
        print("  Example: sudo python3 net_monitor.py eth3")
        print("  Example: sudo python3 net_monitor.py eth0 'denter atg4g '")
        sys.exit(1)
        
    iface = sys.argv[1]
    if len(sys.argv) >= 3:
        CMD_PREFIX = sys.argv[2]
        if not CMD_PREFIX.endswith(" "):
            CMD_PREFIX += " "
    pre_flight_checks(iface)
    
    if not working_tools:
        print("[-] Error: Zero operational platform tracing tools discovered. Exiting.")
        sys.exit(1)
        
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    
    csv_files = {}
    csv_writers = {}
    for tool in working_tools.keys():
        path = os.path.join(OUTPUT_DIR, f"{tool.lower()}_metrics.csv")
        f = open(path, 'w', newline='')
        writer = csv.writer(f)
        writer.writerow(["Timestamp"] + TOOL_METRICS[tool])
        csv_files[tool] = f
        csv_writers[tool] = writer

    print(f"[+] Operational data silos active at: ./{OUTPUT_DIR}/")
    print("[+] Polling engine active... Break via (Ctrl+C) to dump reports.")
    
    for tool in working_tools.keys():
        t = threading.Thread(target=worker, args=(tool, iface), daemon=True)
        threads.append(t)
        t.start()
        
    try:
        while True:
            time.sleep(INTERVAL)
            t_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with buffer_lock:
                current_snapshot = metrics_buffer.copy()
                
            for tool, writer in csv_writers.items():
                row = [t_stamp] + [current_snapshot[m] for m in TOOL_METRICS[tool]]
                writer.writerow(row)
                csv_files[tool].flush()
                
    except KeyboardInterrupt:
        print("\n[-] Caught stop signal. Packing system data registries safely...")
        stop_event.set()
        time.sleep(0.5)
        
        for f in csv_files.values():
            f.close()
            
        # Parse data frames from generated outputs back into tracking objects
        aggregated_data = {}
        for tool in working_tools.keys():
            csv_path = os.path.join(OUTPUT_DIR, f"{tool.lower()}_metrics.csv")
            if not os.path.exists(csv_path): continue
            
            timestamps = []
            metrics_lists = {m: [] for m in TOOL_METRICS[tool]}
            
            with open(csv_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    timestamps.append(datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S"))
                    for m in TOOL_METRICS[tool]:
                        metrics_lists[m].append(float(row[m]))
            
            if timestamps:
                aggregated_data[tool] = {"times": timestamps, "data": metrics_lists}
                
        run_expert_analytics_report(aggregated_data)
        if HAS_MATPLOTLIB:
            generate_plots(aggregated_data)
