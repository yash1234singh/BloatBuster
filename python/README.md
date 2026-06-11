# BloatBuster — Python Toolkit

Bufferbloat measurement using real HTTP/HTTPS browsing traffic as stress load.
Runs a two-phase traceroute test (idle BASELINE → loaded STRESS) to identify
which network hops introduce latency under congestion, and optionally measures
per-direction one-way delay (OWD) using TCP Timestamps or TWAMP-Light UDP probes.

---

## Files in this directory

| File | Description |
|------|-------------|
| `userbufferTest.py` | Main test script — traceroute bufferbloat + OWD |
| `traffic-gen.py` | HTTP/HTTPS/HTTP2 traffic stress generator (spawned automatically) |
| `tcp_owd.py` | TCP Timestamp OWD module — used by `--owd` (requires root + Scapy) |
| `twamp_owd.py` | TWAMP-Light UDP OWD module — used by `--twamp` (no root needed) |
| `net_monitor.py` | System infrastructure telemetry — TC/IP/Softnet/CPU/IO/Netstat/SS monitoring |

---

## Requirements

| Feature | Requirement |
|---------|-------------|
| Core test | Python 3.8+, `traceroute` binary (`apt install traceroute`) |
| `--owd` | root or `CAP_NET_RAW`, `pip install scapy` |
| `--twamp` | No root required, no extra packages (stdlib `socket`/`struct` only) |
| `--netmon` | root (for `tc`, `/proc/net/softnet_stat`); `vmstat`, `iostat`, `mpstat`, `netstat`, `ss` binaries |
| Matplotlib charts | `pip install matplotlib` (auto-generated if available, skipped silently if not) |
| `traffic-gen.py` | `pip install requests h2` |

Install all Python dependencies at once:
```bash
pip install scapy requests h2 matplotlib
```

---

## Quick Start

```bash
# Basic bufferbloat test (30s baseline, 120s stress)
python3 userbufferTest.py -T 8.8.8.8

# Add TWAMP one-way delay measurement (no root needed)
python3 userbufferTest.py -T 8.8.8.8 --twamp

# Add TCP-TSval OWD measurement (requires root + scapy)
sudo python3 userbufferTest.py -T 8.8.8.8 --owd

# Add system telemetry (TC qdisc, NIC stats, softnet, CPU) during stress
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth3

# Kitchen sink — all measurements + auto matplotlib chart
sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp --netmon -b 30 -s 120

sudo python3 userbufferTest.py -T 1.1.1.1 --owd --twamp --twamp-server 34.209.241.130 --netmon --netmon-interface eth3 -b 10 -s 30


```


### Explained Examples

```bash
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 1: Quick sanity check                                           │
# │ What: 10s baseline + 10s stress. Fastest possible run.                  │
# │ When: Verifying connectivity before a longer test.                      │
# └─────────────────────────────────────────────────────────────────────────┘
python3 userbufferTest.py -T 8.8.8.8 -b 10 -s 10

# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 2: Cellular/LTE bufferbloat diagnosis                           │
# │ What: Longer stress (3 min) to capture slow-start and steady state.     │
# │       TWAMP gives upload/download OWD split without root.               │
# │       Wider chart (120 cols) to see fine-grained patterns.              │
# └─────────────────────────────────────────────────────────────────────────┘
python3 userbufferTest.py -T 8.8.8.8 -b 30 -s 180 -W 120 --twamp

# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 3: Full kernel-level diagnosis on a Linux router                │
# │ What: Identifies if packets queue in TC qdisc, NIC ring buffer, or      │
# │       CPU softIRQ backlog. Reports sysctl tuning recommendations.       │
# │       Auto-generates matplotlib PNG with all data + stats tables.       │
# │ Requires: root, matplotlib installed, sysstat (iostat/mpstat).          │
# └─────────────────────────────────────────────────────────────────────────┘
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth3 \
    --twamp -b 30 -s 120

# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 4: Per-direction OWD with TCP timestamps (most accurate)        │
# │ What: Decomposes RTT into upload vs download delay. Shows which         │
# │       direction suffers bufferbloat. Requires target to echo TCP TSval.  │
# │       Port 443 works for most CDN/cloud targets.                        │
# └─────────────────────────────────────────────────────────────────────────┘
sudo python3 userbufferTest.py -T 1.1.1.1 --owd --owd-port 443

# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 5: Wire-level throughput + all OWD methods + results saved      │
# │ What: Reads actual NIC byte counters (not just curl app-level).         │
# │       Both TCP-TSval and TWAMP OWD active. Everything saved to CSV.     │
# └─────────────────────────────────────────────────────────────────────────┘
sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp \
    -m procnetdev -I eth0 -b 30 -s 120 -o results.csv

# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 6: Net monitor standalone (without bufferbloat test)            │
# │ What: Run net_monitor.py directly to watch kernel queuing in real-time. │
# │       Ctrl+C to stop and get stats report + PNG chart.                  │
# │       Optional second arg: command prefix for namespace/container.      │
# └─────────────────────────────────────────────────────────────────────────┘
sudo python3 net_monitor.py eth3
sudo python3 net_monitor.py eth0 "denter atg4g"
```

---

## userbufferTest.py — Full Option Reference

```
python3 userbufferTest.py -T <target> [options]
```

### Core Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-T` | *required* | Traceroute target host or IP |
| `--baseline` | `-b` | `30` | Baseline phase duration (seconds) |
| `--stress` | `-s` | `120` | Stress phase duration (seconds) |
| `--interval` | `-i` | `1` | Traceroute poll interval (seconds) |
| `--timeout` | `-w` | `2` | Per-hop traceroute wait timeout (seconds) |
| `--max-rtt` | | `5` | Kill traceroute subprocess if it takes longer than this (seconds) |
| `--dl-clients` | `-d` | `30` | Download threads for traffic-gen.py |
| `--ul-clients` | `-u` | `50` | Upload threads for traffic-gen.py |
| `--output` | `-o` | | Save results to CSV file |
| `--chart-width` | `-W` | `80` | ASCII chart width in columns |
| `--chart-height` | `-H` | `20` | ASCII chart height in rows |

### Throughput Measurement (`-m`)

| Value | Description |
|-------|-------------|
| `auto` | Default — uses `statsfile` (counts only traffic-gen bytes) |
| `statsfile` | Reads traffic-gen.py app-level byte counters |
| `procnetdev` | Reads `/proc/net/dev` on the WAN NIC (wire-level, all traffic) |
| `ss` | Uses `ss -i -t -n` — sums `bytes_acked` (UL) and `bytes_received` (DL) |

```bash
# Wire-level throughput on auto-detected WAN interface
python3 userbufferTest.py -T 8.8.8.8 -m procnetdev

# Specify interface explicitly
python3 userbufferTest.py -T 8.8.8.8 -m procnetdev -I eth0
```

### One-Way Delay — TCP Timestamp (`--owd`)

Uses RFC 7323 TCP Timestamp options on a persistent TCP connection to decompose
RTT into per-direction upload/download delay. No server daemon required.
**Requires root and `pip install scapy`.**

| Flag | Default | Description |
|------|---------|-------------|
| `--owd` | off | Enable TCP-TSval OWD measurement |
| `--owd-port` | `80` | TCP port to connect to on the target |
| `--owd-interval` | `0.2` | Seconds between keep-alive probes |
| `--owd-timeout` | `2.0` | Per-probe receive timeout (seconds); increase under heavy bloat |

Metrics produced: `RTT`, `FwdOWD†` (upload), `BwdOWD†` (download), `FwdIPDV`, `BwdIPDV`

> **Note:** OWD† values use the server TSval clock — no NTP needed. IPDV (jitter)
> is per-probe directional variation and is always accurate.

### One-Way Delay — TWAMP-Light (`--twamp`)

Sends RFC 5357 unauthenticated UDP test packets to a TWAMP-Light reflector.
**No root required.** Reflector is pre-deployed at `34.209.241.130:4200`.

| Flag | Default | Description |
|------|---------|-------------|
| `--twamp` | off | Enable TWAMP-Light OWD measurement |
| `--twamp-server` | `34.209.241.130` | Reflector IP or hostname |
| `--twamp-port` | `4200` | Reflector UDP port |
| `--twamp-interval` | `0.2` | Seconds between UDP probe packets |
| `--twamp-timeout` | `2.0` | Per-probe receive timeout (seconds) |
| `--twamp-padding` | `27` | Padding bytes appended to each sender packet (total sender pkt = 41 B) |
| `--twamp-backend` | `native` | Sender backend: `native` (built-in RFC 5357 UDP, per-probe data, full chart overlay) or `nokia` (Nokia twampy subprocess, summary stats only, requires `pip install twampy`) |

Metrics produced: `RTT`, `FwdOWD‡` (upload), `BwdOWD‡` (download), `FwdIPDV`, `BwdIPDV`

> **Note:** FwdOWD‡/BwdOWD‡ are accurate only with NTP-synchronised clocks; without
> sync they reflect RTT/2 (symmetric assumption). IPDV/jitter is always accurate.

> **Note on result variation:** OWD values from different test runs will vary by 1–3 ms
> due to network jitter and load — this is normal, not a bug. Both `native` and `nokia`
> backends measure the same physical quantities; small differences between runs are expected.

### System Infrastructure Telemetry (`--netmon`)

Runs kernel-level subsystem monitoring during the stress phase to correlate
bufferbloat with packet queuing, CPU stalls, and I/O contention.

| Flag | Default | Description |
|------|---------|-------------|
| `--netmon` | off | Enable system telemetry during stress phase |
| `--netmon-interface` | auto | Interface(s) for TC qdisc / IP link stats (space-separated; defaults to `-I` interface) |
| `--netmon-prefix` | *(empty)* | Command prefix for namespace/container execution (e.g. `denter atg4g` or `ip netns exec ns1`) |
| `--netstat-prefix` | *(same as --netmon-prefix)* | Independent prefix(es) for netstat monitoring (repeatable, space-separated). Runs `netstat -s -t`, `netstat -s -u`, `netstat -anu` per prefix. Omit for local. |

**Multiple interfaces:** Pass more than one interface to monitor all of them
simultaneously (each gets its own report section and chart panels):
```bash
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth0 eth3
```

**Command prefix (namespace/container):** Use `--netmon-prefix` to run all
monitoring commands inside a different namespace or container:
```bash
# Monitor inside network namespace "atg4g"
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth0 \
    --netmon-prefix "denter atg4g"

# Monitor inside ip netns
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface veth0 \
    --netmon-prefix "ip netns exec myns"

# Multi-interface + prefix + all OWD methods
sudo python3 userbufferTest.py -T 1.1.1.1 --owd --twamp --twamp-server x.x.x.x \
    --netmon --netmon-interface eth1 eth3 --netmon-prefix "denter atg4g" -b 10 -s 30
```

**Netstat prefix (independent namespace monitoring):** Use `--netstat-prefix` to
run netstat in one or more namespaces independently from the main `--netmon-prefix`.
Useful when you want TCP/UDP protocol stats from multiple containers:
```bash
# Netstat in a specific namespace (TC/IP use the main prefix)
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth1 \
    --netmon-prefix "denter atg4g" --netstat-prefix "denter atg4g"

# Netstat in multiple namespaces simultaneously
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth1 \
    --netmon-prefix "denter atg4g" --netstat-prefix "denter atg4g" "denter ns2"

# Local netstat (no prefix) + remote TC/IP monitoring
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth1 \
    --netmon-prefix "denter atg4g" --netstat-prefix ""
```

**Subsystems monitored:**

| Subsystem | What it reveals |
|-----------|----------------|
| TC (qdisc) | HTB/pfifo queue depth, drops, overlimits, requeues |
| IP Link | NIC-level RX/TX bytes, drops, errors, overruns |
| Softnet | Per-CPU backlog drops & softIRQ squeeze events |
| VMstat | Run-queue, blocked procs, swap |
| IOstat | Disk TPS, read/write throughput |
| MPstat | CPU user/system/iowait/softirq/idle |
| Netstat TCP | Active/passive opens, segments in/out, retransmits, resets |
| Netstat UDP | Datagrams in/out, port unreachable, rcvbuf/sndbuf errors |
| Netstat Sockets | Active UDP socket count, aggregate Recv-Q/Send-Q depths |
| SS Info | TCP internal state: cwnd, ssthresh, RTT, retransmits, pacing/delivery rate, buffer-limited time |
| SS Queues | Per-socket Send-Q/Recv-Q depths for TCP and UDP (kernel buffer pressure) |
| SS Summary | Socket state counts: TCP estab/closed/orphaned/timewait, UDP total |

**Report includes:**
- Per-subsystem statistical table (min/max/mean/median/stdev/P95)
- Burst analysis (peak rates, squeeze detection)
- Live `sysctl` queue/burst parameter snapshot with tuning explanations

### Matplotlib Graphical Output

If `matplotlib` is installed (`pip install matplotlib`), a multi-panel PNG chart
is **automatically generated** at the end of every test run. No flag needed.

**Output file:** `bufferbloat_analysis.png` (saved in the working directory)

**Panels included:**
1. RTT over time (baseline vs stress) with statistical annotation
2. Throughput over time (DL/UL fill chart) with stats
3. TCP OWD (if `--owd` used) — baseline vs stress, fwd/bwd
4. TWAMP OWD (if `--twamp` used)
5. Net Monitor rate charts (if `--netmon` used) — one panel per subsystem per interface
6. Netstat TCP/UDP stats — segment/datagram rates + error events
7. Netstat UDP Sockets — socket count and queue depths
8. SS Info — cwnd/pacing/delivery rates + retransmit/buffer-limited events
9. SS Queues — TCP/UDP kernel socket buffer depths (Send-Q/Recv-Q)
10. SS Summary — connection state counts (estab, orphaned, timewait)

**Panel labeling convention:**
- **Per-interface** panels (TC, IP_Link, Softnet, VMstat, IOstat, MPstat):
  labeled `Tool [interface @ prefix]` — runs inside the namespace on specific NICs
- **Per-prefix** panels (Netstat_TCP, Netstat_UDP, Netstat_Sockets, SS_Info, SS_Queues, SS_Summary):
  labeled `Netstat: Tool [prefix]` — runs namespace-wide using `--netstat-prefix`, independent of interface

**Report section labeling:**
- `SYSTEM INFRASTRUCTURE TELEMETRY [interface: eth1 @ denter atg4g]` → per-interface tools
- `NETSTAT / SS PROTOCOL STATISTICS [prefix: denter atg4g]` → per-prefix tools

This makes it immediately clear from both the chart and the out.log which tools are
tied to a specific NIC and which are namespace-wide protocol statistics.

**Long test handling (`PLOT_SPLIT_SECS`):**

For tests exceeding `PLOT_SPLIT_SECS` (default: 3600s = 1 hour), plots are
automatically split into per-hour chunks to avoid matplotlib memory exhaustion:
- `bufferbloat_analysis_h0-h1.png` — first hour
- `bufferbloat_analysis_h1-h2.png` — second hour
- ...
- `bufferbloat_analysis.png` — combined (downsampled to `PLOT_MAX_POINTS`)

Configure in `userbufferTest.py`:
```python
PLOT_SPLIT_SECS = 3600   # seconds per chunk (0 = disable splitting)
PLOT_MAX_POINTS = 1800   # max points in combined plot (0 = no limit)
```

Short tests (duration < `PLOT_SPLIT_SECS`) produce a single plot as before.

If matplotlib is not installed, the chart is silently skipped — all terminal
output remains unaffected.

---

## Output Sections Explained

Each run produces these sections in order:

| # | Section | Description |
|---|---------|-------------|
| 1 | Per-Segment Bloat Table | Incremental delay increase per hop-pair |
| 2 | Ranked Bloat Summary | Worst links sorted by bloat severity |
| 3 | ASCII Network Diagram | Visual path with per-link delay annotation |
| 4 | Overall Latency Summary | RTT avg/P95/max/loss%; OWD†/OWD‡ rows if enabled |
| 5 | OWD Analysis | `--owd` BASELINE vs STRESS IPDV comparison table |
| 5b | TWAMP OWD Analysis | `--twamp` BASELINE vs STRESS comparison table |
| 6 | Throughput Summary | DL/UL mean, max, median, P10, P90 |
| 7 | Time-Series Table | Per-second RTT + throughput snapshots |
| 8 | ASCII Chart | Dual-axis: throughput bars + RTT/OWD dots (see legend below) |
| 9 | Traffic Summary | Per-client success/fail/socket stats |
| 10 | System Telemetry | `--netmon` stats tables + burst analysis + sysctl snapshot |
| — | Matplotlib PNG | Auto-saved `bufferbloat_analysis.png` (if matplotlib installed) |

### ASCII Chart Legend

```
▓  DL throughput (Mbps)       ░  UL throughput (Mbps)
○  Baseline RTT                ●  Stress RTT
▲  FwdOWD† upload  [--owd]    ▽  BwdOWD† download  [--owd]
◆  FwdOWD‡ upload  [--twamp]  ◇  BwdOWD‡ download  [--twamp]
x  |FwdIPDV| jitter magnitude  X  Dropped OWD probe (queue full)
T  TWAMP probe timeout
```

---

## Sample Commands

```bash
# ── Basic ────────────────────────────────────────────────────────────────────

# Minimum — traceroute-based bufferbloat test (30s idle, 120s loaded)
python3 userbufferTest.py -T 8.8.8.8

# Shorter test
python3 userbufferTest.py -T 8.8.8.8 -b 20 -s 60

# More aggressive traffic load
python3 userbufferTest.py -T 8.8.8.8 -d 50 -u 80

# Save results to CSV
python3 userbufferTest.py -T 8.8.8.8 -o results.csv

# Wire-level throughput measurement
python3 userbufferTest.py -T 8.8.8.8 -m procnetdev

# ── TCP-TSval OWD (requires root + scapy) ────────────────────────────────────

sudo python3 userbufferTest.py -T 8.8.8.8 --owd
sudo python3 userbufferTest.py -T 1.1.1.1 --owd --owd-port 443 --owd-interval 0.2
sudo python3 userbufferTest.py -T 1.1.1.1 --owd -b 30 -s 120 -o results.csv

# ── TWAMP-Light OWD (no root needed) ─────────────────────────────────────────

python3 userbufferTest.py -T 8.8.8.8 --twamp
python3 userbufferTest.py -T 8.8.8.8 --twamp --twamp-server 34.209.241.130 --twamp-port 4200
python3 userbufferTest.py -T 8.8.8.8 --twamp --twamp-padding 100   # larger UDP payload

# Use Nokia twampy subprocess as sender (requires: pip install twampy)
python3 userbufferTest.py -T 8.8.8.8 --twamp --twamp-backend nokia

# Explicit native backend (default; no extra packages needed)
python3 userbufferTest.py -T 8.8.8.8 --twamp --twamp-backend native

# ── Both OWD methods simultaneously ─────────────────────────────────────────

sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp -b 30 -s 120 -o full_results.csv
sudo python3 userbufferTest.py -T 1.1.1.1 --owd --twamp --twamp-backend nokia --twamp-server 34.209.241.130 --twamp-port 4200 -b 30 -s 60

# ── System Infrastructure Telemetry (--netmon) ───────────────────────────────

# Monitor TC/IP/Softnet/CPU during stress — identifies kernel queuing points
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth3

# Combine with TWAMP for full picture (queue diagnosis + OWD split)
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth3 --twamp -b 30 -s 120

# All measurements combined — maximum diagnostic coverage
sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp --netmon --netmon-interface eth3 \
    -m procnetdev -I eth3 -b 30 -s 120 -o full_diag.csv

# Multiple interfaces simultaneously
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth0 eth3 --twamp -b 30 -s 120

# With command prefix (namespace/container)
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth0 \
    --netmon-prefix "denter atg4g" --twamp -b 30 -s 120

# Multi-interface + prefix
sudo python3 userbufferTest.py -T 8.8.8.8 --netmon --netmon-interface eth1 eth3 \
    --netmon-prefix "ip netns exec myns" --owd --twamp -b 30 -s 300

# ── Specialised scenarios ────────────────────────────────────────────────────

# LTE/cellular: longer phases, wider chart
python3 userbufferTest.py -T 8.8.8.8 -b 30 -s 180 -W 120 --twamp

# Low-traffic baseline (fewer clients)
python3 userbufferTest.py -T 8.8.8.8 -d 10 -u 10 -b 20 -s 60

# Quick connectivity sanity check (10s each)
python3 userbufferTest.py -T 8.8.8.8 -b 10 -s 10

# Full run with all metrics, saved
sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp --netmon --netmon-interface eth0 \
    -m procnetdev -W 120 -H 25 -o $(date +%Y%m%d_%H%M)_results.csv
```

---

## Manual Verification: Test Each Monitoring Command

Run these commands manually (with your prefix) to verify all tools work before
launching a full test. Replace `<PREFIX>` with your namespace/container command
(e.g. `denter atg4g `, `ip netns exec myns `) or leave empty for local.

```bash
# ── Per-interface tools (replace eth3 with your interface) ───────────────────

# TC qdisc stats — shows queue discipline, backlog, drops
<PREFIX>tc -s qdisc show dev eth3

# IP Link stats — NIC-level byte counters, errors, drops
<PREFIX>ip -s link show dev eth3

# Softnet — per-CPU backlog (only works locally or with prefix that has /proc access)
<PREFIX>cat /proc/net/softnet_stat

# ── System-wide tools ────────────────────────────────────────────────────────

# VMstat — CPU run-queue, blocked procs, swap activity
<PREFIX>vmstat 1 1

# IOstat — disk I/O throughput and transactions
<PREFIX>iostat 1 1

# MPstat — per-CPU breakdown (user/system/iowait/softirq/idle)
<PREFIX>mpstat 1 1

# ── Netstat protocol stats (namespace-wide) ──────────────────────────────────

# TCP protocol counters — segments, retransmits, resets
<PREFIX>netstat -s -t

# UDP protocol counters — datagrams, errors, buffer overflows
<PREFIX>netstat -s -u

# Active UDP sockets — queue depths (Recv-Q / Send-Q)
<PREFIX>netstat -anu

# ── SS socket statistics (namespace-wide) ────────────────────────────────────

# TCP internal info — cwnd, ssthresh, RTT, retransmits, pacing/delivery rate
<PREFIX>ss -tin

# TCP socket queues — per-connection Send-Q/Recv-Q with process info
<PREFIX>ss -tnp

# UDP socket queues — per-socket Send-Q/Recv-Q with process info
<PREFIX>ss -unp

# Socket summary — connection state counts (estab, orphaned, timewait)
<PREFIX>ss -s
```

### Quick copy-paste test with a real prefix

```bash
# Example: test all commands inside namespace "atg4g"
PREFIX="denter atg4g "

${PREFIX}tc -s qdisc show dev eth1
${PREFIX}ip -s link show dev eth1
${PREFIX}cat /proc/net/softnet_stat
${PREFIX}vmstat 1 1
${PREFIX}iostat 1 1
${PREFIX}mpstat 1 1
${PREFIX}netstat -s -t
${PREFIX}netstat -s -u
${PREFIX}netstat -anu
${PREFIX}ss -tin
${PREFIX}ss -tnp
${PREFIX}ss -unp
${PREFIX}ss -s
```

If any command fails (e.g. `command not found`), install the missing package:
```bash
# RHEL/CentOS
yum install -y iproute2 net-tools sysstat procps-ng

# Debian/Ubuntu
apt install -y iproute2 net-tools sysstat procps
```

---

## Standalone: twamp_owd.py

Can be used independently to probe a TWAMP-Light reflector without running a full
bufferbloat test — useful as a quick connectivity / latency check.

```bash
# 20 single-phase probes with verbose output
python3 twamp_owd.py --server 34.209.241.130 --port 4200 --count 20 --verbose

# Two-phase mode (baseline + stress generated internally)
python3 twamp_owd.py --server 34.209.241.130 --port 4200 --baseline 30 --stress 60

# Save probe-level data to CSV
python3 twamp_owd.py --server 34.209.241.130 --port 4200 --count 50 --output probes.csv

# Custom probe interval and padding
python3 twamp_owd.py --server 34.209.241.130 --port 4200 --interval 0.5 --padding 100
```

**twamp_owd.py options:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--server` | `-S` | `34.209.241.130` | TWAMP reflector IP or hostname |
| `--port` | `-p` | `4200` | Reflector UDP port |
| `--count` | `-n` | `20` | Number of probes (single-phase mode) |
| `--interval` | `-i` | `0.2` | Seconds between probes |
| `--timeout` | `-w` | `2.0` | Per-probe receive timeout (seconds) |
| `--padding` | `-P` | `28` | Padding bytes in sender packet |
| `--baseline` | `-b` | `0` | Baseline phase duration (0 = use --count) |
| `--stress` | `-s` | `0` | Stress phase duration (seconds) |
| `--output` | `-o` | | Save per-probe CSV |
| `--verbose` | `-v` | off | Print raw timestamps per probe |

---

## Packaging — buildPkg.sh

`buildPkg.sh` (in the repo root) uses PyInstaller to bundle the Python interpreter,
all pip dependencies, and the four scripts into a **single standalone ELF binary**
(`dist/bloatbuster`). No Python installation is required on the target machine.

### What gets bundled

| Feature | Pip package | How bundled |
|---------|-------------|-------------|
| Core + traceroute | *(system binary)* | NOT bundled — install separately |
| `--owd` | `scapy` | `--collect-all scapy` |
| `--twamp` | stdlib only | Included automatically |
| `traffic-gen.py` | `requests`, `h2` | Auto-detected imports |
| `--twamp-backend nokia` | `twampy` | NOT bundled — install separately: `pip install twampy` |

### Build steps

```bash
# Run from repo root (not from python/)
cd /path/to/BloatBuster
bash buildPkg.sh
```

The script:
1. Creates `.bb_build_venv/` (reused on subsequent runs — delete to force clean rebuild)
2. `pip install pyinstaller scapy requests h2`
3. `pyinstaller --onefile --collect-all scapy --add-data python/tcp_owd.py:. ...`
4. Reports binary size and usage examples

### Deploy and run

```bash
# Copy single file to target (no Python needed)
scp dist/bloatbuster user@host:/usr/local/bin/

# Run on target
bloatbuster -T 8.8.8.8 --twamp
bloatbuster -T 8.8.8.8 --twamp --twamp-server 34.209.241.130 --twamp-port 4200
sudo bloatbuster -T 8.8.8.8 --owd
sudo bloatbuster -T 8.8.8.8 --owd --twamp -b 30 -s 120 -o results.csv
```

### Runtime requirements on target machine

```bash
# traceroute must be present
apt install traceroute       # Debian/Ubuntu
yum install traceroute       # RHEL/CentOS

# --owd requires root or CAP_NET_RAW (Scapy raw socket)
# --twamp does NOT require root
```

---

## CSV Output Format

When `-o results.csv` is specified, the file contains three sections:

```
# PER-HOP BLOAT
hop, ip, baseline_avg_ms, baseline_p95_ms, stress_avg_ms, stress_p95_ms, bloat_ms

# TIME-SERIES
timestamp, phase, elapsed_sec, e2e_rtt_ms, dl_rate_mbps, ul_rate_mbps, dl_bytes_total, ul_bytes_total

# TWAMP-LIGHT PROBES   (only when --twamp is used)
probe, phase, seq, rtt_ms, fwd_owd_ms, bwd_owd_ms, fwd_ipdv_ms, bwd_ipdv_ms, timed_out
```
