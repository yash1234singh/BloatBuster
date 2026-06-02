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

---

## Requirements

| Feature | Requirement |
|---------|-------------|
| Core test | Python 3.8+, `traceroute` binary (`apt install traceroute`) |
| `--owd` | root or `CAP_NET_RAW`, `pip install scapy` |
| `--twamp` | No root required, no extra packages (stdlib `socket`/`struct` only) |
| `traffic-gen.py` | `pip install requests h2` |

Install all Python dependencies at once:
```bash
pip install scapy requests h2
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
# ── Specialised scenarios ────────────────────────────────────────────────────

# LTE/cellular: longer phases, wider chart
python3 userbufferTest.py -T 8.8.8.8 -b 30 -s 180 -W 120 --twamp

# Low-traffic baseline (fewer clients)
python3 userbufferTest.py -T 8.8.8.8 -d 10 -u 10 -b 20 -s 60

# Quick connectivity sanity check (10s each)
python3 userbufferTest.py -T 8.8.8.8 -b 10 -s 10

# Full run with all metrics, saved
sudo python3 userbufferTest.py -T 8.8.8.8 --owd --twamp -b 30 -s 120 \
    -m procnetdev -W 120 -H 25 -o $(date +%Y%m%d_%H%M)_results.csv
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
