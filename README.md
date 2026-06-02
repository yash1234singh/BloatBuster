# Bufferbloat Testing Toolkit

Two approaches for detecting, mitigating, and benchmarking bufferbloat on Linux network links — particularly useful for LTE/5G, satellite, and other variable-bandwidth WANs.

## Overview

### Two Testing Approaches

| Approach | Scripts | Requires | Best For |
|----------|---------|----------|----------|
| **Python (no server)** | `python/userbufferTest.py` + `python/traffic-gen.py` | Python 3, `curl`, `traceroute` | Quick tests without iperf3 server setup |
| **Bash (iperf3 server)** | `bash/bufferTest.sh` + `bash/bufferManager.sh` + `bash/bufferScenarioTest.sh` + `bash/bloatChart.sh` | `iperf3`, `traceroute`, `jq`, `tc`, root | Production shaping, A/B benchmarking |

### Directory Structure

```
BloatBuster/
├── README.md
├── LICENSE
├── config.json   # Bash tool configs
│
├── python/                         # Python-based (no server needed)
│   ├── userbufferTest.py           #   Bufferbloat measurement + OWD analysis
│   ├── traffic-gen.py              #   Browsing traffic generator
│   └── tcp_owd.py                  #   TCP Timestamp OWD estimator (standalone + library)
│
├── bash/                           # Bash-based (requires iperf3 server)
│   ├── bufferManager.sh            #   Traffic shaping (CAKE/HTB/fq_codel)
│   ├── bufferTest.sh               #   Bufferbloat measurement
│   ├── bufferScenarioTest.sh       #   A/B scenario comparison
│   └── bloatChart.sh               #   ASCII time-series charts
```

### Tool Summary

| Script | Purpose | Requires |
|--------|---------|----------|
| **python/userbufferTest.py** | Measure bufferbloat via per-hop traceroute + real browsing traffic stress | Python 3, `curl`, `traceroute` |
| **python/traffic-gen.py** | Standalone browsing traffic simulator (HTTP/HTTPS/QUIC) | Python 3, `curl`, `dd` |
| **python/tcp_owd.py** | Estimate per-direction OWD/jitter via TCP Timestamps — no server required; used as library by `userbufferTest.py` | Python 3, `scapy`, root/CAP_NET_RAW, Linux |
| **bash/bufferManager.sh** | Apply/remove traffic shaping strategies (CAKE, HTB, fq_codel) and TCP tuning (BBR, ECN) | `tc`, `ip`, `sysctl`, `jq`, root |
| **bash/bufferTest.sh** | Measure bufferbloat via per-hop traceroute + iperf3 stress testing | `iperf3`, `traceroute`, `jq`, iperf3 server |
| **bash/bufferScenarioTest.sh** | Orchestrate A/B comparisons: apply strategy → run test → compare results | Both bash scripts above, `jq`, `bc` |
| **bash/bloatChart.sh** | ASCII time-series chart: overlay throughput, RTT, and autorate limits | `jq`, `awk` |

Bash scripts read configuration from a single **`config.json`** file (requires `jq`).

```
python/userbufferTest.py                    bash/bufferScenarioTest.sh
  │                                           │
  └─ python/traffic-gen.py (stress load)      ├─ bash/bufferManager.sh (apply strategy)
                                              ├─ bash/bufferTest.sh    (run bloat test)
                                              └─ Compare all scenarios
```

---

## Python Tools (No Server Required)

### userbufferTest.py

Two-phase bufferbloat measurement using real browsing traffic as stress. Same per-hop methodology as `bufferTest.sh` but uses `traffic-gen.py` instead of iperf3 — **no remote server setup needed**.

#### How It Works

```
Discovery (1 traceroute):
  └─ Determine route depth (N hops) → set min_probe_depth = max(3, N-5)

Phase 1: BASELINE (30s)
  ├─ Traceroute every 1s to all hops → record per-hop latency (no load)
  │  Probes reaching < min_probe_depth hops → counted as SHALLOW (lost)
  └─ [--owd] OWD thread: fire-and-forget HTTP HEAD probes via send(); a daemon
     thread runs sniff() to capture server ACKs; responses matched by TSecr (server
     echoes our TSval back, RFC 7323). In-window data → exact TSecr match → correct RTT.
     → FwdOWD†/BwdOWD†

Phase 2: STRESS (60s default)
  ├─ Launch traffic-gen.py (30 DL + 50 UL threads browsing real websites)
  ├─ Traceroute every 1s to all hops → record per-hop latency (under load)
  │  Probes reaching < min_probe_depth hops → counted as SHALLOW (lost)
  └─ [--owd] OWD thread: async HTTP HEAD probes on the SAME TCP connection
     Bufferbloat probes (queued): return with real high RTT → large jitter
     Drop-tail probes (discarded): timed_out=True, rtt_ms=None → high Loss%
     100% probe loss under severe upload congestion = drop-tail signal
```

> **Shallow probe detection**: Under heavy congestion, routers drop ICMP TTL-exceeded packets to save CPU. Traceroute may only hear from local hops (e.g. hop 1 at 0.1 ms) rather than the full path. Without filtering, this 0.1 ms would corrupt baseline and stress RTT statistics. Probes that don't reach `min_probe_depth` hops are discarded and shown as `SHALLOW (N/M hops)` in the console output.

> **MAX_RTT_ALLOWED**: When every hop times out, a single traceroute call can block for `timeout × max_hops` seconds (e.g. 40 s). This stalls the 1-second sampling loop. `--max-rtt` (default 5 s) kills the subprocess if it exceeds the wall-clock limit and counts the probe as lost (`TIMEOUT`).

#### Throughput Measurement Methods

| Method | Flag | DL source | UL source | Platform |
|--------|------|-----------|-----------|----------|
| **statsfile** (default) | `-m statsfile` | Progressive curl stdout reads | NIC TX bytes (`/proc/net/dev`) | Linux |
| **procnetdev** | `-m procnetdev -I eth0` | NIC RX bytes (`/proc/net/dev`) | NIC TX bytes (`/proc/net/dev`) | Linux |
| **ss** | `-m ss` | NIC RX bytes (`/proc/net/dev`) | `ss -i` `bytes_acked` sum | Linux |
| **auto** | `-m auto` | Same as `statsfile` | Same as `statsfile` | Any |

#### Measurement Accuracy & Known Limitations

All methods report approximate throughput. Each has specific failure modes — understanding them helps interpret spiky or zero readings correctly.

---

##### `statsfile` method (default)

**DL — accurate.**
`traffic-gen.py` reads curl's stdout chunk-by-chunk (`p.stdout.read(65536)`). This call blocks until data arrives from the network, so every byte counted has already crossed the wire. The counter is strictly monotonically increasing and reflects true download rate.

> DL may show **0.0 Mbps** for 1–4 seconds when all 30 download workers happen to be in their inter-request sleep gap simultaneously. This is a real measurement gap, not a bug.

**UL — approximate, inflated during TCP slow start.**
`traffic-gen.py` writes `/proc/net/dev` TX bytes (NIC-level) to the stats file. This is the most accurate UL measurement available from the test machine side, but has one known failure mode:

> **TCP slow-start burst on mobile hotspot topology.**
> Setup: test machine (eth0) → iPhone hotspot → cellular WAN.
> When 50 upload workers all start simultaneously, each TCP connection's CWND grows from ~14 KB toward the LAN capacity (100 Mbps) before the cellular WAN bottleneck (2–9 Mbps) provides congestion feedback. During this ~10–20 second slow-start phase, the iPhone's TCP receive buffer absorbs data at LAN speed. NIC TX (eth0) measures LAN bytes sent to the phone, not WAN bytes actually transmitted over cellular.
>
> **Observed effect:** UL spikes of 100–600 Mbps for the first ~17 seconds, then settles to the true WAN rate (~2–9 Mbps) once congestion is established. Periodic smaller spikes (~25–93 Mbps) occur each time a worker completes one upload and opens a new TCP connection.
>
> **On a direct WAN connection** (test machine → cable/DSL modem, no buffering router between them), NIC TX equals WAN TX and the measurement is accurate.
>
> **Mitigation:** Use the derived-rate mode in `traffic-gen.py` — set `MAX_UL_MBPS` to your WAN speed (e.g. `9.0`). Per-worker limit = 9 Mbps / 8 / 50 workers ≈ 22 KB/s. NIC TX then paces to WAN speed rather than flooding the gateway buffer. The link is still fully saturated. See [Rate Limiting Modes](#rate-limiting-modes) below. Default stays static `'3M'` to test without an artificial ceiling.

---

##### `procnetdev` method

**DL — accurate.**
Reads `/proc/net/dev` RX bytes for the WAN interface. Kernel counters are monotonically increasing and wire-level. Includes all incoming traffic (ICMP traceroute replies, ARP, etc.) which adds ~1–3% overhead, acceptable for a stress test.

**UL — same slow-start limitation as `statsfile`.**
Reads `/proc/net/dev` TX bytes. On a direct WAN connection this is accurate. On a mobile hotspot, shows the same TCP slow-start burst pattern described above — the measurement point (eth0 TX) is on the LAN side of the phone's buffer.

> The interface is auto-detected via `ip route get <target>`. Specify `-I eth0` explicitly if auto-detection picks the wrong interface.

---

##### `ss` method (hybrid: NIC RX + `bytes_acked`)

**DL — accurate (uses NIC RX, not `bytes_received`).**
Earlier versions summed `bytes_received` across all open TCP connections, which is non-monotonic: when a DL connection closes, its counter disappears from `ss -i`, causing the cumulative sum to drop and DL to read 0 Mbps even during active downloads.

The current implementation uses `/proc/net/dev` RX bytes (same monotonic NIC counter as `procnetdev`) for DL. This fixes the 0-Mbps issue entirely. Falls back to `ss bytes_received` only if no interface can be detected.

**UL — marginally better than `procnetdev`, same slow-start limitation.**
Sums `bytes_acked` across all TCP connections. `bytes_acked` excludes retransmitted bytes (procnetdev TX counts retransmissions), giving ~2–5% lower counts. Because upload connections are large (10–49 MB) and typically don't close during the 120 s test, the sum is approximately monotonic for UL. Still subject to the TCP slow-start burst on mobile hotspot topology.

> **When to use `ss`:** When you want to exclude TCP retransmission overhead from UL counts. DL accuracy is now equivalent to `procnetdev`.

---

##### UL measurement — fundamental topology constraint

There is **no measurement point on the test machine** that gives perfectly accurate UL rates when a buffering router sits between the machine and the WAN:

| What we measure | What it reflects |
|---|---|
| NIC TX (eth0) | Bytes sent to router's LAN receive buffer |
| `ss bytes_acked` | Bytes the router's TCP stack acknowledged (same rate — router ACKs at LAN speed) |
| `curl %{size_upload}` | Bytes sent when curl finishes (burst spike at completion, zero otherwise) |
| Router WAN TX | **Actual WAN bytes** — not accessible from test machine |

The accurate solution requires either (a) using the derived-rate mode (`MAX_UL_MBPS`) to cap per-worker throughput below the WAN bottleneck (see [Rate Limiting Modes](#rate-limiting-modes) below), or (b) measuring at the router/WAN side.

#### Rate Limiting Modes

`traffic-gen.py` supports two modes for controlling per-worker curl `--limit-rate`. The active mode is determined by whether `MAX_UL_MBPS` / `MAX_DL_MBPS` are set (not `None`).

##### Mode A — Static per-worker (default)

Edit the constants at the top of `traffic-gen.py`:

```python
UL_RATE_LIMIT = '3M'   # per curl worker; None = unlimited
DL_RATE_LIMIT = '5M'   # per curl worker; None = unlimited
```

Each worker gets exactly this rate regardless of thread count. At `'3M'` with 50 UL workers, the theoretical burst is 150 MB/s — far above any WAN link — but this is expected, since the real bottleneck is TCP congestion control at the gateway, not curl's rate limiter. This mode maximises stress with no artificial ceiling.

**When to use:** Direct WAN connections (modem/cable gateway, no large intermediate buffer), or any topology where NIC TX equals WAN TX.

##### Mode B — Derived from total WAN speed

Edit the constants at the top of `traffic-gen.py`:

```python
MAX_UL_MBPS = 9.0    # your WAN UL speed in Mbps
MAX_DL_MBPS = 50.0   # your WAN DL speed in Mbps
```

Per-worker limit = `MAX_*_MBPS × 1,000,000 / 8 / n_workers` bytes/sec, formatted as a curl rate string. With 50 UL workers and 9 Mbps WAN: `9 × 1e6 / 8 / 50 = 22,500 B/s → "22K"`. NIC TX then paces data at WAN speed rather than flooding the gateway buffer, so rate readings reflect actual WAN throughput. The link is still fully saturated.

**When to use:** Mobile hotspot topology (test machine → phone → cellular WAN) or any setup where a router with a large receive buffer sits between the test machine and the WAN bottleneck.

##### Selection priority

| What is set | Mode used |
|---|---|
| `MAX_UL_MBPS` is not `None` | **Derived** — `UL_RATE_LIMIT` is ignored |
| `MAX_UL_MBPS = None` | **Static** — uses `UL_RATE_LIMIT` |
| Both `None` | **Unlimited** — no `--limit-rate` arg passed to curl |

Same logic applies symmetrically for DL. CLI flags override the constants at runtime:

| Flag | Effect |
|---|---|
| `--max-ul-mbps 9.0` | Derived UL mode (overrides `MAX_UL_MBPS` constant) |
| `--max-dl-mbps 50.0` | Derived DL mode (overrides `MAX_DL_MBPS` constant) |
| `--ul-rate 200K` | Static UL override (ignored if `--max-ul-mbps` is also set) |
| `--dl-rate 1M` | Static DL override (ignored if `--max-dl-mbps` is also set) |

```bash
# Derived mode — accurate readings on a 9/50 Mbps hotspot connection
python3 python/traffic-gen.py --max-ul-mbps 9 --max-dl-mbps 50 -u 50 -d 30
# Banner shows:  DL rate : 1666K (derived: 50.0 Mbps / 30 workers)
#                UL rate : 22K (derived: 9.0 Mbps / 50 workers)

# Static mode (default) — maximum stress, no per-worker cap
python3 python/traffic-gen.py
# Banner shows:  DL rate : 5M
#                UL rate : 3M
```

#### traffic-gen.py CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --dl-clients` | Parallel download threads | `30` |
| `-u, --ul-clients` | Parallel upload threads | `50` |
| `-t, --duration` | Run time in minutes (`0` = unlimited) | `3000` |
| `-l, --log` | Save final report to CSV | — |
| `-p, --progress` | Progress summary interval in seconds (`0` = off) | `60` |
| `-S, --stats-file` | Write byte counters to file (for `userbufferTest.py`) | — |
| `--ul-rate` | Static per-worker UL rate (e.g. `'200K'`, `'3M'`) | `3M` |
| `--dl-rate` | Static per-worker DL rate (e.g. `'500K'`, `'5M'`) | `5M` |
| `--max-ul-mbps` | Total WAN UL Mbps — derives per-worker limit automatically | — |
| `--max-dl-mbps` | Total WAN DL Mbps — derives per-worker limit automatically | — |

#### Usage

```bash
# Basic test (auto-detects interface and measurement method)
python3 python/userbufferTest.py -T 8.8.8.8

# Specify interface and method explicitly
python3 python/userbufferTest.py -T 8.8.8.8 -m procnetdev -I eth0

# Custom clients and duration
python3 python/userbufferTest.py -T 10.1.2.1 -b 20 -s 60 -d 15 -u 25

# Save results to CSV
python3 python/userbufferTest.py -T 1.1.1.1 -o results.csv

# With OWD measurement (requires root + scapy)
sudo python3 python/userbufferTest.py -T 1.1.1.1 --owd

# OWD + custom port and probe rate
sudo python3 python/userbufferTest.py -T 1.1.1.1 --owd --owd-port 80 --owd-interval 0.5
```

#### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-T, --target` | Traceroute target host/IP (required) | — |
| `-b, --baseline` | Baseline phase duration (seconds) | `30` |
| `-s, --stress` | Stress phase duration (seconds) | `120` |
| `-i, --interval` | Traceroute poll interval (seconds) | `1` |
| `-w, --timeout` | Traceroute per-hop wait timeout (seconds) | `2` |
| `--max-rtt` | Hard wall-clock limit for one traceroute call (seconds); probe killed and counted as lost if exceeded | `5` |
| `-d, --dl-clients` | Download threads for traffic-gen.py | `30` |
| `-u, --ul-clients` | Upload threads for traffic-gen.py | `50` |
| `-m, --rate-method` | Throughput method: `auto`, `procnetdev`, `statsfile`, `ss` | `auto` |
| `-I, --interface` | Network interface for procnetdev (auto-detected if omitted) | auto |
| `-o, --output` | Save results to CSV file | — |
| `-W, --chart-width` | ASCII chart width in columns | `80` |
| `-H, --chart-height` | ASCII chart height in rows | `20` |
| `--owd` | Enable TCP Timestamp OWD measurement in parallel (requires root + scapy) | off |
| `--owd-port` | TCP port for OWD probe connection | `80` |
| `--owd-interval` | Seconds between OWD probes | `0.2` |
| `--owd-timeout` | Drain-window: seconds to wait after last probe before declaring remaining probes dropped | `2.0` |

#### Analysis Output

1. **Per-Segment Bloat Table** — incremental delay between each hop pair
2. **Ranked Bloat Summary** — worst bloating links sorted by severity
3. **ASCII Network Diagram** — visual path with per-link baseline/stress/bloat
4. **Overall Latency Summary** — end-to-end avg, P95, max, loss %; when `--owd` is used, **FwdOWD† (upload)** and **BwdOWD† (download)** rows appear in the same Phase/Samples/Avg/P95/Max format directly below the RTT rows
5. **One-Way Delay Analysis** — `--owd` only: BASELINE vs STRESS jitter table (received-only RTT range); large jitter = bufferbloat (queued probes returned with real high RTT); high loss% = drop-tail (probes truly discarded). Directional congestion diagnosis (suppressed when STRESS probe loss >50%).
6. **Throughput Summary** — DL/UL mean, max, median, P10, P90 Mbps
7. **Time-Series Table** — 1-second RTT + throughput data
8. **ASCII Chart** — dual-axis: throughput (▓ DL, ░ UL) + RTT (● stress, ○ baseline); when `--owd` is used, **▲ FwdOWD† (UL)** and **▽ BwdOWD† (DL)** overlaid; **X** marks truly dropped probes (no response after drain window)
9. **Traffic Summary** — per-client success/fail/socket stats from traffic-gen.py

#### Sample Output

```
========================================================================
             PER-SEGMENT BLOAT ANALYSIS (Incremental Delay)
========================================================================
Hop  Segment                            Link Base   Link P95    Bloat
------------------------------------------------------------------------
1    (source) -> 172.20.10.1            0.42        0.64        0.22
4    192.168.5.2 -> 10.222.70.81        59.32       1001.65     942.33      <<<

========================================================================
                  OVERALL LATENCY SUMMARY (End-to-End)
========================================================================
Phase        Samples  Loss %   Avg (ms)   P95 (ms)   Max (ms)
------------------------------------------------------------------------
BASELINE           1     0.0      61.50      61.50      61.50
STRESS           120     0.0     547.46    1001.42    1326.19

  — FwdOWD† (upload) —           (shown only with --owd)
Phase        Samples  Loss %   Avg (ms)   P95 (ms)   Max (ms)
------------------------------------------------------------------------
BASELINE          60       —      12.30      14.10      16.00
STRESS           120       —      45.20      67.80      95.00

  — BwdOWD† (download) —
Phase        Samples  Loss %   Avg (ms)   P95 (ms)   Max (ms)
------------------------------------------------------------------------
BASELINE          60       —      11.80      13.20      15.00
STRESS           120       —      89.70     134.50     180.00

========================================================================
                 THROUGHPUT SUMMARY (Browsing Traffic)
========================================================================
Direction    Mean Mbps     Max  Median     P10     P90 Samples
------------------------------------------------------------------------
download        394.94 2468.53    3.27    0.01 1692.65      49
upload          187.52  463.39  139.85   13.61  391.88      20

================================================================================
         ASCII CHART: Throughput (▓DL ░UL) + RTT (●) + OWD (▲▽)   (--owd)
================================================================================
  Y-axis left: Throughput (0-500 Mbps)   Y-axis right: RTT+OWD (0-200 ms)

 500.0│                              ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓           │   200
      │                           ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓           │   180
      │○  ○  ○  ○  ○  ○  ○  ○    ░░░░░░░░░░░░░░░░░░░░░░░░           │   160
      │                              ▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽▽            │   140
      │                              ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲            │   120
      │                                    ●●●●●●●●●●●●●●●            │   100
   0.0│                                                               │     0
      └───────────────────────────────────────────────────┘
  Legend: ▓ DL Mbps   ░ UL Mbps   ○ Base RTT   ● Stress RTT   ▲ FwdOWD†(UL)   ▽ BwdOWD†(DL)   X Dropped probe
```

#### Requirements

- Python 3.8+
- `curl` (with HTTP/3/QUIC support optional)
- `dd` (for upload data generation)
- `traceroute` (`apt install traceroute`)
- `scapy` + root (`pip install scapy`) — required only for `--owd`

---

### traffic-gen.py

Standalone browsing traffic simulator. Spawns concurrent download and upload threads that fetch random URLs via curl, generating realistic HTTP/HTTPS/QUIC traffic patterns.

#### What It Does

- Launches parallel DL and UL worker threads via `ThreadPoolExecutor`
- Downloads from popular sites (Google, Facebook, Wikipedia, etc.) and large test files
- Uploads random-sized data blobs (10–49 MB) to httpbin.org
- Supports HTTP/3 (QUIC) when curl has `--http3` support
- Tracks per-client stats: success/fail, bytes transferred, socket events
- Writes real-time byte counters to a stats file (for use by `userbufferTest.py`)

#### Usage

```bash
# Default: 30 DL + 50 UL threads, runs for 3000 minutes
python3 python/traffic-gen.py

# Custom settings
python3 python/traffic-gen.py -d 15 -u 25 -t 10

# With CSV report and stats file
python3 python/traffic-gen.py -d 20 -u 30 -t 5 -l report.csv -S stats.dat

# No periodic progress (quiet mode)
python3 python/traffic-gen.py -p 0
```

#### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --dl-clients` | Parallel download threads | `30` |
| `-u, --ul-clients` | Parallel upload threads | `50` |
| `-t, --duration` | Run duration in minutes (0 = unlimited) | `3000` |
| `-l, --log` | Save final report to CSV file | — |
| `-p, --progress` | Periodic summary interval in seconds (0 = off) | `60` |
| `-S, --stats-file` | Write cumulative byte counters to this file every second | — |

#### URL Groups

| Group | Protocol | Sites |
|-------|----------|-------|
| G1_QUIC | HTTP/3 | google.com, facebook.com, chatgpt.com, tiktok.com |
| G2_HTTPS | HTTPS | wikipedia.org, reddit.com, amazon.com, github.com, ... |
| G3_HTTP | HTTP | msn.com, yahoo.com, cnn.com, bing.com, bbc.com |
| G4_FILES | HTTP/S | 100MB/512MB test files from thinkbroadband, hetzner, leaseweb |
| G5_UPLOADS | HTTP/S | httpbin.org/post |

---

### tcp_owd.py

Estimates per-direction one-way delay (OWD) and jitter using the TCP Timestamp
Option (RFC 7323) on a single established TCP connection — no server daemon, no NTP
clock synchronisation required.

Supports two modes:

| Mode | Trigger | Use case |
|------|---------|----------|
| **Single-phase** | `--count N` (default) | Quick spot-check of current latency |
| **Two-phase** | `--baseline S --stress S` | Automated bufferbloat diagnosis — idle vs under load |

#### How It Works

**Connection setup:**
1. Establishes a raw TCP connection (Scapy + iptables) to any open port on the target.
2. Sends a real HTTP `HEAD` request to bootstrap the session so CDN infrastructure
   (Cloudflare, Google, etc.) does not rate-limit subsequent probes.
3. Sends HTTP HEAD probes (`seq = our_seq`, `flags=PA`) on the **same** connection.
   The server echoes our exact `TSval` in the ACK `TSecr` field (RFC 7323), enabling
   unambiguous probe matching and correct round-trip RTT measurement.

**Why a single established connection matters:**
Modern hosts implement RFC 7323 §5.4 — each *new* TCP connection receives a unique
random `TSval` base (derived from a secret key + the connection 4-tuple).  Sending a
fresh SYN per probe produces unrelated `TSval` values whose differences are meaningless.
A single established connection gives a monotonically increasing `TSval` stream whose
increments directly reflect forward-path delay changes.

**OWD calculation — direct server TSval clock:**

The handshake gives us a fixed time anchor: the server sent the SYN-ACK with `TSval = S0`
at approximately `T_anchor = t_synack − RTT_hs/2` (client monotonic clock).
Every subsequent probe ACK contains a new server TSval `S_i` from the **same clock**.

For each probe i (received at `t_recv_i`, server TSval `S_i`):

```
T_server_tx_i = T_anchor  +  (S_i − S0) / Hz           # when server sent this ACK
BwdOWD†[i]   = t_recv_i  −  T_server_tx_i              # download delay (server→client)
FwdOWD†[i]   = RTT[i]    −  BwdOWD†[i]                 # upload delay   (client→server)
```

Each probe is computed **independently** against the handshake anchor — no cumulative
drift, no cross-probe dependencies.  Under heavy bufferbloat where most probes time out,
the few surviving probes each yield a correct, uncontaminated OWD estimate.

Per-probe IPDV deltas (consecutive pairs) are also reported for diagnostics:

```
fwd_ipdv[i]  = (TSval[i] − TSval[i−1]) / Hz  −  (t_send[i] − t_send[i−1])
             = upload_delay[i]  − upload_delay[i−1]    # exact Δ in upload delay
bwd_ipdv[i]  = RTT_delta[i] − fwd_ipdv[i]
             = download_delay[i] − download_delay[i−1]  # exact Δ in download delay
```

The anchor `RTT_hs/2` treats the handshake as a symmetric baseline.  On asymmetric links
(e.g. download 35 ms / upload 5 ms of a 40 ms RTT) this places T_anchor too early,
producing `BwdOWD > RTT` and `FwdOWD < 0` — physically impossible.  To fix this the code
applies an **anchor asymmetry correction** after computing all OWD values:

```
delta = max(0, −min(FwdOWD across BASELINE probes))
FwdOWD[all] += delta          # shift fwd up so minimum = 0
BwdOWD[all] -= delta          # compensate bwd by the same amount
```

The shift preserves all relative trends and phase deltas; its magnitude equals the link's
upload/download asymmetry at handshake time.

**Probe DSCP marking:** probes use `tos=0` (normal best-effort), so they join the same
queue as bulk data.  This is essential — marking probes DSCP EF would let them bypass
the congested upload queue, showing propagation-only RTT (~30 ms) instead of the true
bufferbloat RTT (~600 ms).

**Async probing (fire-and-forget) — `run_probes_async()`:**

When called from `userbufferTest.py`, all probes are sent without blocking (`send()`).
A background **daemon thread** running `sniff()` captures server ACKs; each response is
matched to its originating probe via `TSecr` (the server echoes our `TSval` back in every
ACK). The response filter accepts **only pure ACK packets** (`flags == 0x10`) — this
rejects TCP FIN/ACK frames that CDN edge servers (e.g. Cloudflare) send when an idle
connection times out, which would otherwise be mistaken for probe responses. After all
probes are sent, the drain window (`--owd-timeout`, default 2 s) collects late-arriving
responses before declaring remaining probes dropped.

```
Main thread:                         sniff() daemon thread:
  send probe 1 → pending[TSval1]       pkt (flags=ACK): TSecr=TSval1
  send probe 2 → pending[TSval2]         → exact match → pop pending[TSval1]
  send probe 3 → pending[TSval3]         → RTT = t_recv - t_send → results
  ...                                  pkt (flags=ACK): TSecr=TSval3 (late, 1.8 s) → match
  wait drain window (2 s)              pkt (flags=FIN|ACK): → rejected (flags≠0x10)
  probe 2 still in pending → timed_out=True, rtt_ms=None (truly dropped)
```

Result:
- **Bufferbloat** (probe queued, eventually responds): arrives at real high RTT (e.g. 800 ms) → `rtt_ms=800` → included in jitter naturally
- **Drop-tail** (probe discarded, no response): `timed_out=True, rtt_ms=None` → counted as Loss%; jitter computed from surviving probes only
**Probe format — HTTP HEAD requests (in-window data):**  The async prober
(`run_probes_async`) sends `HEAD / HTTP/1.1` requests as probes.  These are *in-window* data
segments (`seq=our_seq`, `flags=PA`): the server echoes our exact probe `TSval` in the ACK
(`TSecr`), enabling **unambiguous one-to-one TSecr matching** and correct RTT measurement.
The sniffer ACKs the server's HTTP response automatically to keep the TCP window clear.

Keep-alives (`seq=our_seq-1`, *out-of-window*) are not used: RFC 7323 §3.4 prohibits servers
from updating `TSecr` from out-of-window segments, so CDNs (Cloudflare, etc.) would echo the
bootstrap `TSval` instead of the probe `TSval`, requiring an unreliable LIFO fallback.

**TCP flag filtering in the response sniffer:**  The response handler explicitly filters:
- **RST (0x04):** Connection reset — silently discarded; pending probe times out at drain window.
- **FIN / FIN+ACK (0x01):** Server closing connection — discarded to prevent a FIN from being
  matched as a probe response (the FIN's `TSecr` is the last valid TSval sent, not a probe key).
- **Pure ACK (0x10) and PSH+ACK (0x18):** Accepted and matched via exact TSecr lookup.

**Known limitation (M2 probe method):** HTTP HEAD responses include variable server-side
processing time (~0–50ms for CDN edge nodes). This adds noise to probe RTT (~±25ms) and
FwdIPDV measurements compared to a pure network echo. Phase *deltas* (BASELINE→STRESS change)
remain reliable; absolute OWD values are estimates.

**HTTP/2 PING probes (M3) — `run_h2_ping_probes()`:**  A second probe method connects to
port 443 via TLS with HTTP/2 (ALPN `h2`) negotiation and sends RFC 7540 §6.7 `PING` frames.
The server responds with a `PING ACK` frame at the **kernel TCP level** with no application-layer
processing (CDN edge nodes echo H2 PINGs immediately in the TCP stack, similar to ICMP echo).
The expected RTT for H2 PING ≈ traceroute ICMP RTT; FwdIPDV noise is much lower (~1–10ms vs
~50–100ms for HTTP HEAD).  OWD direction split uses the same server TSval clock method.

A parallel Scapy sniffer captures TCP timestamps on port 443 (both outgoing and incoming
packets) to:
1. Learn the kernel-assigned `TSval` for each outgoing PING frame (not controlled by the app layer)
2. Match the server's `TSecr` in the incoming ACK to compute RTT and BwdOWD

No `iptables` RST suppression is needed for H2 PING — the kernel manages the connection and
does not send spurious RSTs.

**OWD comparison output:**  The tool reports all three OWD estimation methods side by side:

| Method | Port | Probe | FwdOWD split | Notes |
|--------|------|-------|--------------|-------|
| M1: RTT/2 | 80 | HTTP HEAD | Symmetric (RTT/2 each) | Simplest; valid when path is symmetric |
| M2: TSval-dir | 80 | HTTP HEAD | Server TSval clock | Directional; noise from CDN processing |
| M3: H2 PING | 443 | HTTP/2 PING | Server TSval clock | Cleanest RTT; kernel-level echo |

M1 and M2 use the identical HTTP HEAD probe data — they differ only in how the RTT is split
into directions.  M3 uses a separate TLS+H2 connection running concurrently during the same
measurement phase, so all three methods see the same network conditions.

**Probe matching — exact TSecr lookup:**  Each probe embeds a unique `TSval`; the server
echoes it as `TSecr` in its ACK.  The match is direct dictionary lookup (`pending[tsecr]`)
with no fallback needed.  Probes not matched within the drain window are counted as loss.

**Probe loss ~50–66% on CDN targets** remains possible when the server batches ACKs
(delayed-ACK: one ACK per two consecutive incoming segments).  This is a normal TCP
behaviour and not a measurement error.  Only one of the two batched probes gets an
individual ACK; the other is counted as no-response.

The standalone `__main__` path uses synchronous `run_probes()` with `sr1()` (per-probe
blocking receive with a 2 s timeout per probe) — simpler and also correct, at the cost of
serialised probe sending.

#### Two-Phase Bufferbloat Test

When `--baseline` and/or `--stress` are set the tool runs an automated congestion test:

```
[Phase 1 — BASELINE]  probe for --baseline seconds  (network idle)
         ↓
[traffic-gen.py starts]  waits 5 s for congestion to build
         ↓
[Phase 2 — STRESS]    probe for --stress seconds    (network under load)
         ↓
[traffic-gen.py stops]
         ↓
[Phase Comparison table]
```

All probes across both phases run on the **same TCP connection** so TSval values remain
comparable.  Each probe is anchored directly to the handshake, so phase-boundary gaps
(while traffic-gen ramps up) do not corrupt OWD estimates.

The **Phase Comparison** summary shows avg and p95 per direction for each phase plus
the delta, so it is immediately clear which direction was hit hardest by congestion:

```
--------------------------------------------------------------------------
 Phase Comparison
--------------------------------------------------------------------------
  Phase        FwdOWD†avg  FwdOWD†p95  BwdOWD†avg  BwdOWD†p95   RTT avg   RTT p95
  --------------------------------------------------------------------------
  BASELINE          12.30       14.10       11.80       13.20      24.10     27.30
  STRESS            45.20       67.80       89.70      134.50     134.90    202.30
  --------------------------------------------------------------------------
  Change           +32.90      +53.70      +77.90     +121.30    +110.80   +175.00
```

#### Output Columns

| Column | Meaning |
|--------|---------|
| `Phase` | `BASELINE` or `STRESS` (two-phase mode only) |
| `RTT(ms)` | Round-trip time for this probe (pure network RTT, matches traceroute) |
| `FwdOWD†(ms)` | Upload OWD (client→server) = RTT − BwdOWD† |
| `BwdOWD†(ms)` | Download OWD (server→client), estimated via server TSval clock |
| `FwdIPDV(ms)` | Change in upload delay vs previous probe (`+` = got worse) |
| `BwdIPDV(ms)` | Change in download delay vs previous probe (`+` = got worse) |
| `RTTJitter(ms)` | Total path jitter: `max(RTT) − min(RTT)` within the phase |
| `FwdJitter(ms)` | Upload jitter: range of `FwdIPDV` values within the phase |
| `BwdJitter(ms)` | Download jitter: range of `BwdIPDV` values within the phase |

`†` = anchored to handshake RTT/2 with auto-calibration for link asymmetry; each probe computed independently.

**Note on jitter columns:** `FwdJitter` and `BwdJitter` are IPDV ranges (`max − min` of per-probe
delay deltas), not OWD ranges.  They measure how much the per-direction delay *varied* between
consecutive probes — the correct metric for congestion jitter.  A positive `FwdJitter` spike
during STRESS is the primary indicator of upload path congestion.

#### Limitations

- **Absolute values have a residual offset.** The anchor asymmetry correction zeroes
  the minimum baseline FwdOWD, so both directions are non-negative.  The exact split
  between upload and download OWD is an estimate (no clock sync with the server), but
  **trends and phase deltas are accurate** — sufficient for bufferbloat diagnosis.
- **Hz accuracy.** The server TSval clock rate is estimated from the first 10 probe pairs.
  A 1% Hz error introduces ~1.2 ms drift over a 2-minute test — negligible in practice.
- True directional OWD (as measured by TWAMP/RFC 5357) requires NTP/PTP-synchronized
  clocks on both ends.  This tool provides the closest achievable approximation without
  any clock infrastructure or remote software.
- **Drain window adds latency per phase.** After all probes are sent, the tool waits up
  to 5 s for late responses before declaring drops. On a 60 s STRESS phase this adds ~5 s
  of wait time. On satellite or very high-latency links, increase the drain timeout to
  match the expected maximum queue delay.
- **OWD probe loss under heavy upload congestion.** HTTP HEAD probes compete for the same
  upload buffer as real traffic.  Under severe upload bufferbloat (drop-tail), probes queue
  behind megabytes of pending data and either time out or are dropped entirely.
  **100% probe loss during STRESS = confirmed drop-tail congestion** — a diagnostic signal,
  not a measurement failure.  The **per-hop bloat table** (from traceroute) remains the
  reliable magnitude signal; OWD probe loss % indicates whether the bottleneck queue is
  drop-tail or AQM-managed.
- **M2 probe RTT includes server processing time.** HTTP HEAD responses from CDN edge nodes
  include variable processing time (~0–50ms for Cloudflare).  Probe RTT range at idle is
  typically ~±25ms wider than traceroute ICMP RTT range.  Use M3 (H2 PING) for a cleaner
  RTT that matches traceroute; use phase *deltas* (BASELINE→STRESS) for reliable congestion
  direction even with M2 processing noise.
- **M3 (H2 PING) requires port 443 and HTTP/2 support.**  If the target does not support
  TLS or HTTP/2 (ALPN `h2` negotiation fails), M3 is skipped and only M1/M2 are reported.
  M3 also uses a separate TLS connection; its RTT includes TLS handshake overhead on the
  *first* probe only — subsequent probes are purely network + kernel ACK latency.
- Linux only (requires `iptables` to suppress kernel-generated RST packets on the raw
  Scapy connection for M1/M2).  Requires root or `CAP_NET_RAW`.  M3 (H2 PING) does not
  need iptables suppression as it uses a normal kernel TCP connection.

#### CLI Options

**Single-phase options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--target / -T` | *(required)* | Target IP address |
| `--port / -p` | `80` | Open TCP port on target |
| `--count / -n` | `20` | Number of OWD probes (single-phase) |
| `--interval / -i` | `0.2 s` | Time between probes |
| `--timeout / -w` | `2.0 s` | Wait time per probe |
| `--output / -o` | — | Save per-probe results to CSV |
| `--verbose / -v` | — | Print raw TSval / TSecr per probe |

**Two-phase options** (any value > 0 activates two-phase mode, replacing `--count`):

| Option | Default | Description |
|--------|---------|-------------|
| `--baseline / -b` | `0` | Idle baseline measurement duration (seconds) |
| `--stress / -s` | `0` | Under-load stress measurement duration (seconds) |
| `--dl-clients` | `4` | Download clients spawned by traffic-gen |
| `--ul-clients` | `4` | Upload clients spawned by traffic-gen |

#### Usage

```bash
# Install dependency
pip install scapy

# Single-phase: quick latency check
sudo python3 python/tcp_owd.py --target 1.1.1.1 --port 80

# Single-phase: 30 probes at 500 ms intervals, save CSV
sudo python3 python/tcp_owd.py --target 8.8.8.8 --count 30 --interval 0.5 --output owd.csv

# Two-phase bufferbloat test: 30 s baseline → congest → 60 s stress
sudo python3 python/tcp_owd.py --target 1.1.1.1 --baseline 30 --stress 60

# Two-phase with custom traffic load and CSV output
sudo python3 python/tcp_owd.py --target 192.168.1.1 \
    --baseline 20 --stress 60 \
    --dl-clients 8 --ul-clients 4 \
    --output bloat.csv
```

---

## Known Limitations (OWD / Jitter Measurement)

### Absolute OWD split (Fwd/Bwd) is approximate

`tcp_owd.py` estimates per-direction OWD by treating the server's TCP Timestamp (TSval)
as a clock (RFC 7323). The method has two error sources:

- **Hz estimation noise**: The server TSval rate (Hz) is estimated from quiet BASELINE
  probes. Under CPU load the server stamps TSval at kernel-scheduled time, not wire
  arrival — this introduces noise. A 50 ppm Hz error over 40 s = 20 ms OWD drift.
- **Calibration shift**: When the estimated fwd OWD goes negative (impossible), all
  probes are shifted by `-min(fwd_owd)`. This corrects systematic error but the
  shift magnitude tells you how accurate the split is — shifts >5 ms mean the
  absolute Fwd/Bwd split is approximate (±shift ms).

The calibration shift and Hz estimate are shown in the summary footer so you can judge
reliability at a glance. If the shift is large (>5 ms), trust IPDV jitter and RTT jitter
more than the absolute OWD numbers.

### IPDV jitter is more reliable than absolute OWD

Fwd IPDV = `server_TSval_gap − client_send_gap`. This is immune to Hz drift and anchor
errors because it only uses *differences* between adjacent TSval samples, not absolute
positions. It is the primary per-direction congestion signal.

### RTT jitter is the most reliable congestion indicator

`max(RTT) − min(RTT)` per phase comes from traceroute ICMP data and has no TSval
dependency. When OWD probe loss is high (>50%) or the calibration shift is large, RTT
jitter from the segment bloat table is the most trustworthy congestion magnitude signal.

### Bufferbloat vs drop-tail congestion: different signals

The async probing architecture (`run_probes_async` + `sniff()` daemon thread) correctly
distinguishes the two types of congestion:

| Congestion type | OWD jitter (RTT range) | Loss% | Primary signal |
|---|---|---|---|
| **Bufferbloat** (queue building, packets delayed) | **Large** — queued probes return with real high RTT (e.g. 2500 ms) | Low | Jitter — large spread in received RTTs |
| **Drop-tail** (queue full, packets discarded) | **Small** — only drain-gap survivors; `rtt_ms=None` for drops | **High (>50%)** | Loss% — probes are truly gone |

Under drop-tail, the surviving probes all hit queue-drain gaps and show similar low RTT
(~25 ms), producing small jitter that understates congestion severity. Loss% is the correct
signal. On the ASCII chart, truly dropped probes appear as `X` marks at the top row.

### OWD direction diagnosis can be inverted under high probe loss

When STRESS probe loss exceeds 50%, surviving probes are not a random sample — they are
"lucky" probes that slipped through queue-drain gaps. These probes show *low* FwdOWD
(fast upload) because the queue happened to be empty. Since BwdOWD = RTT − FwdOWD, and
RTT is still elevated, BwdOWD appears high — the diagnosis can conclude "download degraded"
when the congestion is actually in the upload direction.

`userbufferTest.py` detects this and **suppresses** the OWD direction diagnosis when
STRESS probe loss > 50%, replacing it with an explicit warning. When the calibration shift
exceeds 5 ms, diagnosis is marked low-confidence in both `userbufferTest.py` and standalone
`tcp_owd.py`.

**When probe loss is high, use these reliable signals instead:**
- **Per-hop bloat table**: the hop with the highest bloat ms is where the queue is
- **RTT jitter** (`max(RTT) − min(RTT)`): no TSval dependency, immune to survivorship bias
- **Probe drop rate increase** (BASELINE% → STRESS%): direct drop-tail congestion indicator

---

## Configuration (config.json)

All settings are centralized in `config.json`. Each bash script reads the keys it needs at startup.

To switch profiles, change `"active_profile"` — no need to edit any script.

To use a different config file: `CONFIG_FILE=/path/to/config.json bash/bufferManager.sh <cmd>`

### Structure

```json
{
  "active_profile": "config1",       // Select which profile to use

  "profiles": {
    "config1": {
      "manager": { ... },            // bufferManager.sh settings
      "test": { ... }                // bufferTest.sh settings
    },
    "config2": { ... }
  },

  "ifb_device": "ifb0",             // IFB device for ingress shaping
  "fq_codel": { ... },              // fq_codel qdisc parameters
  "cake": { ... },                  // CAKE qdisc parameters
  "test": { ... },                  // bufferTest.sh general/logging/iperf settings
  "scenario": { ... }               // bufferScenarioTest.sh settings
}
```

### Profile: manager (bufferManager.sh)

| Key | Description | Example |
|-----|-------------|---------|
| `interface` | Network interface to shape | `"eth1"` |
| `mode` | `"static"` (fixed rates) or `"adaptive"` (RTT-based) | `"adaptive"` |
| `egress_rate` / `ingress_rate` | Fixed shaping rates (static mode) | `"2mbit"` |
| `max_egress` / `max_ingress` | Rate ceilings (adaptive mode) | `"10mbit"` |
| `min_egress_pct` / `min_ingress_pct` | Rate floors as % of max | `2` |
| `baseline_rtt` | Known good RTT in ms (no bloat) | `60` |
| `max_rtt` | RTT at which rates hit the floor | `150` |
| `autorate_target` | Host to ping for RTT probes | `"10.1.2.1"` |
| `autorate_interval` | Seconds between RTT probes | `5` |
| `dampen_pct` | Max rate change per step (%) | `10` |

### Profile: test (bufferTest.sh)

| Key | Description | Example |
|-----|-------------|---------|
| `target` | Remote iperf3 server IP | `"10.1.2.1"` |
| `bind_ip` | Local interface IP to bind | `"192.168.1.1"` |
| `udp_bw_dl` | UDP downlink bandwidth | `"15M"` |
| `udp_bw_ul` | UDP uplink bandwidth | `"5M"` |

### Shared: fq_codel / cake

| Key | Description | Default |
|-----|-------------|---------|
| `fq_codel.target` | AQM target delay | `"5ms"` |
| `fq_codel.interval` | AQM interval | `"100ms"` |
| `fq_codel.limit` | Queue packet limit | `1000` |
| `fq_codel.flows` | Flow count | `1024` |
| `fq_codel.quantum` | Bytes per round | `1514` |
| `fq_codel.mem_limit` | Memory limit | `"32Mb"` |
| `cake.rtt` | CAKE RTT estimate | `"50ms"` |
| `cake.overhead` | Link-layer overhead | `0` |
| `cake.mpu` | Min packet unit | `0` |
| `cake.diffserv` | Diffserv mode | `"diffserv4"` |

### Shared: test settings (bufferTest.sh)

| Key | Description | Default |
|-----|-------------|---------|
| `test.general.baseline_sec` | Phase 1 duration (s) | `30` |
| `test.general.stress_sec` | Phase 2 duration (s) | `200` |
| `test.general.poll_interval` | Traceroute frequency (s) | `1` |
| `test.general.timeout` | Traceroute per-hop wait (s) | `2` |
| `test.general.max_rtt_sec` | Hard wall-clock limit for one traceroute round (s); probes exceeding this are counted as lost | `5` |
| `test.logging.main_log` | CSV output filename | `"bloat_results.log"` |
| `test.logging.stress_type` | `"tcp"` or `"udp"` | `"tcp"` |
| `test.iperf_common.enable_stress` | Run iperf3 or monitor-only | `true` |
| `test.iperf_common.enable_dl` | Run downlink iperf3 | `true` |
| `test.iperf_common.enable_ul` | Run uplink iperf3 | `true` |
| `test.iperf_common.connect_timeout` | Seconds to wait before declaring a port failed | `10` |
| `test.iperf_common.port_retries` | Times to cycle through the full port list before giving up | `2` |
| `test.iperf_common.report_interval` | iperf3 -i value | `1` |
| `test.iperf_common.show_diagram` | Show ASCII diagram | `true` |
| `test.udp.port_dl` | UDP DL port(s) — single value or array | `[5991, 5993]` |
| `test.udp.port_ul` | UDP UL port(s) — single value or array | `[5992, 5994]` |
| `test.udp.parallel` | UDP parallel streams | `1` |
| `test.tcp.port_dl` | TCP DL port(s) — single value or array | `[5991, 5993]` |
| `test.tcp.port_ul` | TCP UL port(s) — single value or array | `[5992, 5994]` |
| `test.tcp.parallel` | TCP parallel streams | `4` |

### Shared: scenario (bufferScenarioTest.sh)

| Key | Description | Default |
|-----|-------------|---------|
| `scenario.runs` | Repetitions per scenario | `1` |
| `scenario.log_dir` | Output log directory | `"scenario_logs"` |
| `scenario.default_scenarios` | Array of `"label:cmd1,cmd2"` entries | (see config.json) |

---

## The Problem: Bufferbloat

When you saturate a network link, excess packets queue in buffers — often large, dumb FIFOs in routers and modems. This adds **hundreds of milliseconds** of latency under load, destroying VoIP, gaming, video calls, and interactive SSH even though throughput looks fine.

**The fix**: Shape traffic *below* the bottleneck speed at your device, using a smart qdisc (CAKE/fq_codel) that drops or ECN-marks packets early — so queuing happens at *your* device instead of in an upstream buffer you can't control.

---

## Bash Tools (iperf3 Server Required)

### bufferManager.sh

Traffic shaping and TCP stack tuning. Supports multiple qdisc strategies with static or adaptive (RTT-based) rate control.

#### Architecture

```
EGRESS (upload):
  App → [CAKE/HTB+fq_codel @ shaped rate] → NIC → wire → gateway

INGRESS (download, cake-bidir only):
  wire → NIC → [ingress qdisc] → redirect → [IFB0: CAKE @ shaped rate] → App
```

#### Strategies

| Command | Qdisc | Shaping | Best For |
|---------|-------|---------|----------|
| `cake-bidir` | CAKE egress + CAKE ingress via IFB | Yes (both directions) | **Recommended** — full bloat control |
| `cake` | CAKE egress only | Upload only | When download bloat isn't an issue |
| `htb` | HTB + fq_codel | Upload only | Kernels without CAKE module |
| `fq_codel` | fq_codel only | None | When bottleneck is at the NIC itself |
| `aggressive` | fq_codel (tight limits) | None | Last resort, aggressive AQM |

#### Adaptive Mode (autorate)

Instead of fixed rates, `autorate` continuously probes RTT and adjusts CAKE bandwidth:

```
Every 5s:
  1. Ping target → median RTT
  2. RTT ≤ baseline (60ms) → MAX rate
     RTT ≥ max (150ms)     → floor rate (2-5% of MAX)
     In between             → linear interpolation
  3. Dampen: cap change to ±10% per step (no oscillation)
  4. tc qdisc change (live, no traffic disruption)
```

#### TCP Tuning

`tune` applies complementary TCP stack optimizations:
- **BBR** congestion control (model-based, doesn't fill buffers)
- **ECN** enabled (CAKE marks instead of drops)
- **Reduced rmem/wmem** (limits TCP receive window → server sends slower)
- **Timestamps on**, slow_start_after_idle off

#### Config Profiles

Edit `config.json` to define link-specific profiles:

```json
{
  "active_profile": "config1",
  "profiles": {
    "config1": {
      "manager": {
        "interface": "eth1",
        "mode": "adaptive",
        "max_egress": "10mbit",
        "max_ingress": "25mbit",
        "baseline_rtt": 60,
        "max_rtt": 150,
        "autorate_target": "10.1.2.1"
      }
    }
  }
}
```

Switch profiles by changing `"active_profile"` — no script edits needed.

### Quick Start

```bash
# Static shaping
bash/bufferManager.sh tune && bash/bufferManager.sh cake-bidir

# Adaptive shaping
bash/bufferManager.sh tune && bash/bufferManager.sh cake-bidir && bash/bufferManager.sh autorate

# Check what's active
bash/bufferManager.sh diagnose

# View counters
bash/bufferManager.sh counters

# Remove everything
bash/bufferManager.sh remove && bash/bufferManager.sh untune
```

#### All Commands

```
Strategies:    cake-bidir | cake | htb | fq_codel | aggressive
TCP tuning:    tune | untune
Adaptive:      probe | adapt | autorate
Management:    status | counters | clear | diagnose | remove
```

---

### bufferTest.sh

Two-phase bufferbloat measurement using per-hop traceroute latency under idle and load conditions.

### How It Works

```
Discovery (1 traceroute):
  └─ Determine route depth (N hops) → used for per-hop probe jobs

Phase 1: BASELINE (30s)
  └─ Each hop probed in parallel every 1s → record per-hop latency (no load)

Phase 2: STRESS (200s)
  ├─ Launch iperf3 downlink + uplink (TCP or UDP, parallel streams)
  └─ Each hop probed in parallel every 1s → record per-hop latency (under load)
     Hops that don't respond → logged as Timeout (shown as '-' in chart)
```

> **`max_rtt_sec`** (config, default 5 s): Printed in the startup banner for reference. Parallel per-hop probes already bound each round to ~`timeout` seconds, so no additional kill logic is needed in bash.

#### Analysis Output

1. **Per-Segment Bloat Table** — incremental delay between each hop pair, baseline avg vs stress P95
2. **Ranked Bloat Summary** — worst bloating links sorted by severity
3. **ASCII Network Diagram** — visual path with per-link baseline/stress/bloat
4. **Overall Latency Summary** — end-to-end avg, P95, max, loss % per phase
5. **iperf3 Throughput Table** — DL/UL mean, max, median, P10, P90 Mbps

#### Sample Output

```
========================================================================
             PER-SEGMENT BLOAT ANALYSIS (Incremental Delay)
========================================================================
Hop  Segment                                Link Base    Link P95     Bloat
------------------------------------------------------------------------
2    (source) -> 10.0.1.1                   17.08        513.28       496.20
3    10.0.1.1 -> 10.0.2.1                   0.64         13.75        13.11
4    10.0.2.1 -> 10.1.2.1                   0.55         11.52        10.98

========================================================================
            LINK SEGMENTS RANKED BY BLOAT (Worst First)
========================================================================
IP Address         Bloat (ms)
------------------------------------------------------------------------
10.0.1.1           496.20       ms
10.0.2.1           13.11        ms
10.1.2.1           10.98        ms

========================================================================
             NETWORK PATH DIAGRAM (Baseline / Stress)
========================================================================

+---------------+
|  (source)    |
+---------------+
    |  Base:  17.08 ms
    |  P95:  513.28 ms
    |  Bloat: 496.20 ms  <<<
    v
+---------------+
| 10.0.1.1     |
+---------------+
    |  Base:   0.64 ms
    |  P95:   13.75 ms
    |  Bloat: 13.11 ms  <<<
    v
+---------------+
| 10.0.2.1     |
+---------------+
    |  Base:   0.55 ms
    |  P95:   11.52 ms
    |  Bloat: 10.98 ms  <<<
    v
+---------------+
| 10.1.2.1     |
+---------------+


========================================================================
             OVERALL LATENCY SUMMARY (End-to-End to 10.1.2.1)
========================================================================
Phase        Samples  Loss %     Avg (ms)   P95 (ms)   Max (ms)
------------------------------------------------------------------------
BASELINE     5        0.0        17.24      18.02      18.56
STRESS       32       3.0        447.03     524.32     530.20

==========================================================================================
             IPERF3 THROUGHPUT SUMMARY
==========================================================================================
Direction  Type   Data (MB)  Mean Mbps      Max   Median      P10      P90   Smpls
------------------------------------------------------------------------------------------
downlink   TCP        119.0       4.82     8.39     5.24     3.15     6.29     204
uplink     TCP         65.2       8.10    19.90     7.34     4.19    12.60      70
```

**Reading the results:**
- **Bloat column** shows added latency under load per hop — the `<<<` markers flag significant bloat
- **Hop 2 (source → 10.0.1.1)** jumped from 17ms baseline to 513ms P95 — this is the primary bloating link (the LTE/modem uplink buffer)
- **Overall**: baseline 17ms → stress P95 524ms = **~507ms of bufferbloat**
- **Throughput**: 4.82 Mbps downlink, 8.10 Mbps uplink (LTE link, uplink bursting without shaping)
- **RTT probe loss**: only 38/204 traceroute probes got through — ICMP packets dropped by congested buffers (this itself confirms bloat)

#### Config

All settings are read from `config.json`. Key parameters for this script:

```json
{
  "active_profile": "config1",
  "profiles": {
    "config1": {
      "test": {
        "target": "10.1.2.1",
        "bind_ip": "192.168.1.1",
        "udp_bw_dl": "15M",
        "udp_bw_ul": "5M"
      }
    }
  },
  "test": {
    "general": { "baseline_sec": 30, "stress_sec": 200 },
    "logging": { "stress_type": "tcp" },
    "iperf_common": { "enable_stress": true },
    "tcp": { "parallel": 4, "port_dl": 5991, "port_ul": 5992 }
  }
}
```

Run `bash/bufferTest.sh -h` for a full list of config keys.

#### Prerequisites

- **iperf3 server** running on the target host on each configured port. Start one listener per port in the `port_dl`/`port_ul` arrays — iperf3 handles one client connection per instance:
  ```bash
  iperf3 -s -p 5991 &   # DL primary
  iperf3 -s -p 5993 &   # DL fallback
  iperf3 -s -p 5992 &   # UL primary
  iperf3 -s -p 5994 &   # UL fallback
  ```
- `traceroute` installed
- iperf3 3.7+ required (for `--connect-timeout`, `--forceflush`); 3.9+ recommended (adds `--timestamps`)

#### Usage

```bash
bash/bufferTest.sh
```

Output files: `bloat_results.log` (CSV), `iperf_tcp_downlink.log`, `iperf_tcp_uplink.log`

---

### bufferScenarioTest.sh

Automated A/B testing wrapper. Runs multiple shaping strategies back-to-back, captures qdisc counters and iperf/latency metrics, and displays a color-coded comparison table.

#### What It Does Per Scenario

```
1. Clean slate     → bufferManager.sh remove + untune
2. Apply strategy  → bufferManager.sh tune, cake-bidir, autorate, etc.
3. Clear counters  → bufferManager.sh clear
4. Read counters   → capture pre-test snapshot
5. Run test        → bufferTest.sh (live output shown)
6. Read counters   → capture post-test snapshot, compute delta
7. Parse results   → extract iperf throughput + latency summaries
8. Kill autorate   → if it was running in background
```

### Sample Result (5 runs, base vs shaped+autorate)

Command: `bash/bufferScenarioTest.sh -r 5 -s "base:remove;shaped+autorate:tune,cake-bidir,autorate"`

```
════════════════════════════════════════════════════════════════
  SCENARIO COMPARISON TABLE  (5 run(s) per scenario, averaged)
════════════════════════════════════════════════════════════════
Metric                 │ base               │ shaped+autorate
────────────────────────────────────────────────────────────────
  IPERF3 THROUGHPUT
  DL Mean (Mbps)         │ 4.78               │ 4.72
  DL P90 (Mbps)          │ 6.29               │ 6.29
  UL Mean (Mbps)         │ 7.72               │ 2.53 (-67%)
  UL P90 (Mbps)          │ 12.38              │ 4.40 (-64%)
────────────────────────────────────────────────────────────────
  END-TO-END LATENCY
  Baseline Avg (ms)      │ 18.14              │ 17.32
  Baseline P95 (ms)      │ 18.18              │ 17.54
  Stress Avg (ms)        │ 448.07             │ 347.58 (-22%)
  Stress P95 (ms)        │ 512.99             │ 514.22
  Stress Loss %          │ 2.42               │ 3.04 (+26%)
────────────────────────────────────────────────────────────────
  QDISC COUNTERS (delta during test)
  Egress Pkts            │ 0.00               │ 75999.40
  Egress Dropped         │ 0.00               │ 21.80
  Egress Overlimits      │ 0.00               │ 123474.60
  Egress ECN Marks       │ 0.00               │ 0.00
  Ingress Pkts           │ 0.00               │ 0.00
  Ingress Dropped        │ 0.00               │ 0.00
  Ingress Overlimits     │ 0.00               │ 0.00
  Ingress ECN Marks      │ 0.00               │ 0.00
════════════════════════════════════════════════════════════════

  Green = better than 'base' baseline (>5% diff)
  Red   = worse than 'base' baseline (>5% diff)
  Values within 5% of baseline shown without color.
  All values averaged across 5 run(s).


  Per-Run Detail: base
  Run      DL Mbps    UL Mbps  St Avg ms  St P95 ms    Eg Drop    In Drop     Eg ECN
  ───── ────────── ────────── ────────── ────────── ────────── ────────── ──────────
  1           4.82       8.10     447.03     524.32          0          0          0
  2           4.86       7.47     451.30     520.74          0          0          0
  3           4.63       8.26     453.70     508.93          0          0          0
  4           4.81       7.96     445.62     504.11          0          0          0
  5           4.78       6.80     442.68     506.84          0          0          0

  Per-Run Detail: shaped+autorate
  Run      DL Mbps    UL Mbps  St Avg ms  St P95 ms    Eg Drop    In Drop     Eg ECN
  ───── ────────── ────────── ────────── ────────── ────────── ────────── ──────────
  1           4.70       2.74     347.62     520.97         57          0          0
  2           4.74       2.54     335.23     518.95         15          0          0
  3           4.69       2.29     351.57     503.62         18          0          0
  4           4.76       2.56     336.28     514.46         17          0          0
  5           4.71       2.53     367.18     513.11          2          0          0

Results saved to:
  Full log:    /var/TEST/BLOATBUSTER/scenario_logs/scenario_20260429_220813.log
  Summary:     /var/TEST/BLOATBUSTER/scenario_logs/summary_20260429_220813.txt
  Raw data:    /var/TEST/BLOATBUSTER/scenario_logs/results_20260429_220813/
```

**Reading the results:**
- **Stress Avg latency** dropped from 448ms → 348ms (**-22%**) with CAKE+autorate shaping
- **UL throughput** reduced from 7.72 → 2.53 Mbps (**-67%**) — intended trade-off: CAKE rate-shapes upload below the bottleneck to prevent the upstream buffer from filling
- **DL throughput** nearly unchanged (4.78 → 4.72 Mbps) — download not impacted
- **Egress Overlimits** (123k) shows CAKE actively delaying packets to enforce the shaped rate
- **Egress Drops** (avg 21.8/run) confirms CAKE is managing the queue at your device rather than the upstream FIFO
- **Per-run consistency**: shaped+autorate shows tight clustering (335–367ms stress avg vs 442–454ms for base)

#### Usage

```bash
# Baseline vs CAKE with autorate
bash/bufferScenarioTest.sh -s "base:remove;shaped+autorate:tune,cake-bidir,autorate"

# Full 3-way comparison, 3 runs each
bash/bufferScenarioTest.sh -r 3 -s "base:remove;shaped:tune,cake-bidir;shaped+autorate:tune,cake-bidir,autorate"

# All built-in scenarios
bash/bufferScenarioTest.sh

# List built-in scenarios
bash/bufferScenarioTest.sh -l
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r N` | Repetitions per scenario | 1 |
| `-s "..."` | Custom scenarios (`label:cmd1,cmd2;label2:cmd1,...`) | 6 built-in |
| `-o DIR` | Output directory | `./scenario_logs` |
| `-l` | List built-in scenarios | — |
| `-h` | Help | — |

#### Built-in Scenarios

| Label | Commands | Tests |
|-------|----------|-------|
| no-queue | `remove` | No shaping (control group) |
| fq_codel | `fq_codel` | AQM only, no rate shaping |
| cake-bidir | `tune,cake-bidir` | Static CAKE + TCP tuning |
| cake-bidir+autorate | `tune,cake-bidir,autorate` | Adaptive CAKE + TCP tuning |
| htb+tune | `tune,htb` | HTB + fq_codel fallback |
| aggressive | `tune,aggressive` | Tight fq_codel limits |

#### Output Files

```
scenario_logs/
├── scenario_20260428_190807.log          # Full execution log
├── summary_20260428_190807.txt           # Comparison table (plain text)
└── results_20260428_190807/
    ├── base/
    │   └── run_1/
    │       ├── counters_before.dat       # Pre-test qdisc counters
    │       ├── counters_after.dat        # Post-test qdisc counters
    │       ├── counter_delta.dat         # Computed delta
    │       ├── iperf_summary.dat         # Parsed throughput metrics
    │       ├── latency_summary.dat       # Parsed latency metrics
    │       └── bufferTest_full_output.txt # Complete bufferTest.sh output
    └── shaped_autorate/
        └── run_1/
            └── ...
```

---

## Technology

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Traffic shaping** | Linux `tc` (traffic control) | Qdisc management (CAKE, HTB, fq_codel) |
| **Ingress shaping** | IFB (Intermediate Functional Block) device | Redirect incoming traffic through CAKE |
| **Congestion control** | BBR (Bottleneck Bandwidth and RTT) | Model-based CC that avoids filling buffers |
| **ECN** | Explicit Congestion Notification | Signal congestion without dropping packets |
| **Latency measurement** | `traceroute` (ICMP) | Per-hop latency at 1-second intervals |
| **Throughput stress** | `iperf3` (TCP/UDP) | Saturate the link for bloat detection |
| **Rate adaptation** | ICMP ping + linear interpolation | RTT-driven CAKE bandwidth adjustment |
| **Visualization** | `bloatChart.sh` (AWK + ASCII) | Time-series overlay of throughput, RTT, rate limits |

---

### bloatChart.sh

ASCII time-series overlay chart showing iperf throughput, RTT, and autorate adjustments on a unified timeline. Runs automatically at the end of `bufferTest.sh` or standalone.

#### What It Shows

Three data series aligned by time (1-second intervals):
1. **iperf3 throughput** — DL (▓) and UL (░) in Mbps
2. **End-to-end RTT** — latency in ms (●) from traceroute probes
3. **Autorate limits** — egress (E) and ingress (I) rate caps applied by CAKE, with direction indicators (▲ increasing, ▼ decreasing, . stable)

### Sample Output

```
════════════════════════════════════════════════════════════════════════════════
             TIME-SERIES DATA (1-second intervals)
════════════════════════════════════════════════════════════════════════════════
Time     │ DL Mbps UL Mbps │  RTT ms │ Eg mbit In mbit │ Dir
─────────┼─────────────────┼─────────┼─────────────────┼────
22:45:19 │       -       - │    19.0 │      10      25 │ -
22:45:27 │    4.20    0.00 │       - │      10      25 │ -
22:45:30 │    4.19    0.00 │       - │       9      23 │ ▼
22:45:45 │    5.24    0.00 │       - │       7      19 │ ▼
22:46:00 │    5.24    1.05 │       - │       5      17 │ ▼
22:46:15 │    4.19    6.29 │       - │       3      15 │ ▼
22:46:30 │    5.24    1.05 │       - │       1      13 │ ▼
22:46:45 │    4.19    0.00 │       - │       1      11 │ ▼
22:47:00 │    8.39    0.00 │       - │       1       9 │ ▼
22:47:15 │    3.15    0.00 │       - │       1       7 │ ▼
22:47:30 │    7.34    2.10 │       - │       1       5 │ ▼
22:48:06 │    3.15    0.00 │       - │       2       6 │ ▲
22:48:21 │    5.25    1.05 │       - │       2       6 │ ▲
22:48:36 │    5.24    2.10 │       - │       2       6 │ ▲
...

════════════════════════════════════════════════════════════════════════════════
             ASCII CHART: Throughput (DL ▓, UL ░) + RTT (●)
════════════════════════════════════════════════════════════════════════════════
  Y-axis left: Throughput (0-13 Mbps)   Y-axis right: RTT (0-521 ms)

  12.6│                                                                        │  521
  11.9│                                     ●     ● ●                          │  494
  11.3│                                       ● ●                              │  466
  10.6│                                                                        │  439
   9.9│   ─                                                                    │  411
   8.6│      ─                                                                 │  356
   7.3│                      ▓    ▓                            ▓               │  302
   6.6│           ─          ▓    ▓                            ▓               │  274
   6.0│        ▓ ▓  ▓       ░▓    ▓          ▓  ▓   ▓     ▓   ▓▓        ▓      │  247
   4.6│        ▓▓▓▓ ▓  ▓ ▓ ▓░▓▓ ▓▓▓       ▓▓ ▓  ▓   ▓ ▓▓ ▓▓▓  ▓▓ ▓   ▓▓ ▓▓   ▓ │  192
   4.0│     ▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓ │  165
   2.7│     ▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │  110
   2.0│     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │   82
   0.0│  ● ●▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │    0
      └────────────────────────────────────────────────────────────────────────┘
        22:44:55      22:46:06      22:47:01      22:47:52            22:48:47

  Legend: ▓ DL Mbps   ░ UL Mbps   ● RTT (ms)   ─ Egress Rate Limit

════════════════════════════════════════════════════════════════════════════════
             ASCII CHART: Autorate Adjustment
════════════════════════════════════════════════════════════════════════════════
  Egress (E) and Ingress (I) rate limits over time.
  Range: 0-25 mbit   Direction: ▲=increase ▼=decrease .=stable

   25 │ IIIIII
   22 │       I
   20 │        I
   18 │         I
   15 │          III
   13 │             II
   11 │               II
    9 │ EEEEEE          II
    6 │       EEE         III
    4 │          EE          IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
    2 │            EE
    0 │              EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
      └───────────────────────────────────────────────────────────────────────
        ......▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▲▼▲▼▲▼▲▼▲▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼  ← Direction (▲ up ▼ down . stable)

  Legend: E=Egress rate  I=Ingress rate  X=Overlap  ▲▼.=Direction
```

#### Usage

```bash
# Runs automatically at the end of bufferTest.sh

# Or run standalone after a test
bash/bloatChart.sh

# Custom files and dimensions
bash/bloatChart.sh -r my_results.log -a autorate.log -w 120 -H 25

# Without autorate (just throughput + RTT)
bash/bloatChart.sh -r bloat_results.log -d iperf_tcp_downlink.log -u iperf_tcp_uplink.log
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r FILE` | RTT/latency CSV log | `bloat_results.log` |
| `-d FILE` | iperf3 downlink log | `iperf_<type>_downlink.log` |
| `-u FILE` | iperf3 uplink log | `iperf_<type>_uplink.log` |
| `-a FILE` | Autorate log (optional) | `autorate.log` |
| `-w WIDTH` | Chart width in columns | `80` |
| `-H HEIGHT` | Chart height in rows | `20` |
| `-h` | Help | — |

#### How It Helps

- **Correlate RTT spikes with throughput drops** — see exactly when bloat causes performance degradation
- **Verify autorate is responding** — watch rate limits decrease as RTT rises, and recover when RTT drops
- **Identify oscillation** — rapid ▲▼▲▼ patterns indicate dampen_pct is too high or probe interval too short
- **Compare baseline vs stress visually** — flat RTT in baseline, spikes under load = classic bufferbloat

---

## Deployment Scenarios

### LTE/4G Router Shaping
Low, variable bandwidth. High baseline latency. CAKE + autorate handles fluctuating link quality.

```bash
# Config: MAX_EGRESS=10mbit, MAX_INGRESS=25mbit, BASELINE_RTT=60ms
bash/bufferManager.sh tune && bash/bufferManager.sh cake-bidir && bash/bufferManager.sh autorate
```

### 5G / Fixed Wireless
Higher bandwidth but still variable. Larger rate ranges, same adaptive approach.

```bash
# Config: MAX_EGRESS=15mbit, MAX_INGRESS=65mbit
bash/bufferScenarioTest.sh -r 3 -s "base:remove;cake:tune,cake-bidir;adaptive:tune,cake-bidir,autorate"
```

### VPN / Tunnel Endpoints
Shape the tunnel interface to prevent the tunnel's encapsulation overhead from causing bloat at the underlying link.

### VoIP / Real-Time Traffic
CAKE's `diffserv4` classification prioritizes voice traffic. Combined with ECN, avoids drops on latency-sensitive flows.

### Benchmarking Before/After
Use `bufferScenarioTest.sh` to quantify the impact of different strategies on your specific link:

```bash
# "Is CAKE actually helping on my link?"
bash/bufferScenarioTest.sh -r 5 -s "baseline:remove;cake:tune,cake-bidir"
```

---

## Comparison with Other Bufferbloat Tools

### Why BloatBuster vs Flent / betterspeedtest / web tests?

Most existing bufferbloat tools (Flent, netperfrunner, web tests) tell you **"you have bloat"** but don't tell you **where in the network path** the bloat occurs. BloatBuster's per-hop traceroute under load pinpoints the exact link (hop) that's buffering — so you know whether the problem is your router, your ISP's DSLAM, or a backhaul node.

Additionally, Flent and netperf-based tools require **both a client and a dedicated server** (netperf/iperf running on both ends). BloatBuster's bash tools only need a standard iperf3 server on the remote end — no custom daemon, no Flent installation on the server, no coordination. The Python tools (`userbufferTest.py`) go further: they need **no server at all** — they use real HTTP/HTTPS/QUIC traffic to public websites for stress, so you can run a bufferbloat test from any Linux machine with internet access.

### Where in the Network You See Bloat

BloatBuster's per-hop analysis shows **incremental delay per link segment**:

```
Hop  Segment                     Link Base    Link P95     Bloat
--------------------------------------------------------------------
2    (source) -> 10.0.1.1        17.08        513.28       496.20  ← YOUR UPLINK BUFFER
3    10.0.1.1 -> 10.0.2.1         0.64         13.75        13.11  ← ISP backhaul
4    10.0.2.1 -> 10.1.2.1         0.55         11.52        10.98  ← Core network
```

- **Hop 2 has 496ms of bloat** → the modem/router uplink FIFO is the problem
- **Hops 3-4 have minimal bloat** → ISP core is fine
- Other tools only show end-to-end latency and can't distinguish where the queue is

### Detailed Comparison Table

| Feature | BloatBuster (Bash) | BloatBuster (Python) | Flent (RRUL) | betterspeedtest.sh | Web Tests (Waveform/Cloudflare) |
|---------|-------------------|---------------------|--------------|--------------------|---------------------------------|
| **Measures bloat location (per-hop)** | Yes | Yes | No | No | No |
| **Server requirement** | iperf3 server | **None** | netperf server + Flent | netperf server | None (CDN) |
| **Client-only operation** | Yes (needs iperf3 server) | **Yes (fully standalone)** | No | Yes | Yes |
| **Identifies bloating hop** | Yes | Yes | No | No | No |
| **Throughput measurement** | iperf3 (reliable) | /proc/net/dev or curl stats | netperf | netperf | Proprietary |
| **Built-in traffic shaping** | Yes (CAKE/HTB/fq_codel + autorate) | No | No | No | No |
| **A/B scenario comparison** | Yes — automated | No | Manual | No | No |
| **Graphical output** | ASCII diagrams + tables | ASCII chart + time-series | matplotlib plots | Text | Web UI |
| **Dependencies** | iperf3, traceroute, jq, tc | Python 3, curl, traceroute | Flent, netperf, matplotlib | netperf | Browser |
| **Works on embedded/router** | Yes (bash + basic tools) | Needs Python 3 | No | Yes | No |

### BloatBuster Advantages

1. **Per-hop bloat localization** — The key differentiator. Traceroute under load reveals which specific link in the path is bloated. Other tools only give you a single end-to-end latency number.

2. **Zero-server option (Python tools)** — `userbufferTest.py` needs no iperf3 server, no netperf, no custom daemon. It uses real browsing traffic to stress the link. Just point it at any IP and go.

3. **Client-side only** — Even the bash tools only need a standard iperf3 server on the remote end. No Flent/netperf installation on the server.

4. **Integrated shaping + measurement** — Test, shape, re-test in one workflow. Flent measures but doesn't fix; you need separate SQM/CAKE setup.

5. **Adaptive rate control (autorate)** — Continuous RTT-based bandwidth adjustment for variable links (LTE/5G).

6. **Automated A/B benchmarking** — `bufferScenarioTest.sh` runs N strategies × M repetitions and produces a comparison table.

7. **Wire-level throughput via /proc/net/dev** — `userbufferTest.py` reads kernel interface counters for smooth, accurate throughput data instead of relying on application-level byte counting.

8. **Lightweight / embeddable** — Bash tools are pure bash + standard Linux tools. Python tools need only Python 3 + curl.

### What Flent Does Better (gaps to consider)

| Flent Strength | BloatBuster Gap | Potential Improvement |
|----------------|-----------------|----------------------|
| Beautiful matplotlib graphs (time-series) | ASCII tables only | Add CSV export for external plotting (gnuplot/grafana) |
| RRUL test is an industry standard benchmark | Custom test, not directly comparable | Document methodology for reproducibility |
| Tested to 40GigE | Limited by iperf3 single-stream performance | Use DPDK or other ways to flood network |
| CDF/percentile plots over time | Summary statistics only | Add time-series CSV logging per interval |
| Metadata (kernel version, qdisc, etc.) in output | Not captured automatically | Add system info capture to logs |
| Large community + academic citations | New project | Publish methodology, invite comparison |

### When to Use What

| Scenario | Recommended Tool |
|----------|-----------------|
| "Where in my network is the bloat?" | **BloatBuster** (either approach) |
| Quick test, no server available | **userbufferTest.py** (Python) |
| Apply + test shaping in one workflow | **bufferTest.sh** + **bufferManager.sh** (Bash) |
| A/B comparison of shaping strategies | **bufferScenarioTest.sh** (Bash) |
| Router/embedded device (no Python) | **Bash tools** |
| LTE/5G with variable bandwidth | **Bash** (autorate) or **Python** (measurement only) |
| Quick letter-grade check | Web test (Waveform) |
| Academic/publishable benchmark | Flent (RRUL) |
| Pretty graphs for a presentation | Flent |

---

## Requirements

### System

| Requirement | Notes |
|-------------|-------|
| Linux | Required for both approaches. Bash tools need kernel 4.19+ for CAKE. |
| Root / sudo | Required by bash tools (`tc`, `ip link`, `sysctl`). Python tools run as regular user. |

### Python Tools Requirements

| Tool | Package | Purpose |
|------|---------|---------|
| Python 3.8+ | `python3` | Script interpreter |
| `curl` | `curl` | HTTP/HTTPS/QUIC traffic generation |
| `dd` | `coreutils` | Upload data generation |
| `traceroute` | `traceroute` | Per-hop ICMP latency measurement |

```bash
apt install python3 curl traceroute
```

### Bash Tools Requirements

| Tool | Package (Debian/Ubuntu) | Used By | Purpose |
|------|------------------------|---------|---------|
| `bash` 4+ | pre-installed | all scripts | Script interpreter |
| `tc` | `iproute2` | `bufferManager.sh` | Traffic control — create/modify qdiscs and filters |
| `ip` | `iproute2` | `bufferManager.sh` | Manage IFB device (`ip link add/set/del`) |
| `sysctl` | `procps` | `bufferManager.sh` | Apply TCP stack settings (BBR, ECN, buffer sizes) |
| `modprobe` | `kmod` | `bufferManager.sh` | Load `ifb` kernel module for ingress shaping |
| `ping` | `iputils-ping` | `bufferManager.sh` | RTT probes for autorate adaptation |
| `iperf3` 3.7+ | `iperf3` | `bufferTest.sh` | Saturate the link (TCP/UDP stress test) |
| `traceroute` | `traceroute` | `bufferTest.sh` | Per-hop ICMP latency measurement |
| `jq` | `jq` | all bash scripts | Parse and read `config.json` |
| `awk` | `gawk` / `mawk` | `bufferTest.sh`, `bloatChart.sh` | Log parsing and ASCII chart rendering |
| `bc` | `bc` | `bufferScenarioTest.sh` | Floating-point arithmetic |

```bash
apt install iproute2 procps kmod iputils-ping iperf3 traceroute jq gawk bc
```

### Kernel Modules

The following modules must be loadable (built-in or available as `.ko`):

| Module | Required For |
|--------|-------------|
| `sch_cake` | `cake`, `cake-bidir` strategies |
| `sch_fq_codel` | `fq_codel`, `htb`, `aggressive` strategies |
| `sch_htb` | `htb` strategy |
| `ifb` | Ingress shaping (`cake-bidir`) — loaded automatically via `modprobe ifb` |
| `tcp_bbr` | BBR congestion control (`tune` command) |

Check availability: `modinfo sch_cake` / `modinfo tcp_bbr`

### Remote iperf3 Server

`bufferTest.sh` requires an **iperf3 server** listening on the target host. Since iperf3 handles only one client connection per process, run one listener per port in your `port_dl`/`port_ul` arrays:

```bash
iperf3 -s -p 5991 &   # DL primary
iperf3 -s -p 5993 &   # DL fallback
iperf3 -s -p 5992 &   # UL primary
iperf3 -s -p 5994 &   # UL fallback
```

Configure ports via `test.tcp.port_dl` / `test.tcp.port_ul` (or UDP equivalents) in `config.json`. Both accept a single integer or an array of ports for automatic failover.

---

## Quick Reference

```bash
# ─── Python approach (no server needed) ───

# Quick bufferbloat test
python3 python/userbufferTest.py -T 8.8.8.8

# With custom interface and method
python3 python/userbufferTest.py -T 8.8.8.8 -m procnetdev -I wlan0

# Just generate traffic (standalone)
python3 python/traffic-gen.py -d 20 -u 30 -t 5

# ─── Bash approach (needs iperf3 server) ───

# 1. Edit config.json: set active_profile, interface, target, rates
#    (no script edits needed)

# 2. Verify connectivity
bash/bufferManager.sh probe

# 3. Run bufferTest.sh independently (measures bloat without shaping)
bash/bufferTest.sh

# 4. Run bufferManager.sh independently (apply shaping)
bash/bufferManager.sh tune && bash/bufferManager.sh cake-bidir

# 5. Run a quick before/after comparison
bash/bufferScenarioTest.sh -s "before:remove;after:tune,cake-bidir,autorate"

# 6. Run a thorough benchmark (3 repetitions)
bash/bufferScenarioTest.sh -r 3

# 7. Check results
cat scenario_logs/summary_*.txt

# Show help for each script
bash/bufferManager.sh          # (no args shows help)
bash/bufferTest.sh -h
bash/bufferScenarioTest.sh -h

# Override config file path
CONFIG_FILE=/etc/bloatbuster/config.json bash/bufferManager.sh cake-bidir
```
