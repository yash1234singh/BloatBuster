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
│   ├── userbufferTest.py           #   Bufferbloat measurement
│   └── traffic-gen.py              #   Browsing traffic generator
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
Phase 1: BASELINE (30s)
  └─ Traceroute every 1s to all hops → record per-hop latency (no load)

Phase 2: STRESS (120s)
  ├─ Launch traffic-gen.py (30 DL + 50 UL threads browsing real websites)
  └─ Traceroute every 1s to all hops → record per-hop latency (under load)
```

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
> **Mitigation:** Set `UL_RATE_LIMIT` in `traffic-gen.py` to `'100K'`–`'200K'` per worker. 50 × 200 KB/s = 10 MB/s max burst (vs 150 MB/s at `3M`). NIC TX then settles to WAN rate immediately. The link is still saturated (10 MB/s >> 9 Mbps WAN). Default stays `'3M'` to test at full rate.

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

The accurate solution requires either (a) setting `UL_RATE_LIMIT` low enough to prevent buffer flooding, or (b) measuring at the router/WAN side.

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

# Use statsfile method (curl-based, works on non-Linux)
python3 python/userbufferTest.py -T 8.8.8.8 -m statsfile
```

#### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-T, --target` | Traceroute target host/IP (required) | — |
| `-b, --baseline` | Baseline phase duration (seconds) | `30` |
| `-s, --stress` | Stress phase duration (seconds) | `120` |
| `-i, --interval` | Traceroute poll interval (seconds) | `1` |
| `-w, --timeout` | Traceroute wait timeout (seconds) | `2` |
| `-d, --dl-clients` | Download threads for traffic-gen.py | `30` |
| `-u, --ul-clients` | Upload threads for traffic-gen.py | `50` |
| `-m, --rate-method` | Throughput method: `auto`, `procnetdev`, `statsfile`, `ss` | `auto` |
| `-I, --interface` | Network interface for procnetdev (auto-detected if omitted) | auto |
| `-o, --output` | Save results to CSV file | — |
| `-W, --chart-width` | ASCII chart width in columns | `80` |
| `-H, --chart-height` | ASCII chart height in rows | `20` |

#### Analysis Output

1. **Per-Segment Bloat Table** — incremental delay between each hop pair
2. **Ranked Bloat Summary** — worst bloating links sorted by severity
3. **ASCII Network Diagram** — visual path with per-link baseline/stress/bloat
4. **Overall Latency Summary** — end-to-end avg, P95, max, loss %
5. **Throughput Summary** — DL/UL mean, max, median, P10, P90 Mbps
6. **Time-Series Table** — 1-second RTT + throughput data
7. **ASCII Chart** — dual-axis: throughput (▓ DL, ░ UL) + RTT (● stress, ○ baseline)
8. **Traffic Summary** — per-client success/fail/socket stats from traffic-gen.py

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
Phase       Samples  Loss %   Avg (ms)   P95 (ms)   Max (ms)
------------------------------------------------------------------------
BASELINE    1        0.0      61.50      61.50      61.50
STRESS      120      0.0      547.46     1001.42    1326.19

========================================================================
                 THROUGHPUT SUMMARY (Browsing Traffic)
========================================================================
Direction    Mean Mbps     Max  Median     P10     P90 Samples
------------------------------------------------------------------------
download        394.94 2468.53    3.27    0.01 1692.65      49
upload          187.52  463.39  139.85   13.61  391.88      20
```

#### Requirements

- Python 3.8+
- `curl` (with HTTP/3/QUIC support optional)
- `dd` (for upload data generation)
- `traceroute` (`apt install traceroute`)

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
| `test.general.timeout` | Traceroute wait (s) | `2` |
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
Phase 1: BASELINE (30s)
  └─ Traceroute every 1s to all hops → record per-hop latency (no load)

Phase 2: STRESS (200s)
  ├─ Launch iperf3 downlink + uplink (TCP or UDP, parallel streams)
  └─ Traceroute every 1s to all hops → record per-hop latency (under load)
```

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
