# Bufferbloat Testing Toolkit

Three scripts for detecting, mitigating, and benchmarking bufferbloat on Linux network links — particularly useful for LTE/5G, satellite, and other variable-bandwidth WANs.

## Overview

| Script | Purpose | Requires |
|--------|---------|----------|
| **bufferManager.sh** | Apply/remove traffic shaping strategies (CAKE, HTB, fq_codel) and TCP tuning (BBR, ECN) | `tc`, `ip`, `sysctl`, `jq`, root |
| **bufferTest.sh** | Measure bufferbloat via per-hop traceroute + iperf3 stress testing | `iperf3`, `traceroute`, `jq`, iperf3 server |
| **bufferScenarioTest.sh** | Orchestrate A/B comparisons: apply strategy → run test → record results → compare | Both scripts above, `jq`, `bc` |

All scripts read their configuration from a single **`config.json`** file (requires `jq`).

```
bufferScenarioTest.sh
  │
  ├─ bufferManager.sh remove/tune/cake-bidir/autorate  (apply strategy)
  ├─ bufferManager.sh clear                             (zero counters)
  ├─ bufferTest.sh                                      (run bloat test)
  ├─ bufferManager.sh counters                          (read counters)
  └─ Compare all scenarios in a table
```

---

## Configuration (config.json)

All settings are centralized in `config.json`. Each script reads the keys it needs at startup.

To switch profiles, change `"active_profile"` — no need to edit any script.

To use a different config file: `CONFIG_FILE=/path/to/config.json ./bufferManager.sh <cmd>`

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
| `test.iperf_common.report_interval` | iperf3 -i value | `1` |
| `test.iperf_common.show_diagram` | Show ASCII diagram | `true` |
| `test.udp.port_dl` / `port_ul` | UDP server ports | `5991` / `5992` |
| `test.udp.parallel` | UDP parallel streams | `1` |
| `test.tcp.port_dl` / `port_ul` | TCP server ports | `5991` / `5992` |
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

## bufferManager.sh

Traffic shaping and TCP stack tuning. Supports multiple qdisc strategies with static or adaptive (RTT-based) rate control.

### Architecture

```
EGRESS (upload):
  App → [CAKE/HTB+fq_codel @ shaped rate] → NIC → wire → gateway

INGRESS (download, cake-bidir only):
  wire → NIC → [ingress qdisc] → redirect → [IFB0: CAKE @ shaped rate] → App
```

### Strategies

| Command | Qdisc | Shaping | Best For |
|---------|-------|---------|----------|
| `cake-bidir` | CAKE egress + CAKE ingress via IFB | Yes (both directions) | **Recommended** — full bloat control |
| `cake` | CAKE egress only | Upload only | When download bloat isn't an issue |
| `htb` | HTB + fq_codel | Upload only | Kernels without CAKE module |
| `fq_codel` | fq_codel only | None | When bottleneck is at the NIC itself |
| `aggressive` | fq_codel (tight limits) | None | Last resort, aggressive AQM |

### Adaptive Mode (autorate)

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

### TCP Tuning

`tune` applies complementary TCP stack optimizations:
- **BBR** congestion control (model-based, doesn't fill buffers)
- **ECN** enabled (CAKE marks instead of drops)
- **Reduced rmem/wmem** (limits TCP receive window → server sends slower)
- **Timestamps on**, slow_start_after_idle off

### Config Profiles

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
./bufferManager.sh tune && ./bufferManager.sh cake-bidir

# Adaptive shaping
./bufferManager.sh tune && ./bufferManager.sh cake-bidir && ./bufferManager.sh autorate

# Check what's active
./bufferManager.sh diagnose

# View counters
./bufferManager.sh counters

# Remove everything
./bufferManager.sh remove && ./bufferManager.sh untune
```

### All Commands

```
Strategies:    cake-bidir | cake | htb | fq_codel | aggressive
TCP tuning:    tune | untune
Adaptive:      probe | adapt | autorate
Management:    status | counters | clear | diagnose | remove
```

---

## bufferTest.sh

Two-phase bufferbloat measurement using per-hop traceroute latency under idle and load conditions.

### How It Works

```
Phase 1: BASELINE (30s)
  └─ Traceroute every 1s to all hops → record per-hop latency (no load)

Phase 2: STRESS (200s)
  ├─ Launch iperf3 downlink + uplink (TCP or UDP, parallel streams)
  └─ Traceroute every 1s to all hops → record per-hop latency (under load)
```

### Analysis Output

1. **Per-Segment Bloat Table** — incremental delay between each hop pair, baseline avg vs stress P95
2. **Ranked Bloat Summary** — worst bloating links sorted by severity
3. **ASCII Network Diagram** — visual path with per-link baseline/stress/bloat
4. **Overall Latency Summary** — end-to-end avg, P95, max, loss % per phase
5. **iperf3 Throughput Table** — DL/UL mean, max, median, P10, P90 Mbps

### Sample Output

```
========================================================================
             PER-SEGMENT BLOAT ANALYSIS (Incremental Delay)
========================================================================
Hop  Segment                                Link Base    Link P95     Bloat
------------------------------------------------------------------------
2    (source) -> 10.1.2.1                   17.30        491.37       474.07
3    10.1.2.1 -> 10.1.3.1                   0.88         23.51        22.63
4    10.1.3.1 -> 1.2.3.4                    0.79         21.38        20.59
3    (source) -> 10.1.3.1                   0.00         517.01       517.01

========================================================================
            LINK SEGMENTS RANKED BY BLOAT (Worst First)
========================================================================
IP Address         Bloat (ms)
------------------------------------------------------------------------
10.1.3.1           517.01       ms
10.1.2.1           474.07       ms
10.1.3.1           22.63        ms
1.2.3.4            20.59        ms

========================================================================
             NETWORK PATH DIAGRAM (Baseline / Stress)
========================================================================

+---------------+
|   (source)    |
+---------------+
    |  Base:  17.30 ms
    |  P95:  491.37 ms
    |  Bloat: 474.07 ms  <<<
    v
+---------------+
|  10.1.2.1     |
+---------------+
    |  Base:   0.88 ms
    |  P95:   23.51 ms
    |  Bloat: 22.63 ms  <<<
    v
+---------------+
|  10.1.3.1     |
+---------------+
    |  Base:   0.79 ms
    |  P95:   21.38 ms
    |  Bloat: 20.59 ms  <<<
    v
+---------------+
|   1.2.3.4     |
+---------------+
    |  Base:   0.00 ms
    |  P95:  517.01 ms
    |  Bloat: 517.01 ms  <<<
    v
+---------------+
|  10.1.3.1     |
+---------------+

========================================================================
             OVERALL LATENCY SUMMARY (End-to-End to 1.2.3.4)
========================================================================
Phase        Samples  Loss %     Avg (ms)   P95 (ms)   Max (ms)
------------------------------------------------------------------------
BASELINE     10       0.0        17.76      18.83      20.31
STRESS       97       1.0        197.38     494.30     533.06

==========================================================================================
             IPERF3 THROUGHPUT SUMMARY
==========================================================================================
Direction  Type   Data (MB)  Mean Mbps      Max   Median      P10      P90   Smpls
------------------------------------------------------------------------------------------
downlink   TCP        169.0       4.68     7.34     4.19     4.19     6.29     303
uplink     TCP         43.5       2.06    12.60     2.10     1.05     3.15     183
```

**Reading the results:**
- **Bloat column** shows added latency under load per hop — the `<<<` markers flag significant bloat
- **Hop 2 (source → 10.1.2.1)** jumped from 17ms baseline to 491ms P95 — this is the primary bloating link (likely the LTE/modem uplink buffer)
- **Overall**: baseline 18ms → stress P95 494ms = **~476ms of bufferbloat**
- **Throughput**: 4.68 Mbps downlink, 2.06 Mbps uplink (expected for an LTE link)

### Config

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

Run `./bufferTest.sh -h` for a full list of config keys.

### Prerequisites

- **iperf3 server** running on the target host (`iperf3 -s -p 5991` and `iperf3 -s -p 5992`)
- `traceroute` installed
- iperf3 3.9+ recommended (for `--timestamps`)

### Usage

```bash
./bufferTest.sh
```

Output files: `bloat_results.log` (CSV), `iperf_tcp_downlink.log`, `iperf_tcp_uplink.log`

---

## bufferScenarioTest.sh

Automated A/B testing wrapper. Runs multiple shaping strategies back-to-back, captures qdisc counters and iperf/latency metrics, and displays a color-coded comparison table.

### What It Does Per Scenario

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

### Sample Result (10 runs, base vs shaped+autorate)

Command: `./bufferScenarioTest.sh -r 10 -s "base:remove;shaped+autorate:tune,cake-bidir,autorate"`

```
════════════════════════════════════════════════════════════════
  SCENARIO COMPARISON TABLE  (10 run(s) per scenario, averaged)
════════════════════════════════════════════════════════════════
Metric                 │ base               │ shaped+autorate
────────────────────────────────────────────────────────────────
  IPERF3 THROUGHPUT
  DL Mean (Mbps)         │ 4.80               │ 4.68
  DL P90 (Mbps)          │ 6.29               │ 5.87 (-7%)
  UL Mean (Mbps)         │ 11.44              │ 2.29 (-80%)
  UL P90 (Mbps)          │ 17.52              │ 3.78 (-78%)
────────────────────────────────────────────────────────────────
  END-TO-END LATENCY
  Baseline Avg (ms)      │ 17.70              │ 17.88
  Baseline P95 (ms)      │ 19.14              │ 20.34 (+6%)
  Stress Avg (ms)        │ 460.45             │ 194.17 (-58%)
  Stress P95 (ms)        │ 520.23             │ 490.70 (-6%)
  Stress Loss %          │ 2.36               │ 0.70 (-70%)
────────────────────────────────────────────────────────────────
  QDISC COUNTERS (delta during test)
  Egress Pkts            │ 0.00               │ 110677.00
  Egress Dropped         │ 0.00               │ 12.70
  Egress Overlimits      │ 0.00               │ 199363.50
  Egress ECN Marks       │ 0.00               │ 0.00
  Ingress Pkts           │ 0.00               │ 0.00
  Ingress Dropped        │ 0.00               │ 0.00
  Ingress Overlimits     │ 0.00               │ 0.00
  Ingress ECN Marks      │ 0.00               │ 0.00
════════════════════════════════════════════════════════════════

  Green = better than 'base' baseline (>5% diff)
  Red   = worse than 'base' baseline (>5% diff)
  Values within 5% of baseline shown without color.
  All values averaged across 10 run(s).


  Per-Run Detail: base
  Run      DL Mbps    UL Mbps  St Avg ms  St P95 ms    Eg Drop    In Drop     Eg ECN
  ───── ────────── ────────── ────────── ────────── ────────── ────────── ──────────
  1           4.83      11.16     466.76     528.95          0          0          0
  2           4.83      11.80     468.37     518.84          0          0          0
  3           4.76      10.77     458.69     517.07          0          0          0
  4           4.79       9.05     459.08     516.61          0          0          0
  5           4.75      10.37     450.55     516.61          0          0          0
  6           4.79      12.01     459.46     521.94          0          0          0
  7           4.81      12.58     464.94     523.34          0          0          0
  8           4.82      13.25     458.94     521.21          0          0          0
  9           4.84      11.83     452.44     514.37          0          0          0
  10          4.82      11.61     465.32     523.40          0          0          0

  Per-Run Detail: shaped+autorate
  Run      DL Mbps    UL Mbps  St Avg ms  St P95 ms    Eg Drop    In Drop     Eg ECN
  ───── ────────── ────────── ────────── ────────── ────────── ────────── ──────────
  1           4.69       2.33     189.67     486.36         10          0          0
  2           4.68       2.10     196.77     479.29          3          0          0
  3           4.63       2.45     192.50     482.69         41          0          0
  4           4.70       2.13     197.38     506.58         13          0          0
  5           4.72       2.60     192.09     482.14          2          0          0
  6           4.67       2.12     189.47     484.73         16          0          0
  7           4.67       2.34     194.59     498.24         17          0          0
  8           4.68       2.60     193.47     487.82         19          0          0
  9           4.69       2.14     198.39     504.80          1          0          0
  10          4.68       2.06     197.38     494.30          5          0          0

Results saved to:
  Full log:    /var/TEST/scenario_logs/scenario_20260429_015504.log
  Summary:     /var/TEST/scenario_logs/summary_20260429_015504.txt
  Raw data:    /var/TEST/scenario_logs/results_20260429_015504/
```

**Reading the results:**
- **Stress Avg latency** dropped from 460ms → 194ms (**-58%**) with CAKE+autorate shaping
- **Stress Loss** dropped from 2.36% → 0.70% (**-70%**) — fewer packets dropped under load
- **UL throughput** reduced from 11.44 → 2.29 Mbps (**-80%**) — this is the intended trade-off: CAKE rate-shapes upload below bottleneck to prevent upstream buffer filling
- **DL throughput** nearly unchanged (4.80 → 4.68 Mbps) — download not impacted
- **Egress Overlimits** (199k) shows CAKE actively delaying packets to enforce the shaped rate
- **Per-run consistency**: shaped+autorate shows tight clustering (189-198ms stress avg vs 450-468ms for base)

### Usage

```bash
# Baseline vs CAKE with autorate
./bufferScenarioTest.sh -s "base:remove;shaped+autorate:tune,cake-bidir,autorate"

# Full 3-way comparison, 3 runs each
./bufferScenarioTest.sh -r 3 -s "base:remove;shaped:tune,cake-bidir;shaped+autorate:tune,cake-bidir,autorate"

# All built-in scenarios
./bufferScenarioTest.sh

# List built-in scenarios
./bufferScenarioTest.sh -l
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r N` | Repetitions per scenario | 1 |
| `-s "..."` | Custom scenarios (`label:cmd1,cmd2;label2:cmd1,...`) | 6 built-in |
| `-o DIR` | Output directory | `./scenario_logs` |
| `-l` | List built-in scenarios | — |
| `-h` | Help | — |

### Built-in Scenarios

| Label | Commands | Tests |
|-------|----------|-------|
| no-queue | `remove` | No shaping (control group) |
| fq_codel | `fq_codel` | AQM only, no rate shaping |
| cake-bidir | `tune,cake-bidir` | Static CAKE + TCP tuning |
| cake-bidir+autorate | `tune,cake-bidir,autorate` | Adaptive CAKE + TCP tuning |
| htb+tune | `tune,htb` | HTB + fq_codel fallback |
| aggressive | `tune,aggressive` | Tight fq_codel limits |

### Output Files

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

---

## Deployment Scenarios

### LTE/4G Router Shaping
Low, variable bandwidth. High baseline latency. CAKE + autorate handles fluctuating link quality.

```bash
# Config: MAX_EGRESS=10mbit, MAX_INGRESS=25mbit, BASELINE_RTT=60ms
./bufferManager.sh tune && ./bufferManager.sh cake-bidir && ./bufferManager.sh autorate
```

### 5G / Fixed Wireless
Higher bandwidth but still variable. Larger rate ranges, same adaptive approach.

```bash
# Config: MAX_EGRESS=15mbit, MAX_INGRESS=65mbit
./bufferScenarioTest.sh -r 3 -s "base:remove;cake:tune,cake-bidir;adaptive:tune,cake-bidir,autorate"
```

### VPN / Tunnel Endpoints
Shape the tunnel interface to prevent the tunnel's encapsulation overhead from causing bloat at the underlying link.

### VoIP / Real-Time Traffic
CAKE's `diffserv4` classification prioritizes voice traffic. Combined with ECN, avoids drops on latency-sensitive flows.

### Benchmarking Before/After
Use `bufferScenarioTest.sh` to quantify the impact of different strategies on your specific link:

```bash
# "Is CAKE actually helping on my link?"
./bufferScenarioTest.sh -r 5 -s "baseline:remove;cake:tune,cake-bidir"
```

---

## Requirements

- Linux kernel 4.9+ (BBR support), 4.19+ (CAKE module)
- `tc`, `ip`, `sysctl` (iproute2 package)
- `jq` (JSON parser — `apt install jq`)
- `iperf3` (3.9+ recommended)
- `traceroute`
- `bc` (for arithmetic in scenario comparisons)
- Root access (traffic control and sysctl operations)
- An iperf3 server running on the remote target host

---

## Quick Reference

```bash
# 1. Edit config.json: set active_profile, interface, target, rates
#    (no script edits needed)

# 2. Verify connectivity
./bufferManager.sh probe

# 3. Run bufferTest.sh independently (measures bloat without shaping)
./bufferTest.sh

# 4. Run bufferManager.sh independently (apply shaping)
./bufferManager.sh tune && ./bufferManager.sh cake-bidir

# 5. Run a quick before/after comparison
./bufferScenarioTest.sh -s "before:remove;after:tune,cake-bidir,autorate"

# 6. Run a thorough benchmark (3 repetitions)
./bufferScenarioTest.sh -r 3

# 7. Check results
cat scenario_logs/summary_*.txt

# Show help for each script
./bufferManager.sh          # (no args shows help)
./bufferTest.sh -h
./bufferScenarioTest.sh -h

# Override config file path
CONFIG_FILE=/etc/bloatbuster/config.json ./bufferManager.sh cake-bidir
```
