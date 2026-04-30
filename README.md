# Bufferbloat Testing Toolkit

Three scripts for detecting, mitigating, and benchmarking bufferbloat on Linux network links — particularly useful for LTE/5G, satellite, and other variable-bandwidth WANs.

## Overview

| Script | Purpose | Requires |
|--------|---------|----------|
| **bufferManager.sh** | Apply/remove traffic shaping strategies (CAKE, HTB, fq_codel) and TCP tuning (BBR, ECN) | `tc`, `ip`, `sysctl`, `jq`, root |
| **bufferTest.sh** | Measure bufferbloat via per-hop traceroute + iperf3 stress testing | `iperf3`, `traceroute`, `jq`, iperf3 server |
| **bufferScenarioTest.sh** | Orchestrate A/B comparisons: apply strategy → run test → record results → compare | Both scripts above, `jq`, `bc` |
| **bloatChart.sh** | ASCII time-series chart: overlay throughput, RTT, and autorate limits | `jq`, `awk` (runs automatically or standalone) |

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

### Sample Result (5 runs, base vs shaped+autorate)

Command: `./bufferScenarioTest.sh -r 5 -s "base:remove;shaped+autorate:tune,cake-bidir,autorate"`

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
| **Visualization** | `bloatChart.sh` (AWK + ASCII) | Time-series overlay of throughput, RTT, rate limits |

---

## bloatChart.sh

ASCII time-series overlay chart showing iperf throughput, RTT, and autorate adjustments on a unified timeline. Runs automatically at the end of `bufferTest.sh` or standalone.

### What It Shows

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

### Usage

```bash
# Runs automatically at the end of bufferTest.sh

# Or run standalone after a test
./bloatChart.sh

# Custom files and dimensions
./bloatChart.sh -r my_results.log -a autorate.log -w 120 -H 25

# Without autorate (just throughput + RTT)
./bloatChart.sh -r bloat_results.log -d iperf_tcp_downlink.log -u iperf_tcp_uplink.log
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r FILE` | RTT/latency CSV log | `bloat_results.log` |
| `-d FILE` | iperf3 downlink log | `iperf_<type>_downlink.log` |
| `-u FILE` | iperf3 uplink log | `iperf_<type>_uplink.log` |
| `-a FILE` | Autorate log (optional) | `autorate.log` |
| `-w WIDTH` | Chart width in columns | `80` |
| `-H HEIGHT` | Chart height in rows | `20` |
| `-h` | Help | — |

### How It Helps

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

## Comparison with Other Bufferbloat Tools

### Why BloatBuster vs Flent / betterspeedtest / web tests?

Most existing bufferbloat tools (Flent, netperfrunner, web tests) tell you **"you have bloat"** but don't tell you **where in the network path** the bloat occurs. BloatBuster's per-hop traceroute under load pinpoints the exact link (hop) that's buffering — so you know whether the problem is your router, your ISP's DSLAM, or a backhaul node.

Additionally, Flent and netperf-based tools require **both a client and a dedicated server** (netperf/iperf running on both ends). BloatBuster only needs a standard iperf3 server on the remote end — no custom daemon, no Flent installation on the server, no coordination. You can point it at any existing iperf3 endpoint.

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

| Feature | BloatBuster | Flent (RRUL) | betterspeedtest.sh | Web Tests (Waveform/Cloudflare) |
|---------|-------------|--------------|--------------------|---------------------------------|
| **Measures bloat location (per-hop)** | Yes — traceroute under load | No — end-to-end only | No — end-to-end only | No — end-to-end only |
| **Server requirement** | iperf3 server only | netperf server + Flent install | netperf server | None (uses CDN) |
| **Client-only operation** | Yes (just needs iperf3 server) | No (Flent needed on both ends) | Yes (needs netperf server) | Yes |
| **Identifies bloating hop** | Yes — ranked by severity | No | No | No |
| **Simultaneous DL + UL stress** | Yes (TCP/UDP, configurable streams) | Yes (RRUL: 4 up + 4 down) | Yes (sequential, not simultaneous) | Varies by test |
| **Latency measurement method** | ICMP traceroute per-hop | ICMP/UDP ping (end-to-end) | ICMP ping (end-to-end) | Proprietary |
| **Built-in traffic shaping** | Yes — CAKE/HTB/fq_codel + autorate | No (measurement only) | No (measurement only) | No |
| **Adaptive rate control** | Yes — RTT-based live CAKE adjustment | No | No | No |
| **A/B scenario comparison** | Yes — automated multi-strategy benchmark | Manual (re-run + compare plots) | No | No |
| **Graphical output** | ASCII diagrams + tables | Yes — matplotlib plots | Text summary | Web UI |
| **Repeatability / scripted runs** | Yes — automated N-run averaging | Yes — repeatable via CLI | Partially | No |
| **Protocol support** | TCP + UDP (configurable) | TCP (netperf) | TCP (netperf) | HTTP/HTTPS |
| **High bandwidth (>1Gbps)** | Depends on iperf3 | Yes (tested to 40GigE) | Limited | No |
| **Dependencies** | iperf3, traceroute, jq, tc | Flent, netperf, matplotlib, Python | netperf | Browser |
| **Works on embedded/router** | Yes (bash + basic tools) | No (Python + heavy deps) | Yes | No |
| **Centralized config** | Yes — config.json for all scripts | No (CLI flags per run) | No (hardcoded) | N/A |
| **ECN / qdisc counter tracking** | Yes — per-test delta analysis | No | No | No |

### BloatBuster Advantages

1. **Per-hop bloat localization** — The key differentiator. Traceroute under load reveals which specific link in the path is bloated. Other tools only give you a single end-to-end latency number.

2. **Client-side only** — No Flent/netperf installation on the server. Any iperf3 endpoint works (even public ones).

3. **Integrated shaping + measurement** — Test, shape, re-test in one workflow. Flent measures but doesn't fix; you need separate SQM/CAKE setup.

4. **Adaptive rate control (autorate)** — Continuous RTT-based bandwidth adjustment for variable links (LTE/5G). Similar to [cake-autorate](https://github.com/lynxthecat/cake-autorate) but integrated into the test/shape workflow.

5. **Automated A/B benchmarking** — `bufferScenarioTest.sh` runs N strategies × M repetitions and produces a comparison table. Flent requires manual re-runs and eyeballing plots.

6. **Lightweight / embeddable** — Pure bash + standard Linux tools. Runs on routers, embedded devices, containers. Flent needs Python 3, matplotlib, and netperf compiled on both ends.

7. **Qdisc counter analysis** — Tracks dropped/overlimit/ECN-marked packets per test run to understand AQM behavior, not just throughput/latency.

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
| "Where in my network is the bloat?" | **BloatBuster** |
| Quick letter-grade check | Web test (Waveform) |
| Academic/publishable benchmark | Flent (RRUL) |
| Apply + test shaping in one workflow | **BloatBuster** |
| Router/embedded device (no Python) | **BloatBuster** |
| 10-40GigE data center testing | Flent |
| LTE/5G with variable bandwidth | **BloatBuster** (autorate) |
| Pretty graphs for a presentation | Flent |

---

## Requirements

### System

| Requirement | Notes |
|-------------|-------|
| Linux kernel 4.9+ | BBR congestion control (`tcp_bbr` module) |
| Linux kernel 4.19+ | CAKE qdisc (`sch_cake` module) |
| Root / sudo | Required by `tc`, `ip link`, `sysctl`, `modprobe` |
| Writable log directory | Scripts write CSV logs, iperf output, and scenario results to the working directory (or `scenario.log_dir`). The path must be writable by the running user. |

### Required Tools

| Tool | Package (Debian/Ubuntu) | Used By | Purpose |
|------|------------------------|---------|---------|
| `bash` 4+ | pre-installed | all scripts | Script interpreter |
| `tc` | `iproute2` | `bufferManager.sh` | Traffic control — create/modify qdiscs and filters |
| `ip` | `iproute2` | `bufferManager.sh` | Manage IFB device (`ip link add/set/del`) |
| `sysctl` | `procps` | `bufferManager.sh` | Apply TCP stack settings (BBR, ECN, buffer sizes) |
| `modprobe` | `kmod` | `bufferManager.sh` | Load `ifb` kernel module for ingress shaping |
| `ping` | `iputils-ping` | `bufferManager.sh` | RTT probes for autorate adaptation |
| `iperf3` 3.9+ | `iperf3` | `bufferTest.sh` | Saturate the link (TCP/UDP stress test). Version 3.9+ needed for `--timestamps`. |
| `traceroute` | `traceroute` | `bufferTest.sh` | Per-hop ICMP latency measurement (needs `-I` flag support) |
| `jq` | `jq` | all scripts | Parse and read `config.json` |
| `awk` | `gawk` / `mawk` | `bufferTest.sh`, `bloatChart.sh` | Log parsing and ASCII chart rendering |
| `bc` | `bc` | `bufferScenarioTest.sh` | Floating-point arithmetic in scenario comparisons |

Install everything at once on Debian/Ubuntu:

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

`bufferTest.sh` requires an **iperf3 server** listening on the target host. Run on the remote machine:

```bash
iperf3 -s -p 5991 &   # downlink port
iperf3 -s -p 5992 &   # uplink port
```

Ports are configurable via `test.tcp.port_dl` / `test.tcp.port_ul` (or UDP equivalents) in `config.json`.

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
