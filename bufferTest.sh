#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# LOAD CONFIG FROM config.json (requires jq)
# ══════════════════════════════════════════════════════════════════════════════
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/config.json}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: config.json not found at $CONFIG_FILE" >&2
    exit 1
fi
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed. Install with: apt install jq" >&2
    exit 1
fi

# Read active profile
ACTIVE_PROFILE=$(jq -r '.active_profile' "$CONFIG_FILE")
PROFILE=".profiles.$ACTIVE_PROFILE.test"

# --- Profile-specific settings ---
TARGET=$(jq -r "$PROFILE.target" "$CONFIG_FILE")
BIND_IP=$(jq -r "$PROFILE.bind_ip" "$CONFIG_FILE")
UDP_BW_DL=$(jq -r "$PROFILE.udp_bw_dl" "$CONFIG_FILE")
UDP_BW_UL=$(jq -r "$PROFILE.udp_bw_ul" "$CONFIG_FILE")

# --- General configuration ---
BASELINE_SEC=$(jq -r '.test.general.baseline_sec' "$CONFIG_FILE")
STRESS_SEC=$(jq -r '.test.general.stress_sec' "$CONFIG_FILE")
POLL_INTERVAL=$(jq -r '.test.general.poll_interval' "$CONFIG_FILE")
TIMEOUT=$(jq -r '.test.general.timeout' "$CONFIG_FILE")

# --- Logging configuration ---
MAIN_LOG=$(jq -r '.test.logging.main_log' "$CONFIG_FILE")
STRESS_TYPE=$(jq -r '.test.logging.stress_type' "$CONFIG_FILE")
IPERF_LOG_DL="iperf_${STRESS_TYPE}_downlink.log"
IPERF_LOG_UL="iperf_${STRESS_TYPE}_uplink.log"

# --- iperf common settings ---
ENABLE_STRESS=$(jq -r '.test.iperf_common.enable_stress' "$CONFIG_FILE")
REPORT_INT=$(jq -r '.test.iperf_common.report_interval' "$CONFIG_FILE")
SHOW_DIAGRAM=$(jq -r '.test.iperf_common.show_diagram' "$CONFIG_FILE")

# --- UDP settings ---
UDP_PARALLEL=$(jq -r '.test.udp.parallel' "$CONFIG_FILE")

# --- TCP settings ---
TCP_PARALLEL=$(jq -r '.test.tcp.parallel' "$CONFIG_FILE")

# --- iperf direction and port settings ---
ENABLE_DL=$(jq -r '.test.iperf_common.enable_dl // true' "$CONFIG_FILE")
ENABLE_UL=$(jq -r '.test.iperf_common.enable_ul // true' "$CONFIG_FILE")
CONNECT_TIMEOUT=$(jq -r '.test.iperf_common.connect_timeout // 10' "$CONFIG_FILE")
PORT_RETRIES=$(jq -r '.test.iperf_common.port_retries // 2' "$CONFIG_FILE")

# Port lists — accept array or single value in config
if [[ "$STRESS_TYPE" == "udp" ]]; then
    mapfile -t PORT_DL_LIST < <(jq -r '.test.udp.port_dl | if type == "array" then .[] else . end' "$CONFIG_FILE")
    mapfile -t PORT_UL_LIST < <(jq -r '.test.udp.port_ul | if type == "array" then .[] else . end' "$CONFIG_FILE")
else
    mapfile -t PORT_DL_LIST < <(jq -r '.test.tcp.port_dl | if type == "array" then .[] else . end' "$CONFIG_FILE")
    mapfile -t PORT_UL_LIST < <(jq -r '.test.tcp.port_ul | if type == "array" then .[] else . end' "$CONFIG_FILE")
fi

# ══════════════════════════════════════════════════════════════════════════════
# USAGE / HELP
# ══════════════════════════════════════════════════════════════════════════════
usage() {
    cat <<EOF
Usage: $0 [-h]

Two-phase bufferbloat measurement: traceroute latency at idle (baseline) and
under iperf3 load (stress). Can run independently or via bufferScenarioTest.sh.

Options:
  -h    Show this help and exit

Prerequisites:
  - jq, iperf3, traceroute installed
  - iperf3 server running on the remote target host
    (e.g., iperf3 -s -p 5991 && iperf3 -s -p 5992)
  - iperf3 3.9+ recommended (for --timestamps)

Configuration (config.json):
  All settings are read from config.json (or CONFIG_FILE env var).

  active_profile                  Which profile to load (config1/config2)

  profiles.<name>.test:
    target                        Remote iperf3 server IP
    bind_ip                       Local interface IP to bind
    udp_bw_dl                     UDP downlink bandwidth (e.g. "15M")
    udp_bw_ul                     UDP uplink bandwidth (e.g. "5M")

  test.general:
    baseline_sec                  Phase 1 duration in seconds (default: 30)
    stress_sec                    Phase 2 duration in seconds (default: 200)
    poll_interval                 Traceroute frequency in seconds (default: 1)
    timeout                       Traceroute wait time in seconds (default: 2)

  test.logging:
    main_log                      Output CSV filename (default: bloat_results.log)
    stress_type                   "tcp" or "udp"

  test.iperf_common:
    enable_stress                 true = run iperf3, false = monitor-only
    enable_dl                     true = run downlink iperf3 (default: true)
    enable_ul                     true = run uplink iperf3 (default: true)
    connect_timeout               Seconds to wait before declaring a port failed (default: 10)
    port_retries                  Number of times to cycle through the port list before giving up (default: 2)
    report_interval               iperf3 -i interval (default: 1)
    show_diagram                  true = show ASCII network diagram
    (When both enable_dl and enable_ul are true, both must connect or both are killed
     and the next port pair is tried. When only one direction is enabled, ports are
     retried independently. Stress timer starts only after successful connection.)

  test.udp:
    port_dl                       UDP DL port(s): single value or array e.g. [5991,5993]
    port_ul                       UDP UL port(s): single value or array e.g. [5992,5994]
    parallel                      Parallel streams per UDP session

  test.tcp:
    port_dl                       TCP DL port(s): single value or array e.g. [5991,5993]
    port_ul                       TCP UL port(s): single value or array e.g. [5992,5994]
    parallel                      Parallel streams per TCP session

Current config (profile: $ACTIVE_PROFILE):
  TARGET=$TARGET  BIND_IP=$BIND_IP
  STRESS_TYPE=$STRESS_TYPE  BASELINE=${BASELINE_SEC}s  STRESS=${STRESS_SEC}s
  UDP_BW_DL=$UDP_BW_DL  UDP_BW_UL=$UDP_BW_UL
  TCP_PARALLEL=$TCP_PARALLEL  UDP_PARALLEL=$UDP_PARALLEL
  ENABLE_DL=$ENABLE_DL  ENABLE_UL=$ENABLE_UL  CONNECT_TIMEOUT=${CONNECT_TIMEOUT}s  PORT_RETRIES=$PORT_RETRIES
  DL ports: ${PORT_DL_LIST[*]}  UL ports: ${PORT_UL_LIST[*]}

Override config path:
  CONFIG_FILE=/path/to/config.json $0

Output files:
  $MAIN_LOG (CSV), $IPERF_LOG_DL, $IPERF_LOG_UL
EOF
    exit 0
}

# Handle -h flag
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

# --- SETUP ---
WORK_DIR=$(mktemp -d "/tmp/bloat_XXXXXX")
IPERF_PID_FILE="$WORK_DIR/iperf_pids"

cleanup() {
    if [ -f "$IPERF_PID_FILE" ]; then
        while IFS= read -r pid; do kill "$pid" 2>/dev/null; done < "$IPERF_PID_FILE"
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Pre-flight checks
for cmd in iperf3 traceroute; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd not found"; exit 1; }
done
if ! iperf3 --help 2>&1 | grep -q timestamps; then
    echo "WARNING: iperf3 may not support --timestamps/--connect-timeout/--forceflush (need 3.7+), upgrade for full robustness"
fi

# Discovery traceroute — auto-detect hop count
echo "Discovering route to $TARGET..."
MAX_HOP=$(traceroute -I -n -q 1 -w "$TIMEOUT" "$TARGET" 2>/dev/null \
    | awk '/^ *[0-9]/{hop=$1} END{print hop}')
if [[ -z "$MAX_HOP" || "$MAX_HOP" -lt 1 ]]; then
    echo "ERROR: Cannot reach $TARGET via traceroute"; exit 1
fi
echo "Route discovered: $MAX_HOP hops to $TARGET"

# Initialize Logs
echo "Timestamp,Hop,IP,Latency,Phase" > "$MAIN_LOG"
echo "--- iperf3 Downlink ($STRESS_TYPE) Start: $(date) ---" > "$IPERF_LOG_DL"
echo "--- iperf3 Uplink ($STRESS_TYPE) Start: $(date) ---" > "$IPERF_LOG_UL"

probe_hop() {
    local hop=$1 target=$2 phase=$3 timeout=$4 outfile=$5
    local timestamp=$(date +%H:%M:%S)

    LINE=$(traceroute -I -n -q 1 -w "$timeout" -f "$hop" -m "$hop" "$target" 2>/dev/null | grep "^ *${hop}")

    if [[ -z "$LINE" || "$LINE" == *"*"* ]]; then
        local timeout_ms=$(( timeout * 1000 ))
        echo "$timestamp,$hop,Timeout,${timeout_ms},$phase" > "$outfile"
    else
        IP=$(echo "$LINE" | awk '{print $2}')
        MS=$(echo "$LINE" | awk '{for(i=2;i<=NF;i++) if($i ~ /^[0-9.]+$/ && $i !~ /\..*\./) {print $i; break}}')
        [[ -z "$MS" ]] && MS=0
        echo "$timestamp,$hop,$IP,$MS,$phase" > "$outfile"
    fi
}

# Launch a single iperf3 instance in the background; echoes its PID.
# Args: logfile port direction(dl|ul)
_start_iperf_instance() {
    local logfile="$1" port="$2" direction="$3"
    local ct_ms=$(( CONNECT_TIMEOUT * 1000 ))
    if [[ "$STRESS_TYPE" == "udp" ]]; then
        if [[ "$direction" == "dl" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 DL: -B $BIND_IP -c $TARGET -i $REPORT_INT -t $STRESS_SEC -p $port -u -b $UDP_BW_DL -P $UDP_PARALLEL -R --connect-timeout $ct_ms --forceflush" >> "$logfile"
            iperf3 -B "$BIND_IP" -c "$TARGET" -i "$REPORT_INT" -t "$STRESS_SEC" \
                -p "$port" -u -b "$UDP_BW_DL" -P "$UDP_PARALLEL" -R \
                --connect-timeout "$ct_ms" --forceflush --timestamps='[%H:%M:%S] ' >> "$logfile" 2>&1 &
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 UL: -B $BIND_IP -c $TARGET -i $REPORT_INT -t $STRESS_SEC -p $port -u -b $UDP_BW_UL -P $UDP_PARALLEL --connect-timeout $ct_ms --forceflush" >> "$logfile"
            iperf3 -B "$BIND_IP" -c "$TARGET" -i "$REPORT_INT" -t "$STRESS_SEC" \
                -p "$port" -u -b "$UDP_BW_UL" -P "$UDP_PARALLEL" \
                --connect-timeout "$ct_ms" --forceflush --timestamps='[%H:%M:%S] ' >> "$logfile" 2>&1 &
        fi
    else
        if [[ "$direction" == "dl" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 DL: -B $BIND_IP -c $TARGET -i $REPORT_INT -t $STRESS_SEC -p $port -P $TCP_PARALLEL -R --connect-timeout $ct_ms --forceflush" >> "$logfile"
            iperf3 -B "$BIND_IP" -c "$TARGET" -i "$REPORT_INT" -t "$STRESS_SEC" \
                -p "$port" -P "$TCP_PARALLEL" -R \
                --connect-timeout "$ct_ms" --forceflush --timestamps='[%H:%M:%S] ' >> "$logfile" 2>&1 &
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 UL: -B $BIND_IP -c $TARGET -i $REPORT_INT -t $STRESS_SEC -p $port -P $TCP_PARALLEL --connect-timeout $ct_ms --forceflush" >> "$logfile"
            iperf3 -B "$BIND_IP" -c "$TARGET" -i "$REPORT_INT" -t "$STRESS_SEC" \
                -p "$port" -P "$TCP_PARALLEL" \
                --connect-timeout "$ct_ms" --forceflush --timestamps='[%H:%M:%S] ' >> "$logfile" 2>&1 &
        fi
    fi
    echo $!
}

# Returns 0 if iperf3 PID is alive AND its log file contains at least one data interval.
_iperf_ok() {
    local pid="$1" logfile="$2"
    kill -0 "$pid" 2>/dev/null || return 1       # process still alive
    grep -q 'bits/sec' "$logfile" 2>/dev/null     # at least one reported interval
}

# Launch iperf3 with port rotation and retry logic.
# Paired mode (both DL+UL enabled): if either fails, kill both and try the next port pair.
# Single mode (one direction only): retry that direction independently across its port list.
# Stress timer must start AFTER this returns 0.
# Returns 0 on success (PIDs appended to IPERF_PID_FILE), 1 if all ports exhausted.
launch_iperf() {
    if [[ "$ENABLE_DL" != true && "$ENABLE_UL" != true ]]; then
        echo "WARNING: Both enable_dl and enable_ul are false — no iperf3 launched."
        return 1
    fi

    local n_dl=${#PORT_DL_LIST[@]} n_ul=${#PORT_UL_LIST[@]}
    local paired=false
    [[ "$ENABLE_DL" == true && "$ENABLE_UL" == true ]] && paired=true

    local n_ports_paired=$(( n_dl > n_ul ? n_dl : n_ul ))
    local max_attempts
    if $paired; then
        max_attempts=$(( n_ports_paired * PORT_RETRIES ))
    elif [[ "$ENABLE_DL" == true ]]; then
        max_attempts=$(( n_dl * PORT_RETRIES ))
    else
        max_attempts=$(( n_ul * PORT_RETRIES ))
    fi

    local attempt dl_pid ul_pid dl_ok ul_ok reason cycle total_cycles=$PORT_RETRIES
    for (( attempt=0; attempt<max_attempts; attempt++ )); do
        local dl_port="${PORT_DL_LIST[$(( attempt % n_dl ))]}"
        local ul_port="${PORT_UL_LIST[$(( attempt % n_ul ))]}"
        # Which cycle are we on? (1-based, based on the relevant port list size)
        if $paired; then
            cycle=$(( attempt / n_ports_paired + 1 ))
        elif [[ "$ENABLE_DL" == true ]]; then
            cycle=$(( attempt / n_dl + 1 ))
        else
            cycle=$(( attempt / n_ul + 1 ))
        fi
        dl_pid=""; ul_pid=""

        [[ "$ENABLE_UL" == true ]] && ul_pid=$(_start_iperf_instance "$IPERF_LOG_UL" "$ul_port" "ul")
        [[ "$ENABLE_DL" == true ]] && dl_pid=$(_start_iperf_instance "$IPERF_LOG_DL" "$dl_port" "dl")

        # Phase 1 — connection check: wait for --connect-timeout to fire on failures
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Waiting for iperf3 connection(s) (${CONNECT_TIMEOUT}s)..."
        sleep "$CONNECT_TIMEOUT"

        dl_ok=true; ul_ok=true
        [[ "$ENABLE_DL" == true && -n "$dl_pid" ]] && ! kill -0 "$dl_pid" 2>/dev/null && dl_ok=false
        [[ "$ENABLE_UL" == true && -n "$ul_pid" ]] && ! kill -0 "$ul_pid" 2>/dev/null && ul_ok=false

        # Phase 2 — data check: wait one report interval so the first data line is in the log
        if [[ "$dl_ok" == true || "$ul_ok" == true ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Waiting for first data interval (${REPORT_INT}s)..."
            sleep "$REPORT_INT"
            [[ "$ENABLE_DL" == true && -n "$dl_pid" && "$dl_ok" == true ]] && ! _iperf_ok "$dl_pid" "$IPERF_LOG_DL" && dl_ok=false
            [[ "$ENABLE_UL" == true && -n "$ul_pid" && "$ul_ok" == true ]] && ! _iperf_ok "$ul_pid" "$IPERF_LOG_UL" && ul_ok=false
        fi

        if $paired; then
            if [[ "$dl_ok" == true && "$ul_ok" == true ]]; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 DL verified (PID $dl_pid, port $dl_port)"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 UL verified (PID $ul_pid, port $ul_port)"
                echo "$dl_pid" >> "$IPERF_PID_FILE"; echo "$ul_pid" >> "$IPERF_PID_FILE"
                return 0
            fi
            # Kill both before trying next port pair
            [[ -n "$dl_pid" ]] && kill "$dl_pid" 2>/dev/null
            [[ -n "$ul_pid" ]] && kill "$ul_pid" 2>/dev/null
            reason=""
            [[ "$dl_ok" == false ]] && reason+=" DL(port $dl_port)"
            [[ "$ul_ok" == false ]] && reason+=" UL(port $ul_port)"
            echo "WARNING: iperf3$reason failed (attempt $((attempt+1))/${max_attempts}, cycle ${cycle}/${total_cycles}), trying next port pair..."
        else
            if [[ "$ENABLE_DL" == true ]]; then
                if [[ "$dl_ok" == true ]]; then
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 DL verified (PID $dl_pid, port $dl_port)"
                    echo "$dl_pid" >> "$IPERF_PID_FILE"
                    return 0
                fi
                [[ -n "$dl_pid" ]] && kill "$dl_pid" 2>/dev/null
                echo "WARNING: iperf3 DL failed (attempt $((attempt+1))/${max_attempts}, cycle ${cycle}/${total_cycles}, port $dl_port), trying next..."
            else
                if [[ "$ul_ok" == true ]]; then
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 UL verified (PID $ul_pid, port $ul_port)"
                    echo "$ul_pid" >> "$IPERF_PID_FILE"
                    return 0
                fi
                [[ -n "$ul_pid" ]] && kill "$ul_pid" 2>/dev/null
                echo "WARNING: iperf3 UL failed (attempt $((attempt+1))/${max_attempts}, cycle ${cycle}/${total_cycles}, port $ul_port), trying next..."
            fi
        fi
    done

    echo "ERROR: iperf3 could not connect after $max_attempts attempt(s) ($total_cycles cycle(s) through port list)."
    return 1
}

run_monitor() {
    local duration=$1 mode=$2

    if [[ "$mode" == "STRESS" && "$ENABLE_STRESS" == true ]]; then
        echo ">>> LAUNCHING IPERF3 AND TRACEROUTE SIMULTANEOUSLY <<<"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting iperf3 ($STRESS_TYPE) to $TARGET for ${STRESS_SEC}s"
        if ! launch_iperf; then
            echo "ERROR: Could not establish iperf3 on any configured port. Stress phase aborted."
            return 1
        fi
    fi

    local start_time=$SECONDS  # Start timing after successful iperf3 launch

    while [ $((SECONDS - start_time)) -lt "$duration" ]; do
        echo -ne "Phase: $mode | Time Left: $((duration - (SECONDS - start_time)))s   \r"
        PROBE_PIDS=()
        for h in $(seq 1 "$MAX_HOP"); do
            probe_hop "$h" "$TARGET" "$mode" "$TIMEOUT" "$WORK_DIR/probe_${h}" &
            PROBE_PIDS+=($!)
        done
        wait "${PROBE_PIDS[@]}"
        # Merge per-hop results sequentially — no write race
        for h in $(seq 1 "$MAX_HOP"); do
            [ -f "$WORK_DIR/probe_${h}" ] && cat "$WORK_DIR/probe_${h}" >> "$MAIN_LOG"
            rm -f "$WORK_DIR/probe_${h}"
        done
        sleep "$POLL_INTERVAL"
    done
    echo -e "\n$mode Phase Complete."
}

# --- EXECUTION ---
run_monitor "$BASELINE_SEC" "BASELINE"
run_monitor "$STRESS_SEC" "STRESS"

# Terminate iperf3 by saved PIDs (not pkill)
if [ -f "$IPERF_PID_FILE" ]; then
    while IFS= read -r pid; do kill "$pid" 2>/dev/null; done < "$IPERF_PID_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] iperf3 terminated (PIDs: $(tr '\n' ' ' < "$IPERF_PID_FILE"))"
fi

# ==============================================================================
# ANALYSIS
# ==============================================================================

RANK_FILE="$WORK_DIR/rank.tmp"

# Step 1: Find canonical (most common) IP per hop
awk -F, 'NR>1 && $3 != "No-Response" && $3 != "Timeout" {
    count[$2","$3]++
} END {
    for (k in count) {
        split(k, a, ","); hop = a[1]; ip = a[2]
        if (count[k] > best[hop]) { best[hop] = count[k]; canon[hop] = ip }
    }
    for (h = 1; h <= 100; h++) if (canon[h] != "") print h, canon[h]
}' "$MAIN_LOG" | sort -n > "$WORK_DIR/hop_map"

# Steps 2-4 (COMBINED): Per-probe segment analysis
# Correctly computes per-segment latency by differencing within each probe round,
# THEN aggregating (avg for baseline, P95 for stress).
# This avoids the statistical error of subtracting independent P95 aggregates.
SEGMENT_FILE="$WORK_DIR/segments.dat"

awk -F, -v maxhop="$MAX_HOP" -v mapfile="$WORK_DIR/hop_map" -v segfile="$SEGMENT_FILE" '
BEGIN {
    while ((getline line < mapfile) > 0) {
        split(line, a, " ")
        nhops++
        hop_order[nhops] = a[1] + 0
        hop_ip[a[1] + 0] = a[2]
    }
}
NR == 1 { next }
{
    row = NR - 2
    r = int(row / maxhop)
    h = $2 + 0
    lat = $4 + 0
    ip = $3
    phase = $5

    if (ip != "No-Response" && ip != "Timeout" && lat > 0) {
        rnd_lat[r, h] = lat
    }
    rnd_phase[r] = phase
    if (r > max_round) max_round = r
}
END {
    # For each round, compute per-segment incremental latency
    for (r = 0; r <= max_round; r++) {
        ph = rnd_phase[r]
        prev_lat = 0
        prev_ip = "(source)"

        for (i = 1; i <= nhops; i++) {
            h = hop_order[i]
            ip = hop_ip[h]
            if (ip == prev_ip) continue

            if ((r, h) in rnd_lat) {
                seg_val = rnd_lat[r, h] - prev_lat
                if (seg_val < 0) seg_val = 0

                seg = prev_ip SUBSEP ip
                if (!(seg in seg_hop)) {
                    seg_hop[seg] = h
                    nseg++
                    seg_order[nseg] = seg
                }

                if (ph == "BASELINE") {
                    bl_sum[seg] += seg_val
                    bl_n[seg]++
                } else if (ph == "STRESS") {
                    st_n[seg]++
                    st_vals[seg, st_n[seg]] = seg_val
                }

                prev_lat = rnd_lat[r, h]
                prev_ip = ip
            }
            # If hop did not respond, do not update prev — next responding
            # hop absorbs this gap (acceptable approximation)
        }
    }

    # Compute stats and output segments.dat
    for (si = 1; si <= nseg; si++) {
        seg = seg_order[si]
        split(seg, parts, SUBSEP)
        from_ip = parts[1]
        to_ip = parts[2]
        h = seg_hop[seg]

        # Baseline average
        if (bl_n[seg] > 0)
            base = bl_sum[seg] / bl_n[seg]
        else
            base = 0

        # Stress P95 (insertion sort then pick 95th percentile)
        n = st_n[seg] + 0
        if (n > 0) {
            for (j = 1; j <= n; j++) tmp[j] = st_vals[seg, j]
            for (j = 2; j <= n; j++) {
                key = tmp[j]; k = j - 1
                while (k >= 1 && tmp[k] > key) { tmp[k+1] = tmp[k]; k-- }
                tmp[k+1] = key
            }
            p95_idx = int(n * 0.95)
            if (p95_idx < 1) p95_idx = 1
            s_p95 = tmp[p95_idx]
            delete tmp
        } else {
            s_p95 = 0
        }

        bloat = s_p95 - base
        if (bloat < 0) bloat = 0

        printf "%d|%s|%s|%.2f|%.2f|%.2f\n", h, from_ip, to_ip, base, s_p95, bloat > segfile
    }
}' "$MAIN_LOG"

# Step 4a: Per-segment bloat table
echo -e "\n========================================================================"
echo -e "             PER-SEGMENT BLOAT ANALYSIS (Incremental Delay)"
echo -e "========================================================================"
printf "%-4s %-38s %-12s %-12s %-10s\n" "Hop" "Segment" "Link Base" "Link P95" "Bloat"
echo "------------------------------------------------------------------------"

RANK_WRITTEN=false
while IFS='|' read -r hop from_ip to_ip link_b link_s bloat; do
    seg="${from_ip} -> ${to_ip}"
    printf "%-4s %-38s %-12s %-12s %-10s\n" "$hop" "$seg" "$link_b" "$link_s" "$bloat"
    if (( $(echo "$bloat > 0.5" | bc -l 2>/dev/null || echo 0) )); then
        echo "${to_ip},${bloat}" >> "$RANK_FILE"
        RANK_WRITTEN=true
    fi
done < "$SEGMENT_FILE"

# Step 5: Ranked bloat summary (unique IPs)
echo -e "\n========================================================================"
echo -e "            LINK SEGMENTS RANKED BY BLOAT (Worst First)"
echo -e "========================================================================"
printf "%-18s %-12s\n" "IP Address" "Bloat (ms)"
echo "------------------------------------------------------------------------"
if [ -f "$RANK_FILE" ]; then
    sort -t, -k2,2rn "$RANK_FILE" | awk -F, '{printf "%-18s %-12.2f ms\n", $1, $2}'
else
    echo "No significant per-link bloat detected."
fi

# Step 5a: ASCII Network Diagram (optional)
if [[ "$SHOW_DIAGRAM" == true && -f "$SEGMENT_FILE" ]]; then
    echo -e "\n========================================================================"
    echo -e "             NETWORK PATH DIAGRAM (Baseline / Stress)"
    echo -e "========================================================================"
    echo ""

    awk -F'|' '
    {
        n++
        from[n]=$2; to[n]=$3; lb[n]=$4; ls[n]=$5; bl[n]=$6
    }
    END {
        # Collect unique IPs in order: first from, then all to
        nips = 0
        ips[++nips] = from[1]
        for (i = 1; i <= n; i++) ips[++nips] = to[i]

        # Determine box width (max IP length + 4 padding)
        maxlen = 0
        for (i = 1; i <= nips; i++) {
            l = length(ips[i])
            if (l > maxlen) maxlen = l
        }
        boxw = maxlen + 4

        # Draw each node and the link to the next
        for (i = 1; i <= nips; i++) {
            ip = ips[i]
            pad = boxw - length(ip) - 4
            lpad = int(pad / 2)
            rpad = pad - lpad

            # Box top
            border = "+"
            for (j = 1; j <= boxw - 2; j++) border = border "-"
            border = border "+"
            printf "%s\n", border

            # Box content
            line = "| "
            for (j = 1; j < lpad; j++) line = line " "
            line = line ip
            for (j = 1; j <= rpad; j++) line = line " "
            line = line " |"
            printf "%s\n", line

            # Box bottom
            printf "%s\n", border

            # Link arrow with latency (except after last node)
            if (i < nips) {
                bval = lb[i]; sval = ls[i]; blval = bl[i]

                # Baseline line
                printf "    |  Base: %6s ms\n", bval
                # Stress line
                printf "    |  P95:  %6s ms\n", sval
                # Bloat indicator
                if (blval + 0 > 0.5) {
                    printf "    |  Bloat: %5s ms  <<<\n", blval
                }
                printf "    v\n"
            }
        }
    }' "$SEGMENT_FILE"
    echo ""
fi

# Step 6: Overall latency summary (all samples across all hops for target IP)
echo -e "\n========================================================================"
echo -e "             OVERALL LATENCY SUMMARY (End-to-End to $TARGET)"
echo -e "========================================================================"
printf "%-12s %-8s %-10s %-10s %-10s %-10s\n" "Phase" "Samples" "Loss %" "Avg (ms)" "P95 (ms)" "Max (ms)"
echo "------------------------------------------------------------------------"

# Compute stats per phase (using ALL hops mapped to target IP via hop_map)
for phase in BASELINE STRESS; do
    awk -F, -v mapfile="$WORK_DIR/hop_map" -v t="$TARGET" -v ph="$phase" '
    BEGIN {
        while ((getline line < mapfile) > 0) {
            split(line, a, " "); if (a[2] == t) target_hops[a[1]] = 1
        }
    }
    NR>1 && $5 == ph && ($2 in target_hops) {
        total++
        if ($3 == "No-Response" || $3 == "Timeout" || $4 + 0 <= 0) { lost++ }
        else { print $4 }
    }
    END {
        printf "META %d %d\n", total+0, lost+0
    }' "$MAIN_LOG" | sort -n | awk -v ph="$phase" '{
        if ($1 == "META") { total=$2; lost=$3; next }
        vals[++n] = $1; sum += $1
    } END {
        good = total - lost
        loss_pct = (total > 0) ? (lost * 100.0 / total) : 0
        if (n > 0) {
            avg = sum/n; max = vals[n]
            p95_idx = int(n * 0.95); if (p95_idx < 1) p95_idx = 1
            p95 = vals[p95_idx]
            printf "%-12s %-8d %-10.1f %-10.2f %-10.2f %-10.2f\n", ph, n, loss_pct, avg, p95, max
        } else {
            printf "%-12s %-8d %-10.1f %-10s %-10s %-10s\n", ph, 0, loss_pct, "N/A", "N/A", "N/A"
        }
    }'
done

# Reliability warning
B_SAMPLES=$(awk -F, -v t="$TARGET" 'NR>1 && $3==t && $4>0 && $5=="BASELINE" {n++} END{print n+0}' "$MAIN_LOG")
S_SAMPLES=$(awk -F, -v t="$TARGET" 'NR>1 && $3==t && $4>0 && $5=="STRESS" {n++} END{print n+0}' "$MAIN_LOG")
if [[ "$S_SAMPLES" -lt 10 ]]; then
    echo -e "\n⚠️  WARNING: Only $S_SAMPLES stress samples reached target (vs $B_SAMPLES baseline)."
    echo "   ICMP probes likely dropped under load — stress numbers may UNDERSTATE actual bloat."
    echo "   High probe loss during stress is itself evidence of bufferbloat."
fi

# ==============================================================================
# IPERF3 THROUGHPUT SUMMARY TABLE
# ==============================================================================

parse_iperf_log() {
    local logfile="$1" dir="$2" proto="$3"
    awk -v dir="$dir" -v proto="$proto" '
    BEGIN {
        has_sum = 0
    }
    # First pass detect: does log contain [SUM] lines? (parallel -P mode)
    /\[SUM\]/ { has_sum = 1 }

    /[0-9].*bits\/sec/ && !/Interval/ && !/\[ *ID\]/ {
        # Determine if this is a per-stream line or [SUM] aggregate
        is_sum_line = ($0 ~ /\[SUM\]/) ? 1 : 0
        is_stream_line = ($0 ~ /\[ *[0-9]+\]/) ? 1 : 0
        is_summary = ($0 ~ /sender/ || $0 ~ /receiver/) ? 1 : 0

        # When parallel streams exist, skip per-stream interval lines
        # (only use [SUM] for intervals, and [SUM] sender/receiver for totals)
        if (has_sum && is_stream_line && !is_summary) next
        # For summary lines with -P, only use [SUM] sender/receiver
        if (has_sum && is_summary && !is_sum_line) next

        bps = 0; bps_unit = ""; xfer = 0; xfer_unit = ""
        for (i = 1; i <= NF; i++) {
            if ($(i) ~ /^[KMG]?Bytes$/ && xfer == 0) {
                xfer = $(i-1) + 0; xfer_unit = $(i)
            }
            if ($(i) ~ /^[KMG]?bits\/sec$/) {
                bps = $(i-1) + 0; bps_unit = $(i)
            }
        }

        # Normalize bitrate to Mbits/sec
        if (bps_unit ~ /^Gbits/) bps *= 1000
        else if (bps_unit ~ /^Kbits/) bps /= 1000
        else if (bps_unit ~ /^bits/)  bps /= 1000000

        # Normalize transfer to MBytes
        if (xfer_unit == "GBytes")     xfer *= 1024
        else if (xfer_unit == "KBytes") xfer /= 1024
        else if (xfer_unit == "Bytes")  xfer /= (1024*1024)

        # Summary lines: pick the non-zero total (sender for UL, receiver for DL with -R)
        if (/sender/)        { s_xfer = xfer }
        else if (/receiver/) { r_xfer = xfer }
        else if (bps > 0)    { n++; v[n] = bps }
    }
    END {
        if (n == 0) exit 1

        # Total data = whichever summary line is non-zero (covers -R flag reversal)
        total_mb = (s_xfer > r_xfer) ? s_xfer : r_xfer

        # Insertion sort
        for (j = 2; j <= n; j++) {
            key = v[j]; k = j - 1
            while (k >= 1 && v[k] > key) { v[k+1] = v[k]; k-- }
            v[k+1] = key
        }

        # Stats
        sum = 0
        for (i = 1; i <= n; i++) sum += v[i]
        mean = sum / n
        max_val = v[n]
        if (n % 2 == 1) med = v[int(n/2) + 1]
        else             med = (v[n/2] + v[n/2 + 1]) / 2
        p10i = int(n * 0.10 + 0.5); if (p10i < 1) p10i = 1
        p90i = int(n * 0.90 + 0.5); if (p90i < 1) p90i = 1; if (p90i > n) p90i = n
        p10 = v[p10i]; p90 = v[p90i]

        printf "%-10s %-5s %10.1f %10.2f %8.2f %8.2f %8.2f %8.2f    %4d\n", \
            dir, toupper(proto), total_mb, mean, max_val, med, p10, p90, n
    }' "$logfile"
}

echo -e "\n=========================================================================================="
echo -e "             IPERF3 THROUGHPUT SUMMARY"
echo -e "=========================================================================================="
printf "%-10s %-5s %10s %10s %8s %8s %8s %8s   %5s\n" \
    "Direction" "Type" "Data (MB)" "Mean Mbps" "Max" "Median" "P10" "P90" "Smpls"
echo "------------------------------------------------------------------------------------------"

IPERF_HAS_DATA=false
for direction in downlink uplink; do
    logfile="iperf_${STRESS_TYPE}_${direction}.log"
    if [[ -f "$logfile" && -s "$logfile" ]]; then
        row=$(parse_iperf_log "$logfile" "$direction" "$STRESS_TYPE")
        if [[ -n "$row" ]]; then
            echo "$row"
            IPERF_HAS_DATA=true
        fi
    fi
done

if [[ "$IPERF_HAS_DATA" != true ]]; then
    echo "  No iperf3 throughput data found. Ensure ENABLE_STRESS=true and iperf3 server is reachable."
fi

# ==============================================================================
# ASCII TIME-SERIES CHART (overlay)
# ==============================================================================
CHART_SCRIPT="$SCRIPT_DIR/bloatChart.sh"
if [ -x "$CHART_SCRIPT" ]; then
    echo ""
    "$CHART_SCRIPT" -r "$MAIN_LOG" \
        -d "iperf_${STRESS_TYPE}_downlink.log" \
        -u "iperf_${STRESS_TYPE}_uplink.log" \
        -a "${AUTORATE_LOG:-autorate.log}"
elif [ -f "$CHART_SCRIPT" ]; then
    echo ""
    bash "$CHART_SCRIPT" -r "$MAIN_LOG" \
        -d "iperf_${STRESS_TYPE}_downlink.log" \
        -u "iperf_${STRESS_TYPE}_uplink.log" \
        -a "${AUTORATE_LOG:-autorate.log}"
fi