#!/bin/bash
# bufferScenarioTest.sh — Automated bufferbloat scenario comparator
# Runs bufferManager.sh strategies + bufferTest.sh, records counters & iperf
# summaries, and displays a comparison table with highlighted differences.

set -u

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BM="$SCRIPT_DIR/bufferManager.sh"
BT="$SCRIPT_DIR/bufferTest.sh"

RUNS=1                          # Repetitions per scenario (override with -r)
LOG_DIR="$SCRIPT_DIR/scenario_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/scenario_${TIMESTAMP}.log"
SUMMARY_FILE="$LOG_DIR/summary_${TIMESTAMP}.txt"

# Scenarios to run (override with -s). Format: "label:cmd1,cmd2,..."
# Commands are bufferManager.sh subcommands executed in order.
# "autorate" is special: runs in background, killed after bufferTest.sh finishes.
DEFAULT_SCENARIOS=(
    "no-queue:remove"
    "fq_codel:fq_codel"
    "cake-bidir:tune,cake-bidir"
    "cake-bidir+autorate:tune,cake-bidir,autorate"
    "htb+tune:tune,htb"
    "aggressive:tune,aggressive"
)

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; N='\033[0m'
DIM='\033[2m'; INV='\033[7m'

# ══════════════════════════════════════════════════════════════════════════════
# USAGE
# ══════════════════════════════════════════════════════════════════════════════
usage() {
    cat <<EOF
${B}Usage:${N} $0 [OPTIONS]

Run bufferbloat test scenarios, record qdisc counters & iperf throughput,
and display a comparison table.

${B}Options:${N}
  -r RUNS       Number of repetitions per scenario (default: $RUNS)
  -s SCENARIOS  Comma-separated scenario list (overrides defaults)
                Format: "label:cmd1,cmd2;label2:cmd1,cmd2"
  -o DIR        Output directory for logs (default: $LOG_DIR)
  -l            List built-in scenarios and exit
  -h            Show this help

${B}Built-in Scenarios:${N}
EOF
    for s in "${DEFAULT_SCENARIOS[@]}"; do
        local label="${s%%:*}"
        local cmds="${s#*:}"
        printf "  %-25s %s\n" "$label" "$cmds"
    done
    cat <<EOF

${B}Examples:${N}
  # Run all built-in scenarios once
  $0

  # Run all built-in scenarios 3 times each
  $0 -r 3

  # Baseline vs static CAKE
  $0 -s "base:remove;shaped:tune,cake-bidir"

  # Baseline vs CAKE with autorate
  $0 -s "base:remove;shaped+autorate:tune,cake-bidir,autorate"

  # Full comparison: no shaping vs static vs adaptive, 3 runs each
  $0 -r 3 -s "base:remove;shaped:tune,cake-bidir;shaped+autorate:tune,cake-bidir,autorate"

  # Custom output directory
  $0 -o /tmp/bloat_results -s "base:remove;htb:tune,htb"

${B}Available bufferManager.sh Commands (for -s):${N}
  remove        Remove all qdiscs (no shaping)
  tune          BBR + ECN + reduced TCP buffers
  untune        Revert TCP to cubic defaults
  cake-bidir    CAKE egress + ingress via IFB
  cake          CAKE egress only
  htb           HTB + fq_codel
  fq_codel      fq_codel only (no shaping)
  aggressive    Tight fq_codel (last resort)
  autorate      Continuous RTT-based CAKE adaptation (runs in background)

${B}Notes:${N}
  - "autorate" command runs in background and is killed after the test.
  - Counters are cleared before each run and read before/after.
  - Requires root (tc/sysctl operations).
  - First scenario is used as the comparison baseline in the results table.
  - Use bash (not sh): bash $0 ...
EOF
    exit 0
}

list_scenarios() {
    echo -e "${B}Built-in Scenarios:${N}"
    echo ""
    printf "  ${B}%-25s %-40s${N}\n" "Label" "Commands"
    echo "  ──────────────────────── ────────────────────────────────────────"
    for s in "${DEFAULT_SCENARIOS[@]}"; do
        local label="${s%%:*}"
        local cmds="${s#*:}"
        printf "  %-25s %s\n" "$label" "$cmds"
    done
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# PARSE ARGS
# ══════════════════════════════════════════════════════════════════════════════
CUSTOM_SCENARIOS=""
while getopts "r:s:o:lh" opt; do
    case $opt in
        r) RUNS="$OPTARG" ;;
        s) CUSTOM_SCENARIOS="$OPTARG" ;;
        o) LOG_DIR="$OPTARG" ;;
        l) list_scenarios ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Build scenario array
SCENARIOS=()
if [ -n "$CUSTOM_SCENARIOS" ]; then
    IFS=';' read -ra SCENARIOS <<< "$CUSTOM_SCENARIOS"
else
    SCENARIOS=("${DEFAULT_SCENARIOS[@]}")
fi

mkdir -p "$LOG_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

log() { echo -e "$1" | tee -a "$LOG_FILE"; }

# Extract numeric counter values from `bufferManager.sh counters` output.
# Outputs a parseable line: sent_bytes sent_pkts dropped overlimits ecn_marks backlog
# for egress and ingress separately.
capture_counters() {
    local label="$1"  # "before" or "after"
    local outfile="$2"

    local raw
    raw=$("$BM" counters 2>&1) || true

    # Parse egress stats (|| true prevents exit on no-match)
    local eg_sent_bytes eg_sent_pkts eg_dropped eg_overlimits eg_ecn eg_backlog
    eg_sent_bytes=$(echo "$raw" | grep -A5 '\[Egress\]' | grep -oP 'Sent \K[0-9]+(?= bytes)' | head -1 || true)
    eg_sent_pkts=$(echo "$raw" | grep -A5 '\[Egress\]' | grep -oP 'Sent [0-9]+ bytes \K[0-9]+(?= pkt)' | head -1 || true)
    eg_dropped=$(echo "$raw" | grep -A5 '\[Egress\]' | grep -oP 'dropped \K[0-9]+' | head -1 || true)
    eg_overlimits=$(echo "$raw" | grep -A5 '\[Egress\]' | grep -oP 'overlimits \K[0-9]+' | head -1 || true)
    eg_ecn=$(echo "$raw" | grep -A10 '\[Egress\]' | grep -oP 'ecn_mark \K[0-9]+' | head -1 || true)
    eg_backlog=$(echo "$raw" | grep -A5 '\[Egress\]' | grep -oP 'backlog \K[0-9]+' | head -1 || true)

    # Parse ingress stats (IFB)
    local in_sent_bytes in_sent_pkts in_dropped in_overlimits in_ecn in_backlog
    in_sent_bytes=$(echo "$raw" | grep -A5 '\[Ingress IFB\]' | grep -oP 'Sent \K[0-9]+(?= bytes)' | head -1 || true)
    in_sent_pkts=$(echo "$raw" | grep -A5 '\[Ingress IFB\]' | grep -oP 'Sent [0-9]+ bytes \K[0-9]+(?= pkt)' | head -1 || true)
    in_dropped=$(echo "$raw" | grep -A5 '\[Ingress IFB\]' | grep -oP 'dropped \K[0-9]+' | head -1 || true)
    in_overlimits=$(echo "$raw" | grep -A5 '\[Ingress IFB\]' | grep -oP 'overlimits \K[0-9]+' | head -1 || true)
    in_ecn=$(echo "$raw" | grep -A10 '\[Ingress IFB\]' | grep -oP 'ecn_mark \K[0-9]+' | head -1 || true)
    in_backlog=$(echo "$raw" | grep -A5 '\[Ingress IFB\]' | grep -oP 'backlog \K[0-9]+' | head -1 || true)

    cat > "$outfile" <<EOF
label=$label
eg_sent_bytes=${eg_sent_bytes:-0}
eg_sent_pkts=${eg_sent_pkts:-0}
eg_dropped=${eg_dropped:-0}
eg_overlimits=${eg_overlimits:-0}
eg_ecn=${eg_ecn:-0}
eg_backlog=${eg_backlog:-0}
in_sent_bytes=${in_sent_bytes:-0}
in_sent_pkts=${in_sent_pkts:-0}
in_dropped=${in_dropped:-0}
in_overlimits=${in_overlimits:-0}
in_ecn=${in_ecn:-0}
in_backlog=${in_backlog:-0}
EOF
}

# Parse iperf summary from bufferTest.sh output.
# Looks for the throughput table and extracts DL/UL rows.
parse_iperf_summary() {
    local bt_output="$1"
    local outfile="$2"

    # Extract lines between "IPERF3 THROUGHPUT SUMMARY" and the next "===" section or EOF
    local in_table=0
    local dl_mean="" dl_max="" dl_median="" dl_p10="" dl_p90="" dl_data=""
    local ul_mean="" ul_max="" ul_median="" ul_p10="" ul_p90="" ul_data=""

    while IFS= read -r line; do
        if echo "$line" | grep -q "IPERF3 THROUGHPUT SUMMARY"; then
            in_table=1; continue
        fi
        [ "$in_table" -eq 0 ] && continue

        if echo "$line" | grep -qi "downlink"; then
            dl_data=$(echo "$line" | awk '{print $3}')
            dl_mean=$(echo "$line" | awk '{print $4}')
            dl_max=$(echo "$line" | awk '{print $5}')
            dl_median=$(echo "$line" | awk '{print $6}')
            dl_p10=$(echo "$line" | awk '{print $7}')
            dl_p90=$(echo "$line" | awk '{print $8}')
        fi
        if echo "$line" | grep -qi "uplink"; then
            ul_data=$(echo "$line" | awk '{print $3}')
            ul_mean=$(echo "$line" | awk '{print $4}')
            ul_max=$(echo "$line" | awk '{print $5}')
            ul_median=$(echo "$line" | awk '{print $6}')
            ul_p10=$(echo "$line" | awk '{print $7}')
            ul_p90=$(echo "$line" | awk '{print $8}')
        fi
    done <<< "$bt_output"

    cat > "$outfile" <<EOF
dl_data=${dl_data:-N/A}
dl_mean=${dl_mean:-N/A}
dl_max=${dl_max:-N/A}
dl_median=${dl_median:-N/A}
dl_p10=${dl_p10:-N/A}
dl_p90=${dl_p90:-N/A}
ul_data=${ul_data:-N/A}
ul_mean=${ul_mean:-N/A}
ul_max=${ul_max:-N/A}
ul_median=${ul_median:-N/A}
ul_p10=${ul_p10:-N/A}
ul_p90=${ul_p90:-N/A}
EOF
}

# Parse latency summary from bufferTest.sh output.
parse_latency_summary() {
    local bt_output="$1"
    local outfile="$2"

    local bl_avg="" bl_p95="" bl_max="" bl_loss=""
    local st_avg="" st_p95="" st_max="" st_loss=""

    while IFS= read -r line; do
        if echo "$line" | grep -q "^BASELINE"; then
            bl_loss=$(echo "$line" | awk '{print $3}')
            bl_avg=$(echo "$line" | awk '{print $4}')
            bl_p95=$(echo "$line" | awk '{print $5}')
            bl_max=$(echo "$line" | awk '{print $6}')
        fi
        if echo "$line" | grep -q "^STRESS"; then
            st_loss=$(echo "$line" | awk '{print $3}')
            st_avg=$(echo "$line" | awk '{print $4}')
            st_p95=$(echo "$line" | awk '{print $5}')
            st_max=$(echo "$line" | awk '{print $6}')
        fi
    done <<< "$bt_output"

    cat > "$outfile" <<EOF
bl_avg=${bl_avg:-N/A}
bl_p95=${bl_p95:-N/A}
bl_max=${bl_max:-N/A}
bl_loss=${bl_loss:-N/A}
st_avg=${st_avg:-N/A}
st_p95=${st_p95:-N/A}
st_max=${st_max:-N/A}
st_loss=${st_loss:-N/A}
EOF
}

# Compute delta between two counter files (after - before).
compute_counter_delta() {
    local before_file="$1"
    local after_file="$2"
    local outfile="$3"

    source "$before_file"
    local b_eg_bytes=$eg_sent_bytes b_eg_pkts=$eg_sent_pkts b_eg_drop=$eg_dropped
    local b_eg_over=$eg_overlimits b_eg_ecn=$eg_ecn
    local b_in_bytes=$in_sent_bytes b_in_pkts=$in_sent_pkts b_in_drop=$in_dropped
    local b_in_over=$in_overlimits b_in_ecn=$in_ecn

    source "$after_file"
    local a_eg_bytes=$eg_sent_bytes a_eg_pkts=$eg_sent_pkts a_eg_drop=$eg_dropped
    local a_eg_over=$eg_overlimits a_eg_ecn=$eg_ecn
    local a_in_bytes=$in_sent_bytes a_in_pkts=$in_sent_pkts a_in_drop=$in_dropped
    local a_in_over=$in_overlimits a_in_ecn=$in_ecn

    cat > "$outfile" <<EOF
eg_sent_bytes=$(( a_eg_bytes - b_eg_bytes ))
eg_sent_pkts=$(( a_eg_pkts - b_eg_pkts ))
eg_dropped=$(( a_eg_drop - b_eg_drop ))
eg_overlimits=$(( a_eg_over - b_eg_over ))
eg_ecn=$(( a_eg_ecn - b_eg_ecn ))
in_sent_bytes=$(( a_in_bytes - b_in_bytes ))
in_sent_pkts=$(( a_in_pkts - b_in_pkts ))
in_dropped=$(( a_in_drop - b_in_drop ))
in_overlimits=$(( a_in_over - b_in_over ))
in_ecn=$(( a_in_ecn - b_in_ecn ))
EOF
}

# Human-readable byte formatting
human_bytes() {
    local bytes=$1
    if [ "$bytes" -ge 1073741824 ]; then
        printf "%.1fGB" "$(echo "$bytes / 1073741824" | bc -l)"
    elif [ "$bytes" -ge 1048576 ]; then
        printf "%.1fMB" "$(echo "$bytes / 1048576" | bc -l)"
    elif [ "$bytes" -ge 1024 ]; then
        printf "%.1fKB" "$(echo "$bytes / 1024" | bc -l)"
    else
        printf "%dB" "$bytes"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# RUN ONE SCENARIO
# ══════════════════════════════════════════════════════════════════════════════

run_scenario() {
    local label="$1"
    local cmds_csv="$2"  # comma-separated bufferManager.sh subcommands
    local run_num="$3"
    local result_dir="$4"

    local run_dir="$result_dir/run_${run_num}"
    mkdir -p "$run_dir"

    log "\n${B}┌──────────────────────────────────────────────────────────────┐${N}"
    log "${B}│  Scenario: ${C}${label}${N}${B}  │  Run: ${run_num}/${RUNS}${N}"
    log "${B}└──────────────────────────────────────────────────────────────┘${N}"

    # Step 1: Remove existing qdiscs for clean slate
    log "${DIM}  [1/6] Removing existing qdiscs...${N}"
    "$BM" remove >> "$LOG_FILE" 2>&1 || true
    "$BM" untune >> "$LOG_FILE" 2>&1 || true

    # Step 2: Apply scenario commands
    IFS=',' read -ra CMD_LIST <<< "$cmds_csv"
    local AUTORATE_PID=""

    log "${DIM}  [2/6] Applying strategy: ${cmds_csv}${N}"
    for cmd in "${CMD_LIST[@]}"; do
        cmd=$(echo "$cmd" | xargs)  # trim whitespace
        if [ "$cmd" = "autorate" ]; then
            # autorate runs as a background loop — launch it and record PID
            log "         → Starting autorate in background..."
            "$BM" autorate >> "$LOG_FILE" 2>&1 &
            AUTORATE_PID=$!
            sleep 3  # let autorate settle and do first probe
        else
            log "         → $BM $cmd"
            "$BM" "$cmd" >> "$LOG_FILE" 2>&1 || true
        fi
    done

    # Step 3: Clear counters + read baseline counters
    log "${DIM}  [3/6] Clearing & reading pre-test counters...${N}"
    "$BM" clear >> "$LOG_FILE" 2>&1 || true
    sleep 1
    capture_counters "before" "$run_dir/counters_before.dat"

    # Step 4: Run bufferTest.sh (live output via tee)
    log "${DIM}  [4/6] Running bufferTest.sh...${N}"
    local bt_start=$(date +%s)
    local bt_output_file="$run_dir/bufferTest_full_output.txt"
    "$BT" 2>&1 | tee "$bt_output_file" || true
    local bt_end=$(date +%s)
    local bt_duration=$(( bt_end - bt_start ))
    local bt_output
    bt_output=$(cat "$bt_output_file")
    log "         Duration: ${bt_duration}s"

    # Step 5: Read post-test counters
    log "${DIM}  [5/6] Reading post-test counters...${N}"
    capture_counters "after" "$run_dir/counters_after.dat"

    # Step 6: Kill autorate if running
    if [ -n "$AUTORATE_PID" ]; then
        log "${DIM}  [6/6] Stopping autorate (PID $AUTORATE_PID)...${N}"
        kill "$AUTORATE_PID" 2>/dev/null || true
        wait "$AUTORATE_PID" 2>/dev/null || true
    else
        log "${DIM}  [6/6] No autorate to stop.${N}"
    fi

    # Parse results
    compute_counter_delta "$run_dir/counters_before.dat" "$run_dir/counters_after.dat" "$run_dir/counter_delta.dat"
    parse_iperf_summary "$bt_output" "$run_dir/iperf_summary.dat"
    parse_latency_summary "$bt_output" "$run_dir/latency_summary.dat"

    log "${G}  ✓ Scenario '$label' run $run_num complete.${N}"
}

# ══════════════════════════════════════════════════════════════════════════════
# AGGREGATE RESULTS ACROSS RUNS FOR ONE SCENARIO
# ══════════════════════════════════════════════════════════════════════════════

# Average a numeric field across run files. Non-numeric values return "N/A".
avg_field() {
    local field="$1"
    shift
    local sum=0 count=0
    for f in "$@"; do
        local val
        val=$(grep "^${field}=" "$f" 2>/dev/null | cut -d= -f2)
        if [ -n "$val" ] && [ "$val" != "N/A" ]; then
            sum=$(echo "$sum + $val" | bc -l 2>/dev/null || echo "$sum")
            count=$((count + 1))
        fi
    done
    if [ "$count" -gt 0 ]; then
        printf "%.2f" "$(echo "$sum / $count" | bc -l)"
    else
        echo "N/A"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# COMPARISON TABLE
# ══════════════════════════════════════════════════════════════════════════════

# Highlight a value if it differs significantly from the first scenario (baseline).
# Green = better, Red = worse. "better" depends on metric type.
highlight_val() {
    local val="$1"
    local baseline="$2"
    local lower_is_better="${3:-1}"  # 1=lower is better (latency,drops), 0=higher is better (throughput)

    [ "$val" = "N/A" ] || [ "$baseline" = "N/A" ] && { echo "$val"; return; }

    local diff
    diff=$(echo "$val - $baseline" | bc -l 2>/dev/null)
    [ -z "$diff" ] && { echo "$val"; return; }

    # Threshold: >5% change
    local abs_base
    abs_base=$(echo "${baseline#-}" | bc -l 2>/dev/null)
    [ -z "$abs_base" ] || [ "$(echo "$abs_base == 0" | bc -l)" -eq 1 ] && { echo "$val"; return; }

    local pct
    pct=$(echo "($diff / $abs_base) * 100" | bc -l 2>/dev/null)
    local abs_pct
    abs_pct=$(echo "${pct#-}" | bc -l 2>/dev/null)

    local is_significant
    is_significant=$(echo "$abs_pct > 5" | bc -l 2>/dev/null)
    [ "$is_significant" != "1" ] && { echo "$val"; return; }

    local is_negative
    is_negative=$(echo "$diff < 0" | bc -l 2>/dev/null)

    if [ "$lower_is_better" -eq 1 ]; then
        # Lower is better: negative diff = green, positive diff = red
        if [ "$is_negative" = "1" ]; then
            printf "${G}%s (%.0f%%)${N}" "$val" "$pct"
        else
            printf "${R}%s (+%.0f%%)${N}" "$val" "$pct"
        fi
    else
        # Higher is better: positive diff = green, negative diff = red
        if [ "$is_negative" = "1" ]; then
            printf "${R}%s (%.0f%%)${N}" "$val" "$pct"
        else
            printf "${G}%s (+%.0f%%)${N}" "$val" "$pct"
        fi
    fi
}

print_comparison_table() {
    local result_base="$1"
    shift
    local scenario_labels=("$@")

    local num_scenarios=${#scenario_labels[@]}

    # ─── Collect aggregated data per scenario ───
    declare -A AGG  # AGG[scenario_idx,field]=value

    for si in $(seq 0 $((num_scenarios - 1))); do
        local label="${scenario_labels[$si]}"
        local safe_label
        safe_label=$(echo "$label" | tr ' /+' '___')
        local sdir="$result_base/$safe_label"

        # Gather run files
        local delta_files=() iperf_files=() latency_files=()
        for r in $(seq 1 "$RUNS"); do
            local rdir="$sdir/run_${r}"
            [ -f "$rdir/counter_delta.dat" ] && delta_files+=("$rdir/counter_delta.dat")
            [ -f "$rdir/iperf_summary.dat" ] && iperf_files+=("$rdir/iperf_summary.dat")
            [ -f "$rdir/latency_summary.dat" ] && latency_files+=("$rdir/latency_summary.dat")
        done

        # Counter deltas (averaged across runs)
        AGG[$si,eg_dropped]=$(avg_field "eg_dropped" "${delta_files[@]}")
        AGG[$si,eg_overlimits]=$(avg_field "eg_overlimits" "${delta_files[@]}")
        AGG[$si,eg_ecn]=$(avg_field "eg_ecn" "${delta_files[@]}")
        AGG[$si,eg_sent_pkts]=$(avg_field "eg_sent_pkts" "${delta_files[@]}")
        AGG[$si,in_dropped]=$(avg_field "in_dropped" "${delta_files[@]}")
        AGG[$si,in_overlimits]=$(avg_field "in_overlimits" "${delta_files[@]}")
        AGG[$si,in_ecn]=$(avg_field "in_ecn" "${delta_files[@]}")
        AGG[$si,in_sent_pkts]=$(avg_field "in_sent_pkts" "${delta_files[@]}")

        # Iperf (averaged)
        AGG[$si,dl_mean]=$(avg_field "dl_mean" "${iperf_files[@]}")
        AGG[$si,dl_p90]=$(avg_field "dl_p90" "${iperf_files[@]}")
        AGG[$si,ul_mean]=$(avg_field "ul_mean" "${iperf_files[@]}")
        AGG[$si,ul_p90]=$(avg_field "ul_p90" "${iperf_files[@]}")

        # Latency (averaged)
        AGG[$si,bl_avg]=$(avg_field "bl_avg" "${latency_files[@]}")
        AGG[$si,bl_p95]=$(avg_field "bl_p95" "${latency_files[@]}")
        AGG[$si,st_avg]=$(avg_field "st_avg" "${latency_files[@]}")
        AGG[$si,st_p95]=$(avg_field "st_p95" "${latency_files[@]}")
        AGG[$si,st_loss]=$(avg_field "st_loss" "${latency_files[@]}")
    done

    # ─── Print table ───
    local col_w=18
    local label_w=22

    # Header row
    local hdr
    hdr=$(printf "%-${label_w}s" "Metric")
    for si in $(seq 0 $((num_scenarios - 1))); do
        hdr+=$(printf " │ %-${col_w}s" "${scenario_labels[$si]}")
    done

    local sep_len=$(( label_w + (col_w + 3) * num_scenarios ))
    local sep=$(printf '═%.0s' $(seq 1 "$sep_len"))
    local thin_sep=$(printf '─%.0s' $(seq 1 "$sep_len"))

    echo -e "\n${B}${sep}${N}"
    echo -e "${B}${INV}  SCENARIO COMPARISON TABLE  (${RUNS} run(s) per scenario, averaged)  ${N}"
    echo -e "${B}${sep}${N}"

    echo -e "${B}${hdr}${N}"
    echo "$thin_sep"

    # ─── Throughput section ───
    echo -e "${C}  IPERF3 THROUGHPUT${N}"

    local tp_metrics=(
        "DL Mean (Mbps)"  "dl_mean" "0"
        "DL P90 (Mbps)"   "dl_p90"  "0"
        "UL Mean (Mbps)"  "ul_mean" "0"
        "UL P90 (Mbps)"   "ul_p90"  "0"
    )
    local ti=0
    while [ $ti -lt ${#tp_metrics[@]} ]; do
        local metric_label="${tp_metrics[$ti]}"
        local metric_key="${tp_metrics[$((ti+1))]}"
        local better_dir="${tp_metrics[$((ti+2))]}"
        ti=$((ti + 3))

        local row
        row=$(printf "  %-${label_w}s" "$metric_label")
        local base_val="${AGG[0,$metric_key]}"
        for si in $(seq 0 $((num_scenarios - 1))); do
            local val="${AGG[$si,$metric_key]}"
            if [ "$si" -eq 0 ]; then
                row+=$(printf " │ %-${col_w}s" "$val")
            else
                local hval
                hval=$(highlight_val "$val" "$base_val" "$better_dir")
                row+=$(printf " │ %-${col_w}b" "$hval")
            fi
        done
        echo -e "$row"
    done

    echo "$thin_sep"

    # ─── Latency section ───
    echo -e "${C}  END-TO-END LATENCY${N}"

    local lat_metrics=(
        "Baseline Avg (ms)"  "bl_avg"  "1"
        "Baseline P95 (ms)"  "bl_p95"  "1"
        "Stress Avg (ms)"    "st_avg"  "1"
        "Stress P95 (ms)"    "st_p95"  "1"
        "Stress Loss %"      "st_loss" "1"
    )
    local li=0
    while [ $li -lt ${#lat_metrics[@]} ]; do
        local metric_label="${lat_metrics[$li]}"
        local metric_key="${lat_metrics[$((li+1))]}"
        local better_dir="${lat_metrics[$((li+2))]}"
        li=$((li + 3))

        local row
        row=$(printf "  %-${label_w}s" "$metric_label")
        local base_val="${AGG[0,$metric_key]}"
        for si in $(seq 0 $((num_scenarios - 1))); do
            local val="${AGG[$si,$metric_key]}"
            if [ "$si" -eq 0 ]; then
                row+=$(printf " │ %-${col_w}s" "$val")
            else
                local hval
                hval=$(highlight_val "$val" "$base_val" "$better_dir")
                row+=$(printf " │ %-${col_w}b" "$hval")
            fi
        done
        echo -e "$row"
    done

    echo "$thin_sep"

    # ─── Qdisc counters section ───
    echo -e "${C}  QDISC COUNTERS (delta during test)${N}"

    local qd_metrics=(
        "Egress Pkts"        "eg_sent_pkts"   "0"
        "Egress Dropped"     "eg_dropped"     "1"
        "Egress Overlimits"  "eg_overlimits"  "1"
        "Egress ECN Marks"   "eg_ecn"         "0"
        "Ingress Pkts"       "in_sent_pkts"   "0"
        "Ingress Dropped"    "in_dropped"     "1"
        "Ingress Overlimits" "in_overlimits"  "1"
        "Ingress ECN Marks"  "in_ecn"         "0"
    )
    local qi=0
    while [ $qi -lt ${#qd_metrics[@]} ]; do
        local metric_label="${qd_metrics[$qi]}"
        local metric_key="${qd_metrics[$((qi+1))]}"
        local better_dir="${qd_metrics[$((qi+2))]}"
        qi=$((qi + 3))

        local row
        row=$(printf "  %-${label_w}s" "$metric_label")
        local base_val="${AGG[0,$metric_key]}"
        for si in $(seq 0 $((num_scenarios - 1))); do
            local val="${AGG[$si,$metric_key]}"
            if [ "$si" -eq 0 ]; then
                row+=$(printf " │ %-${col_w}s" "$val")
            else
                local hval
                hval=$(highlight_val "$val" "$base_val" "$better_dir")
                row+=$(printf " │ %-${col_w}b" "$hval")
            fi
        done
        echo -e "$row"
    done

    echo -e "${B}${sep}${N}"

    # ─── Legend ───
    echo ""
    echo -e "  ${G}Green${N} = better than '${scenario_labels[0]}' baseline (>5% diff)"
    echo -e "  ${R}Red${N}   = worse than '${scenario_labels[0]}' baseline (>5% diff)"
    echo -e "  Values within 5% of baseline shown without color."
    echo -e "  All values averaged across ${RUNS} run(s)."
}

# ══════════════════════════════════════════════════════════════════════════════
# PER-RUN DETAIL TABLE (when RUNS > 1)
# ══════════════════════════════════════════════════════════════════════════════

print_run_detail_table() {
    local result_base="$1"
    local label="$2"
    local safe_label
    safe_label=$(echo "$label" | tr ' /+' '___')
    local sdir="$result_base/$safe_label"

    [ "$RUNS" -le 1 ] && return

    echo -e "\n${B}  Per-Run Detail: ${C}${label}${N}"
    printf "  %-5s %10s %10s %10s %10s %10s %10s %10s\n" \
        "Run" "DL Mbps" "UL Mbps" "St Avg ms" "St P95 ms" "Eg Drop" "In Drop" "Eg ECN"
    printf "  %-5s %10s %10s %10s %10s %10s %10s %10s\n" \
        "─────" "──────────" "──────────" "──────────" "──────────" "──────────" "──────────" "──────────"

    for r in $(seq 1 "$RUNS"); do
        local rdir="$sdir/run_${r}"
        [ -f "$rdir/iperf_summary.dat" ] && source "$rdir/iperf_summary.dat" || continue
        [ -f "$rdir/latency_summary.dat" ] && source "$rdir/latency_summary.dat" || continue
        [ -f "$rdir/counter_delta.dat" ] && source "$rdir/counter_delta.dat" || continue

        printf "  %-5s %10s %10s %10s %10s %10s %10s %10s\n" \
            "$r" "${dl_mean:-N/A}" "${ul_mean:-N/A}" "${st_avg:-N/A}" "${st_p95:-N/A}" \
            "${eg_dropped:-0}" "${in_dropped:-0}" "${eg_ecn:-0}"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

echo -e "${B}╔══════════════════════════════════════════════════════════════╗${N}"
echo -e "${B}║          BUFFERBLOAT SCENARIO TEST RUNNER                   ║${N}"
echo -e "${B}╚══════════════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "  Scenarios: ${#SCENARIOS[@]}"
echo -e "  Runs/scenario: $RUNS"
echo -e "  Log dir: $LOG_DIR"
echo -e "  Timestamp: $TIMESTAMP"
echo ""

# Verify scripts exist and are executable
for script in "$BM" "$BT"; do
    if [ ! -x "$script" ]; then
        echo -e "${R}ERROR: $script not found or not executable.${N}"
        echo "  Run: chmod +x $script"
        exit 1
    fi
done

RESULT_BASE="$LOG_DIR/results_${TIMESTAMP}"
mkdir -p "$RESULT_BASE"

# Collect scenario labels for table
SCENARIO_LABELS=()

log "Start: $(date)"
log "═══════════════════════════════════════════════════════════════"

TOTAL_TESTS=$(( ${#SCENARIOS[@]} * RUNS ))
TEST_NUM=0

for scenario in "${SCENARIOS[@]}"; do
    label="${scenario%%:*}"
    cmds="${scenario#*:}"
    SCENARIO_LABELS+=("$label")

    safe_label=$(echo "$label" | tr ' /+' '___')
    sdir="$RESULT_BASE/$safe_label"
    mkdir -p "$sdir"

    for run in $(seq 1 "$RUNS"); do
        TEST_NUM=$((TEST_NUM + 1))
        echo -e "\n${Y}>>> Test $TEST_NUM/$TOTAL_TESTS: '$label' run $run/$RUNS <<<${N}"
        run_scenario "$label" "$cmds" "$run" "$sdir"
    done
done

# ─── Cleanup: restore to default ───
log "\n${DIM}Restoring system to defaults...${N}"
"$BM" remove >> "$LOG_FILE" 2>&1 || true
"$BM" untune >> "$LOG_FILE" 2>&1 || true

log "\n═══════════════════════════════════════════════════════════════"
log "End: $(date)"

# ══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ══════════════════════════════════════════════════════════════════════════════

echo ""
print_comparison_table "$RESULT_BASE" "${SCENARIO_LABELS[@]}" | tee -a "$SUMMARY_FILE"

# Per-run detail tables (only if >1 run)
if [ "$RUNS" -gt 1 ]; then
    echo "" | tee -a "$SUMMARY_FILE"
    for label in "${SCENARIO_LABELS[@]}"; do
        print_run_detail_table "$RESULT_BASE" "$label" | tee -a "$SUMMARY_FILE"
    done
fi

echo ""
echo -e "${B}Results saved to:${N}"
echo -e "  Full log:    $LOG_FILE"
echo -e "  Summary:     $SUMMARY_FILE"
echo -e "  Raw data:    $RESULT_BASE/"
echo ""
echo -e "${G}Done.${N}"
