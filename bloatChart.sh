#!/bin/bash
# bloatChart.sh — ASCII time-series overlay chart
# Plots iperf throughput, RTT, and autorate limits on a unified timeline.
# Can be run standalone after a test, or called by bufferTest.sh.

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

# ══════════════════════════════════════════════════════════════════════════════
# USAGE
# ══════════════════════════════════════════════════════════════════════════════
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Generate an ASCII time-series chart overlaying:
  - iperf3 throughput (DL/UL Mbps) per 1-second interval
  - End-to-end RTT (ms) from traceroute probes
  - Autorate applied rates (egress/ingress mbit) if available

Options:
  -r FILE    RTT/latency log (default: bloat_results.log)
  -d FILE    iperf3 downlink log (default: iperf_tcp_downlink.log / iperf_udp_downlink.log)
  -u FILE    iperf3 uplink log (default: iperf_tcp_uplink.log / iperf_udp_uplink.log)
  -a FILE    Autorate log (default: autorate.log, optional)
  -w WIDTH   Chart width in columns (default: 80)
  -H HEIGHT  Chart height in rows (default: 20)
  -h         Show this help

Input file formats:
  RTT log:      CSV with columns: Timestamp,Hop,IP,Latency,Phase
  iperf log:    Standard iperf3 output with --timestamps
  Autorate log: CSV with columns: Timestamp,RTT_ms,Egress_mbit,Ingress_mbit,Direction

Example:
  # After running bufferTest.sh + autorate
  $0

  # Custom files
  $0 -r my_results.log -a my_autorate.log -w 120

  # Only iperf + RTT (no autorate)
  $0 -r bloat_results.log -d iperf_tcp_downlink.log -u iperf_tcp_uplink.log
EOF
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# DEFAULTS
# ══════════════════════════════════════════════════════════════════════════════
STRESS_TYPE=$(jq -r '.test.logging.stress_type' "$CONFIG_FILE")
RTT_LOG="bloat_results.log"
DL_LOG="iperf_${STRESS_TYPE}_downlink.log"
UL_LOG="iperf_${STRESS_TYPE}_uplink.log"
AR_LOG="autorate.log"
CHART_WIDTH=80
CHART_HEIGHT=20

while getopts "r:d:u:a:w:H:h" opt; do
    case $opt in
        r) RTT_LOG="$OPTARG" ;;
        d) DL_LOG="$OPTARG" ;;
        u) UL_LOG="$OPTARG" ;;
        a) AR_LOG="$OPTARG" ;;
        w) CHART_WIDTH="$OPTARG" ;;
        H) CHART_HEIGHT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ══════════════════════════════════════════════════════════════════════════════
# DATA EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
WORK_DIR=$(mktemp -d "/tmp/bloatChart_XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

# Extract per-second RTT to target (last hop, highest latency per timestamp).
# If all hops at a timestamp timed out (no valid response), report timeout_ms
# so the chart shows worst-case latency instead of a missing ("-") entry.
CHART_TIMEOUT_MS=$(( $(jq -r '.test.general.timeout' "$CONFIG_FILE") * 1000 ))
if [ -f "$RTT_LOG" ]; then
    awk -F, -v tms="$CHART_TIMEOUT_MS" 'NR>1 {
        ts = $1
        if ($3 != "No-Response" && $3 != "Timeout" && $4+0 > 0) {
            lat = $4 + 0
            if (lat > max[ts]) max[ts] = lat
            if (!(ts in order)) { order[ts] = ++n; ts_list[n] = ts }
            has_valid[ts] = 1
        } else if ($3 == "Timeout") {
            if (!(ts in order)) { order[ts] = ++n; ts_list[n] = ts }
        }
    } END {
        for (i = 1; i <= n; i++) {
            t = ts_list[i]
            if (has_valid[t]) printf "%s,%.2f\n", t, max[t]
            else printf "%s,%.2f\n", t, tms
        }
    }' "$RTT_LOG" > "$WORK_DIR/rtt.csv"
fi

# Extract per-second iperf DL throughput (Mbps)
extract_iperf_per_sec() {
    local logfile="$1" outfile="$2"
    [ ! -f "$logfile" ] && return

    awk '
    /\[SUM\]/ { has_sum = 1 }
    /[0-9].*bits\/sec/ && !/sender/ && !/receiver/ && !/Interval/ && !/\[ *ID\]/ {
        is_sum_line = ($0 ~ /\[SUM\]/) ? 1 : 0
        is_stream_line = ($0 ~ /\[ *[0-9]+\]/) ? 1 : 0
        if (has_sum && is_stream_line) next

        # Extract timestamp if present [HH:MM:SS]
        ts = ""
        if (match($0, /\[([0-9]{2}:[0-9]{2}:[0-9]{2})\]/, m)) {
            ts = m[1]
        }

        # Extract bitrate
        bps = 0; bps_unit = ""
        for (i = 1; i <= NF; i++) {
            if ($(i) ~ /^[KMG]?bits\/sec$/) {
                bps = $(i-1) + 0; bps_unit = $(i)
            }
        }
        if (bps_unit ~ /^Gbits/) bps *= 1000
        else if (bps_unit ~ /^Kbits/) bps /= 1000
        else if (bps_unit ~ /^bits/)  bps /= 1000000

        if (bps_unit != "") {
            n++
            if (ts != "") printf "%s,%.2f\n", ts, bps
            else          printf "%d,%.2f\n", n, bps
        }
    }' "$logfile" > "$outfile"
}

extract_iperf_per_sec "$DL_LOG" "$WORK_DIR/dl.csv"
extract_iperf_per_sec "$UL_LOG" "$WORK_DIR/ul.csv"

# Extract autorate data (already CSV)
if [ -f "$AR_LOG" ]; then
    tail -n +2 "$AR_LOG" > "$WORK_DIR/ar.csv"
fi

# ══════════════════════════════════════════════════════════════════════════════
# BUILD UNIFIED TIMELINE + RENDER ASCII CHART
# ══════════════════════════════════════════════════════════════════════════════

awk -v width="$CHART_WIDTH" -v height="$CHART_HEIGHT" \
    -v rtt_file="$WORK_DIR/rtt.csv" \
    -v dl_file="$WORK_DIR/dl.csv" \
    -v ul_file="$WORK_DIR/ul.csv" \
    -v ar_file="$WORK_DIR/ar.csv" '
BEGIN {
    # ─── Load all data series ───
    n_rtt = 0; n_dl = 0; n_ul = 0; n_ar = 0

    while ((getline line < rtt_file) > 0) {
        n_rtt++
        split(line, a, ",")
        rtt_ts[n_rtt] = a[1]; rtt_val[n_rtt] = a[2] + 0
    }
    close(rtt_file)

    while ((getline line < dl_file) > 0) {
        n_dl++
        split(line, a, ",")
        dl_ts[n_dl] = a[1]; dl_val[n_dl] = a[2] + 0
    }
    close(dl_file)

    while ((getline line < ul_file) > 0) {
        n_ul++
        split(line, a, ",")
        ul_ts[n_ul] = a[1]; ul_val[n_ul] = a[2] + 0
    }
    close(ul_file)

    while ((getline line < ar_file) > 0) {
        n_ar++
        split(line, a, ",")
        ar_ts[n_ar] = a[1]; ar_eg[n_ar] = a[2] + 0  # RTT in autorate
        ar_egress[n_ar] = a[3] + 0
        ar_ingress[n_ar] = a[4] + 0
        ar_dir[n_ar] = a[5]
    }
    close(ar_file)

    # ─── Determine total data points (use max series length) ───
    # Build unified timeline by timestamp (HH:MM:SS)
    # Merge all timestamps into a single sorted sequence
    for (i = 1; i <= n_rtt; i++) { ts = rtt_ts[i]; if (ts != "" && !(ts in seen)) { seen[ts] = 1; n_all++; all_ts[n_all] = ts } }
    for (i = 1; i <= n_dl; i++)  { ts = dl_ts[i];  if (ts != "" && !(ts in seen)) { seen[ts] = 1; n_all++; all_ts[n_all] = ts } }
    for (i = 1; i <= n_ul; i++)  { ts = ul_ts[i];  if (ts != "" && !(ts in seen)) { seen[ts] = 1; n_all++; all_ts[n_all] = ts } }
    for (i = 1; i <= n_ar; i++)  { ts = ar_ts[i];  if (ts != "" && !(ts in seen)) { seen[ts] = 1; n_all++; all_ts[n_all] = ts } }

    # Sort timestamps (insertion sort on HH:MM:SS strings — lexicographic works)
    for (j = 2; j <= n_all; j++) {
        key = all_ts[j]; k = j - 1
        while (k >= 1 && all_ts[k] > key) { all_ts[k+1] = all_ts[k]; k-- }
        all_ts[k+1] = key
    }

    # Build lookup maps: ts → value
    for (i = 1; i <= n_rtt; i++) ts_rtt[rtt_ts[i]] = rtt_val[i]
    for (i = 1; i <= n_dl; i++)  ts_dl[dl_ts[i]] = dl_val[i]
    for (i = 1; i <= n_ul; i++)  ts_ul[ul_ts[i]] = ul_val[i]
    for (i = 1; i <= n_ar; i++) {
        ts_ar_eg[ar_ts[i]] = ar_egress[i]
        ts_ar_in[ar_ts[i]] = ar_ingress[i]
        ts_ar_dir[ar_ts[i]] = ar_dir[i]
    }

    total = n_all
    if (total == 0) {
        # Fallback: no timestamps parsed, use index-based
        total = n_rtt
        if (n_dl > total) total = n_dl
        if (n_ul > total) total = n_ul
    }
    if (total == 0) {
        print "ERROR: No data found in any log file."
        exit 1
    }

    # Chart usable width (leave room for Y-axis labels)
    label_w = 8
    plot_w = width - label_w - 2
    if (plot_w < 20) plot_w = 20

    # ─── Compute ranges ───
    max_throughput = 0; max_rtt_val = 0; max_rate = 0
    for (i = 1; i <= n_dl; i++) if (dl_val[i] > max_throughput) max_throughput = dl_val[i]
    for (i = 1; i <= n_ul; i++) if (ul_val[i] > max_throughput) max_throughput = ul_val[i]
    for (i = 1; i <= n_rtt; i++) if (rtt_val[i] > max_rtt_val) max_rtt_val = rtt_val[i]
    for (i = 1; i <= n_ar; i++) {
        if (ar_egress[i] > max_rate) max_rate = ar_egress[i]
        if (ar_ingress[i] > max_rate) max_rate = ar_ingress[i]
    }

    if (max_throughput == 0) max_throughput = 1
    if (max_rtt_val == 0) max_rtt_val = 1
    if (max_rate == 0 && n_ar > 0) max_rate = 1

    # ─── Print Summary Table (1-sec intervals) ───
    print ""
    print "════════════════════════════════════════════════════════════════════════════════"
    print "             TIME-SERIES DATA (1-second intervals)"
    print "════════════════════════════════════════════════════════════════════════════════"

    # Header
    has_ar = (n_ar > 0) ? 1 : 0
    if (has_ar) {
        printf "%-8s │ %7s %7s │ %7s │ %7s %7s │ %3s\n", \
            "Time", "DL Mbps", "UL Mbps", "RTT ms", "Eg mbit", "In mbit", "Dir"
        print "─────────┼─────────────────┼─────────┼─────────────────┼────"
    } else {
        printf "%-8s │ %7s %7s │ %7s\n", "Time", "DL Mbps", "UL Mbps", "RTT ms"
        print "─────────┼─────────────────┼────────"
    }

    # Merge by timestamp (all series aligned by actual time)
    max_rows = total
    # Limit table to 60 rows, sample if needed
    show_rows = max_rows
    sample = 1
    if (show_rows > 60) { sample = int(show_rows / 60); if (sample < 1) sample = 1 }

    last_eg_s = "      -"; last_in_s = "      -"; last_dir_s = " "
    for (i = 1; i <= max_rows; i += sample) {
        ts = all_ts[i]
        if (ts == "") ts = sprintf("%ds", i)

        dl_s = (ts in ts_dl) ? sprintf("%7.2f", ts_dl[ts]) : "      -"
        ul_s = (ts in ts_ul) ? sprintf("%7.2f", ts_ul[ts]) : "      -"
        rtt_s = (ts in ts_rtt) ? sprintf("%7.1f", ts_rtt[ts]) : "      -"

        if (has_ar) {
            # Find autorate entry at or before this timestamp
            if (ts in ts_ar_eg) {
                eg_s = sprintf("%7d", ts_ar_eg[ts])
                in_s = sprintf("%7d", ts_ar_in[ts])
                dir_s = ts_ar_dir[ts]
                # Show Dir: ▲/▼ at probe, O if probe but no change, - otherwise
                if (dir_s == "." || dir_s == "") show_dir = "O";
                else show_dir = dir_s;
            } else {
                # Use last known autorate value (hold previous), but Dir is always '-'
                eg_s = last_eg_s; in_s = last_in_s; show_dir = "-"
            }
            last_eg_s = eg_s; last_in_s = in_s; last_dir_s = dir_s
            printf "%-8s │ %s %s │ %s │ %s %s │ %s\n", ts, dl_s, ul_s, rtt_s, eg_s, in_s, show_dir
        } else {
            printf "%-8s │ %s %s │ %s\n", ts, dl_s, ul_s, rtt_s
        }
    }
    if (sample > 1) printf "\n  (Showing every %d-th sample, %d total data points)\n", sample, max_rows

    # Data availability summary
    printf "\n  Data coverage: DL=%d samples  UL=%d samples  RTT=%d samples  Autorate=%d samples\n", \
        n_dl, n_ul, n_rtt, n_ar
    if (n_ul < n_dl * 0.5) {
        printf "  ⚠  UL iperf3 ran for only %d/%d seconds — likely crashed due to severe bloat\n", n_ul, n_dl
        printf "     (TCP connections reset when queue overflow drops cause repeated retransmits)\n"
    }
    if (n_rtt < n_dl * 0.5) {
        printf "  ⚠  RTT probes lost under load — %d/%d probes reached target\n", n_rtt, n_dl
        printf "     (ICMP traceroute dropped by congested buffers; this itself confirms bloat)\n"
    }

    # ─── ASCII CHART: Throughput ───
    print ""
    print "════════════════════════════════════════════════════════════════════════════════"
    print "             ASCII CHART: Throughput (DL ▓, UL ░) + RTT (●)"
    print "════════════════════════════════════════════════════════════════════════════════"
    printf "  Y-axis left: Throughput (0-%d Mbps)   Y-axis right: RTT (0-%d ms)\n", \
        int(max_throughput + 0.5), int(max_rtt_val + 0.5)
    print ""

    # Build chart grid
    for (row = 0; row < height; row++) {
        for (col = 0; col < plot_w; col++) {
            grid[row, col] = " "
        }
    }

    # Map data to chart columns (sample unified timeline to fit plot width)
    step = 1
    if (total > plot_w) step = total / plot_w

    for (col = 0; col < plot_w; col++) {
        idx = int(col * step) + 1
        if (idx > total) idx = total
        ts = all_ts[idx]

        # DL throughput bar (▓)
        if ((ts in ts_dl) && ts_dl[ts] > 0) {
            dl_row = int((ts_dl[ts] / max_throughput) * (height - 1))
            if (dl_row >= height) dl_row = height - 1
            for (r = 0; r <= dl_row; r++) {
                grid[height - 1 - r, col] = "▓"
            }
        }

        # UL throughput bar (░) — only where DL not already drawn
        if ((ts in ts_ul) && ts_ul[ts] > 0) {
            ul_row = int((ts_ul[ts] / max_throughput) * (height - 1))
            if (ul_row >= height) ul_row = height - 1
            for (r = 0; r <= ul_row; r++) {
                if (grid[height - 1 - r, col] == " ")
                    grid[height - 1 - r, col] = "░"
            }
        }

        # RTT marker (●) at the row corresponding to RTT value
        if ((ts in ts_rtt) && ts_rtt[ts] > 0) {
            rtt_row = int((ts_rtt[ts] / max_rtt_val) * (height - 1))
            if (rtt_row >= height) rtt_row = height - 1
            grid[height - 1 - rtt_row, col] = "●"
        }

        # Autorate egress line (─) if available
        if (n_ar > 0 && max_rate > 0 && (ts in ts_ar_eg)) {
            eg_row = int((ts_ar_eg[ts] / max_rate) * (height - 1) * (max_rate / max_throughput))
            if (eg_row >= 0 && eg_row < height) {
                cur = grid[height - 1 - eg_row, col]
                if (cur == " " || cur == "░")
                    grid[height - 1 - eg_row, col] = "─"
            }
        }
    }

    # Render chart with Y-axis
    for (row = 0; row < height; row++) {
        # Left Y-axis (throughput)
        tp_val = max_throughput * (height - 1 - row) / (height - 1)
        printf "%6.1f│ ", tp_val

        # Chart body
        for (col = 0; col < plot_w; col++) {
            printf "%s", grid[row, col]
        }

        # Right Y-axis (RTT)
        rtt_y = max_rtt_val * (height - 1 - row) / (height - 1)
        printf " │%5.0f", rtt_y
        print ""
    }

    # X-axis
    printf "%6s└─", ""
    for (col = 0; col < plot_w; col++) printf "─"
    printf "─┘\n"

    # X-axis labels (time)
    printf "%8s", ""
    marks = 5
    for (m = 0; m < marks; m++) {
        pos = int(m * plot_w / (marks - 1))
        idx = int(pos * step) + 1
        if (idx > total) idx = total
        if (idx < 1) idx = 1
        ts = all_ts[idx]
        if (ts == "") ts = sprintf("%ds", idx)
        # Pad to position
        if (m == 0) printf "%-*s", int(plot_w / marks), ts
        else if (m == marks - 1) printf "%*s", int(plot_w / marks), ts
        else printf "%-*s", int(plot_w / marks), ts
    }
    print ""

    # Legend
    print ""
    printf "  Legend: ▓ DL Mbps   ░ UL Mbps   ● RTT (ms)"
    if (n_ar > 0) printf "   ─ Egress Rate Limit"
    print ""

    # ─── Autorate chart (if data exists) ───
    if (n_ar > 0) {
        print ""
        print "════════════════════════════════════════════════════════════════════════════════"
        print "             ASCII CHART: Autorate Adjustment"
        print "════════════════════════════════════════════════════════════════════════════════"
        printf "  Egress (E) and Ingress (I) rate limits over time.\n"
        printf "  Range: 0-%d mbit   Direction: ▲=increase ▼=decrease .=stable\n\n", int(max_rate + 0.5)

        ar_height = int(height * 0.6)
        if (ar_height < 8) ar_height = 8

        # Build autorate chart
        for (row = 0; row < ar_height; row++) {
            for (col = 0; col < plot_w; col++) {
                ar_grid[row, col] = " "
            }
        }

        ar_step = 1
        if (n_ar > plot_w) ar_step = n_ar / plot_w

        for (col = 0; col < plot_w; col++) {
            idx = int(col * ar_step) + 1
            if (idx > n_ar) idx = n_ar

            # Egress (E)
            eg_r = int((ar_egress[idx] / max_rate) * (ar_height - 1))
            if (eg_r >= ar_height) eg_r = ar_height - 1
            if (eg_r >= 0) ar_grid[ar_height - 1 - eg_r, col] = "E"

            # Ingress (I)
            in_r = int((ar_ingress[idx] / max_rate) * (ar_height - 1))
            if (in_r >= ar_height) in_r = ar_height - 1
            if (in_r >= 0) {
                if (ar_grid[ar_height - 1 - in_r, col] == "E")
                    ar_grid[ar_height - 1 - in_r, col] = "X"  # overlap
                else
                    ar_grid[ar_height - 1 - in_r, col] = "I"
            }
        }

        # Render autorate chart
        for (row = 0; row < ar_height; row++) {
            rate_val = max_rate * (ar_height - 1 - row) / (ar_height - 1)
            printf "%5d │ ", int(rate_val)
            for (col = 0; col < plot_w; col++) printf "%s", ar_grid[row, col]
            print ""
        }
        printf "%5s └─", ""
        for (col = 0; col < plot_w; col++) printf "─"
        print ""

        # Direction timeline
        printf "%8s", ""
        for (col = 0; col < plot_w; col++) {
            idx = int(col * ar_step) + 1
            if (idx > n_ar) idx = n_ar
            d = ar_dir[idx]
            if (d == "▲" || d == "▼") printf "%s", d
            else printf "."
        }
        print "  ← Direction (▲ up ▼ down . stable)"

        print ""
        printf "  Legend: E=Egress rate  I=Ingress rate  X=Overlap  ▲▼.=Direction\n"
    }

    print ""
}' /dev/null

echo ""
echo "Chart source files:"
[ -f "$RTT_LOG" ] && echo "  RTT:      $RTT_LOG ($(wc -l < "$RTT_LOG") lines)"
[ -f "$DL_LOG" ] && echo "  DL iperf: $DL_LOG"
[ -f "$UL_LOG" ] && echo "  UL iperf: $UL_LOG"
[ -f "$AR_LOG" ] && echo "  Autorate: $AR_LOG ($(wc -l < "$AR_LOG") lines)"
