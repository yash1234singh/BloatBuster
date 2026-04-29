#!/bin/bash
# tc.sh — Buffer Bloat Killer
# Rate-shape below bottleneck speed so queuing happens at YOUR smart qdisc
# instead of at the upstream router's dumb FIFO.

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
PROFILE=".profiles.$ACTIVE_PROFILE.manager"

# --- Device & profile settings ---
IFB_DEVICE=$(jq -r '.ifb_device' "$CONFIG_FILE")
INTERFACE=$(jq -r "$PROFILE.interface" "$CONFIG_FILE")
MODE=$(jq -r "$PROFILE.mode" "$CONFIG_FILE")
EGRESS_RATE=$(jq -r "$PROFILE.egress_rate" "$CONFIG_FILE")
INGRESS_RATE=$(jq -r "$PROFILE.ingress_rate" "$CONFIG_FILE")
MAX_EGRESS=$(jq -r "$PROFILE.max_egress" "$CONFIG_FILE")
MAX_INGRESS=$(jq -r "$PROFILE.max_ingress" "$CONFIG_FILE")
MIN_EGRESS_PCT=$(jq -r "$PROFILE.min_egress_pct" "$CONFIG_FILE")
MIN_INGRESS_PCT=$(jq -r "$PROFILE.min_ingress_pct" "$CONFIG_FILE")
BASELINE_RTT=$(jq -r "$PROFILE.baseline_rtt" "$CONFIG_FILE")
MAX_RTT=$(jq -r "$PROFILE.max_rtt" "$CONFIG_FILE")
AUTORATE_TARGET=$(jq -r "$PROFILE.autorate_target" "$CONFIG_FILE")
AUTORATE_INTERVAL=$(jq -r "$PROFILE.autorate_interval" "$CONFIG_FILE")
DAMPEN_PCT=$(jq -r "$PROFILE.dampen_pct" "$CONFIG_FILE")

# --- fq_codel params ---
TARGET=$(jq -r '.fq_codel.target' "$CONFIG_FILE")
INTERVAL=$(jq -r '.fq_codel.interval' "$CONFIG_FILE")
LIMIT=$(jq -r '.fq_codel.limit' "$CONFIG_FILE")
FLOWS=$(jq -r '.fq_codel.flows' "$CONFIG_FILE")
QUANTUM=$(jq -r '.fq_codel.quantum' "$CONFIG_FILE")
MEM_LIMIT=$(jq -r '.fq_codel.mem_limit' "$CONFIG_FILE")

# --- CAKE params ---
CAKE_RTT=$(jq -r '.cake.rtt' "$CONFIG_FILE")
CAKE_OVERHEAD=$(jq -r '.cake.overhead' "$CONFIG_FILE")
CAKE_MPU=$(jq -r '.cake.mpu' "$CONFIG_FILE")
CAKE_DIFFSERV=$(jq -r '.cake.diffserv' "$CONFIG_FILE")

# --- Colors ---
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; N='\033[0m'

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

show_sysctl() {
    echo -e "\n${B}[TCP]${N}"
    sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_ecn 2>/dev/null
}

# Parse CAKE/qdisc stats into one-line summary: sent/dropped/overlimits/backlog
_qdisc_summary() {
    local dev=$1 label=$2
    local stats=$(tc -s qdisc show dev $dev 2>/dev/null)
    [ -z "$stats" ] && return
    local line1=$(echo "$stats" | head -1)
    local sent=$(echo "$stats" | grep -oP 'Sent \K[0-9]+ bytes [0-9]+ pkt')
    local dropped=$(echo "$stats" | grep -oP 'dropped \K[0-9]+')
    local overlimits=$(echo "$stats" | grep -oP 'overlimits \K[0-9]+')
    local backlog=$(echo "$stats" | grep -oP 'backlog \K\S+')
    local marks=$(echo "$stats" | awk '/marks/{for(i=1;i<=NF;i++) if($i=="marks") total+=$(i+1)} END{print total+0}')
    # Extract qdisc type and bandwidth
    local qtype=$(echo "$line1" | awk '{print $2}')
    local bw=$(echo "$line1" | grep -oP 'bandwidth \K\S+')
    [ -n "$bw" ] && qtype="$qtype@$bw"
    printf "  %-8s %-16s  sent:%-22s  drop:%-6s  overlim:%-8s  ecn:%-6s  backlog:%s\n" \
        "$label" "$qtype" "$sent" "$dropped" "$overlimits" "$marks" "$backlog"
}

show_status() {
    echo -e "\n${B}[QDISC Summary]${N}"
    _qdisc_summary $INTERFACE "egress"
    if ip link show $IFB_DEVICE &>/dev/null 2>&1; then
        local q=$(tc qdisc show dev $IFB_DEVICE 2>/dev/null | head -1)
        [ -n "$q" ] && _qdisc_summary $IFB_DEVICE "ingress"
    fi
}

detect_qdisc() {
    tc qdisc show dev $INTERFACE 2>/dev/null | head -1
}

# ══════════════════════════════════════════════════════════════════════════════
# RATE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

# Parse "Xmbit" → integer Mbps
_parse_mbit() { echo "$1" | grep -oP '^[0-9]+'; }

# Ensure rates are set (static mode uses config values directly)
_ensure_rates() {
    [ -n "$EGRESS_RATE" ] && [ -n "$INGRESS_RATE" ] && return
    echo -e "${R}ERROR: EGRESS_RATE or INGRESS_RATE not set.${N}"
    echo "  In static mode, set both in the config section."
    exit 1
}

# Ensure rates for strategy apply (adaptive starts at MAX, static uses defined rates)
_ensure_rates_for_strategy() {
    if [ "$MODE" = "adaptive" ]; then
        EGRESS_RATE="$MAX_EGRESS"
        INGRESS_RATE="$MAX_INGRESS"
        echo -e "${C}[Adaptive]${N} Starting at MAX rates (autorate will adjust live)"
    else
        _ensure_rates
    fi
}

# Get default gateway IP
_get_gateway() {
    if [ -n "$AUTORATE_TARGET" ]; then
        echo "$AUTORATE_TARGET"
    else
        ip route show default 2>/dev/null | awk '/default/{print $3; exit}'
    fi
}

# Measure median RTT in ms (integer)
# Uses awk parsing for portability (no grep -oP dependency)
_measure_rtt_ms() {
    local target=$1 count=${2:-3}
    local output=$(ping -c "$count" -W 2 "$target" 2>&1)
    local rtts=$(echo "$output" \
        | awk -F'[= ]' '/time=/{for(i=1;i<=NF;i++) if($i=="time") {printf "%d\n", $(i+1)+0.5; break}}' \
        | sort -n)
    [ -z "$rtts" ] && return 1
    local n=$(echo "$rtts" | wc -l)
    local mid=$(( (n + 1) / 2 ))
    echo "$rtts" | sed -n "${mid}p"
}

# Debug: show raw ping output for troubleshooting
_probe_debug() {
    local target=$1
    echo -e "${B}[Probe Debug]${N} Target: $target"
    echo -e "${C}Raw ping output:${N}"
    ping -c 3 -W 2 "$target" 2>&1
    echo ""
    local rtt=$(_measure_rtt_ms "$target" 3)
    if [ -n "$rtt" ]; then
        echo -e "${G}Parsed median RTT: ${rtt}ms${N}"
    else
        echo -e "${R}Failed to parse RTT from ping output.${N}"
        echo "  Possible causes:"
        echo "    - Target blocks ICMP (try a different AUTORATE_TARGET)"
        echo "    - No route to host"
        echo "    - Firewall dropping packets"
        echo ""
        echo "  Try: AUTORATE_TARGET=8.8.8.8 or AUTORATE_TARGET=1.1.1.1"
    fi
}

# Live-adjust CAKE bandwidth without traffic disruption
_adjust_cake_rate() {
    local dev=$1 new_rate=$2 direction=${3:-egress}
    if [ "$direction" = "ingress" ]; then
        tc qdisc change dev "$dev" root cake \
            bandwidth "$new_rate" besteffort rtt $CAKE_RTT noatm nat wash ingress 2>/dev/null
    else
        tc qdisc change dev "$dev" root cake \
            bandwidth "$new_rate" $CAKE_DIFFSERV rtt $CAKE_RTT noatm nat wash 2>/dev/null
    fi
}

# Map RTT (ms) linearly to a rate between max and min
# rtt <= BASELINE_RTT → max rate
# rtt >= MAX_RTT      → min rate
# in between          → linear interpolation
_rtt_to_rate() {
    local rtt=$1 max_rate=$2 min_rate=$3
    if [ "$rtt" -le "$BASELINE_RTT" ]; then
        echo "$max_rate"
    elif [ "$rtt" -ge "$MAX_RTT" ]; then
        echo "$min_rate"
    else
        # Linear: rate = max - (max-min) * (rtt-baseline) / (max_rtt-baseline)
        local range_rtt=$(( MAX_RTT - BASELINE_RTT ))
        local range_rate=$(( max_rate - min_rate ))
        local excess=$(( rtt - BASELINE_RTT ))
        local rate=$(( max_rate - (range_rate * excess / range_rtt) ))
        echo "$rate"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE — RTT-based shaping (MODE=adaptive)
# ══════════════════════════════════════════════════════════════════════════════

# One-shot: measure RTT, compute rates, apply CAKE, done.
adapt() {
    if [ "$MODE" != "adaptive" ]; then
        echo -e "${R}adapt requires MODE=adaptive (current: $MODE)${N}"
        return 1
    fi

    local gw=$(_get_gateway)
    [ -z "$gw" ] && { echo -e "${R}Cannot detect gateway. Set AUTORATE_TARGET.${N}"; return 1; }

    local max_eg=$(_parse_mbit "$MAX_EGRESS")
    local max_in=$(_parse_mbit "$MAX_INGRESS")
    local min_eg=$(( max_eg * MIN_EGRESS_PCT / 100 ))
    local min_in=$(( max_in * MIN_INGRESS_PCT / 100 ))
    [ "$min_eg" -lt 1 ] && min_eg=1
    [ "$min_in" -lt 1 ] && min_in=1

    echo -e "${B}[Adapt]${N} Measuring RTT to $gw (5 probes)..."
    local rtt=$(_measure_rtt_ms "$gw" 5)
    if [ -z "$rtt" ]; then
        echo -e "${R}Ping to $gw failed. Run '$0 probe' to debug.${N}"
        echo -e "${Y}Falling back to MAX rates.${N}"
        EGRESS_RATE="$MAX_EGRESS"
        INGRESS_RATE="$MAX_INGRESS"
    else
        local eg=$(_rtt_to_rate "$rtt" "$max_eg" "$min_eg")
        local ing=$(_rtt_to_rate "$rtt" "$max_in" "$min_in")
        EGRESS_RATE="${eg}mbit"
        INGRESS_RATE="${ing}mbit"
        echo -e "${G}RTT: ${rtt}ms → egress=${EGRESS_RATE} ingress=${INGRESS_RATE}${N}"
        echo "  (baseline=${BASELINE_RTT}ms→MAX, max=${MAX_RTT}ms→floor)"
    fi
}

# Continuous loop: re-measures and adjusts CAKE bandwidth every interval.
autorate() {
    if [ "$MODE" != "adaptive" ]; then
        echo -e "${R}Autorate requires MODE=adaptive (current: $MODE)${N}"
        return 1
    fi

    local gw=$(_get_gateway)
    [ -z "$gw" ] && { echo -e "${R}Cannot detect gateway. Set AUTORATE_TARGET.${N}"; return 1; }

    local max_eg=$(_parse_mbit "$MAX_EGRESS")
    local max_in=$(_parse_mbit "$MAX_INGRESS")
    local min_eg=$(( max_eg * MIN_EGRESS_PCT / 100 ))
    local min_in=$(( max_in * MIN_INGRESS_PCT / 100 ))
    [ "$min_eg" -lt 1 ] && min_eg=1
    [ "$min_in" -lt 1 ] && min_in=1

    # Start at MAX rates
    EGRESS_RATE="${max_eg}mbit"
    INGRESS_RATE="${max_in}mbit"

    echo -e "${B}[Autorate]${N} Probing $gw  baseline=${BASELINE_RTT}ms  max=${MAX_RTT}ms  dampen=${DAMPEN_PCT}%"
    echo -e "  Egress:  ${min_eg}-${max_eg}mbit"
    echo -e "  Ingress: ${min_in}-${max_in}mbit"
    echo -e "  Probe every ${AUTORATE_INTERVAL}s — Ctrl+C to stop\n"

    local cur_eg=$max_eg cur_in=$max_in

    trap 'echo -e "\n${G}Autorate stopped. Current: egress=${cur_eg}mbit ingress=${cur_in}mbit${N}"; return 0' INT

    while true; do
        local rtt=$(_measure_rtt_ms "$gw" 3)
        if [ -z "$rtt" ]; then
            printf "  RTT: ----ms  .  egress: %dmbit  ingress: %dmbit  (probe failed)\n" "$cur_eg" "$cur_in"
            sleep "$AUTORATE_INTERVAL"
            continue
        fi

        local target_eg=$(_rtt_to_rate "$rtt" "$max_eg" "$min_eg")
        local target_in=$(_rtt_to_rate "$rtt" "$max_in" "$min_in")

        # Dampen: cap change per step to DAMPEN_PCT% of current rate
        local max_step_eg=$(( cur_eg * DAMPEN_PCT / 100 ))
        local max_step_in=$(( cur_in * DAMPEN_PCT / 100 ))
        [ "$max_step_eg" -lt 1 ] && max_step_eg=1
        [ "$max_step_in" -lt 1 ] && max_step_in=1

        local new_eg=$target_eg new_in=$target_in
        local diff_eg=$(( target_eg - cur_eg ))
        local diff_in=$(( target_in - cur_in ))
        # Clamp egress
        if [ "$diff_eg" -gt "$max_step_eg" ]; then
            new_eg=$(( cur_eg + max_step_eg ))
        elif [ "$diff_eg" -lt "-$max_step_eg" ]; then
            new_eg=$(( cur_eg - max_step_eg ))
        fi
        # Clamp ingress
        if [ "$diff_in" -gt "$max_step_in" ]; then
            new_in=$(( cur_in + max_step_in ))
        elif [ "$diff_in" -lt "-$max_step_in" ]; then
            new_in=$(( cur_in - max_step_in ))
        fi
        # Enforce bounds
        [ "$new_eg" -gt "$max_eg" ] && new_eg=$max_eg
        [ "$new_eg" -lt "$min_eg" ] && new_eg=$min_eg
        [ "$new_in" -gt "$max_in" ] && new_in=$max_in
        [ "$new_in" -lt "$min_in" ] && new_in=$min_in

        local changed=""

        if [ "$new_eg" -ne "$cur_eg" ] || [ "$new_in" -ne "$cur_in" ]; then
            local delta_eg=$(( new_eg - cur_eg ))
            local delta_in=$(( new_in - cur_in ))
            if [ "$new_eg" -lt "$cur_eg" ] || [ "$new_in" -lt "$cur_in" ]; then
                changed="▼"
            else
                changed="▲"
            fi
            printf "  %s ADJUSTED  egress: %d→%dmbit (%+dmbit)  ingress: %d→%dmbit (%+dmbit)\n" \
                "$changed" "$cur_eg" "$new_eg" "$delta_eg" "$cur_in" "$new_in" "$delta_in"
            cur_eg=$new_eg
            cur_in=$new_in
            _adjust_cake_rate "$INTERFACE" "${cur_eg}mbit" "egress"
            if ip link show "$IFB_DEVICE" &>/dev/null 2>&1; then
                _adjust_cake_rate "$IFB_DEVICE" "${cur_in}mbit" "ingress"
            fi
        fi

        printf "  RTT: %4dms  %s  egress: %dmbit  ingress: %dmbit\n" \
            "$rtt" "${changed:-.}" "$cur_eg" "$cur_in"
        sleep "$AUTORATE_INTERVAL"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIES
# ══════════════════════════════════════════════════════════════════════════════

apply_fq_codel() {
    echo -e "${Y}[fq_codel] No rate shaping — only works if bottleneck is AT your NIC${N}"
    tc qdisc replace dev $INTERFACE root fq_codel \
        limit $LIMIT flows $FLOWS target $TARGET \
        interval $INTERVAL quantum $QUANTUM memory_limit $MEM_LIMIT
}

apply_htb_fq_codel() {
    _ensure_rates_for_strategy
    echo -e "${G}[HTB + fq_codel] Egress: $EGRESS_RATE${N}"
    tc qdisc del dev $INTERFACE root 2>/dev/null
    tc qdisc add dev $INTERFACE root handle 1: htb default 10
    tc class add dev $INTERFACE parent 1: classid 1:10 htb \
        rate $EGRESS_RATE burst 15k cburst 15k
    tc qdisc add dev $INTERFACE parent 1:10 handle 10: fq_codel \
        limit $LIMIT flows $FLOWS target $TARGET \
        interval $INTERVAL quantum $QUANTUM memory_limit $MEM_LIMIT
}

apply_cake() {
    _ensure_rates_for_strategy
    echo -e "${G}[CAKE] Egress: $EGRESS_RATE${N}"
    if ! modprobe sch_cake 2>/dev/null; then
        echo -e "${R}CAKE module not found, falling back to HTB + fq_codel${N}"
        apply_htb_fq_codel; return
    fi
    tc qdisc del dev $INTERFACE root 2>/dev/null
    local cmd="tc qdisc add dev $INTERFACE root cake bandwidth $EGRESS_RATE"
    cmd="$cmd $CAKE_DIFFSERV rtt $CAKE_RTT noatm"
    [ "$CAKE_OVERHEAD" != "0" ] && cmd="$cmd overhead $CAKE_OVERHEAD"
    [ "$CAKE_MPU" != "0" ] && cmd="$cmd mpu $CAKE_MPU"
    cmd="$cmd nat wash"
    eval $cmd
}

apply_cake_bidir() {
    _ensure_rates_for_strategy
    echo -e "${G}[CAKE bidir] Egress: $EGRESS_RATE  Ingress: $INGRESS_RATE${N}"
    if ! modprobe sch_cake 2>/dev/null; then
        echo -e "${R}CAKE module not found, falling back to HTB + fq_codel${N}"
        apply_htb_fq_codel; return
    fi
    # Egress
    tc qdisc del dev $INTERFACE root 2>/dev/null
    tc qdisc add dev $INTERFACE root cake \
        bandwidth $EGRESS_RATE $CAKE_DIFFSERV rtt $CAKE_RTT noatm nat wash
    # Ingress via IFB
    modprobe ifb 2>/dev/null
    ip link set dev $IFB_DEVICE up 2>/dev/null || {
        ip link add $IFB_DEVICE type ifb; ip link set dev $IFB_DEVICE up; }
    tc qdisc del dev $INTERFACE ingress 2>/dev/null
    tc qdisc add dev $INTERFACE handle ffff: ingress
    tc filter add dev $INTERFACE parent ffff: protocol all \
        u32 match u32 0 0 action mirred egress redirect dev $IFB_DEVICE
    tc qdisc del dev $IFB_DEVICE root 2>/dev/null
    tc qdisc add dev $IFB_DEVICE root cake \
        bandwidth $INGRESS_RATE besteffort rtt $CAKE_RTT noatm nat wash ingress
}

apply_fq_codel_aggressive() {
    echo -e "${Y}[Aggressive fq_codel] Tight limits, no shaping${N}"
    tc qdisc replace dev $INTERFACE root fq_codel \
        limit 256 flows 1024 target 1ms interval 50ms quantum 300 \
        memory_limit 8Mb ecn
}

# ══════════════════════════════════════════════════════════════════════════════
# TCP TUNING
# ══════════════════════════════════════════════════════════════════════════════

apply_tcp_tuning() {
    echo -e "\n${B}TCP STACK TUNING${N}"

    # BBR
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if modprobe tcp_bbr 2>/dev/null; then
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
        echo -e "  congestion: ${G}bbr${N} (was: $cc) — model-based, doesn't fill buffers"
    else
        echo -e "  congestion: ${Y}$cc (BBR unavailable, kernel < 4.9)${N}"
    fi

    # ECN
    sysctl -w net.ipv4.tcp_ecn=1 >/dev/null 2>&1
    echo -e "  ecn: ${G}1${N} — CAKE marks instead of drops, faster signaling"

    # Buffer sizes — rmem controls TCP receive window (limits how fast SENDER pushes)
    # For download bloat: smaller rmem = smaller rwnd = server sends slower
    # BDP for 5mbit @ 50ms RTT = ~31KB. Set max to 256KB (8x BDP headroom).
    local wmem_old=$(sysctl -n net.ipv4.tcp_wmem | awk '{print $3}')
    local rmem_old=$(sysctl -n net.ipv4.tcp_rmem | awk '{print $3}')
    sysctl -w net.ipv4.tcp_wmem="4096 32768 524288" >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_rmem="4096 32768 262144" >/dev/null 2>&1
    echo "  wmem max: 512KB (was: $wmem_old) — limits upload in-flight"
    echo "  rmem max: 256KB (was: $rmem_old) — limits download rwnd (KEY for bloat)"

    # Timestamps + slow start
    sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1
    echo "  timestamps: on (BBR needs this)"
    echo "  slow_start_after_idle: off (prevents burst bloat)"

    echo -e "\n${Y}Runtime only — add to /etc/sysctl.conf to persist${N}"
}

revert_tcp_tuning() {
    echo -e "${B}Reverting TCP tuning...${N}"
    sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_ecn=2 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_wmem="4096 131072 6291456" >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_rmem="4096 131072 6291456" >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_slow_start_after_idle=1 >/dev/null 2>&1
    echo -e "${G}Reverted: cubic, ecn=2, default buffers${N}"
}

# ══════════════════════════════════════════════════════════════════════════════
# COUNTERS
# ══════════════════════════════════════════════════════════════════════════════

read_counters() {
    echo -e "\n${B}QDISC COUNTERS — $INTERFACE${N}"
    echo -e "\n${C}[Egress]${N}"
    tc -s -d qdisc show dev $INTERFACE 2>/dev/null
    tc -s -d class show dev $INTERFACE 2>/dev/null
    tc -s filter show dev $INTERFACE 2>/dev/null

    if ip link show $IFB_DEVICE &>/dev/null; then
        echo -e "\n${C}[Ingress IFB ($IFB_DEVICE)]${N}"
        tc -s -d qdisc show dev $IFB_DEVICE 2>/dev/null
    fi

    echo -e "\n${C}[Ingress on $INTERFACE]${N}"
    tc -s qdisc show dev $INTERFACE ingress 2>/dev/null

    echo -e "\n${C}[Counter Reference]${N}"
    cat <<'EOF'
  Sent        Bytes/pkts dequeued and sent
  dropped     Pkts dropped by AQM (good if moderate)
  overlimits  Shaper delayed pkts (token exhaustion)
  requeues    Pkts returned to queue (driver busy)
  backlog     Pkts in queue RIGHT NOW
  ecn_mark    Pkts marked ECN (efficient congestion signal)
  way_miss    New flow hashes (CAKE)
  drops/marks Per-tin drop/ECN counts (CAKE)
EOF
}

clear_counters() {
    _ensure_rates_for_strategy
    echo -e "${B}Resetting counters...${N}"
    # tc has no "reset counters" — must del + add to zero stats
    local q=$(detect_qdisc)
    if echo "$q" | grep -q "cake"; then
        local bw=$(echo "$q" | grep -oP 'bandwidth \S+' | awk '{print $2}')
        [ -z "$bw" ] && bw=$EGRESS_RATE
        tc qdisc del dev $INTERFACE root 2>/dev/null
        tc qdisc add dev $INTERFACE root cake \
            bandwidth $bw $CAKE_DIFFSERV rtt $CAKE_RTT noatm nat wash
    elif echo "$q" | grep -q "htb"; then
        apply_htb_fq_codel
    elif echo "$q" | grep -q "fq_codel"; then
        tc qdisc del dev $INTERFACE root 2>/dev/null
        tc qdisc add dev $INTERFACE root fq_codel \
            limit $LIMIT flows $FLOWS target $TARGET \
            interval $INTERVAL quantum $QUANTUM memory_limit $MEM_LIMIT
    else
        echo -e "${Y}Unknown qdisc, cannot auto-reset${N}"; return 1
    fi
    # Reset IFB ingress CAKE
    if ip link show $IFB_DEVICE &>/dev/null 2>&1; then
        local iq=$(tc qdisc show dev $IFB_DEVICE 2>/dev/null | head -1)
        if echo "$iq" | grep -q "cake"; then
            tc qdisc del dev $IFB_DEVICE root 2>/dev/null
            tc qdisc add dev $IFB_DEVICE root cake \
                bandwidth $INGRESS_RATE besteffort rtt $CAKE_RTT noatm nat wash ingress
        fi
    fi
    # Reset ingress qdisc + filter on main interface (if bidir was active)
    if tc qdisc show dev $INTERFACE 2>/dev/null | grep -q "ingress"; then
        tc qdisc del dev $INTERFACE ingress 2>/dev/null
        tc qdisc add dev $INTERFACE handle ffff: ingress
        tc filter add dev $INTERFACE parent ffff: protocol all \
            u32 match u32 0 0 action mirred egress redirect dev $IFB_DEVICE
    fi
    echo -e "${G}Done. Run '$0 counters' to verify.${N}"
}

# ══════════════════════════════════════════════════════════════════════════════
# DIAGNOSE — shows diagram of ACTIVE strategy
# ══════════════════════════════════════════════════════════════════════════════

diagnose() {
    _ensure_rates_for_strategy
    echo -e "\n${B}═══ DIAGNOSIS ═══${N}"

    # Interface
    local speed=$(ethtool $INTERFACE 2>/dev/null | grep 'Speed:' | awk '{print $2}')
    [ -z "$speed" ] && speed="unknown"
    echo -e "\n${C}[Interface]${N}  $INTERFACE: $speed (physical, not bottleneck)"

    # Active qdisc
    local q=$(detect_qdisc)
    echo -e "\n${C}[Active Qdisc]${N}"
    echo "  $q"
    if ip link show $IFB_DEVICE &>/dev/null 2>&1; then
        local iq=$(tc qdisc show dev $IFB_DEVICE 2>/dev/null | head -1)
        [ -n "$iq" ] && echo "  IFB: $iq"
    fi

    # TCP stack
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local ecn=$(sysctl -n net.ipv4.tcp_ecn 2>/dev/null)
    local wmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}')
    echo -e "\n${C}[TCP Stack]${N}"
    echo "  congestion: $cc  ecn: $ecn  wmem_max: $wmem"
    [ "$cc" != "bbr" ] && echo -e "  ${Y}^ Run '$0 tune' to switch to BBR + ECN${N}"

    # Show diagram for ACTIVE strategy
    echo -e "\n${C}[Active Strategy Diagram]${N}"

    if echo "$q" | grep -q "cake"; then
        local bw=$(echo "$q" | grep -oP 'bandwidth \S+' | awk '{print $2}')
        if ip link show $IFB_DEVICE &>/dev/null 2>&1 && \
           tc qdisc show dev $IFB_DEVICE 2>/dev/null | grep -q "cake"; then
            local ibw=$(tc qdisc show dev $IFB_DEVICE 2>/dev/null | grep -oP 'bandwidth \S+' | awk '{print $2}')
            cat <<EOF

  CAKE Bidirectional (active)

  EGRESS (upload shaping):
    App ──► [CAKE @ $bw] ──► wire ──► gateway
             ├─ Shaper (token bucket)
             ├─ Diffserv tins (Voice > Video > Best Effort > Bulk)
             ├─ Per-flow FQ + COBALT AQM
             └─ Drops/ECN if sojourn > target

  INGRESS (download shaping):
    wire ──► [ingress qdisc] ──► redirect ──► [IFB0: CAKE @ $ibw] ──► App
                                               ├─ Shapes download traffic
                                               └─ Drops excess → TCP backs off

EOF
        else
            cat <<EOF

  CAKE Egress Only (active)

    App ──► [CAKE @ $bw] ──► wire ──► gateway
             ├─ Shaper (token bucket at $bw)
             ├─ Diffserv tins (Voice > Video > Best Effort > Bulk)
             ├─ Per-flow FQ + COBALT AQM (CoDel + BLUE)
             └─► out to NIC

    No ingress shaping. Download bloat not controlled.
    Consider: $0 cake-bidir

EOF
        fi
    elif echo "$q" | grep -q "htb"; then
        cat <<EOF

  HTB + fq_codel (active)

    App ──► [HTB root: default class 1:10]
                    │
                    ▼
            [HTB class @ $EGRESS_RATE]  ◄── rate shaper
                    │
                    ▼
            [fq_codel leaf]             ◄── per-flow AQM
             ├─ 1024 flow buckets
             ├─ CoDel drops if sojourn > $TARGET
             └─ DRR fair dequeue
                    │
                    ▼
               Out to NIC

EOF
    elif echo "$q" | grep -q "fq_codel"; then
        cat <<EOF

  fq_codel Only (active) — NO RATE SHAPING

    App ──► [fq_codel @ NIC speed] ──► wire ──► [Gateway FIFO: BLOATS]
             │                                    ▲▲▲ problem here
             ├─ 1024 flow buckets + CoDel AQM
             └─ BUT: no rate limit = pkts leave instantly
                     gateway buffers the excess

    This WON'T fix bloat if bottleneck is downstream.
    Use: $0 cake-bidir

EOF
    else
        cat <<EOF

  Default pfifo_fast (active) — WORST FOR BLOAT

    App ──► [pfifo_fast: 3 FIFO bands] ──► wire
             No AQM, no flow isolation, no shaping

    Use: $0 cake-bidir

EOF
    fi

    # Rate guidance
    echo -e "${C}[Rate Config — MODE=$MODE]${N}"
    if [ "$MODE" = "adaptive" ]; then
        echo "  MAX_EGRESS   = $MAX_EGRESS"
        echo "  MAX_INGRESS  = $MAX_INGRESS"
        echo "  BASELINE_RTT = ${BASELINE_RTT}ms"
        echo "  MAX_RTT      = ${MAX_RTT}ms"
        echo "  EGRESS_RATE  = $EGRESS_RATE (initial, autorate adjusts live)"
        echo "  INGRESS_RATE = $INGRESS_RATE (initial, autorate adjusts live)"
        echo ""
        echo "  Run '$0 autorate' for continuous RTT-based adaptation."
    else
        echo "  EGRESS_RATE  = $EGRESS_RATE (static)"
        echo "  INGRESS_RATE = $INGRESS_RATE (static)"
        echo ""
        echo "  Switch to adaptive: set MODE=adaptive in config."
    fi

    # Command reference
    local min_eg_val=$(( $(_parse_mbit "$MAX_EGRESS") * MIN_EGRESS_PCT / 100 ))
    local min_in_val=$(( $(_parse_mbit "$MAX_INGRESS") * MIN_INGRESS_PCT / 100 ))
    [ "$min_eg_val" -lt 1 ] && min_eg_val=1
    [ "$min_in_val" -lt 1 ] && min_in_val=1

    echo -e "\n${C}[Command Reference]${N}"
    cat <<EOF

  ── cake-bidir ──────────────────────────────────────────────────────
  Apply CAKE qdisc on egress ($INTERFACE) + ingress (IFB redirect).
  Uses EGRESS_RATE/INGRESS_RATE directly (static) or MAX rates (adaptive).
    1. Delete existing qdiscs
    2. Add CAKE on $INTERFACE (egress shaping)
    3. Create IFB device, redirect ingress traffic
    4. Add CAKE on $IFB_DEVICE (ingress shaping)
  Rates are FIXED after apply. No ongoing adjustment.

  ── adapt (one-shot, adaptive only) ─────────────────────────────────
  Measure RTT once, compute rates, apply CAKE. Done.
    1. Ping ${AUTORATE_TARGET:-(gateway)} x5 → median RTT
    2. Map RTT to rates via linear interpolation:
       RTT <=${BASELINE_RTT}ms → MAX (${MAX_EGRESS}/${MAX_INGRESS})
       RTT >=${MAX_RTT}ms  → floor (${min_eg_val}mbit/${min_in_val}mbit)
    3. Apply cake-bidir with computed rates
    4. Exit. Rates stay FIXED until next run.
  Good for: cron jobs, stable-ish links, set-and-forget.

  ── autorate (continuous loop, adaptive only) ───────────────────────
  Start CAKE at MAX rates, then continuously adjust via RTT probing.
  Dampened: each step limited to ${DAMPEN_PCT}% of current rate (no bang-bang).
    1. Apply cake-bidir at MAX (${MAX_EGRESS}/${MAX_INGRESS})
    2. Loop every ${AUTORATE_INTERVAL}s:
       a. Ping ${AUTORATE_TARGET:-(gateway)} x3 → median RTT
       b. Map RTT → target rate (same linear formula as adapt)
       c. Clamp change to ±${DAMPEN_PCT}% of current rate per step
          Example at 10mbit: max step = ±$(( 10 * DAMPEN_PCT / 100 ))mbit per cycle
       d. If rate changed: tc qdisc change (live, no disruption)
       e. Log: ▼/▲ ADJUSTED egress: old→new (+Xmbit) ingress: old→new
    3. Ctrl+C to stop (rates stay at last value)
  Good for: fluctuating WiFi, mobile, congested links.
  Tune DAMPEN_PCT: lower = smoother/slower, higher = more responsive.

  ── adapt vs cake-bidir + autorate ──────────────────────────────────
    adapt         = measure once → apply once → exit (rates frozen)
    cake-bidir    = apply CAKE at MAX → exit (rates frozen at MAX)
    autorate      = loop forever → re-probe → adjust live

    adapt alone:  snapshot of current conditions, quick and done.
    bidir + auto: start at MAX, then track conditions in real-time.

  ── tune / untune ───────────────────────────────────────────────────
  tune:   BBR congestion control + ECN + reduced TCP buffers.
  untune: Revert to cubic + default buffers.
  Runtime only — does not persist across reboot.

  ── probe ───────────────────────────────────────────────────────────
  Debug: raw ping output + parsed RTT to verify AUTORATE_TARGET works.
  Run this first when setting up adaptive mode.

EOF
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

case "$1" in
    fq_codel)     show_sysctl; apply_fq_codel; show_status ;;
    htb)          show_sysctl; apply_htb_fq_codel; show_status ;;
    cake)         show_sysctl; apply_cake; show_status ;;
    cake-bidir)   show_sysctl; apply_cake_bidir; show_status ;;
    aggressive)   show_sysctl; apply_fq_codel_aggressive; show_status ;;
    tune)         apply_tcp_tuning ;;
    untune)       revert_tcp_tuning ;;
    remove)
        echo "Removing all qdiscs on $INTERFACE..."
        tc qdisc del dev $INTERFACE root 2>/dev/null
        tc qdisc del dev $INTERFACE ingress 2>/dev/null
        # Fully tear down IFB device
        if ip link show $IFB_DEVICE &>/dev/null 2>&1; then
            tc qdisc del dev $IFB_DEVICE root 2>/dev/null
            ip link set dev $IFB_DEVICE down 2>/dev/null
            ip link del dev $IFB_DEVICE 2>/dev/null
        fi
        echo -e "${G}Returned to default.${N}"
        show_status ;;
    status)       show_sysctl; show_status ;;
    counters)     read_counters ;;
    clear)        clear_counters ;;
    probe)
        gw=$(_get_gateway)
        [ -z "$gw" ] && { echo -e "${R}No gateway found. Set AUTORATE_TARGET.${N}"; exit 1; }
        _probe_debug "$gw" ;;
    adapt)
        adapt
        if ! detect_qdisc | grep -q "cake"; then
            echo -e "${Y}No CAKE qdisc. Applying cake-bidir...${N}"
        fi
        apply_cake_bidir
        show_status ;;
    autorate)
        show_sysctl
        if ! detect_qdisc | grep -q "cake"; then
            echo -e "${Y}Autorate requires CAKE. Applying cake-bidir first...${N}"
            apply_cake_bidir
        fi
        autorate ;;
    diagnose)     diagnose ;;
    *)
        echo -e "${B}Usage: $0 <command>${N}"
        echo ""
        echo -e "${B}Strategies:${N}"
        echo "  cake-bidir     CAKE egress + ingress via IFB (recommended)"
        echo "  cake           CAKE egress only"
        echo "  htb            HTB + fq_codel (if CAKE unavailable)"
        echo "  fq_codel       fq_codel only (no shaping)"
        echo "  aggressive     Tight fq_codel (last resort)"
        echo ""
        echo -e "${B}TCP Tuning:${N}"
        echo "  tune           BBR + ECN + buffer limits"
        echo "  untune         Revert to cubic defaults"
        echo ""
        echo -e "${B}Adaptive (MODE=adaptive):${N}"
        echo "  probe          Test if RTT probe reaches gateway (debug)"
        echo "  adapt          One-shot: measure RTT, compute rates, apply CAKE"
        echo "  autorate       Continuous RTT-based adaptation (loop)"
        echo ""
        echo -e "${B}Management:${N}"
        echo "  status         Current qdisc config"
        echo "  counters       Detailed stats with explanations"
        echo "  clear          Reset counters to zero"
        echo "  diagnose       Show active strategy diagram + guidance"
        echo "  remove         Remove all, return to default"
        echo ""
        echo -e "${B}Quick start (static):${N}"
        echo "  1. Edit config.json: set profiles.<name>.manager.egress_rate/ingress_rate"
        echo "  2. $0 tune && $0 cake-bidir && $0 diagnose"
        echo ""
        echo -e "${B}Quick start (adaptive):${N}"
        echo "  1. Edit config.json: set profiles.<name>.manager.mode to \"adaptive\""
        echo "  2. Set autorate_target to a pingable host (gateway or 8.8.8.8)"
        echo "     Run '$0 probe' to verify it responds"
        echo "  3. Set max_egress / max_ingress to your ISP plan limits"
        echo "  4. Set baseline_rtt (good RTT in ms) and max_rtt (worst RTT)"
        echo "     Run 'ping <target>' with no load to find your baseline"
        echo "  5. $0 tune && $0 adapt          (one-shot)"
        echo "     $0 tune && $0 cake-bidir && $0 autorate  (continuous)"
        echo ""
        echo -e "${B}Current config:${N} (from $CONFIG_FILE, profile: $ACTIVE_PROFILE)"
        echo "  MODE=$MODE  INTERFACE=$INTERFACE"
        if [ "$MODE" = "adaptive" ]; then
            echo "  AUTORATE_TARGET=${AUTORATE_TARGET:-(auto-detect gateway)}"
            echo "  MAX_EGRESS=$MAX_EGRESS  MAX_INGRESS=$MAX_INGRESS"
            echo "  BASELINE_RTT=${BASELINE_RTT}ms  MAX_RTT=${MAX_RTT}ms"
        else
            echo "  EGRESS_RATE=$EGRESS_RATE  INGRESS_RATE=$INGRESS_RATE"
        fi
        echo ""
        echo -e "${B}Config file:${N} $CONFIG_FILE"
        echo -e "${B}Active profile:${N} $ACTIVE_PROFILE"
        echo ""
        echo -e "${B}config.json keys used by this script:${N}"
        echo "  active_profile              Which profile to load (config1/config2)"
        echo "  profiles.<name>.manager:"
        echo "    interface                 Network interface to shape"
        echo "    mode                      \"static\" or \"adaptive\""
        echo "    egress_rate / ingress_rate Fixed rates (static mode)"
        echo "    max_egress / max_ingress  Rate ceilings (adaptive mode)"
        echo "    min_egress_pct / min_ingress_pct  Rate floors as % of max"
        echo "    baseline_rtt / max_rtt    RTT thresholds (ms) for rate mapping"
        echo "    autorate_target           Host to ping for RTT probes"
        echo "    autorate_interval         Seconds between probes"
        echo "    dampen_pct                Max rate change per step (%)"
        echo "  ifb_device                  IFB device name for ingress shaping"
        echo "  fq_codel.*                  fq_codel parameters (target, interval, etc.)"
        echo "  cake.*                      CAKE parameters (rtt, overhead, diffserv, etc.)"
        echo ""
        echo -e "${B}Override config path:${N} CONFIG_FILE=/path/to/config.json $0 <command>"
        exit 1 ;;
esac
