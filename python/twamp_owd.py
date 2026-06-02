#!/usr/bin/env python3
"""
twamp_owd.py — TWAMP-Light (RFC 5357 / RFC 6812) UDP probe client.

Sends stamped UDP test packets to a TWAMP-Light reflector and collects
per-probe RTT, one-way delay estimates, and IPDV (jitter).

Packet format (unauthenticated mode):

  Sender → Reflector:
    Sequence Number   4B  (uint32, big-endian)
    Timestamp T1      8B  (NTP 64-bit: seconds since 1900-01-01 | frac)
    Error Estimate    2B  (0x0101 = unsynchronised, multiplier=1ms)
    Padding           N B (zeros; default 27 B → 41-byte total sender pkt)

  Reflector → Sender (RFC 5357 §4.2.1 unauthenticated):
    Sequence Number   4B  (reflector's own sequence)
    Timestamp T3      8B  (reflector send time)
    Error Estimate    2B
    MBZ               2B
    Receive Timestamp 8B  (T2 — when reflector received the probe)
    Sender Seq Number 4B  (echoed sender sequence)
    Sender Timestamp  8B  (T1 echoed)
    Sender Err Est    2B
    MBZ               1B
    Sender TTL        1B
    Padding           N B
    (total reflector pkt header: 41 bytes + padding)

Metrics (mirror of tcp_owd.py result dict):
  rtt_ms      = T4 − T1   (accurate regardless of clock sync)
  fwd_owd_ms  = T2 − T1   (accurate if clocks are NTP-synced, else RTT/2†)
  bwd_owd_ms  = T4 − T3   (accurate if clocks are NTP-synced, else RTT/2†)
  fwd_ipdv_ms = ΔFwdOWD between consecutive valid probes
  bwd_ipdv_ms = ΔBwdOWD between consecutive valid probes

Usage (standalone):
    python3 twamp_owd.py --server 34.209.241.130 --port 4200 --count 20
    python3 twamp_owd.py --server 34.209.241.130 --port 4200 --baseline 30 --stress 60

No root required — uses regular UDP socket.
"""

import argparse
import re
import socket
import struct
import statistics
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# NTP epoch offset: seconds between 1900-01-01 and 1970-01-01
_NTP_DELTA = 2208988800

# TWAMP sender packet: SeqNum(4) + NTP-TS(8) + ErrEst(2) = 14 bytes header
_SENDER_HDR_FMT  = '!IQH'   # uint32, uint64, uint16
_SENDER_HDR_SIZE = struct.calcsize(_SENDER_HDR_FMT)  # 14

# TWAMP reflector packet header (before padding):
# SeqNum(4) + T3(8) + ErrEst(2) + MBZ(2) + T2(8) + SenderSeq(4) + T1(8) + SenderErrEst(2) + MBZ(1) + SenderTTL(1) = 41 bytes
_REFLECT_HDR_FMT  = '!IQ H H Q I Q H B B'
_REFLECT_HDR_SIZE = struct.calcsize(_REFLECT_HDR_FMT)  # 41

DEFAULT_SERVER   = '34.209.241.130'
DEFAULT_PORT     = 4200
DEFAULT_COUNT    = 20
DEFAULT_INTERVAL = 0.2
DEFAULT_TIMEOUT  = 2.0
DEFAULT_PADDING  = 27    # bytes; sender pkt = 14 + 27 = 41 bytes total (Nokia twampy default)

PERCENTILE_P95 = 95

# ---------------------------------------------------------------------------
# NTP timestamp helpers
# ---------------------------------------------------------------------------

def _to_ntp64(t: float) -> int:
    """Convert a float POSIX timestamp to a 64-bit NTP timestamp (uint64)."""
    ntp_secs = int(t) + _NTP_DELTA
    ntp_frac = int((t % 1.0) * (2**32))
    return (ntp_secs << 32) | (ntp_frac & 0xFFFFFFFF)


def _from_ntp64(ntp64: int) -> float:
    """Convert a 64-bit NTP timestamp (uint64) to a float POSIX timestamp."""
    ntp_secs = (ntp64 >> 32) & 0xFFFFFFFF
    ntp_frac = ntp64 & 0xFFFFFFFF
    return (ntp_secs - _NTP_DELTA) + ntp_frac / (2**32)


# ---------------------------------------------------------------------------
# Core probe loop
# ---------------------------------------------------------------------------

def run_twamp_probes(server, port, count=0, interval=DEFAULT_INTERVAL,
                     phase='BASELINE', duration_secs=0,
                     timeout=DEFAULT_TIMEOUT, padding=DEFAULT_PADDING,
                     verbose=False):
    """Send TWAMP-Light UDP test packets and collect per-probe results.

    Parameters
    ----------
    server        : str   — reflector IP or hostname
    port          : int   — reflector UDP port
    count         : int   — number of probes (used when duration_secs==0)
    interval      : float — seconds between probes
    phase         : str   — label for result dicts ('BASELINE' or 'STRESS')
    duration_secs : float — if >0, run for this many seconds instead of count
    timeout       : float — per-probe socket receive timeout (seconds)
    padding       : int   — padding bytes appended to sender packet
    verbose       : bool  — print raw timestamps for every probe

    Returns
    -------
    list of dicts — one entry per probe attempt (including timed-out ones)
    """
    results = []
    seq = 0

    try:
        addr_info = socket.getaddrinfo(server, port, socket.AF_INET,
                                        socket.SOCK_DGRAM)
        server_ip = addr_info[0][4][0]
    except socket.gaierror as exc:
        print(f"[TWAMP] DNS resolution failed for '{server}': {exc}", file=sys.stderr)
        return results

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((server_ip, port))

    padding_bytes = b'\x00' * max(0, padding)
    error_estimate = 0x0101   # S=0, Z=0, Scale=0, Multiplier=1 (unsynchronised, ~1ms)

    deadline = time.monotonic() + duration_secs if duration_secs > 0 else None

    probe_num = 0
    while True:
        if deadline is not None:
            if time.monotonic() >= deadline:
                break
        else:
            if count > 0 and probe_num >= count:
                break

        t1_posix = time.time()
        t1_mono  = time.monotonic()
        t1_ntp   = _to_ntp64(t1_posix)

        pkt = struct.pack(_SENDER_HDR_FMT, seq, t1_ntp, error_estimate) + padding_bytes

        try:
            sock.send(pkt)
        except OSError as exc:
            results.append({
                'probe': probe_num, 'phase': phase, 'seq': seq,
                'rtt_ms': None, 'fwd_owd_ms': None, 'bwd_owd_ms': None,
                'fwd_ipdv_ms': None, 'bwd_ipdv_ms': None,
                'timed_out': True, 'cal_shift_ms': 0.0,
                'error': str(exc),
            })
            seq += 1
            probe_num += 1
            time.sleep(interval)
            continue

        try:
            data = sock.recv(4096)
            t4_mono = time.monotonic()
            t4_posix = t1_posix + (t4_mono - t1_mono)
        except socket.timeout:
            results.append({
                'probe': probe_num, 'phase': phase, 'seq': seq,
                'rtt_ms': None, 'fwd_owd_ms': None, 'bwd_owd_ms': None,
                'fwd_ipdv_ms': None, 'bwd_ipdv_ms': None,
                'timed_out': True, 'cal_shift_ms': 0.0,
            })
            seq += 1
            probe_num += 1
            time.sleep(interval)
            continue

        rtt_ms = (t4_mono - t1_mono) * 1000.0

        # Parse reflector packet
        t2_posix = None
        t3_posix = None
        echoed_seq = None

        if len(data) >= _REFLECT_HDR_SIZE:
            try:
                fields = struct.unpack_from(_REFLECT_HDR_FMT, data, 0)
                # fields: refl_seq, t3_ntp, err_est, mbz, t2_ntp,
                #         sender_seq, t1_echo_ntp, sender_err_est, mbz2, sender_ttl
                t3_posix   = _from_ntp64(fields[1])
                t2_posix   = _from_ntp64(fields[4])
                echoed_seq = fields[5]
            except struct.error:
                pass

        # Compute OWD
        if t2_posix is not None and t3_posix is not None:
            fwd_owd_ms = (t2_posix - t1_posix) * 1000.0
            bwd_owd_ms = (t4_posix - t3_posix) * 1000.0
        else:
            # Fallback: symmetric assumption
            fwd_owd_ms = rtt_ms / 2.0
            bwd_owd_ms = rtt_ms / 2.0

        if verbose:
            print(f"  probe={probe_num:4d} seq={seq:4d} "
                  f"RTT={rtt_ms:7.2f}ms  FwdOWD={fwd_owd_ms:7.2f}ms  "
                  f"BwdOWD={bwd_owd_ms:7.2f}ms  "
                  f"T2={t2_posix:.6f}  T3={t3_posix:.6f}"
                  if t2_posix else
                  f"  probe={probe_num:4d} seq={seq:4d} "
                  f"RTT={rtt_ms:7.2f}ms  (no T2/T3 in reply, using RTT/2)")

        results.append({
            'probe':        probe_num,
            'phase':        phase,
            'seq':          seq,
            'rtt_ms':       rtt_ms,
            'fwd_owd_ms':   fwd_owd_ms,
            'bwd_owd_ms':   bwd_owd_ms,
            'fwd_ipdv_ms':  None,   # filled by compute_twamp_owd()
            'bwd_ipdv_ms':  None,
            'timed_out':    False,
            'cal_shift_ms': 0.0,
            't1_posix':     t1_posix,
            't4_posix':     t4_posix,
            'echoed_seq':   echoed_seq,
        })

        seq += 1
        probe_num += 1

        elapsed = time.monotonic() - t1_mono
        sleep_time = interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

    sock.close()
    return results


# ---------------------------------------------------------------------------
# Post-processing: compute IPDV from consecutive probes
# ---------------------------------------------------------------------------

def compute_twamp_owd(results):
    """Compute per-probe IPDV (fwd_ipdv_ms / bwd_ipdv_ms) in-place.

    Operates within each phase independently so BASELINE→STRESS boundary
    does not produce a spurious large IPDV value.
    """
    by_phase = {}
    for r in results:
        ph = r.get('phase') or 'ALL'
        by_phase.setdefault(ph, []).append(r)

    for ph, recs in by_phase.items():
        valid = [r for r in recs if not r.get('timed_out')
                 and r.get('fwd_owd_ms') is not None]
        for i, r in enumerate(valid):
            if i == 0:
                r['fwd_ipdv_ms'] = None
                r['bwd_ipdv_ms'] = None
            else:
                prev = valid[i - 1]
                r['fwd_ipdv_ms'] = r['fwd_owd_ms'] - prev['fwd_owd_ms']
                r['bwd_ipdv_ms'] = r['bwd_owd_ms'] - prev['bwd_owd_ms']


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def _percentile(data, pct):
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * pct / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _jitter_range(ipdv_list):
    """Peak-to-peak IPDV range (ms)."""
    vals = [v for v in ipdv_list if v is not None]
    if len(vals) < 2:
        return 0.0
    return max(vals) - min(vals)


_SEP = '-' * 72


def print_phase_summary(results, phase_loss=None):
    """Print BASELINE vs STRESS comparison table (TWAMP variant).

    Mirrors tcp_owd.print_phase_summary() column layout so output looks
    consistent when both --owd and --twamp are used in the same run.
    """
    by_phase = {}
    for r in results:
        if r.get('timed_out'):
            continue
        ph = r.get('phase') or 'ALL'
        by_phase.setdefault(ph, []).append(r)

    if len(by_phase) < 2:
        return

    col  = 11
    jcol = 12
    hdr = (f"  {'Phase':10}  {'FwdOWD‡avg':>{col}}  {'FwdOWD‡p95':>{col}}  "
           f"{'BwdOWD‡avg':>{col}}  {'BwdOWD‡p95':>{col}}  "
           f"{'RTT avg':>8}  {'RTT p95':>8}  "
           f"{'FwdJitter':>{jcol}}  {'BwdJitter':>{jcol}}")
    print()
    print(hdr)
    print('  ' + '-' * (len(hdr) - 2))

    stats = {}
    for ph in ('BASELINE', 'STRESS'):
        recs = by_phase.get(ph)
        if not recs:
            continue
        rtts = [r['rtt_ms']     for r in recs]
        fwds = [r['fwd_owd_ms'] for r in recs]
        bwds = [r['bwd_owd_ms'] for r in recs]
        fipd = [r['fwd_ipdv_ms'] for r in recs if r.get('fwd_ipdv_ms') is not None]
        bipd = [r['bwd_ipdv_ms'] for r in recs if r.get('bwd_ipdv_ms') is not None]
        fwd_j = _jitter_range(fipd)
        bwd_j = _jitter_range(bipd)
        stats[ph] = {
            'fwd_avg': statistics.mean(fwds), 'fwd_p95': _percentile(fwds, PERCENTILE_P95),
            'bwd_avg': statistics.mean(bwds), 'bwd_p95': _percentile(bwds, PERCENTILE_P95),
            'rtt_avg': statistics.mean(rtts), 'rtt_p95': _percentile(rtts, PERCENTILE_P95),
            'fwd_j': fwd_j, 'bwd_j': bwd_j,
        }
        print(f"  {ph:10}  "
              f"{stats[ph]['fwd_avg']:>{col}.2f}  {stats[ph]['fwd_p95']:>{col}.2f}  "
              f"{stats[ph]['bwd_avg']:>{col}.2f}  {stats[ph]['bwd_p95']:>{col}.2f}  "
              f"{stats[ph]['rtt_avg']:>8.2f}  {stats[ph]['rtt_p95']:>8.2f}  "
              f"{fwd_j:>{jcol}.2f}  {bwd_j:>{jcol}.2f}")

    if 'BASELINE' in stats and 'STRESS' in stats:
        b, s = stats['BASELINE'], stats['STRESS']
        print('  ' + '-' * (len(hdr) - 2))
        print(f"  {'Change':10}  "
              f"{s['fwd_avg']-b['fwd_avg']:>+{col}.2f}  {s['fwd_p95']-b['fwd_p95']:>+{col}.2f}  "
              f"{s['bwd_avg']-b['bwd_avg']:>+{col}.2f}  {s['bwd_p95']-b['bwd_p95']:>+{col}.2f}  "
              f"{s['rtt_avg']-b['rtt_avg']:>+8.2f}  {s['rtt_p95']-b['rtt_p95']:>+8.2f}  "
              f"{s['fwd_j']-b['fwd_j']:>+{jcol}.2f}  {s['bwd_j']-b['bwd_j']:>+{jcol}.2f}")

    # Direction diagnosis
    if 'BASELINE' in stats and 'STRESS' in stats:
        b, s = stats['BASELINE'], stats['STRESS']
        fwd_delta = s['fwd_avg'] - b['fwd_avg']
        bwd_delta = s['bwd_avg'] - b['bwd_avg']
        threshold = 2.0
        if fwd_delta > threshold or bwd_delta > threshold:
            print()
            if abs(fwd_delta - bwd_delta) < 5.0:
                print(f"  ► Symmetric congestion (ΔFwd={fwd_delta:+.1f}ms, ΔBwd={bwd_delta:+.1f}ms)")
            elif fwd_delta > bwd_delta:
                print(f"  ► Upload path more congested "
                      f"(ΔFwd={fwd_delta:+.1f}ms > ΔBwd={bwd_delta:+.1f}ms)")
            else:
                print(f"  ► Download path more congested "
                      f"(ΔBwd={bwd_delta:+.1f}ms > ΔFwd={fwd_delta:+.1f}ms)")

    # Loss summary
    if phase_loss:
        print()
        for ph in ('BASELINE', 'STRESS'):
            pct = phase_loss.get(ph, 0.0)
            if pct > 0:
                print(f"  [{ph}] probe loss: {pct:.1f}%")


# ---------------------------------------------------------------------------
# Nokia twampy subprocess backend
# ---------------------------------------------------------------------------

def _find_twampy_python():
    """Return the first Python executable that has twampy installed, or None.

    Tries sys.executable first (works when twampy is installed in the same
    environment), then falls back to system 'python3' / 'python' so that
    installations via the system package manager or a different venv are found.
    """
    import shutil
    candidates = [sys.executable, shutil.which('python3'), shutil.which('python')]
    seen = set()
    for py in candidates:
        if not py or py in seen:
            continue
        seen.add(py)
        try:
            r = subprocess.run(
                [py, '-m', 'twampy', '--help'],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                return py
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def check_nokia_twampy():
    """Return True if Nokia twampy is installed and callable."""
    return _find_twampy_python() is not None


def run_twamp_probes_nokia(server, port, count=0, interval=DEFAULT_INTERVAL,
                           phase='BASELINE', duration_secs=0,
                           timeout=DEFAULT_TIMEOUT, padding=DEFAULT_PADDING,
                           verbose=False):
    """Run Nokia twampy sender subprocess and return results in our dict format.

    Nokia twampy outputs summary stats only (no per-probe data).  This function:
      - Runs: python3 -m twampy sender <server>:<port> --count N ...
      - Parses the 3-line Outbound/Inbound/Roundtrip summary table
      - Generates N synthetic equi-spaced probe dicts from the avg values
        (all probes share fwd_owd=avg, bwd_owd=avg; IPDV is always 0)
      - Represents packet loss by marking the last loss_pct% of probes timed_out=True

    Returns list of dicts in the same schema as run_twamp_probes(), or None if
    Nokia twampy is not installed (so callers can handle the error explicitly).
    """
    py = _find_twampy_python()
    if py is None:
        return None   # genuinely not installed

    count_arg = count if count > 0 else max(10, int(duration_secs / interval))
    interval_ms = max(1, int(interval * 1000))   # Nokia twampy uses milliseconds

    cmd = [
        py, '-m', 'twampy', 'sender',
        f'{server}:{port}',
        '--count',    str(count_arg),
        '--interval', str(interval_ms),
        '--padding',  str(padding),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration_secs + count_arg * interval + 30,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None

    output = proc.stdout + proc.stderr

    # Nokia twampy dp() helper uses different units depending on magnitude:
    #   ≤1ms  → us  (e.g. "     683us")
    #   >1ms  → ms  (e.g. "   26.59ms")
    #   >1s   → sec (e.g. "    1.22sec")
    #   >60s  → min
    # Loss can be negative due to NTP drift on the reflector.
    #
    # Example lines:
    #   Outbound:   750.24ms     1.22sec    969.40ms     38.89ms      0.0%
    #   Inbound:     46.47ms   209.30ms     98.68ms     26.37ms    -66.7%
    #   Roundtrip:  832.76ms     1.43sec     1.07sec     43.59ms   -466.7%

    def _to_ms(val, unit):
        u = unit.lower()
        if u == 'us':  return val / 1000.0
        if u == 'sec': return val * 1000.0
        if u == 'min': return val * 60000.0
        return val   # 'ms'

    _ROW_RE = re.compile(
        r'(Outbound|Inbound|Roundtrip):\s+'
        r'([\d.]+)(ms|us|sec|min)\s+'    # min
        r'([\d.]+)(ms|us|sec|min)\s+'    # max
        r'([\d.]+)(ms|us|sec|min)\s+'    # avg   ← groups 6, 7
        r'([\d.]+)(ms|us|sec|min)\s+'    # jitter
        r'([+-]?[\d.]+)%',               # loss  ← group 10 (may be negative)
        re.IGNORECASE,
    )

    parsed = {}
    for line in output.splitlines():
        m = _ROW_RE.search(line)
        if m:
            label = m.group(1).lower()
            parsed[label] = {
                'avg_ms':   _to_ms(float(m.group(6)), m.group(7)),
                'loss_pct': float(m.group(10)),
            }

    if not parsed:
        # twampy ran but output format didn't match — different from "not installed"
        print(
            f"[TWAMP/nokia] Warning: could not parse twampy output "
            f"(returncode={proc.returncode}).\n"
            f"              Raw output:\n{output[:600]}",
            file=sys.stderr,
        )
        return []   # empty list — twampy ran but we got no data

    fwd_avg_ms  = parsed.get('outbound',  {}).get('avg_ms',  0.0)
    bwd_avg_ms  = parsed.get('inbound',   {}).get('avg_ms',  0.0)
    rtt_avg_ms  = parsed.get('roundtrip', {}).get('avg_ms',  fwd_avg_ms + bwd_avg_ms)
    # Nokia twampy can report negative loss when NTP clocks drift; clamp to valid range
    loss_pct    = max(0.0, min(100.0, parsed.get('roundtrip', {}).get('loss_pct', 0.0)))

    n_valid = max(0, count_arg - int(round(count_arg * loss_pct / 100.0)))
    n_lost  = count_arg - n_valid

    now = time.time()
    results = []

    for i in range(n_valid):
        t1 = now + i * interval
        results.append({
            'probe':        i,
            'phase':        phase,
            'seq':          i,
            'rtt_ms':       rtt_avg_ms,
            'fwd_owd_ms':   fwd_avg_ms,
            'bwd_owd_ms':   bwd_avg_ms,
            'fwd_ipdv_ms':  None,
            'bwd_ipdv_ms':  None,
            'timed_out':    False,
            'cal_shift_ms': 0.0,
            't1_posix':     t1,
            't4_posix':     t1 + rtt_avg_ms / 1000.0,
            'echoed_seq':   i,
        })

    for j in range(n_lost):
        results.append({
            'probe':        n_valid + j,
            'phase':        phase,
            'seq':          n_valid + j,
            'rtt_ms':       None,
            'fwd_owd_ms':   None,
            'bwd_owd_ms':   None,
            'fwd_ipdv_ms':  None,
            'bwd_ipdv_ms':  None,
            'timed_out':    True,
            'cal_shift_ms': 0.0,
        })

    if verbose:
        print(f"  [nokia twampy] {phase}: {n_valid}/{count_arg} valid, "
              f"fwd_avg={fwd_avg_ms:.2f}ms bwd_avg={bwd_avg_ms:.2f}ms "
              f"rtt_avg={rtt_avg_ms:.2f}ms loss={loss_pct:.1f}%")

    return results


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description="TWAMP-Light UDP probe client (RFC 5357 unauthenticated mode).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument('--server', '-S', type=str, default=DEFAULT_SERVER,
                   help='TWAMP reflector IP or hostname')
    p.add_argument('--port',   '-p', type=int, default=DEFAULT_PORT,
                   help='TWAMP reflector UDP port')
    p.add_argument('--count',  '-n', type=int, default=DEFAULT_COUNT,
                   help='Number of probes (used when --baseline/--stress not set)')
    p.add_argument('--interval', '-i', type=float, default=DEFAULT_INTERVAL,
                   help='Seconds between probes')
    p.add_argument('--timeout',  '-w', type=float, default=DEFAULT_TIMEOUT,
                   help='Per-probe receive timeout in seconds')
    p.add_argument('--padding',  '-P', type=int,   default=DEFAULT_PADDING,
                   help='Padding bytes appended to each sender packet')
    p.add_argument('--baseline', '-b', type=int, default=0,
                   help='Baseline phase duration in seconds (0 = single-phase)')
    p.add_argument('--stress',   '-s', type=int, default=0,
                   help='Stress phase duration in seconds')
    p.add_argument('--output',   '-o', type=str, default=None,
                   help='Save probe results to CSV file')
    p.add_argument('--verbose',  '-v', action='store_true',
                   help='Print per-probe raw timestamps')
    return p.parse_args()


def main():
    args = _parse_args()

    if args.baseline > 0 and args.stress > 0:
        print(f"[TWAMP] BASELINE phase ({args.baseline}s) → {args.server}:{args.port}")
        results = run_twamp_probes(
            args.server, args.port,
            duration_secs=args.baseline, interval=args.interval,
            phase='BASELINE', timeout=args.timeout, padding=args.padding,
            verbose=args.verbose,
        )
        print(f"[TWAMP] STRESS phase ({args.stress}s) → {args.server}:{args.port}")
        results += run_twamp_probes(
            args.server, args.port,
            duration_secs=args.stress, interval=args.interval,
            phase='STRESS', timeout=args.timeout, padding=args.padding,
            verbose=args.verbose,
        )
    else:
        print(f"[TWAMP] {args.count} probes → {args.server}:{args.port}")
        results = run_twamp_probes(
            args.server, args.port,
            count=args.count, interval=args.interval,
            phase='SINGLE', timeout=args.timeout, padding=args.padding,
            verbose=args.verbose,
        )

    compute_twamp_owd(results)

    valid = [r for r in results if not r.get('timed_out')]
    lost  = len(results) - len(valid)
    print(f"\n  Probes sent={len(results)}  valid={len(valid)}  lost={lost}"
          f"  ({100*lost/max(len(results),1):.1f}% loss)")

    if valid:
        rtts  = [r['rtt_ms']     for r in valid]
        fwds  = [r['fwd_owd_ms'] for r in valid]
        bwds  = [r['bwd_owd_ms'] for r in valid]
        print(f"  RTT     avg={statistics.mean(rtts):.2f}ms  "
              f"p95={_percentile(rtts, 95):.2f}ms  max={max(rtts):.2f}ms")
        print(f"  FwdOWD‡ avg={statistics.mean(fwds):.2f}ms  "
              f"p95={_percentile(fwds, 95):.2f}ms  max={max(fwds):.2f}ms")
        print(f"  BwdOWD‡ avg={statistics.mean(bwds):.2f}ms  "
              f"p95={_percentile(bwds, 95):.2f}ms  max={max(bwds):.2f}ms")

    if args.baseline > 0 and args.stress > 0:
        print_phase_summary(results)

    if args.output:
        import csv
        with open(args.output, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=[
                'probe', 'phase', 'seq', 'rtt_ms', 'fwd_owd_ms', 'bwd_owd_ms',
                'fwd_ipdv_ms', 'bwd_ipdv_ms', 'timed_out', 'cal_shift_ms',
            ])
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k) for k in w.fieldnames})
        print(f"  Results saved to {args.output}")


if __name__ == '__main__':
    main()
