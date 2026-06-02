#!/usr/bin/env python3
"""
tcp_owd.py — TCP Timestamp-based one-way delay (OWD) estimator.

Maintains a single established TCP connection and uses RFC 7323 Timestamp
options (TSval/TSecr) in TCP keep-alive probes to decompose RTT into per-
direction components.  No server daemon is required.

What this measures:
  - RTT per probe         : accurate round-trip time
  - FwdOWD† (upload)      : client→server OWD estimated via server TSval clock
  - BwdOWD† (download)    : server→client OWD = RTT − FwdOWD†
  - Fwd IPDV (upload)     : per-probe Δ in upload delay (server TSval analysis)
  - Bwd IPDV (download)   : per-probe Δ in download delay = RTT_delta − Fwd_IPDV

Key technique — direct server TSval clock (no NTP, no server code):
  Anchor: server sent SYN-ACK with TSval=S0 at client time T_anchor = t_synack − RTT_hs/2
  Per probe i (TSval=S_i, received at t_recv_i):
      T_server_tx_i = T_anchor + (S_i − S0) / Hz        ← server send time in client clock
      BwdOWD†[i]   = t_recv_i − T_server_tx_i           ← download delay (server→client)
      FwdOWD†[i]   = RTT[i] − BwdOWD†[i]               ← upload delay   (client→server)

  Each probe is computed independently — no cumulative drift, no cross-probe
  dependencies.  Survives sparse measurements under heavy bufferbloat.

This requires ONE established TCP connection so that TSval is monotonic.
Per-connection TSval offsets (RFC 7323 §5.4, used by Cloudflare/Google) make
SYN-per-probe approaches produce garbage results — fresh connections have random
unrelated TSval bases that are not comparable.

HTTP bootstrap: a real HTTP HEAD request is sent after the TCP handshake so
that CDN infrastructure (Cloudflare, etc.) treats the connection as legitimate
and does not rate-limit subsequent TCP keep-alive probes.

Requirements:
    pip install scapy
    Run as root (or CAP_NET_RAW) — raw socket + iptables.
    Linux only.

Usage:
    sudo python3 tcp_owd.py --target 1.1.1.1 --port 80
    sudo python3 tcp_owd.py --target 8.8.8.8 --count 30 --interval 0.5
    sudo python3 tcp_owd.py --target 10.0.0.1 --output results.csv --verbose
"""

import argparse
import atexit
import csv
import logging
import os
import random
import signal
import statistics
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_PORT         = 80     # HTTP — CDN hosts always have an open port 80
DEFAULT_COUNT        = 20
DEFAULT_INTERVAL     = 0.2    # seconds between keep-alive probes
DEFAULT_TIMEOUT      = 2.0    # seconds to wait per probe
HZ_ESTIMATE_N        = 10     # first N valid probe pairs used to estimate server TSval Hz
DEFAULT_BASELINE_SEC = 0      # 0 = single-phase mode (use --count instead)
DEFAULT_STRESS_SEC   = 0
DEFAULT_DL_CLIENTS   = 4
DEFAULT_UL_CLIENTS   = 4
STRESS_RAMP_SEC      = 5      # seconds to wait after starting traffic-gen before stress probes

# Analysis thresholds
OWD_DIAGNOSIS_THRESHOLD = 2.0   # ms avg increase to flag a direction as degraded
OWD_SYMMETRIC_THRESHOLD = 5.0   # ms; |fwd_delta - bwd_delta| < this → symmetric congestion

# Reporting
PERCENTILE_P95          = 95

# TCP / OS internals
MIN_EPHEMERAL_PORT      = 1025
MAX_EPHEMERAL_PORT      = 65000
SIGNAL_EXIT_BASE        = 128   # exit code = 128 + signal number

# ---------------------------------------------------------------------------
# iptables RST suppression
# ---------------------------------------------------------------------------

_rst_active    = False
_rst_target_ip = None


def _iptables(action, ip):
    """Add (-A) or remove (-D) the OUTPUT RST drop rule for ip."""
    subprocess.run(
        ['iptables', action, 'OUTPUT',
         '-p', 'tcp', '--tcp-flags', 'RST', 'RST',
         '-d', ip, '-j', 'DROP'],
        check=True, capture_output=True,
    )


def _install_rst(ip):
    global _rst_active, _rst_target_ip
    _iptables('-A', ip)
    _rst_active    = True
    _rst_target_ip = ip


def _remove_rst():
    global _rst_active
    if _rst_active and _rst_target_ip:
        try:
            _iptables('-D', _rst_target_ip)
        except Exception:
            pass
        _rst_active = False


def _sig_handler(sig, frame):
    _remove_rst()
    sys.exit(SIGNAL_EXIT_BASE + sig)


# ---------------------------------------------------------------------------
# TCP timestamp helpers
# ---------------------------------------------------------------------------

def _tick():
    """32-bit millisecond monotonic counter (1 kHz, wraps ~49 days)."""
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


def _extract_ts(tcp_layer):
    """Return (tsval, tsecr) from TCP Timestamp option, or (None, None)."""
    for name, val in (tcp_layer.options or []):
        if name == 'Timestamp':
            return val[0], val[1]
    return None, None


def _ts_delta(new, old):
    """32-bit unsigned delta — handles TSval wraparound within one connection."""
    return (new - old) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# TCP handshake
# ---------------------------------------------------------------------------

def tcp_handshake(target, port, timeout, verbose):
    """Three-way handshake via raw Scapy socket.

    Returns connection-state dict or raises RuntimeError.
    """
    from scapy.all import IP, TCP, sr1, send, conf
    conf.verb = 0

    sport  = random.randint(MIN_EPHEMERAL_PORT, MAX_EPHEMERAL_PORT)
    isn    = random.randint(0, 0xFFFFFFFF)
    ts_syn = _tick()

    syn = (IP(dst=target) /
           TCP(dport=port, sport=sport, seq=isn, flags='S',
               options=[('Timestamp', (ts_syn, 0)), ('NOP', None), ('NOP', None)]))

    t_syn    = time.monotonic_ns()
    syn_ack  = sr1(syn, timeout=timeout)
    t_synack = time.monotonic_ns()

    if syn_ack is None or not syn_ack.haslayer(TCP):
        raise RuntimeError(f"No SYN-ACK from {target}:{port} — port closed or firewalled")

    tcp = syn_ack[TCP]
    if tcp.flags & 0x04:
        raise RuntimeError(f"RST from {target}:{port} — port is closed")
    if not (tcp.flags & 0x12):
        raise RuntimeError(f"Unexpected TCP flags {tcp.flags:#04x} from {target}:{port}")

    srv_tsval, _ = _extract_ts(tcp)
    if srv_tsval is None:
        raise RuntimeError(
            f"{target} does not support TCP Timestamps (RFC 7323). "
            "Try a different target or port.")

    rtt_hs_ms = (t_synack - t_syn) / 1e6
    if verbose:
        print(f"  [handshake]  RTT={rtt_hs_ms:.2f} ms  srv_tsval={srv_tsval}")

    our_seq   = isn + 1
    their_seq = tcp.seq + 1
    ts_ack    = _tick()

    send(IP(dst=target) /
         TCP(dport=port, sport=sport, seq=our_seq, ack=their_seq, flags='A',
             options=[('Timestamp', (ts_ack, srv_tsval)), ('NOP', None), ('NOP', None)]))

    return {
        'sport':                 sport,
        'our_seq':               our_seq,
        'their_seq':             their_seq,
        'last_srv_tsval':        srv_tsval,
        'rtt_hs_ms':             rtt_hs_ms,
        # Time anchor for compute_owd() — do NOT overwrite these after handshake.
        # t_synack_ns: monotonic ns when we received the SYN-ACK.
        # srv_tsval_at_handshake: server TSval in that SYN-ACK (S0 reference).
        't_synack_ns':           t_synack,
        'srv_tsval_at_handshake': srv_tsval,
    }


# ---------------------------------------------------------------------------
# HTTP bootstrap
# ---------------------------------------------------------------------------

def http_bootstrap(target, port, conn, timeout, verbose):
    """Send one HTTP HEAD request and consume the server's response.

    Purpose: CDN infrastructure (Cloudflare, Google, etc.) silently drops
    TCP keep-alive probes on connections that have never carried application
    traffic.  Sending a real HTTP request makes the connection legitimate and
    prevents rate-limiting of subsequent keep-alive probes.

    Updates conn['their_seq'] and conn['last_srv_tsval'] in-place.
    """
    from scapy.all import IP, TCP, send, sniff, conf
    conf.verb = 0

    req = (f"HEAD / HTTP/1.1\r\nHost: {target}\r\n"
           f"Connection: keep-alive\r\nUser-Agent: tcp-owd/1.0\r\n\r\n").encode()

    pkt = (IP(dst=target) /
           TCP(dport=port, sport=conn['sport'],
               seq=conn['our_seq'], ack=conn['their_seq'],
               flags='PA',
               options=[('Timestamp', (_tick(), conn['last_srv_tsval'])),
                        ('NOP', None), ('NOP', None)]) /
           req)
    send(pkt)
    conn['our_seq'] += len(req)

    # Capture server's HTTP response (headers only for HEAD, no body)
    sport = conn['sport']
    resp_pkts = sniff(
        filter=f"tcp src port {port} and tcp dst port {sport}",
        timeout=timeout,
        stop_filter=lambda p: (
            p.haslayer(TCP) and
            bool(p[TCP].flags & 0x08) and        # PSH — last data segment
            len(bytes(p[TCP].payload)) > 0
        ),
    )

    if not resp_pkts:
        raise RuntimeError(
            f"No HTTP response from {target}:{port} — "
            "try --port 80 or check that the target is reachable")

    # Advance their_seq past all received data; grab the latest server TSval
    for p in resp_pkts:
        if not p.haslayer(TCP):
            continue
        payload_len = len(bytes(p[TCP].payload))
        if payload_len > 0:
            end_seq = p[TCP].seq + payload_len
            # Handle 32-bit seq wraparound: keep the highest seq seen
            if _ts_delta(end_seq, conn['their_seq']) < 0x80000000:
                conn['their_seq'] = end_seq
            srv_tsval, _ = _extract_ts(p[TCP])
            if srv_tsval is not None:
                conn['last_srv_tsval'] = srv_tsval

    # ACK the HTTP response
    send(IP(dst=target) /
         TCP(dport=port, sport=sport,
             seq=conn['our_seq'], ack=conn['their_seq'],
             flags='A',
             options=[('Timestamp', (_tick(), conn['last_srv_tsval'])),
                      ('NOP', None), ('NOP', None)]))

    if verbose:
        print(f"  [bootstrap]  HTTP HEAD sent/received  "
              f"their_seq={conn['their_seq']}  srv_tsval={conn['last_srv_tsval']}")


# ---------------------------------------------------------------------------
# Keep-alive probe burst
# ---------------------------------------------------------------------------

def run_probes(target, port, conn, count, interval, timeout, verbose,
               phase=None, duration_secs=None):
    """Send TCP keep-alive probes on the established connection.

    Probe count is controlled by `count` (default mode) or `duration_secs`
    (two-phase mode — run until the deadline, ignoring `count`).

    Uses seq = our_seq - 1 (one before the last acknowledged sequence byte).
    The remote kernel MUST respond with an ACK per RFC 9293 §3.8.4.
    TSval in all responses comes from the SAME connection → monotonically
    increasing → IPDV computation is valid.

    `phase` (e.g. 'BASELINE', 'STRESS') is stored in each result dict and
    used by print_phase_summary() and save_csv().
    """
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0

    sport          = conn['sport']
    our_seq        = conn['our_seq']
    their_seq      = conn['their_seq']
    last_srv_tsval = conn['last_srv_tsval']

    results        = []
    prev_t_send_ns = None
    probe_num      = 0
    deadline       = (time.monotonic() + duration_secs) if duration_secs is not None else None

    while True:
        if deadline is not None:
            if time.monotonic() >= deadline:
                break
        else:
            if probe_num >= count:
                break

        probe_num += 1
        ts_probe = _tick()
        probe = (IP(dst=target, tos=0) /       # normal DSCP — experience actual queue (incl. bufferbloat)
                 TCP(dport=port, sport=sport,
                     seq=our_seq - 1,   # keep-alive probe
                     ack=their_seq,
                     flags='A',
                     options=[('Timestamp', (ts_probe, last_srv_tsval)),
                               ('NOP', None), ('NOP', None)]))

        t_send = time.monotonic_ns()
        resp   = sr1(probe, timeout=timeout)
        t_recv = time.monotonic_ns()

        if resp is None or not resp.haslayer(TCP):
            if verbose:
                print(f"  probe {probe_num:>3}: TIMEOUT")
            results.append({
                'probe':       probe_num,
                'phase':       phase,
                't_send_ns':   t_send,
                'rtt_ms':      timeout * 1000,   # lower bound; actual delay >= this
                'timed_out':   True,
                'fwd_owd_ms':  None,
                'bwd_owd_ms':  None,
                'fwd_ipdv_ms': None,
                'bwd_ipdv_ms': None,
            })
            prev_t_send_ns = t_send
            time.sleep(max(0.0, interval - (time.monotonic_ns() - t_send) / 1e9))
            continue

        srv_tsval, srv_tsecr = _extract_ts(resp[TCP])
        rtt_ms      = (t_recv - t_send) / 1e6
        send_gap_ms = (t_send - prev_t_send_ns) / 1e6 if prev_t_send_ns is not None else None

        if srv_tsval is not None:
            last_srv_tsval = srv_tsval

        rec = {
            'probe':         probe_num,
            'phase':         phase,
            't_send_ns':     t_send,
            't_recv_ns':     t_recv,    # needed by compute_owd() for direct bwd delay
            'rtt_ms':        rtt_ms,
            'fwd_owd_ms':    rtt_ms / 2,   # overwritten by compute_owd()
            'bwd_owd_ms':    rtt_ms / 2,   # overwritten by compute_owd()
            'ts_sent':       ts_probe,
            'srv_tsval':     srv_tsval,
            'srv_tsecr':     srv_tsecr,
            'send_gap_ms':   send_gap_ms,
            'server_gap_ms': None,
            'fwd_ipdv_ms':   None,
            'bwd_ipdv_ms':   None,
        }
        results.append(rec)

        if verbose:
            gap = f'{send_gap_ms:.1f}' if send_gap_ms is not None else '--'
            ph  = f'[{phase}] ' if phase else ''
            print(f"  {ph}probe {probe_num:>3}: RTT={rtt_ms:7.2f} ms  "
                  f"srv_tsval={srv_tsval}  send_gap={gap} ms")

        prev_t_send_ns = t_send
        elapsed = (time.monotonic_ns() - t_send) / 1e9
        time.sleep(max(0.0, interval - elapsed))

    return results


def run_probes_async(target, port, conn, count, interval, verbose,
                     phase=None, duration_secs=None, drain_timeout=5.0):
    """Send HTTP HEAD probes fire-and-forget; match responses via sniff() thread.

    Unlike run_probes(), this function does not block waiting for each response.
    A background sniff() thread captures all incoming TCP packets from the target
    and matches them to pending probes via exact TSecr lookup.

    Probes are HTTP HEAD requests (in-window data, flags=PA) rather than TCP
    keep-alives (seq=our_seq-1, out-of-window). In-window data causes CDNs like
    Cloudflare to echo our exact TSval in the ACK, enabling unambiguous TSecr
    matching and correct RTT measurement.

    Benefits over synchronous sr1():
    - Bufferbloat probes queued > drain_timeout are still measured correctly
      (their true RTT is recorded, not clamped to a timeout value).
    - Truly dropped probes (no response during drain window) are identified as
      timed_out=True with rtt_ms=None — not confused with high-latency probes.
    - Probes in flight during phase transitions are still matched correctly.

    drain_timeout: seconds to wait after last probe is sent before declaring
    remaining pending probes as dropped. Default 5s catches up to ~5s queuing.
    """
    from scapy.all import IP, TCP, Raw, send, sniff, conf
    conf.verb = 0

    sport          = conn['sport']
    our_seq        = conn['our_seq']  & 0xFFFFFFFF   # mask to 32-bit TCP range
    their_seq      = conn['their_seq'] & 0xFFFFFFFF
    last_srv_tsval = conn['last_srv_tsval']

    # HTTP HEAD request as probe payload. Sending in-window data causes the server
    # to echo our exact TSval in its ACK, enabling precise TSecr-based matching.
    # This avoids the LIFO artifact of keep-alive probes (seq=our_seq-1, out-of-window)
    # where CDNs do not update TSecr.
    HEAD_REQ = (b'HEAD / HTTP/1.1\r\nHost: ' + target.encode() +
                b'\r\nConnection: keep-alive\r\n\r\n')
    HEAD_LEN = len(HEAD_REQ)

    pending = {}      # ts_key → entry (TSecr exact match)
    results = []
    lock    = threading.Lock()

    def _handle_response(pkt):
        nonlocal last_srv_tsval, their_seq
        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        if tcp.sport != port or tcp.dport != sport:
            return
        if int(tcp.flags) & 0x04:   # RST — connection reset
            if verbose:
                print("  [RST received — connection reset by server]")
            return
        if int(tcp.flags) & 0x01:   # FIN or FIN+ACK — server closing
            if verbose:
                print("  [FIN received — server closing connection]")
            return

        srv_tsval, srv_tsecr = _extract_ts(tcp)
        t_recv = time.monotonic_ns()

        # ACK incoming server data (HTTP HEAD response) to keep the TCP window clear.
        data_bytes = bytes(tcp.payload)
        if data_bytes:
            new_their_seq = (tcp.seq + len(data_bytes)) & 0xFFFFFFFF
            with lock:
                if _ts_delta(new_their_seq, their_seq) < 0x80000000:
                    their_seq = new_their_seq
                if srv_tsval is not None:
                    last_srv_tsval = srv_tsval
                cur_our_seq   = our_seq
                cur_their_seq = their_seq
                cur_tsecr     = last_srv_tsval
            ack_pkt = (IP(dst=target) /
                       TCP(dport=port, sport=sport,
                           seq=cur_our_seq, ack=cur_their_seq, flags='A',
                           options=[('Timestamp', (_tick(), cur_tsecr)),
                                    ('NOP', None), ('NOP', None)]))
            send(ack_pkt)

        # Exact TSecr match: server echoed our probe TSval → unambiguous identification.
        if srv_tsecr is None:
            return
        with lock:
            info = pending.pop(srv_tsecr, None)
            if srv_tsval is not None:
                last_srv_tsval = srv_tsval
        if info is None:
            return   # ACK for a previous, duplicate, or non-probe packet; ignore
        rtt_ms = (t_recv - info['t_send_ns']) / 1e6
        send_gap_ms = ((info['t_send_ns'] - info['prev_t_send_ns']) / 1e6
                       if info['prev_t_send_ns'] is not None else None)
        rec = {
            'probe':         info['probe'],
            'phase':         phase,
            't_send_ns':     info['t_send_ns'],
            't_recv_ns':     t_recv,
            'rtt_ms':        rtt_ms,
            'fwd_owd_ms':    rtt_ms / 2,
            'bwd_owd_ms':    rtt_ms / 2,
            'ts_sent':       srv_tsecr,
            'srv_tsval':     srv_tsval,
            'srv_tsecr':     srv_tsecr,
            'send_gap_ms':   send_gap_ms,
            'server_gap_ms': None,
            'fwd_ipdv_ms':   None,
            'bwd_ipdv_ms':   None,
        }
        with lock:
            results.append(rec)
        if verbose:
            gap = f'{send_gap_ms:.1f}' if send_gap_ms is not None else '--'
            ph  = f'[{phase}] ' if phase else ''
            print(f"  {ph}probe {info['probe']:>3}: RTT={rtt_ms:7.2f} ms  "
                  f"srv_tsval={srv_tsval}  send_gap={gap} ms")

    # Start background sniffer using sniff() — same proven mechanism as http_bootstrap
    _sniff_done  = threading.Event()
    _max_sniff_t = ((duration_secs if duration_secs is not None else count * interval)
                    + drain_timeout + 2.0)

    def _do_sniff():
        sniff(
            filter=f"tcp and src host {target} and src port {port} and dst port {sport}",
            prn=_handle_response,
            store=False,
            stop_filter=lambda _: _sniff_done.is_set(),
            timeout=_max_sniff_t,
        )

    sniffer_t = threading.Thread(target=_do_sniff, daemon=True)
    sniffer_t.start()
    time.sleep(0.15)   # brief wait for pcap socket to open

    prev_t_send_ns = None
    probe_num      = 0
    deadline       = (time.monotonic() + duration_secs) if duration_secs is not None else None

    while True:
        if deadline is not None and time.monotonic() >= deadline:
            break
        if deadline is None and probe_num >= count:
            break
        probe_num += 1
        ts_probe = _tick()
        with lock:
            cur_srv_tsval  = last_srv_tsval
            probe_our_seq  = our_seq
            our_seq        = (our_seq + HEAD_LEN) & 0xFFFFFFFF
            cur_their_seq  = their_seq
        pkt = (IP(dst=target, tos=0) /
               TCP(dport=port, sport=sport,
                   seq=probe_our_seq, ack=cur_their_seq,
                   flags='PA',
                   options=[('Timestamp', (ts_probe, cur_srv_tsval)),
                             ('NOP', None), ('NOP', None)]) /
               Raw(HEAD_REQ))
        t_send = time.monotonic_ns()
        entry = {
            'probe':          probe_num,
            't_send_ns':      t_send,
            'prev_t_send_ns': prev_t_send_ns,
            'ts_key':         ts_probe,
        }
        with lock:
            pending[ts_probe] = entry
        send(pkt)
        prev_t_send_ns = t_send
        time.sleep(max(0.0, interval - (time.monotonic_ns() - t_send) / 1e9))

    # Drain window — wait for late-arriving responses
    drain_end = time.monotonic() + drain_timeout
    while time.monotonic() < drain_end:
        with lock:
            n_pending = len(pending)
        if n_pending == 0:
            break
        time.sleep(0.05)

    _sniff_done.set()
    sniffer_t.join(timeout=2.0)   # wait for in-flight packets to be processed

    # Any probes still pending after drain window = truly dropped
    with lock:
        dropped  = list(pending.values())
        all_results = list(results)

    for info in dropped:
        if verbose:
            ph = f'[{phase}] ' if phase else ''
            print(f"  {ph}probe {info['probe']:>3}: DROPPED (no response in {drain_timeout:.0f}s)")
        all_results.append({
            'probe':       info['probe'],
            'phase':       phase,
            't_send_ns':   info['t_send_ns'],
            'rtt_ms':      None,
            'timed_out':   True,
            'fwd_owd_ms':  None,
            'bwd_owd_ms':  None,
            'fwd_ipdv_ms': None,
            'bwd_ipdv_ms': None,
        })

    all_results.sort(key=lambda r: r['probe'])
    return all_results


# ---------------------------------------------------------------------------
# H2 PING probes — HTTP/2 PING frames over TLS (port 443)
# ---------------------------------------------------------------------------

def run_h2_ping_probes(target, count, interval, verbose,
                       phase=None, duration_secs=None, drain_timeout=5.0,
                       h2_port=443):
    """Send HTTP/2 PING frames over TLS; use Scapy sniffer for TSval/RTT measurement.

    A Python ssl socket sends PING frames (RFC 7540 §6.7).  RTT is measured by
    matching PING ACK responses using the unique 8-byte PING payload (unambiguous,
    not affected by kernel TCP ACKs appearing on the same flow).  A parallel Scapy
    sniffer captures incoming TCP timestamps for OWD directional split.

    No iptables RST suppression needed — this is a real kernel-managed connection.

    Returns (results_list, conn_h2) where conn_h2 can be passed to compute_owd().
    Returns ([], None) if H2 is unavailable (port closed, ALPN failure, etc.).
    """
    import ssl
    import socket as _socket
    import os as _os

    from scapy.all import sniff, TCP as ScapyTCP, conf as scapy_conf
    scapy_conf.verb = 0

    # ---- TLS + H2 connection ----
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2'])
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE   # we measure latency, not verify identity

    try:
        raw   = _socket.create_connection((target, h2_port), timeout=5.0)
        sport = raw.getsockname()[1]
        tls   = ctx.wrap_socket(raw, server_hostname=target)
    except OSError as exc:
        if verbose:
            print(f"  [H2 PING] Cannot connect to {target}:{h2_port}: {exc}")
        return [], None

    if tls.selected_alpn_protocol() != 'h2':
        if verbose:
            print(f"  [H2 PING] Server did not negotiate HTTP/2 "
                  f"(got {tls.selected_alpn_protocol()!r})")
        tls.close()
        return [], None

    # ---- Frame I/O helpers ----
    def _recv_exact(n):
        buf = b''
        while len(buf) < n:
            try:
                chunk = tls.recv(n - len(buf))
            except _socket.timeout:
                raise                                  # re-raise; recv loop handles it
            except OSError:
                raise ConnectionError("TLS connection closed")
            if not chunk:
                raise ConnectionError("TLS connection closed")
            buf += chunk
        return buf

    def _read_h2_frame():
        """Read one HTTP/2 frame. Returns (type, flags, stream_id, payload)."""
        hdr    = _recv_exact(9)
        length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
        ftype  = hdr[3]
        flags  = hdr[4]
        sid    = int.from_bytes(hdr[5:9], 'big') & 0x7FFFFFFF
        data   = _recv_exact(length) if length else b''
        return ftype, flags, sid, data

    # ---- HTTP/2 client preface + SETTINGS handshake ----
    try:
        tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        # Empty SETTINGS: length=0, type=0x4, flags=0x0, stream_id=0
        tls.sendall(b'\x00\x00\x00\x04\x00\x00\x00\x00\x00')
        tls.settimeout(5.0)
        deadline_h2 = time.monotonic() + 5.0
        settings_acked = False
        while not settings_acked and time.monotonic() < deadline_h2:
            ftype, flags, _, _ = _read_h2_frame()
            if ftype == 0x04 and not (flags & 0x01):   # SETTINGS (not ACK)
                # SETTINGS ACK: length=0, type=0x4, flags=ACK(0x1), stream_id=0
                tls.sendall(b'\x00\x00\x00\x04\x01\x00\x00\x00\x00')
                settings_acked = True
            # Ignore WINDOW_UPDATE (0x8), SETTINGS ACK, etc.
    except (ConnectionError, OSError) as exc:
        if verbose:
            print(f"  [H2 PING] H2 handshake failed: {exc}")
        tls.close()
        return [], None

    # ---- Two-thread design: recv loop (RTT via payload match) + sniffer (TSval only) ----
    #
    # RTT measurement uses the 8-byte random PING payload as unique probe key.
    # The kernel sends many TCP ACKs as separate outgoing packets that Scapy would
    # capture, making outgoing-TSval → probe matching unreliable. Instead:
    #   Thread A (recv loop): reads H2 frames from TLS socket, matches PING ACKs by
    #                         payload — completely unambiguous, measures accurate RTT.
    #   Thread B (sniffer):   captures INCOMING TCP packets only, records (time, tsval)
    #                         — used to find server's TSval nearest to t_recv for OWD.

    pending_ping    = {}   # payload.hex() → {probe, t_send_ns, prev_t_send_ns}
    incoming_tsvals = []   # [(t_capture_ns, tsval), ...] — incoming from server only
    results         = []
    lock            = threading.Lock()

    def _nearest_tsval(t_recv_ns, window_ns=10_000_000):   # 10 ms window
        """Return server TSval from the incoming packet closest in time to t_recv_ns."""
        best_tsval = None
        best_dist  = window_ns
        for t_cap, tsval in incoming_tsvals:
            dist = abs(t_cap - t_recv_ns)
            if dist < best_dist:
                best_dist  = dist
                best_tsval = tsval
        return best_tsval

    # Thread B — Scapy sniffer: incoming packets only, record TSval + timestamp
    def _h2_sniffer_cb(pkt):
        if not pkt.haslayer(ScapyTCP):
            return
        tcp = pkt[ScapyTCP]
        if tcp.sport != h2_port or tcp.dport != sport:
            return   # only server→client packets
        tsval, _ = _extract_ts(tcp)
        if tsval is None:
            return
        t_now = time.monotonic_ns()
        with lock:
            incoming_tsvals.append((t_now, tsval))

    _sniff_done  = threading.Event()
    _max_sniff_t = ((duration_secs if duration_secs is not None else count * interval)
                    + drain_timeout + 2.0)

    def _do_h2_sniff():
        sniff(
            filter=(f"tcp and host {target} and port {h2_port} and port {sport}"),
            prn=_h2_sniffer_cb,
            store=False,
            stop_filter=lambda _: _sniff_done.is_set(),
            timeout=_max_sniff_t,
        )

    sniffer_t = threading.Thread(target=_do_h2_sniff, daemon=True)
    sniffer_t.start()
    time.sleep(0.15)   # brief wait for pcap socket to open

    # Thread A — TLS recv loop: match PING ACKs by payload, record RTT
    _recv_done = threading.Event()

    def _h2_recv_loop():
        while not _recv_done.is_set():
            try:
                tls.settimeout(0.5)
                ftype, flags, _, payload = _read_h2_frame()
                t_recv = time.monotonic_ns()
            except _socket.timeout:
                continue
            except (OSError, ConnectionError):
                break
            if ftype == 0x06 and (flags & 0x01):   # PING ACK (type=6, flags=ACK)
                key = payload.hex()
                with lock:
                    info = pending_ping.pop(key, None)
                if info is None:
                    continue
                rtt_ms  = (t_recv - info['t_send_ns']) / 1e6
                sgap_ms = ((info['t_send_ns'] - info['prev_t_send_ns']) / 1e6
                           if info['prev_t_send_ns'] is not None else None)
                with lock:
                    srv_tsval = _nearest_tsval(t_recv)
                rec = {
                    'probe':         info['probe'],
                    'phase':         phase,
                    't_send_ns':     info['t_send_ns'],
                    't_recv_ns':     t_recv,
                    'rtt_ms':        rtt_ms,
                    'fwd_owd_ms':    rtt_ms / 2,
                    'bwd_owd_ms':    rtt_ms / 2,
                    'ts_sent':       None,
                    'srv_tsval':     srv_tsval,
                    'srv_tsecr':     None,
                    'send_gap_ms':   sgap_ms,
                    'server_gap_ms': None,
                    'fwd_ipdv_ms':   None,
                    'bwd_ipdv_ms':   None,
                    'method':        'h2_ping',
                }
                with lock:
                    results.append(rec)
                if verbose:
                    gap = f"{sgap_ms:.1f}" if sgap_ms is not None else '--'
                    ph  = f'[{phase}] ' if phase else ''
                    print(f"  {ph}[H2] probe {info['probe']:>3}: RTT={rtt_ms:7.2f} ms  "
                          f"srv_tsval={srv_tsval}  send_gap={gap} ms")
            elif ftype == 0x07:   # GOAWAY — server closing
                break

    recv_t = threading.Thread(target=_h2_recv_loop, daemon=True)
    recv_t.start()

    # ---- PING send loop ----
    prev_t_send_ns = None
    probe_num      = 0
    deadline       = (time.monotonic() + duration_secs) if duration_secs is not None else None

    while True:
        if deadline is not None and time.monotonic() >= deadline:
            break
        if deadline is None and probe_num >= count:
            break
        probe_num += 1

        # PING frame: length=8, type=PING(0x6), flags=0x0, stream_id=0, 8-byte payload
        h2_payload = _os.urandom(8)
        ping_frame = b'\x00\x00\x08\x06\x00\x00\x00\x00\x00' + h2_payload
        t_send     = time.monotonic_ns()

        with lock:
            pending_ping[h2_payload.hex()] = {
                'probe':          probe_num,
                't_send_ns':      t_send,
                'prev_t_send_ns': prev_t_send_ns,
            }

        try:
            tls.sendall(ping_frame)
        except OSError:
            with lock:
                pending_ping.pop(h2_payload.hex(), None)
            break

        prev_t_send_ns = t_send
        elapsed        = (time.monotonic_ns() - t_send) / 1e9
        time.sleep(max(0.0, interval - elapsed))

    # ---- Drain window — wait for late-arriving PING ACKs (recv thread handles reads) ----
    drain_end = time.monotonic() + drain_timeout
    while time.monotonic() < drain_end:
        with lock:
            if not pending_ping:
                break
        time.sleep(0.05)

    _recv_done.set()
    recv_t.join(timeout=2.0)
    _sniff_done.set()
    sniffer_t.join(timeout=2.0)

    try:
        tls.close()
    except Exception:
        pass

    # Probes still pending after drain = truly dropped
    with lock:
        dropped     = list(pending_ping.values())
        all_results = list(results)

    for info in dropped:
        if verbose:
            ph = f'[{phase}] ' if phase else ''
            print(f"  {ph}[H2] probe {info['probe']:>3}: DROPPED "
                  f"(no response in {drain_timeout:.0f}s)")
        all_results.append({
            'probe':       info['probe'],
            'phase':       phase,
            't_send_ns':   info['t_send_ns'],
            'rtt_ms':      None,
            'timed_out':   True,
            'fwd_owd_ms':  None,
            'bwd_owd_ms':  None,
            'fwd_ipdv_ms': None,
            'bwd_ipdv_ms': None,
            'method':      'h2_ping',
        })

    all_results.sort(key=lambda r: r['probe'])

    # Build conn_h2 for compute_owd() — anchor from first valid probe response.
    # The first PING RTT/2 approximates the server's send-time offset from our clock.
    first_valid = next(
        (r for r in all_results
         if not r.get('timed_out') and r.get('srv_tsval') is not None),
        None,
    )
    conn_h2 = None
    if first_valid:
        conn_h2 = {
            'srv_tsval_at_handshake': first_valid['srv_tsval'],
            't_synack_ns':            first_valid['t_recv_ns'],
            'rtt_hs_ms':              first_valid['rtt_ms'],
        }

    return all_results, conn_h2


# ---------------------------------------------------------------------------
# OWD computation — direct server TSval clock method
# ---------------------------------------------------------------------------

def compute_owd(results, conn):
    """Compute per-probe absolute OWD using the server's TSval as a clock.

    Each probe is computed independently — no cumulative drift, no cross-probe
    dependencies.  Works correctly even when many probes time out (e.g. under
    heavy bufferbloat), because each surviving probe is anchored directly to
    the handshake rather than to the previous probe.

    Key insight: the server's TSval ticks at a stable Hz.  The SYN-ACK gives
    us a fixed reference:
        Anchor: server sent SYN-ACK with TSval=S0 at client time T_anchor_ns
                T_anchor_ns = conn['t_synack_ns'] − RTT_hs_ns/2

    For probe i (server TSval=S_i, received at t_recv_ns_i):
        T_server_tx_i = T_anchor_ns + _ts_delta(S_i, S0) / Hz * 1e9
        bwd_owd_ms    = (t_recv_ns_i − T_server_tx_i) / 1e6  ← download (server→client)
        fwd_owd_ms    = rtt_ms_i − bwd_owd_ms               ← upload   (client→server)

    Pass 1 — Hz estimation from first HZ_ESTIMATE_N valid probe pairs.
    Pass 2 — direct per-probe OWD via TSval clock (independent per probe).
    Pass 3 — per-pair IPDV for verbose diagnostics (upload/download deltas).

    Requires conn to contain 't_synack_ns', 'srv_tsval_at_handshake', and
    'rtt_hs_ms' — all populated by tcp_handshake().
    """
    valid = [r for r in results
             if not r.get('timed_out') and r['srv_tsval'] is not None
             and r.get('t_recv_ns') is not None]
    if len(valid) < 2:
        return

    # Pass 1: Hz estimation — prefer ALL BASELINE pairs (clean network, no congestion).
    # Hz error grows linearly with time from anchor; more BASELINE pairs → better median.
    hz_samples = []
    for i in range(1, len(valid)):
        # only use BASELINE-phase pairs when phase info is present
        if (valid[i].get('phase') and valid[i-1].get('phase')
                and valid[i]['phase'] != 'BASELINE'):
            continue
        srv_delta = _ts_delta(valid[i]['srv_tsval'], valid[i-1]['srv_tsval'])
        client_dt = (valid[i]['t_send_ns'] - valid[i-1]['t_send_ns']) / 1e9
        if client_dt > 0 and srv_delta > 0:
            hz_samples.append(srv_delta / client_dt)
    if not hz_samples:
        # standalone (no phases): fall back to first HZ_ESTIMATE_N pairs
        for i in range(1, min(HZ_ESTIMATE_N + 1, len(valid))):
            srv_delta = _ts_delta(valid[i]['srv_tsval'], valid[i-1]['srv_tsval'])
            client_dt = (valid[i]['t_send_ns'] - valid[i-1]['t_send_ns']) / 1e9
            if client_dt > 0 and srv_delta > 0:
                hz_samples.append(srv_delta / client_dt)
    if not hz_samples:
        return
    est_hz = statistics.median(hz_samples)
    hz_sample_count = len(hz_samples)
    if est_hz <= 0:
        return

    # Handshake anchor: server sent SYN-ACK with this TSval at this client time
    S0          = conn['srv_tsval_at_handshake']
    T_anchor_ns = conn['t_synack_ns'] - int(conn['rtt_hs_ms'] / 2 * 1e6)
    rtt_hs_ms   = conn['rtt_hs_ms']

    # Pass 2: direct per-probe OWD (each probe independent — no accumulation)
    for r in valid:
        srv_delta_ticks = _ts_delta(r['srv_tsval'], S0)
        T_server_tx_ns  = T_anchor_ns + int(srv_delta_ticks / est_hz * 1e9)
        bwd_owd_ms = (r['t_recv_ns'] - T_server_tx_ns) / 1e6   # download (server→client)
        fwd_owd_ms = r['rtt_ms'] - bwd_owd_ms                   # upload   (client→server)
        r['bwd_owd_ms']      = bwd_owd_ms
        r['fwd_owd_ms']      = fwd_owd_ms
        r['est_hz']          = round(est_hz)
        r['hz_sample_count'] = hz_sample_count

    # Pass 2b: calibration backstop — shift all probes so min(fwd_owd) >= 0.
    # Uses ALL valid probes (not just BASELINE) to catch Hz drift that accumulates
    # into the STRESS phase even after a good Hz estimate.  The shift preserves all
    # relative trends and phase comparisons; its magnitude = anchor asymmetry +
    # any residual Hz drift error.
    all_fwds = [r['fwd_owd_ms'] for r in valid if r['fwd_owd_ms'] is not None]
    if all_fwds:
        min_fwd = min(all_fwds)
        if min_fwd < 0:
            delta = -min_fwd
            for r in valid:
                if r['fwd_owd_ms'] is not None:
                    r['fwd_owd_ms'] += delta
                    r['bwd_owd_ms'] -= delta
                    r['cal_shift_ms'] = delta
            logging.debug(f"[OWD] calibration shift: fwd +{delta:.2f}ms, bwd -{delta:.2f}ms")

    # Pass 2c: per-probe plausibility clamp.
    # After calibration, each OWD direction must lie in [0, rtt_ms].
    # Violations mean the TSval anchor/Hz is unreliable for that probe;
    # revert to RTT/2 — honest "direction split unknown" estimate.
    for r in valid:
        fwd = r.get('fwd_owd_ms')
        bwd = r.get('bwd_owd_ms')
        if fwd is None or bwd is None:
            continue
        if fwd < 0 or bwd < 0 or fwd > r['rtt_ms']:
            r['fwd_owd_ms'] = r['rtt_ms'] / 2
            r['bwd_owd_ms'] = r['rtt_ms'] / 2

    # Pass 3: per-pair IPDV for diagnostics (upload/download delay deltas)
    for i in range(1, len(valid)):
        srv_delta     = _ts_delta(valid[i]['srv_tsval'], valid[i-1]['srv_tsval'])
        server_gap_ms = srv_delta / est_hz * 1000
        send_gap_ms   = (valid[i]['t_send_ns'] - valid[i-1]['t_send_ns']) / 1e6

        valid[i]['server_gap_ms'] = server_gap_ms
        # est_hz already set on all probes in Pass 2

        if send_gap_ms > 0:
            fwd_ipdv  = server_gap_ms - send_gap_ms   # upload IPDV   (client→server)
            rtt_delta = valid[i]['rtt_ms'] - valid[i-1]['rtt_ms']
            bwd_ipdv  = rtt_delta - fwd_ipdv          # download IPDV (server→client)
            valid[i]['fwd_ipdv_ms'] = fwd_ipdv
            valid[i]['bwd_ipdv_ms'] = bwd_ipdv


def compute_ipdv(results, conn=None):
    """Backward-compatible alias for compute_owd().

    Pass conn (the dict returned by tcp_handshake()) to use the direct
    TSval-clock OWD method.  Without conn this function is a no-op and
    OWD values will remain at the RTT/2 placeholder set by run_probes().
    """
    if conn is not None:
        compute_owd(results, conn)


# ---------------------------------------------------------------------------
# Traffic generator helpers (two-phase mode)
# ---------------------------------------------------------------------------

def start_traffic_gen(dl_clients, ul_clients, duration_secs):
    """Spawn traffic-gen.py in the background. Returns Popen object."""
    from pathlib import Path
    script = Path(__file__).parent / "traffic-gen.py"
    duration_mins = max(1, int(duration_secs / 60) + 1)
    cmd = [
        sys.executable, str(script),
        '-d', str(dl_clients),
        '-u', str(ul_clients),
        '-t', str(duration_mins),
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_traffic_gen(proc):
    """Terminate traffic-gen.py; SIGKILL after 15 s if still alive."""
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

def tcp_teardown(target, port, conn):
    """Send FIN to close the connection gracefully."""
    try:
        from scapy.all import IP, TCP, send, conf
        conf.verb = 0
        send(IP(dst=target) /
             TCP(dport=port, sport=conn['sport'],
                 seq=conn['our_seq'], ack=conn['their_seq'],
                 flags='FA'))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_SEP = '-' * 74


def print_table(results):
    has_phase = any(r.get('phase') for r in results)
    if has_phase:
        hdr = (f"{'#':>5}  {'Phase':>8}  {'RTT(ms)':>8}  {'FwdOWD†(ms)':>11}  "
               f"{'BwdOWD†(ms)':>11}  {'FwdIPDV(ms)':>11}  {'BwdIPDV(ms)':>11}")
    else:
        hdr = (f"{'#':>5}  {'RTT(ms)':>8}  {'FwdOWD†(ms)':>11}  {'BwdOWD†(ms)':>11}  "
               f"{'FwdIPDV(ms)':>11}  {'BwdIPDV(ms)':>11}")
    print(hdr)
    print('-' * len(hdr))
    for r in results:
        if r.get('timed_out'):
            if has_phase:
                print(f"{'--':>5}  {'--':>8}  {'timeout':>8}  {'--':>11}  "
                      f"{'--':>11}  {'--':>11}  {'--':>11}")
            else:
                print(f"{'--':>5}  {'timeout':>8}  {'--':>11}  {'--':>11}  "
                      f"{'--':>11}  {'--':>11}")
            continue
        fipd = f"{r['fwd_ipdv_ms']:+.2f}" if r['fwd_ipdv_ms'] is not None else '       --'
        bipd = f"{r['bwd_ipdv_ms']:+.2f}" if r['bwd_ipdv_ms'] is not None else '       --'
        if has_phase:
            ph = r.get('phase') or '--'
            print(f"{r['probe']:>5}  {ph:>8}  {r['rtt_ms']:>8.2f}  "
                  f"{r['fwd_owd_ms']:>11.2f}  {r['bwd_owd_ms']:>11.2f}  "
                  f"{fipd:>11}  {bipd:>11}")
        else:
            print(f"{r['probe']:>5}  {r['rtt_ms']:>8.2f}  "
                  f"{r['fwd_owd_ms']:>11.2f}  {r['bwd_owd_ms']:>11.2f}  "
                  f"{fipd:>11}  {bipd:>11}")


def _jitter_range(lst):
    """Peak-to-peak range of a list (max - min). Returns 0.0 for lists < 2 items."""
    return max(lst) - min(lst) if len(lst) > 1 else 0.0


def _print_method_comparison(http_results, h2_results=None):
    """Print 3-method OWD comparison table: M1 RTT/2, M2 TSval-dir, M3 H2 PING.

    http_results — results from run_probes_async() (HTTP HEAD port 80).
    h2_results   — results from run_h2_ping_probes() (port 443); optional.
    """
    valid_http = [r for r in http_results if not r.get('timed_out')]
    valid_h2   = [r for r in h2_results   if not r.get('timed_out')] if h2_results else []

    if not valid_http:
        return

    print()
    print(_SEP)
    print(" OWD Method Comparison")
    print(_SEP)
    print(f"  {'Method':<22}  {'Port':>4}  {'RTT avg':>8}  {'FwdOWD avg':>10}  "
          f"{'BwdOWD avg':>10}  {'Probes':>8}")
    print(f"  {'-'*22}  {'-'*4}  {'-'*8}  {'-'*10}  {'-'*10}  {'-'*8}")

    rtts_http = [r['rtt_ms'] for r in valid_http]
    avg_rtt   = statistics.mean(rtts_http)
    n_http    = len(valid_http)
    tot_http  = len(http_results)

    # M1: RTT/2 symmetric (same probe data as M2, symmetric OWD assumption)
    print(f"  {'M1: RTT/2 (symmetric)':<22}  {'80':>4}  {avg_rtt:>7.2f}ms  "
          f"{avg_rtt/2:>9.2f}ms  {avg_rtt/2:>9.2f}ms  {n_http:>4}/{tot_http}")

    # M2: TSval-directional (server clock split)
    fwds = [r['fwd_owd_ms'] for r in valid_http if r.get('fwd_owd_ms') is not None]
    bwds = [r['bwd_owd_ms'] for r in valid_http if r.get('bwd_owd_ms') is not None]
    if fwds and bwds:
        print(f"  {'M2: TSval-dir (server clk)':<22}  {'80':>4}  {avg_rtt:>7.2f}ms  "
              f"{statistics.mean(fwds):>9.2f}ms  {statistics.mean(bwds):>9.2f}ms  "
              f"{n_http:>4}/{tot_http}")

    # M3: H2 PING (port 443)
    if valid_h2:
        rtts_h2   = [r['rtt_ms'] for r in valid_h2]
        fwds_h2   = [r['fwd_owd_ms'] for r in valid_h2 if r.get('fwd_owd_ms') is not None]
        bwds_h2   = [r['bwd_owd_ms'] for r in valid_h2 if r.get('bwd_owd_ms') is not None]
        avg_h2    = statistics.mean(rtts_h2)
        n_h2      = len(valid_h2)
        tot_h2    = len(h2_results)
        fwd_h2    = statistics.mean(fwds_h2) if fwds_h2 else avg_h2 / 2
        bwd_h2    = statistics.mean(bwds_h2) if bwds_h2 else avg_h2 / 2
        print(f"  {'M3: H2 PING (TLS port 443)':<22}  {'443':>4}  {avg_h2:>7.2f}ms  "
              f"{fwd_h2:>9.2f}ms  {bwd_h2:>9.2f}ms  {n_h2:>4}/{tot_h2}")
    else:
        print(f"  {'M3: H2 PING (TLS port 443)':<22}  {'443':>4}  "
              f"{'N/A':>8}  {'N/A':>10}  {'N/A':>10}  {'N/A':>8}")

    print(_SEP)
    print("  M1 and M2 use the same HTTP HEAD probe data — differ only in OWD split method.")
    print("  M3 uses separate HTTP/2 PING probes (kernel-level ACK, no server processing delay).")
    print(_SEP)


def print_summary(results, rtt_hs_ms, h2_results=None):
    valid = [r for r in results if not r.get('timed_out')]
    if not valid:
        print("No valid probe responses.")
        return

    rtts = [r['rtt_ms']      for r in valid]
    fwds = [r['fwd_owd_ms']  for r in valid]
    bwds = [r['bwd_owd_ms']  for r in valid]
    fipd = [r['fwd_ipdv_ms'] for r in valid if r['fwd_ipdv_ms'] is not None]
    bipd = [r['bwd_ipdv_ms'] for r in valid if r['bwd_ipdv_ms'] is not None]

    jitter = _jitter_range

    fwd_change = fwds[-1] - fwds[0] if len(fwds) > 1 else 0.0
    bwd_change = bwds[-1] - bwds[0] if len(bwds) > 1 else 0.0

    print()
    print(_SEP)
    print(" Summary")
    print(_SEP)
    print(f"  Probes     : {len(valid)}/{len(results)} responded")
    print(f"  Handshake  : {rtt_hs_ms:.2f} ms RTT")
    print(f"  RTT        : min={min(rtts):.2f}  avg={statistics.mean(rtts):.2f}  "
          f"max={max(rtts):.2f}  jitter={jitter(rtts):.2f} ms")
    print(f"  Fwd OWD†   : start={fwds[0]:.2f}  end={fwds[-1]:.2f}  "
          f"change={fwd_change:+.2f} ms  [upload/outbound]")
    print(f"  Bwd OWD†   : start={bwds[0]:.2f}  end={bwds[-1]:.2f}  "
          f"change={bwd_change:+.2f} ms  [download/inbound]")

    if fipd and bipd:
        print(f"  Fwd jitter : {jitter(fipd):.2f} ms")
        print(f"  Bwd jitter : {jitter(bipd):.2f} ms")
        net = fwd_change - bwd_change
        if abs(net) > OWD_DIAGNOSIS_THRESHOLD:
            worse = "Upload/outbound" if net > 0 else "Download/inbound"
            print(f"  Asymmetry  : {worse} path degraded {abs(net):.1f} ms more")
        else:
            print(f"  Asymmetry  : Paths changed symmetrically")
    else:
        print(f"  IPDV       : insufficient data (need ≥2 valid probes)")

    est_hz_val = valid[0].get('est_hz') if valid else None
    hz_n       = valid[0].get('hz_sample_count', 0) if valid else 0
    cal_shift  = max((r.get('cal_shift_ms', 0.0) for r in valid), default=0.0)
    if est_hz_val:
        hz_line = f"  TSval clock : {est_hz_val} Hz  ({hz_n} pairs)"
        if cal_shift > 0:
            hz_line += f"  |  cal.shift +{cal_shift:.2f}ms"
            if cal_shift > 5:
                hz_line += "  \u26a0 large shift \u2014 OWD split unreliable"
        print(hz_line)
    print(_SEP)
    print("  \u2020 Direct TSval-clock OWD. Anchor = handshake RTT/2 (assumes symmetric start).")
    print("    Each probe independent \u2014 no cumulative drift.")
    print(_SEP)

    if h2_results is not None:
        _print_method_comparison(results, h2_results)


# ---------------------------------------------------------------------------
# Phase comparison summary (two-phase mode)
# ---------------------------------------------------------------------------

def _percentile(lst, pct):
    """numpy-free percentile on a list of floats."""
    if not lst:
        return 0.0
    s = sorted(lst)
    idx = int(len(s) * pct / 100)
    return s[min(idx, len(s) - 1)]


def _owd_diagnosis(b, s):
    """Return a human-readable congestion direction verdict.

    b, s — stats dicts for BASELINE and STRESS phases
           (keys: fwd_avg, fwd_p95, bwd_avg, bwd_p95).
    Returns a multi-line string suitable for direct printing.
    """
    fwd_d_avg = s['fwd_avg'] - b['fwd_avg']
    bwd_d_avg = s['bwd_avg'] - b['bwd_avg']
    fwd_d_p95 = s['fwd_p95'] - b['fwd_p95']
    bwd_d_p95 = s['bwd_p95'] - b['bwd_p95']

    fwd_worse = fwd_d_avg > OWD_DIAGNOSIS_THRESHOLD
    bwd_worse = bwd_d_avg > OWD_DIAGNOSIS_THRESHOLD

    # fwd = upload (client→server); bwd = download (server→client)
    if fwd_worse and bwd_worse:
        if abs(fwd_d_avg - bwd_d_avg) < OWD_SYMMETRIC_THRESHOLD:
            direction = "Both directions degraded symmetrically (mid-path / end-to-end congestion)"
        elif fwd_d_avg > bwd_d_avg:
            direction = "OUTBOUND (upload) path is the primary bottleneck"
        else:
            direction = "INBOUND (download) path is the primary bottleneck"
    elif fwd_worse:
        direction = "OUTBOUND (upload) path degraded — inbound (download) was stable"
    elif bwd_worse:
        direction = "INBOUND (download) path degraded — outbound (upload) was stable"
    else:
        direction = "No significant OWD increase detected under stress"

    return (
        f"  Diagnosis  : {direction}\n"
        f"               FwdOWD\u2020 (upload)   \u0394avg={fwd_d_avg:>+7.1f}ms  \u0394p95={fwd_d_p95:>+7.1f}ms\n"
        f"               BwdOWD\u2020 (download) \u0394avg={bwd_d_avg:>+7.1f}ms  \u0394p95={bwd_d_p95:>+7.1f}ms"
    )


def print_phase_summary(results, phase_loss=None, phase_jitter_override=None):
    """Print BASELINE vs STRESS side-by-side comparison table.

    phase_loss: optional dict mapping phase tag → probe loss %.
    phase_jitter_override: optional dict mapping phase tag → (fwd_jitter_ms, bwd_jitter_ms).
      When provided, these values replace the IPDV-only jitter computed from received probes.
      Typically passed from userbufferTest.py with timeout-inclusive RTT range jitter.
    """
    phases = {}
    for r in results:
        if r.get('timed_out'):
            continue
        ph = r.get('phase') or 'ALL'
        phases.setdefault(ph, []).append(r)

    if len(phases) < 2:
        return

    print()
    print(_SEP)
    print(" Phase Comparison")
    print(_SEP)

    col = 11
    jcol = 12
    hdr = (f"  {'Phase':10}  {'FwdOWD†avg':>{col}}  {'FwdOWD†p95':>{col}}  "
           f"{'BwdOWD†avg':>{col}}  {'BwdOWD†p95':>{col}}  "
           f"{'RTT avg':>8}  {'RTT p95':>8}  "
           f"{'FwdJitter':>{jcol}}  {'BwdJitter':>{jcol}}")
    print(hdr)
    print('  ' + '-' * (len(hdr) - 2))

    stats = {}
    for ph in ('BASELINE', 'STRESS'):
        recs = phases.get(ph)
        if not recs:
            continue
        rtts = [r['rtt_ms']     for r in recs]
        fwds = [r['fwd_owd_ms'] for r in recs]
        bwds = [r['bwd_owd_ms'] for r in recs]
        fipd = [r['fwd_ipdv_ms'] for r in recs if r.get('fwd_ipdv_ms') is not None]
        bipd = [r['bwd_ipdv_ms'] for r in recs if r.get('bwd_ipdv_ms') is not None]
        fwd_jitter = _jitter_range(fipd)
        bwd_jitter = _jitter_range(bipd)
        stats[ph] = {
            'fwd_avg': statistics.mean(fwds),  'fwd_p95': _percentile(fwds, PERCENTILE_P95),
            'bwd_avg': statistics.mean(bwds),  'bwd_p95': _percentile(bwds, PERCENTILE_P95),
            'rtt_avg': statistics.mean(rtts),  'rtt_p95': _percentile(rtts, PERCENTILE_P95),
            'fwd_jitter': fwd_jitter,          'bwd_jitter': bwd_jitter,
        }
        # Use override jitter (timeout-inclusive, from userbufferTest.py) if provided
        if phase_jitter_override and ph in phase_jitter_override:
            fwd_jitter, bwd_jitter = phase_jitter_override[ph]
            stats[ph]['fwd_jitter'] = fwd_jitter
            stats[ph]['bwd_jitter'] = bwd_jitter
        print(f"  {ph:10}  "
              f"{stats[ph]['fwd_avg']:>{col}.2f}  {stats[ph]['fwd_p95']:>{col}.2f}  "
              f"{stats[ph]['bwd_avg']:>{col}.2f}  {stats[ph]['bwd_p95']:>{col}.2f}  "
              f"{stats[ph]['rtt_avg']:>8.2f}  {stats[ph]['rtt_p95']:>8.2f}  "
              f"{fwd_jitter:>{jcol}.2f}  {bwd_jitter:>{jcol}.2f}")

    if 'BASELINE' in stats and 'STRESS' in stats:
        b, s = stats['BASELINE'], stats['STRESS']
        print('  ' + '-' * (len(hdr) - 2))
        print(f"  {'Change':10}  "
              f"{s['fwd_avg']-b['fwd_avg']:>+{col}.2f}  {s['fwd_p95']-b['fwd_p95']:>+{col}.2f}  "
              f"{s['bwd_avg']-b['bwd_avg']:>+{col}.2f}  {s['bwd_p95']-b['bwd_p95']:>+{col}.2f}  "
              f"{s['rtt_avg']-b['rtt_avg']:>+8.2f}  {s['rtt_p95']-b['rtt_p95']:>+8.2f}  "
              f"{s['fwd_jitter']-b['fwd_jitter']:>+{jcol}.2f}  {s['bwd_jitter']-b['bwd_jitter']:>+{jcol}.2f}")

    all_valid  = [r for r in results if not r.get('timed_out')]
    est_hz_val = all_valid[0].get('est_hz') if all_valid else None
    hz_n       = all_valid[0].get('hz_sample_count', 0) if all_valid else 0
    cal_shift  = max((r.get('cal_shift_ms', 0.0) for r in all_valid), default=0.0)

    if 'BASELINE' in stats and 'STRESS' in stats:
        print(_SEP)
        if cal_shift > 5:
            print(f"  Diagnosis  : \u26a0 Low-confidence \u2014 calibration shift +{cal_shift:.1f}ms (anchor error >5ms).")
            print(f"               OWD direction split unreliable. Use IPDV jitter and RTT jitter.")
        else:
            print(_owd_diagnosis(stats['BASELINE'], stats['STRESS']))
    print(_SEP)
    print("  \u2020 End-to-end only (single TCP connection to target). No NTP required.")
    print("    Direct TSval-clock OWD; anchor = handshake RTT/2. Each probe independent.")
    print("    Fwd = upload (client\u2192server)  |  Bwd = download (server\u2192client)")
    print("  + = latency increased (worse);  \u2212 = latency decreased (better).")
    if est_hz_val:
        hz_line = f"    TSval clock: {est_hz_val} Hz  ({hz_n} pairs used for Hz estimate)"
        if cal_shift > 0:
            hz_line += f"  |  calibration shift applied: +{cal_shift:.2f}ms"
            if cal_shift > 5:
                hz_line += "  \u26a0 large \u2014 OWD split low-confidence"
        print(hz_line)
    print(_SEP)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def save_csv(results, path, target, port):
    has_phase = any(r.get('phase') for r in results)
    base_fields = ['probe', 't_send_ns', 'rtt_ms', 'fwd_owd_ms', 'bwd_owd_ms',
                   'fwd_ipdv_ms', 'bwd_ipdv_ms', 'srv_tsval', 'server_gap_ms', 'send_gap_ms']
    fields = (['phase'] + base_fields) if has_phase else base_fields
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['# tcp_owd.py', f'target={target}', f'port={port}'])
        w.writerow(fields)
        for r in results:
            if r.get('timed_out'):
                w.writerow(['timeout'] + [''] * (len(fields) - 1))
                continue
            row = []
            if has_phase:
                row.append(r.get('phase') or '')
            row.extend([
                r['probe'], r['t_send_ns'],
                f"{r['rtt_ms']:.4f}",
                f"{r['fwd_owd_ms']:.4f}",
                f"{r['bwd_owd_ms']:.4f}",
                f"{r['fwd_ipdv_ms']:.4f}"   if r['fwd_ipdv_ms']   is not None else '',
                f"{r['bwd_ipdv_ms']:.4f}"   if r['bwd_ipdv_ms']   is not None else '',
                r['srv_tsval']              if r['srv_tsval']      is not None else '',
                f"{r['server_gap_ms']:.4f}" if r['server_gap_ms'] is not None else '',
                f"{r['send_gap_ms']:.4f}"   if r['send_gap_ms']   is not None else '',
            ])
            w.writerow(row)
    print(f"\nResults saved → {path}")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description=(
            'TCP Timestamp OWD estimator — per-direction RTT/IPDV/OWD '
            'using RFC 7323 TSval on an established HTTP connection.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 tcp_owd.py --target 1.1.1.1 --port 80
  sudo python3 tcp_owd.py --target 8.8.8.8 --count 30 --interval 0.5
  sudo python3 tcp_owd.py --target 10.0.0.1 --output results.csv --verbose

Requires: root / CAP_NET_RAW,  pip install scapy,  Linux iptables.
Port 80 recommended for CDN targets (HTTP keep-alive works reliably).
""",
    )
    p.add_argument('--target',     '-T', required=True,
                   help='Target IP address')
    p.add_argument('--port',       '-p', type=int,   default=DEFAULT_PORT,
                   help=f'Open TCP port (default: {DEFAULT_PORT})')
    p.add_argument('--count',      '-n', type=int,   default=DEFAULT_COUNT,
                   help=f'Keep-alive probes to send — single-phase mode (default: {DEFAULT_COUNT})')
    p.add_argument('--interval',   '-i', type=float, default=DEFAULT_INTERVAL,
                   help=f'Seconds between probes (default: {DEFAULT_INTERVAL})')
    p.add_argument('--timeout',    '-w', type=float, default=DEFAULT_TIMEOUT,
                   help=f'Seconds to wait per probe (default: {DEFAULT_TIMEOUT})')
    p.add_argument('--output',     '-o',
                   help='Save per-probe results to CSV file')
    p.add_argument('--verbose',    '-v', action='store_true',
                   help='Print raw TSval fields for every probe')

    two = p.add_argument_group(
        'Two-phase mode (baseline → auto-start traffic-gen → stress)',
        'When --baseline or --stress > 0, replaces --count with duration-based loops.')
    two.add_argument('--baseline', '-b', type=float, default=DEFAULT_BASELINE_SEC,
                     metavar='SECS',
                     help=f'Idle baseline measurement duration in seconds (default: {DEFAULT_BASELINE_SEC})')
    two.add_argument('--stress',   '-s', type=float, default=DEFAULT_STRESS_SEC,
                     metavar='SECS',
                     help=f'Stress measurement duration in seconds (default: {DEFAULT_STRESS_SEC})')
    two.add_argument('--dl-clients', type=int, default=DEFAULT_DL_CLIENTS,
                     metavar='N',
                     help=f'Download clients for traffic-gen (default: {DEFAULT_DL_CLIENTS})')
    two.add_argument('--ul-clients', type=int, default=DEFAULT_UL_CLIENTS,
                     metavar='N',
                     help=f'Upload clients for traffic-gen (default: {DEFAULT_UL_CLIENTS})')
    return p.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if os.geteuid() != 0:
        print("Error: tcp_owd.py requires root (raw socket + iptables).", file=sys.stderr)
        print("  sudo python3 tcp_owd.py --target ...", file=sys.stderr)
        sys.exit(1)

    two_phase = args.baseline > 0 or args.stress > 0

    atexit.register(_remove_rst)
    signal.signal(signal.SIGINT,  _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    print(f"\nTCP Timestamp OWD Estimator")
    print(f"  Target   : {args.target}:{args.port}")
    if two_phase:
        print(f"  Mode     : Two-phase  (baseline={args.baseline}s  stress={args.stress}s)")
        print(f"  Traffic  : {args.dl_clients} DL + {args.ul_clients} UL clients")
    else:
        print(f"  Probes   : {args.count} keep-alives @ {args.interval}s interval")
    print(f"  Timeout  : {args.timeout}s per probe")
    print()

    print("Installing iptables RST suppression ...")
    try:
        _install_rst(args.target)
    except subprocess.CalledProcessError as exc:
        print(f"Error: iptables failed: {exc}", file=sys.stderr)
        sys.exit(1)

    conn    = None
    results = []
    tg_proc = None
    try:
        print(f"Connecting to {args.target}:{args.port} ...")
        conn = tcp_handshake(args.target, args.port, args.timeout, args.verbose)
        print(f"  Handshake RTT : {conn['rtt_hs_ms']:.2f} ms")

        print("Bootstrapping connection with HTTP HEAD request ...")
        http_bootstrap(args.target, args.port, conn, args.timeout, args.verbose)
        print("  Bootstrap OK.")
        print()

        _drain = max(args.timeout * 2, 5.0)

        if two_phase:
            all_results = []

            if args.baseline > 0:
                print(f"Phase 1 — BASELINE ({args.baseline:.0f}s, network idle) ...")
                baseline_results = run_probes_async(
                    args.target, args.port, conn,
                    count=0, interval=args.interval, verbose=args.verbose,
                    phase='BASELINE', duration_secs=args.baseline,
                    drain_timeout=_drain,
                )
                all_results.extend(baseline_results)
                n_ok = sum(1 for r in baseline_results if not r.get('timed_out'))
                print(f"  Baseline complete: {n_ok}/{len(baseline_results)} probes responded.")
                print()

            if args.stress > 0:
                total_tg_secs = args.stress + STRESS_RAMP_SEC + 10
                print("Starting traffic generator ...")
                tg_proc = start_traffic_gen(args.dl_clients, args.ul_clients, total_tg_secs)
                print(f"  Waiting {STRESS_RAMP_SEC}s for congestion to build ...")
                time.sleep(STRESS_RAMP_SEC)
                print()

                print(f"Phase 2 — STRESS ({args.stress:.0f}s, network under load) ...")
                stress_results = run_probes_async(
                    args.target, args.port, conn,
                    count=0, interval=args.interval, verbose=args.verbose,
                    phase='STRESS', duration_secs=args.stress,
                    drain_timeout=_drain,
                )
                all_results.extend(stress_results)
                n_ok = sum(1 for r in stress_results if not r.get('timed_out'))
                print(f"  Stress complete: {n_ok}/{len(stress_results)} probes responded.")

                print("\nStopping traffic generator ...")
                stop_traffic_gen(tg_proc)
                tg_proc = None
                print("  Traffic generator stopped.")

            results = all_results

        else:
            print(f"Sending {args.count} HTTP HEAD probes ...")
            results = run_probes_async(
                args.target, args.port, conn,
                count=args.count, interval=args.interval, verbose=args.verbose,
                drain_timeout=_drain,
            )

        compute_owd(results, conn)

    except RuntimeError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
    finally:
        if tg_proc is not None:
            stop_traffic_gen(tg_proc)
        if conn:
            tcp_teardown(args.target, args.port, conn)
        _remove_rst()
        print("\niptables rule removed.")

    if not results:
        sys.exit(1)

    print()
    print_table(results)

    # H2 PING probes — run after HTTP HEAD probes for side-by-side comparison
    h2_results = None
    if results and conn:
        print()
        print(f"Running HTTP/2 PING probes ({args.target}:443) ...")
        h2_res, conn_h2 = run_h2_ping_probes(
            args.target,
            count=len(results),
            interval=args.interval,
            verbose=args.verbose,
        )
        if conn_h2 and h2_res:
            compute_owd(h2_res, conn_h2)
            h2_results = h2_res
            n_h2 = sum(1 for r in h2_results if not r.get('timed_out'))
            print(f"  H2 PING complete: {n_h2}/{len(h2_results)} probes responded.")
        else:
            print("  H2 PING: not available (port 443 closed or HTTP/2 not supported).")

    if two_phase:
        print_phase_summary(results)
    else:
        print_summary(results, conn['rtt_hs_ms'] if conn else 0.0,
                      h2_results=h2_results)

    if args.output:
        save_csv(results, args.output, args.target, args.port)


if __name__ == '__main__':
    main()
