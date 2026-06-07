#!/usr/bin/env python3
"""
CodeAlpha Internship — Task 4: Network Intrusion Detection System (NIDS)
Author: Pawan Kumar V
Description:
    Pure-Python NIDS that monitors live network traffic and detects:
      - Port scans (SYN scan, NULL scan, XMAS scan, FIN scan)
      - Brute-force / login flood (SSH, FTP, Telnet, HTTP)
      - ICMP flood / Ping of Death
      - UDP flood / DNS amplification
      - ARP spoofing / ARP poisoning
      - HTTP suspicious patterns (SQLi, path traversal, XSS probes)
      - Suspicious payloads (common malware signatures)

Run with: sudo python3 nids.py [-i INTERFACE] [-l LOG] [-a ALERT_CMD]
"""

import sys
import os
import re
import time
import datetime
import argparse
import threading
import json
import signal
from collections import defaultdict, deque
from typing import Optional

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, Ether,
        get_if_list
    )
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("[-] Scapy not found. Install: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────────────────
R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"
B = "\033[94m"; M = "\033[95m"; C = "\033[96m"
BOLD = "\033[1m"; RESET = "\033[0m"

SEV_COLOUR = {"CRITICAL": R+BOLD, "HIGH": R, "MEDIUM": Y, "LOW": B, "INFO": C}

# ─────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────
CONFIG = {
    # Port scan detection thresholds
    "port_scan_threshold":    15,    # unique ports within window → alert
    "port_scan_window_sec":   10,

    # Brute-force detection
    "brute_force_threshold":  10,    # SYN packets to same port within window
    "brute_force_window_sec": 5,

    # ICMP flood
    "icmp_flood_threshold":   50,    # ICMP pkts from same src within window
    "icmp_flood_window_sec":  5,

    # UDP flood
    "udp_flood_threshold":    100,
    "udp_flood_window_sec":   5,

    # ARP cache for spoofing detection (ip → mac)
    "arp_cache": {},

    # Services subject to brute-force monitoring
    "brute_force_ports": {22: "SSH", 21: "FTP", 23: "Telnet",
                          3306: "MySQL", 5432: "PostgreSQL",
                          3389: "RDP", 80: "HTTP", 443: "HTTPS"},
}

# ─────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────
# {src_ip: deque of (timestamp, dst_port)}
port_scan_tracker   = defaultdict(deque)
# {src_ip: {dst_port: deque of timestamps}}
brute_force_tracker = defaultdict(lambda: defaultdict(deque))
# {src_ip: deque of timestamps}
icmp_tracker        = defaultdict(deque)
udp_tracker         = defaultdict(deque)

alerts          = []           # All fired alerts
alert_lock      = threading.Lock()
packet_count    = 0
alert_count     = 0
start_time      = time.time()

LOG_FILE        = ""
ALERT_COMMAND   = None         # Optional shell command to execute on CRITICAL alert

# ─────────────────────────────────────────────────────────
# HTTP suspicious patterns
# ─────────────────────────────────────────────────────────
HTTP_PATTERNS = [
    (re.compile(r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|' *or *'|1=1|--\s)", re.I), "SQL Injection probe"),
    (re.compile(r"\.\./|\.\.%2f|%2e%2e%2f",                               re.I), "Path Traversal probe"),
    (re.compile(r"<script|javascript:|onerror=|onload=|alert\(|prompt\(", re.I), "XSS probe"),
    (re.compile(r"/etc/passwd|/etc/shadow|/proc/self",                    re.I), "LFI probe"),
    (re.compile(r"cmd\.exe|powershell|/bin/sh|/bin/bash",                 re.I), "RCE probe"),
    (re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|python-requests",       re.I), "Scanner detected"),
]

# Common malware payload signatures (simplified hex/string patterns)
PAYLOAD_SIGNATURES = [
    (re.compile(rb"cmd\.exe|powershell\.exe",             re.I), "Windows shell execution"),
    (re.compile(rb"/bin/sh|/bin/bash",                    re.I), "Unix shell execution"),
    (re.compile(rb"SELECT.*FROM.*WHERE",                  re.I), "SQL in payload"),
    (re.compile(rb"<script",                              re.I), "JavaScript injection"),
    (re.compile(rb"\x90{10,}",                                ), "NOP sled (shellcode?)"),
    (re.compile(rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",       ), "EICAR test string"),
]

# ─────────────────────────────────────────────────────────
# Alert Engine
# ─────────────────────────────────────────────────────────

def fire_alert(severity: str, category: str, src_ip: str, dst_ip: str,
               message: str, extra: str = ""):
    global alert_count
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_count += 1

    record = {
        "id": alert_count,
        "timestamp": ts,
        "severity": severity,
        "category": category,
        "src": src_ip,
        "dst": dst_ip,
        "message": message,
        "extra": extra,
    }

    col = SEV_COLOUR.get(severity, "")
    line = (
        f"\n{col}{'█'*60}{RESET}\n"
        f"{col}[{ts}] ALERT #{alert_count} — {severity}{RESET}\n"
        f"  Category : {category}\n"
        f"  Source   : {src_ip}  →  {dst_ip}\n"
        f"  Message  : {message}\n"
        f"  Detail   : {extra}\n"
        f"{col}{'█'*60}{RESET}"
    )
    print(line)

    with alert_lock:
        alerts.append(record)
        if LOG_FILE:
            with open(LOG_FILE, "a") as f:
                # Strip ANSI
                clean = re.sub(r'\033\[[0-9;]*m', '', line)
                f.write(clean + "\n")

    # Optional alert action
    if ALERT_COMMAND and severity == "CRITICAL":
        os.system(ALERT_COMMAND.replace("{src}", src_ip))


# ─────────────────────────────────────────────────────────
# Detection Functions
# ─────────────────────────────────────────────────────────

def _prune(dq: deque, window: float):
    """Remove timestamps older than window seconds."""
    cutoff = time.time() - window
    while dq and dq[0] < cutoff:
        dq.popleft()


def detect_port_scan(src_ip: str, dst_ip: str, dst_port: int, flags):
    now = time.time()
    cfg = CONFIG

    # Only track SYN-only, FIN-only, NULL (no flags), XMAS (FIN+PSH+URG)
    flag_val = int(flags)
    scan_type = None
    if flag_val == 0x02:          scan_type = "SYN Scan"
    elif flag_val == 0x01:        scan_type = "FIN Scan"
    elif flag_val == 0x00:        scan_type = "NULL Scan"
    elif flag_val & 0x29 == 0x29: scan_type = "XMAS Scan"
    if not scan_type:
        return

    dq = port_scan_tracker[src_ip]
    dq.append((now, dst_port))
    _prune_port(dq, cfg["port_scan_window_sec"])

    unique_ports = len(set(p for _, p in dq))
    if unique_ports >= cfg["port_scan_threshold"]:
        fire_alert("HIGH", "Port Scan", src_ip, dst_ip,
                   f"{scan_type} detected — {unique_ports} unique ports probed",
                   f"in {cfg['port_scan_window_sec']}s window")
        port_scan_tracker[src_ip].clear()


def _prune_port(dq: deque, window: float):
    cutoff = time.time() - window
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def detect_brute_force(src_ip: str, dst_ip: str, dst_port: int, flags):
    svc = CONFIG["brute_force_ports"].get(dst_port)
    if not svc:
        return
    if not (int(flags) & 0x02):  # Only SYN packets
        return

    now = time.time()
    dq = brute_force_tracker[src_ip][dst_port]
    dq.append(now)
    _prune(dq, CONFIG["brute_force_window_sec"])

    if len(dq) >= CONFIG["brute_force_threshold"]:
        fire_alert("HIGH", "Brute Force / Login Flood", src_ip, dst_ip,
                   f"{svc} brute-force attack — {len(dq)} SYNs on port {dst_port}",
                   f"in {CONFIG['brute_force_window_sec']}s window")
        brute_force_tracker[src_ip][dst_port].clear()


def detect_icmp_flood(src_ip: str, dst_ip: str, icmp_type: int):
    now = time.time()
    dq = icmp_tracker[src_ip]
    dq.append(now)
    _prune(dq, CONFIG["icmp_flood_window_sec"])

    if len(dq) >= CONFIG["icmp_flood_threshold"]:
        fire_alert("HIGH", "ICMP Flood / DoS", src_ip, dst_ip,
                   f"ICMP flood — {len(dq)} packets in {CONFIG['icmp_flood_window_sec']}s",
                   f"ICMP type {icmp_type}")
        icmp_tracker[src_ip].clear()


def detect_udp_flood(src_ip: str, dst_ip: str):
    now = time.time()
    dq = udp_tracker[src_ip]
    dq.append(now)
    _prune(dq, CONFIG["udp_flood_window_sec"])

    if len(dq) >= CONFIG["udp_flood_threshold"]:
        fire_alert("MEDIUM", "UDP Flood / DoS", src_ip, dst_ip,
                   f"UDP flood — {len(dq)} packets in {CONFIG['udp_flood_window_sec']}s",
                   "Possible UDP DDoS or amplification attack")
        udp_tracker[src_ip].clear()


def detect_arp_spoof(src_ip: str, src_mac: str, dst_ip: str):
    cache = CONFIG["arp_cache"]
    if src_ip in cache and cache[src_ip] != src_mac:
        fire_alert("CRITICAL", "ARP Spoofing", src_ip, dst_ip,
                   f"ARP cache poisoning — IP {src_ip} changed MAC",
                   f"Old MAC: {cache[src_ip]}  →  New MAC: {src_mac}")
    cache[src_ip] = src_mac


def detect_http_attack(src_ip: str, dst_ip: str, uri: str, user_agent: str, method: str):
    combined = f"{method} {uri} {user_agent}"
    for pattern, label in HTTP_PATTERNS:
        if pattern.search(combined):
            fire_alert("HIGH", "Web Attack", src_ip, dst_ip,
                       f"{label} detected in HTTP request",
                       f"{method} {uri[:120]}")
            return  # One alert per packet


def detect_payload_signature(src_ip: str, dst_ip: str, payload: bytes):
    for pattern, label in PAYLOAD_SIGNATURES:
        if pattern.search(payload):
            fire_alert("CRITICAL", "Malicious Payload", src_ip, dst_ip,
                       f"Payload signature matched: {label}",
                       f"First 60 bytes: {payload[:60]!r}")
            return


# ─────────────────────────────────────────────────────────
# Packet Handler
# ─────────────────────────────────────────────────────────

def process_packet(packet):
    global packet_count
    packet_count += 1

    # ── ARP ───────────────────────────────────────────────────────────
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 2:   # ARP reply
            detect_arp_spoof(arp.psrc, arp.hwsrc, arp.pdst)
        return

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # ── TCP ───────────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        detect_port_scan(src_ip, dst_ip, tcp.dport, tcp.flags)
        detect_brute_force(src_ip, dst_ip, tcp.dport, tcp.flags)

        # HTTP inspection
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            uri  = req.Path.decode("utf-8", errors="replace")   if hasattr(req, 'Path')       else ""
            ua   = req.User_Agent.decode("utf-8", errors="replace") if hasattr(req, 'User_Agent') else ""
            meth = req.Method.decode("utf-8", errors="replace") if hasattr(req, 'Method')     else "GET"
            detect_http_attack(src_ip, dst_ip, uri, ua, meth)

        # Raw payload signatures
        if packet.haslayer(Raw):
            detect_payload_signature(src_ip, dst_ip, bytes(packet[Raw].load))

    # ── UDP ───────────────────────────────────────────────────────────
    elif packet.haslayer(UDP):
        detect_udp_flood(src_ip, dst_ip)
        if packet.haslayer(Raw):
            detect_payload_signature(src_ip, dst_ip, bytes(packet[Raw].load))

    # ── ICMP ──────────────────────────────────────────────────────────
    elif packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        detect_icmp_flood(src_ip, dst_ip, icmp_type)


# ─────────────────────────────────────────────────────────
# Stats Thread
# ─────────────────────────────────────────────────────────

def stats_thread(interval: int = 30):
    while True:
        time.sleep(interval)
        elapsed = time.time() - start_time
        rate    = packet_count / elapsed if elapsed > 0 else 0
        ts      = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n{C}[{ts}] STATS — Packets: {packet_count} | Alerts: {alert_count} | Rate: {rate:.1f} pkt/s{RESET}")


# ─────────────────────────────────────────────────────────
# Save alerts on exit
# ─────────────────────────────────────────────────────────

def save_json_report():
    fname = f"nids_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump({
            "start": datetime.datetime.fromtimestamp(start_time).isoformat(),
            "packets": packet_count,
            "alerts": alerts
        }, f, indent=2)
    print(f"\n[+] Alert report saved: {fname}")


def graceful_exit(sig, frame):
    print(f"\n\n{BOLD}[!] NIDS stopped.{RESET}")
    save_json_report()
    summary()
    sys.exit(0)


def summary():
    elapsed = time.time() - start_time
    sev_counts = defaultdict(int)
    for a in alerts:
        sev_counts[a["severity"]] += 1

    print(f"\n{'═'*60}")
    print(f"{BOLD}  NIDS SESSION SUMMARY{RESET}")
    print(f"{'─'*60}")
    print(f"  Duration     : {elapsed:.0f}s")
    print(f"  Packets seen : {packet_count}")
    print(f"  Total alerts : {alert_count}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = sev_counts.get(sev, 0)
        if n: print(f"  {SEV_COLOUR[sev]}{sev:<10}{RESET} : {n}")
    print(f"{'═'*60}\n")


# ─────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────

def banner():
    print(f"""
{BOLD}{M}╔══════════════════════════════════════════════════════╗
║  CodeAlpha — Network Intrusion Detection System      ║
║  Task 4 | Cybersecurity Internship                   ║
╚══════════════════════════════════════════════════════╝{RESET}

  Detection capabilities:
  {G}✓{RESET} Port scans (SYN / FIN / NULL / XMAS)
  {G}✓{RESET} Brute-force / login flooding (SSH, FTP, RDP, HTTP ...)
  {G}✓{RESET} ICMP flood & UDP flood / DoS
  {G}✓{RESET} ARP spoofing / cache poisoning
  {G}✓{RESET} Web attacks (SQLi, XSS, LFI, RCE probes, scanners)
  {G}✓{RESET} Malicious payload signatures
""")


def main():
    global LOG_FILE, ALERT_COMMAND

    banner()
    parser = argparse.ArgumentParser(description="CodeAlpha NIDS — Task 4")
    parser.add_argument("-i", "--iface",   default=None,
                        help="Network interface (default: all)")
    parser.add_argument("-l", "--log",     default=None,
                        help="Log file path (default: none)")
    parser.add_argument("-f", "--filter",  default="",
                        help="BPF filter (default: all traffic)")
    parser.add_argument("-a", "--alert",   default=None,
                        help="Shell command to run on CRITICAL alert (use {src} for src IP)")
    parser.add_argument("-s", "--stats",   type=int, default=30,
                        help="Stats print interval in seconds (default: 30)")
    parser.add_argument("--list", action="store_true",
                        help="List interfaces and exit")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable interfaces:")
        for i, iface in enumerate(get_if_list(), 1):
            print(f"  {i}. {iface}")
        return

    LOG_FILE      = args.log     or f"nids_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    ALERT_COMMAND = args.alert

    print(f"  Interface : {args.iface or 'all'}")
    print(f"  Log file  : {LOG_FILE}")
    print(f"  BPF filter: '{args.filter or 'none'}'")
    print(f"  Press Ctrl+C to stop and save the report.\n")

    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # Stats in background
    t = threading.Thread(target=stats_thread, args=(args.stats,), daemon=True)
    t.start()

    try:
        sniff(
            iface=args.iface,
            filter=args.filter or None,
            prn=process_packet,
            store=False,
        )
    except PermissionError:
        print("[-] Permission denied. Run with: sudo python3 nids.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
