#!/usr/bin/env python3
"""Lightweight packet sniffer built with Scapy. Captures live
traffic and flags simple suspicious patterns like port scans
and unencrypted credential-looking traffic."""

import argparse
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, Raw

SCAN_THRESHOLD = 15   # distinct ports from one IP in the window
port_hits = defaultdict(set)

INTERESTING_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS"}


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}")


def handle_packet(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    if TCP in pkt:
        dport = pkt[TCP].dport
        port_hits[src].add(dport)
        if len(port_hits[src]) == SCAN_THRESHOLD:
            log(f"[ALERT] Possible port scan from {src} "
                f"({len(port_hits[src])} distinct ports)")

        if dport in (21, 23) and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b"USER" in payload or b"PASS" in payload:
                log(f"[ALERT] Possible cleartext credentials "
                    f"{src} -> {dst}:{dport} ({INTERESTING_PORTS[dport]})")

    elif UDP in pkt:
        pass  # extend here for DNS/UDP-specific checks

    proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
    log(f"{src} -> {dst} [{proto}]")


def main():
    parser = argparse.ArgumentParser(description="Scapy-based packet sniffer")
    parser.add_argument("-i", "--iface", help="interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="ip",
                        help="BPF filter, e.g. 'tcp port 80'")
    args = parser.parse_args()

    log(f"Starting capture on {args.iface or 'default interface'} "
        f"(filter: {args.filter}) — Ctrl+C to stop")
    sniff(iface=args.iface, filter=args.filter, prn=handle_packet,
          count=args.count, store=False)


if __name__ == "__main__":
    main()q
