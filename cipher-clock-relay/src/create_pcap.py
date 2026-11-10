#!/usr/bin/env python3
"""
Builds relay_dump.pcap (needs scapy).

Two things are hidden in the capture:
  - a decoy: an ICMP echo request whose IP ID is 0x3139, ASCII "19". It looks like the rotation
    the relay wants, and the relay rejects it.
  - the real constant: the gaps between three UDP packets to port 7331 (payload "sync"). Each gap
    in tenths of a second is one digit. Gaps of 100 ms and 700 ms give 1 and 7, so 17.
"""
import os
import random
import sys
import time

from scapy.all import IP, ICMP, TCP, UDP, Raw, wrpcap

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay_dump.pcap")

DECOY_ID = 0x3139
GAPS_MS = [100, 700]


def icmp_decoy(id_val, t):
    pkt = IP(dst="127.0.0.1", src="127.0.0.1", id=id_val) / ICMP(type="echo-request")
    pkt.time = t
    return pkt


def sync_marker(t):
    pkt = IP(dst="10.0.0.53", src="10.0.0.7") / UDP(sport=51820, dport=7331) / Raw(load=b"sync")
    pkt.time = t
    return pkt


def web_syn(dst, port, t):
    pkt = IP(dst=dst, src="10.0.0.1") / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
    pkt.time = t
    return pkt


def main():
    base = time.time() - 300
    pkts = []

    for i in range(3):
        pkts.append(web_syn("example.com", 80, base + i * 3.3))

    pkts.append(icmp_decoy(DECOY_ID, base + 15.0))

    t = base + 40.0
    pkts.append(sync_marker(t))
    for gap in GAPS_MS:
        t += gap / 1000.0
        pkts.append(sync_marker(t))

    for i in range(4):
        pkts.append(web_syn("93.184.216.34", 443, base + 60.0 + i * 2.1))

    pkts.sort(key=lambda p: p.time)
    wrpcap(output_path, pkts)
    print(f"wrote {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
