#!/usr/bin/env python3
"""
Reference solver for Pilgrim's Trace.

Walks the intended chain through the capture (MQTT -> ICMP -> TCP/8443 -> UDP/9999),
recovers the access key, then solves the relay's proof-of-work and trades the key
for the flag.

Usage:
    pip install scapy
    python3 solve.py ../pilgrims_trace.pcap            # stage 1 only
    python3 solve.py ../pilgrims_trace.pcap localhost 9000
"""
import hashlib
import itertools
import re
import socket
import sys
from collections import OrderedDict

from scapy.all import ICMP, IP, TCP, UDP, Raw, rdpcap


def is_prime(n):
    return n > 1 and all(n % d for d in range(2, int(n ** 0.5) + 1))


def stage1(path):
    pkts = rdpcap(path)

    # 1. MQTT beacon tells us which ICMP sequence numbers matter.
    for p in pkts:
        if TCP in p and Raw in p and 1883 in (p[TCP].sport, p[TCP].dport):
            print(f"[mqtt] {bytes(p[Raw].load)[4:].decode(errors='replace')}")

    # 2. Echo requests with a prime sequence number carry 2 bytes each in the IP ID.
    echoes = sorted(
        (p[ICMP].seq, p[IP].id) for p in pkts
        if ICMP in p and p[ICMP].type == 8 and is_prime(p[ICMP].seq) and p[ICMP].seq <= 29
    )
    clue = b"".join(ip_id.to_bytes(2, "big") for _, ip_id in echoes).decode()
    print(f"[icmp] {clue}")
    channel = re.search(r"CHANNEL(\d{4})", clue).group(1)

    # 3. The 8443 banner bound to that channel holds the real XOR key.
    key = None
    for p in pkts:
        if TCP in p and Raw in p and p[TCP].sport == 8443:
            body = bytes(p[Raw].load)
            if f"X-Vault-Channel: {channel}".encode() in body:
                key = re.search(rb"X-Vault-Key: (\S+)", body).group(1)
    print(f"[tcp]  channel {channel} -> key {key.decode()}")

    # 4. Group UDP/9999 fragments by sender, XOR each cluster, keep the readable one.
    clusters = OrderedDict()
    for p in pkts:
        if UDP in p and Raw in p and p[UDP].dport == 9999:
            clusters.setdefault((p[IP].src, p[UDP].sport), b"")
            clusters[(p[IP].src, p[UDP].sport)] += bytes(p[Raw].load)
    for who, blob in clusters.items():
        plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
        m = re.search(rb"[0-9a-f]{20}", plain)
        if m:
            access_key = m.group().decode()
            print(f"[udp]  {who[0]}:{who[1]} -> access key {access_key}")
            return access_key
    raise SystemExit("no readable UDP cluster found")


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def stage2(host, port, access_key):
    with socket.create_connection((host, port), timeout=30) as s:
        banner = recv_until(s, b"Submit S:")
        nonce = re.search(r'sha256\("([0-9a-f]+)"', banner).group(1)
        for i in itertools.count():
            if hashlib.sha256(f"{nonce}{i}".encode()).hexdigest().startswith("0000"):
                break
        s.sendall(f"{i}\n".encode())
        recv_until(s, b"access key:")
        s.sendall(f"{access_key}\n".encode())
        print("[relay]", recv_until(s, b"}").strip().splitlines()[-1])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    k = stage1(sys.argv[1])
    if len(sys.argv) >= 4:
        stage2(sys.argv[2], int(sys.argv[3]), k)
