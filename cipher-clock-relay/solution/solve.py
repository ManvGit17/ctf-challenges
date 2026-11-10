#!/usr/bin/env python3
"""
Reference solver for Cipher-Clock Relay.

Reads the base rotation out of the capture (the gaps between the UDP packets to port 7331),
connects to the relay, adds the announced drift and answers the rounds.
Standard library only; the capture is read as classic pcap.

Usage: python3 solve.py relay_dump.pcap [host] [port]      (defaults: 127.0.0.1 8338)
"""
import re
import socket
import string
import struct
import sys

ALPHABET = string.ascii_uppercase


def base_rotation(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        end = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        end = ">"
    else:
        sys.exit("not a classic pcap file")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    l2 = {1: 14, 101: 0, 228: 0}.get(linktype)
    if l2 is None:
        sys.exit(f"unsupported link type {linktype}")

    times = []
    pos = 24
    while pos + 16 <= len(data):
        sec, usec, caplen, _ = struct.unpack(end + "IIII", data[pos:pos + 16])
        pkt = data[pos + 16:pos + 16 + caplen]
        pos += 16 + caplen
        ip = pkt[l2:]
        if len(ip) < 28 or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        dport = struct.unpack(">H", ip[ihl + 2:ihl + 4])[0]
        if dport == 7331:
            times.append(sec + usec / 1e6)

    gaps = [round((b - a) * 10) for a, b in zip(times, times[1:])]
    if not gaps or any(g < 0 or g > 9 for g in gaps):
        sys.exit(f"could not read digits from the gaps: {gaps}")
    return int("".join(str(g) for g in gaps))


def caesar(text, shift):
    return "".join(ALPHABET[(ALPHABET.index(c) + shift) % 26] if c in ALPHABET else c for c in text)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pcap = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8338

    base = base_rotation(pcap)
    print(f"[*] base rotation from the capture: {base}")

    s = socket.create_connection((host, port))
    f = s.makefile("rw", newline="\n")
    drift = None
    while True:
        line = f.readline()
        if not line:
            break
        line = line.strip()
        print("   ", line)
        m = re.match(r"Clock drift: (\d+)", line)
        if m:
            drift = int(m.group(1))
        m = re.search(r"Rotate this: ([A-Z]+)", line)
        if m:
            f.write(caesar(m.group(1), (base + drift) % 26) + "\n")
            f.flush()
        if "Flag:" in line:
            print("[+] " + line.split("Flag: ", 1)[1])
            return


if __name__ == "__main__":
    main()
