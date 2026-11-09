#!/usr/bin/env python3
"""What a lazy 'just spray and hope' script (no MONITOR, no timing
analysis) looks like against the TCP redesign. Used only to verify the
lockdown defense still holds without raw sockets."""
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

TOKEN_POOL = [f"legacy-badge-{i:02d}" for i in range(8)]

print("[*] spraying continuously for 30s, no timing analysis at all...")
t0 = time.time()
count = 0
while time.time() - t0 < 30:
    try:
        s = socket.create_connection((HOST, PORT), timeout=2)
        for tok in TOKEN_POOL:
            s.sendall((tok + "\n").encode())
            count += 1
        s.close()
    except OSError:
        pass
print(f"[*] sent {count} guesses over 30s")
