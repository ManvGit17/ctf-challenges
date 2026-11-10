#!/usr/bin/env python3
"""
Vault daemon. Listens on 127.0.0.1:9000, only the web relay talks to it.

Every few seconds it swaps the "stale" badge: add it to the valid set, sleep a short random
jitter, remove it. The swap is not atomic, so for that jitter the old badge is still accepted.

Wire protocol (newline-delimited TCP):
  first line "MONITOR"  one-way stream of "REBUILD-START seq_ts=<ns>" and
                        "REBUILD-END seq_ts=<ns>" markers
  any other first line  a badge guess; the connection stays open for more guesses
  reply per guess       "DENY", or "OK <flag>" and the connection closes
"""
import random
import socket
import threading
import time

HOST = "127.0.0.1"  # loopback only
PORT = 9000
FLAG_PATH = "/flag.txt"

TOKEN_POOL = [f"legacy-badge-{i:02d}" for i in range(8)]

MAX_GUESSES_PER_CONN = 2_000_000  # high on purpose: a burst sends thousands of guesses
MONITOR_IDLE_TIMEOUT = 3600

LOCKDOWN_MIN_SEC = 45
LOCKDOWN_MAX_SEC = 90
SLICE_SECONDS = 0.5
PER_SLICE_REJECT_THRESH = 40
SLICES_FOR_LOCKDOWN = 3

lock = threading.Lock()
valid_tokens = set()
reject_counter = 0
lockdown_until = 0.0

monitor_clients = []  # list[socket.socket], pruned lazily
monitor_clients_lock = threading.Lock()


def read_flag():
    with open(FLAG_PATH, "r") as f:
        return f.read().strip()


def broadcast(line):
    msg = (line + "\n").encode()
    with monitor_clients_lock:
        dead = []
        for sock in monitor_clients:
            try:
                sock.sendall(msg)
            except OSError:
                dead.append(sock)
        for sock in dead:
            monitor_clients.remove(sock)


def rotation_loop():
    global lockdown_until, reject_counter

    interval = 4.0 + random.random() * 3.0  # [4, 7)
    jitter_lo_ms = 15.0 + random.random() * 25.0
    jitter_hi_ms = min(90.0, jitter_lo_ms + 20.0 + random.random() * 30.0)
    stale_token = random.choice(TOKEN_POOL)

    last_counter = 0

    while True:
        now = time.time()
        in_lockdown = now < lockdown_until

        jitter_ms = jitter_lo_ms + random.random() * (jitter_hi_ms - jitter_lo_ms)
        jitter = jitter_ms / 1000.0

        start_ts = time.time_ns()
        if not in_lockdown:
            with lock:
                valid_tokens.add(stale_token)
        broadcast(f"REBUILD-START seq_ts={start_ts}")

        time.sleep(jitter)

        if not in_lockdown:
            with lock:
                valid_tokens.discard(stale_token)
        end_ts = time.time_ns()
        broadcast(f"REBUILD-END seq_ts={end_ts}")

        # Flood detection: a single burst trips one slice, constant spraying trips most.
        remaining = interval - jitter
        lit = 0
        while remaining > 0:
            step = min(SLICE_SECONDS, remaining)
            time.sleep(step)
            remaining -= step
            with lock:
                delta = reject_counter - last_counter
                last_counter = reject_counter
            if delta > PER_SLICE_REJECT_THRESH:
                lit += 1

        if lit >= SLICES_FOR_LOCKDOWN and not in_lockdown:
            secs = LOCKDOWN_MIN_SEC + random.randint(0, LOCKDOWN_MAX_SEC - LOCKDOWN_MIN_SEC)
            lockdown_until = time.time() + secs


def handle_guess(conn, token):
    global reject_counter
    with lock:
        ok = token in valid_tokens
        if not ok:
            reject_counter += 1
    if ok:
        conn.sendall(("OK " + read_flag() + "\n").encode())
        return True
    conn.sendall(b"DENY\n")
    return False


def handle_client(conn, addr):
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.settimeout(30)
    f = conn.makefile("rwb", buffering=0)
    try:
        first = f.readline(256).decode(errors="replace").strip()
        if not first:
            return

        if first.upper() == "MONITOR":
            with monitor_clients_lock:
                monitor_clients.append(conn)
            conn.settimeout(MONITOR_IDLE_TIMEOUT)
            try:
                # Only here to notice a disconnect; broadcast() does the writing.
                while conn.recv(256):
                    pass
            except OSError:
                pass
            finally:
                with monitor_clients_lock:
                    if conn in monitor_clients:
                        monitor_clients.remove(conn)
            return

        guesses = 0
        line = first
        while line:
            guesses += 1
            if handle_guess(conn, line):
                return
            if guesses >= MAX_GUESSES_PER_CONN:
                return
            raw = f.readline(256)
            if not raw:
                return
            line = raw.decode(errors="replace").strip()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    threading.Thread(target=rotation_loop, daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(128)
    print(f"[gatekeeper] listening on {HOST}:{PORT}", flush=True)

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
