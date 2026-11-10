#!/usr/bin/env python3
"""
Reference solver for Stark Nightshift. Talks to the relay's /ws endpoint the way a browser tab
does: watches the pulses, fits the period, predicts the next opening and sends a strike.
Standard library only, with a small hand-written WebSocket client.

Usage: python3 solve.py [host] [port]      (defaults: 127.0.0.1 8080)
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

N_CYCLES_MIN = 6
PERIOD_WINDOW = 6
MAX_ATTEMPTS = 12


def ws_connect(host, port, path="/ws"):
    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(req)
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(4096)
    if b"101" not in resp.split(b"\r\n", 1)[0]:
        raise RuntimeError("handshake failed: " + resp.decode(errors="replace"))
    return sock


def ws_send_text(sock, text: str):
    payload = text.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    frame = bytearray([0x81])
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame += struct.pack(">H", length)
    else:
        frame.append(0x80 | 127)
        frame += struct.pack(">Q", length)
    frame += mask + masked
    sock.sendall(bytes(frame))


class WSReader:
    """Minimal buffered WS frame reader for a client (server frames are
    unmasked per spec)."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk

    def read_frame(self):
        self._need(2)
        b0, b1 = self.buf[0], self.buf[1]
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        off = 2
        if length == 126:
            self._need(off + 2)
            length = struct.unpack(">H", self.buf[off:off + 2])[0]
            off += 2
        elif length == 127:
            self._need(off + 8)
            length = struct.unpack(">Q", self.buf[off:off + 8])[0]
            off += 8
        self._need(off + length)
        payload = self.buf[off:off + length]
        self.buf = self.buf[off + length:]
        return opcode, payload


def main():
    sock = ws_connect(HOST, PORT)
    reader = WSReader(sock)
    print(f"[*] connected to bridge ws://{HOST}:{PORT}/ws")

    pulses = []
    opens_local = []

    def pump_until(predicate, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            opcode, payload = reader.read_frame()
            if opcode != 0x1:
                continue
            msg = json.loads(payload.decode(errors="replace"))
            if msg.get("type") == "pulse":
                pulses.append(msg)
                if msg["kind"] == "OPENS":
                    opens_local.append(msg["yourMs"])
            yield msg
            if predicate():
                return

    print(f"[*] waiting for {N_CYCLES_MIN} door-open cycles over the live feed ...")
    for _ in pump_until(lambda: len(opens_local) >= N_CYCLES_MIN):
        pass

    for attempt in range(1, MAX_ATTEMPTS + 1):
        recent = opens_local[-PERIOD_WINDOW:]
        deltas = sorted(b - a for a, b in zip(recent, recent[1:]))
        period_ms = deltas[len(deltas) // 2] if deltas else None
        if period_ms is None:
            time.sleep(0.5)
            continue

        last_open = opens_local[-1]
        next_open = last_open + period_ms
        # use the latest pulse's yourMs as "now"; we strike right after this
        now_proxy = pulses[-1]["yourMs"]
        while next_open < now_proxy:
            next_open += period_ms

        print(f"[*] attempt {attempt}/{MAX_ATTEMPTS}: period={period_ms:.1f}ms "
              f"predicted next door-open at yourMs={next_open:.1f}")
        ws_send_text(sock, json.dumps({"type": "strike", "atMs": next_open}))

        flag = None
        for msg in pump_until(lambda: False, timeout=period_ms / 1000.0 + 5.0):
            if msg.get("type") == "log":
                print("    [bridge]", msg["msg"])
            if msg.get("type") == "outcome":
                if msg["ok"]:
                    flag = msg["flag"]
                print(f"    [bridge] outcome ok={msg['ok']} attempts={msg['attempts']}")
                break
        if flag:
            print("[+] FLAG:", flag)
            return

    print("[-] exhausted attempts; re-run to collect fresh timing.")


if __name__ == "__main__":
    main()
