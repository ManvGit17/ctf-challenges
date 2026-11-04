#!/usr/bin/env python3
"""
Reference solver for Keyhole.

Talks to the deployed service over HTTP, parses each round's ticket,
re-derives the keystream, inverts whichever of the three per-byte
transforms the ticket's mode byte selects, and submits the recovered
access code. Prints the flag on success.

Usage:
    python3 solve.py http://TARGET:PORT
    python3 solve.py http://TARGET:PORT --verify-bin /path/to/keyhole
"""
import base64
import http.client
import http.cookies
import json
import subprocess
import struct
import sys
import tempfile
import urllib.parse

CODE_LEN = 12
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"
M32 = 0xFFFFFFFF


def derive_keystream(seed, n=CODE_LEN):
    state = (seed ^ 0xA53C9D1F) & M32
    k = bytearray(n)
    for i in range(n):
        state = (state * 0x41C64E6D + 0x3039) & M32
        k[i] = (state >> 24) & 0xFF
    return bytes(k)


def rol8(v, n):
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xFF


def ror8(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF


def invert_mode_a(t, k, i):
    # forward: t = rol8(c ^ k, (i % 7) + 1)
    return ror8(t, (i % 7) + 1) ^ k


def invert_mode_b(t, k, i):
    # forward: t = (c + k) ^ (i * 0x1D)
    return (t ^ (i * 0x1D)) - k & 0xFF


def invert_mode_c(t, k, kall, i):
    # forward: t = ror8(c, 3) ^ k ^ kall[(i+5)%12]
    return rol8(t ^ k ^ kall[(i + 5) % CODE_LEN], 3)


def recover_code(target, seed, mode):
    k = derive_keystream(seed)
    out = bytearray(CODE_LEN)
    for i in range(CODE_LEN):
        t = target[i]
        if mode == 0:
            c = invert_mode_a(t, k[i], i)
        elif mode == 1:
            c = invert_mode_b(t, k[i], i)
        elif mode == 2:
            c = invert_mode_c(t, k[i], k, i)
        else:
            raise ValueError(f"unknown mode {mode}")
        out[i] = c
    code = out.decode("ascii", errors="replace")
    for ch in code:
        if ch not in CHARSET:
            raise ValueError(f"recovered byte {ch!r} not in charset - wrong mode/key math?")
    return code


def parse_ticket(raw):
    magic, seed, mode, reserved, target, noise = struct.unpack("<4sIB3s12s8s", raw)
    if magic != b"KHT1":
        raise ValueError(f"bad magic {magic!r}")
    return seed, mode % 3, target


class Client:
    def __init__(self, base_url):
        parsed = urllib.parse.urlsplit(base_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.ssl = parsed.scheme == "https"
        self.cookie = None

    def _conn(self):
        if self.ssl:
            return http.client.HTTPSConnection(self.host, self.port, timeout=15)
        return http.client.HTTPConnection(self.host, self.port, timeout=15)

    def _request(self, method, path, body=None):
        conn = self._conn()
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = f"sid={self.cookie}"
        payload = json.dumps(body).encode() if body is not None else None
        if payload is not None:
            headers["Content-Length"] = str(len(payload))
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        set_cookie = resp.getheader("Set-Cookie")
        if set_cookie:
            c = http.cookies.SimpleCookie()
            c.load(set_cookie)
            if "sid" in c:
                self.cookie = c["sid"].value
        conn.close()
        return json.loads(data)

    def new_session(self):
        return self._request("POST", "/api/new")

    def submit(self, code):
        return self._request("POST", "/api/submit", {"code": code})


def verify_against_binary(bin_path, ticket_bytes, code):
    with tempfile.NamedTemporaryFile(suffix=".bin") as tf:
        tf.write(ticket_bytes)
        tf.flush()
        p = subprocess.run(
            [bin_path, tf.name], input=(code + "\n").encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        )
    out = p.stdout.decode(errors="replace").strip()
    return out.endswith("GRANTED")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    base_url = sys.argv[1]
    verify_bin = None
    if "--verify-bin" in sys.argv:
        verify_bin = sys.argv[sys.argv.index("--verify-bin") + 1]

    client = Client(base_url)
    resp = client.new_session()
    print(f"[+] round {resp['round']}/{resp['total']}")

    while True:
        ticket_bytes = base64.b64decode(resp["ticket"])
        seed, mode, target = parse_ticket(ticket_bytes)
        code = recover_code(target, seed, mode)
        print(f"    seed=0x{seed:08x} mode={mode} code={code}")

        if verify_bin:
            ok = verify_against_binary(verify_bin, ticket_bytes, code)
            print(f"    local binary check: {'GRANTED' if ok else 'DENIED'}")
            assert ok, "recovered code rejected by the real binary - bug in solver math"

        resp = client.submit(code)
        status = resp.get("status")
        if status == "solved":
            print(f"[+] FLAG: {resp['flag']}")
            return
        if status == "correct":
            print(f"[+] round {resp['round']}/{resp['total']} - correct, advancing")
            continue
        print(f"[-] unexpected status: {resp}")
        sys.exit(1)


if __name__ == "__main__":
    main()
