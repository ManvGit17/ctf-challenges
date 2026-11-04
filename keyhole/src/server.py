#!/usr/bin/env python3
"""
Keyhole - gate service.

Pure HTTP, stdlib only, single port, single process.

Endpoints:
  GET  /                 -> HTML instructions page
  GET  /keyhole          -> download the (stripped) checker binary
  POST /api/new          -> start a session, returns round 1 ticket
  POST /api/submit       -> {"code": "<12 chars>"} -> advance / fail / flag

Session state lives in memory only, keyed by a random cookie. Each round's
secret code and target bytes are generated fresh server-side; the flag is
read from /flag.txt only at the moment a session finishes both rounds,
never cached and never baked into the image.
"""
import base64
import http.cookies
import json
import os
import random
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "1337"))
FLAG_PATH = os.environ.get("FLAG_PATH", "/flag.txt")
BIN_PATH = os.environ.get("KEYHOLE_BIN", "/app/keyhole")

ROUNDS = int(os.environ.get("ROUNDS", "2"))
ROUND_SECONDS = int(os.environ.get("ROUND_SECONDS", "300"))
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "40"))
SESSION_TTL = int(os.environ.get("SESSION_TTL", "1200"))
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "512"))

# --- ticket format / transform constants (must match src/keyhole.c) -------
MAGIC = b"KHT1"
CODE_LEN = 12
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"
CHARSET_BYTES = CHARSET.encode()
M32 = 0xFFFFFFFF

rng = random.SystemRandom()
_lock = threading.Lock()
_sessions = {}  # sid -> dict


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


def mode_a(c, k, i):
    return rol8((c ^ k) & 0xFF, (i % 7) + 1)


def mode_b(c, k, i):
    return ((c + k) & 0xFF) ^ ((i * 0x1D) & 0xFF)


def mode_c(c, k, kall, i):
    return ror8(c, 3) ^ k ^ kall[(i + 5) % CODE_LEN]


def apply_mode(mode, c, i, k):
    if mode == 0:
        return mode_a(c, k[i], i)
    if mode == 1:
        return mode_b(c, k[i], i)
    if mode == 2:
        return mode_c(c, k[i], k, i)
    raise ValueError("bad mode")


def forward(code_bytes, seed, mode):
    k = derive_keystream(seed)
    return bytes(apply_mode(mode, c, i, k) for i, c in enumerate(code_bytes))


def build_round(prev_mode=None):
    """Returns (ticket_bytes, seed, mode, target) for one round."""
    seed = rng.getrandbits(32)
    mode = rng.randrange(3)
    if prev_mode is not None:
        choices = [m for m in (0, 1, 2) if m != prev_mode]
        mode = rng.choice(choices)
    code = bytes(rng.choice(CHARSET_BYTES) for _ in range(CODE_LEN))
    target = forward(code, seed, mode)

    reserved = os.urandom(3)
    noise = os.urandom(8)
    ticket = struct.pack(
        "<4sIB3s12s8s", MAGIC, seed, mode, reserved, target, noise
    )
    assert len(ticket) == 32
    return ticket, seed, mode, target


def new_session():
    with _lock:
        _gc_sessions()
        if len(_sessions) >= MAX_SESSIONS:
            raise RuntimeError("too many active sessions")
        sid = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
        ticket, seed, mode, target = build_round()
        sess = {
            "round": 1,
            "seed": seed,
            "mode": mode,
            "target": target,
            "attempts": 0,
            "deadline": time.time() + ROUND_SECONDS,
            "created": time.time(),
        }
        _sessions[sid] = sess
    return sid, ticket, sess


def _gc_sessions():
    now = time.time()
    dead = [sid for sid, s in _sessions.items() if now - s["created"] > SESSION_TTL]
    for sid in dead:
        _sessions.pop(sid, None)


def _validate_code(code):
    if not isinstance(code, str) or len(code) != CODE_LEN:
        return None
    up = code.strip().upper()
    if len(up) != CODE_LEN or any(ch not in CHARSET for ch in up):
        return None
    return up.encode()


def submit(sid, code_raw):
    with _lock:
        sess = _sessions.get(sid)
        if sess is None:
            return {"status": "no_session"}
        now = time.time()
        if now > sess["deadline"]:
            _sessions.pop(sid, None)
            return {"status": "timeout"}

        sess["attempts"] += 1
        if sess["attempts"] > MAX_ATTEMPTS:
            _sessions.pop(sid, None)
            return {"status": "too_many_attempts"}

        guess = _validate_code(code_raw)
        if guess is None:
            return {"status": "wrong"}

        computed = forward(guess, sess["seed"], sess["mode"])
        if computed != sess["target"]:
            return {"status": "wrong"}

        if sess["round"] >= ROUNDS:
            _sessions.pop(sid, None)
            flag = read_flag()
            return {"status": "solved", "flag": flag}

        ticket, seed, mode, target = build_round(prev_mode=sess["mode"])
        sess["round"] += 1
        sess["seed"] = seed
        sess["mode"] = mode
        sess["target"] = target
        sess["attempts"] = 0
        sess["deadline"] = now + ROUND_SECONDS
        return {
            "status": "correct",
            "round": sess["round"],
            "total": ROUNDS,
            "ticket": base64.b64encode(ticket).decode(),
            "deadline": sess["deadline"],
        }


def read_flag():
    try:
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    except OSError:
        return "FLAG_UNAVAILABLE"


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Keyhole</title>
<style>
body{font-family:monospace;background:#0b0e14;color:#c9d1d9;max-width:860px;margin:40px auto;padding:0 20px;line-height:1.55}
h1{color:#58a6ff}
code,pre{background:#161b22;padding:2px 6px;border-radius:4px}
pre{padding:12px;overflow-x:auto}
button{background:#238636;color:#fff;border:0;padding:10px 18px;border-radius:6px;cursor:pointer;font-family:monospace;font-size:14px}
button:hover{background:#2ea043}
#out{white-space:pre-wrap;word-break:break-all;margin-top:16px}
a{color:#58a6ff}
</style>
</head>
<body>
<h1>Keyhole</h1>
<p>A gate hands you a ticket and a lock. Figure out how the lock reads the ticket, and you can
open it yourself. Two locks, back to back.</p>
<p>Download the checker: <a href="/keyhole">/keyhole</a> (static ELF, no network calls, safe to run locally).</p>
<p>Start a session to receive round 1's ticket, base64-encoded:</p>
<button onclick="go()">Start session</button>
<div id="out"></div>
<script>
async function go(){
  const r = await fetch('/api/new', {method:'POST'});
  const j = await r.json();
  render(j);
}
async function submitCode(){
  const code = document.getElementById('codeinput').value.trim();
  const r = await fetch('/api/submit', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({code})});
  const j = await r.json();
  render(j);
}
function render(j){
  let html = '<pre>' + JSON.stringify(j, null, 2) + '</pre>';
  if (j.status !== 'solved' && j.ticket !== undefined) {
    html += '<p>Submit the 12-character access code for this round:</p>';
    html += '<input id="codeinput" style="width:200px;font-family:monospace" placeholder="12 chars, A-Z 2-9">';
    html += ' <button onclick="submitCode()">Submit</button>';
  }
  document.getElementById('out').innerHTML = html;
}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "keyhole/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _sid(self):
        raw = self.headers.get("Cookie", "")
        c = http.cookies.SimpleCookie()
        c.load(raw)
        if "sid" in c:
            return c["sid"].value
        return None

    def _send_json(self, obj, set_cookie=None, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", f"sid={set_cookie}; HttpOnly; Path=/; Max-Age={SESSION_TTL}")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data, content_type, code=200, filename=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f"attachment; filename={filename}")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._send_bytes(INDEX_HTML.encode(), "text/html; charset=utf-8")
        elif self.path == "/keyhole":
            try:
                with open(BIN_PATH, "rb") as f:
                    data = f.read()
            except OSError:
                self._send_json({"error": "binary unavailable"}, code=500)
                return
            self._send_bytes(data, "application/octet-stream", filename="keyhole")
        else:
            self._send_json({"error": "not found"}, code=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""

        if self.path == "/api/new":
            try:
                sid, ticket, sess = new_session()
            except RuntimeError as e:
                self._send_json({"error": str(e)}, code=503)
                return
            self._send_json(
                {
                    "round": sess["round"],
                    "total": ROUNDS,
                    "ticket": base64.b64encode(ticket).decode(),
                    "deadline": sess["deadline"],
                },
                set_cookie=sid,
            )
        elif self.path == "/api/submit":
            sid = self._sid()
            if sid is None:
                self._send_json({"status": "no_session"})
                return
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            code_raw = data.get("code", "")
            result = submit(sid, code_raw)
            self._send_json(result)
        else:
            self._send_json({"error": "not found"}, code=404)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"keyhole service listening on {HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
