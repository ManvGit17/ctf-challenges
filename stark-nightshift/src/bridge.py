#!/usr/bin/env python3
"""
Infiltration Relay -- serves the web console and relays each browser
session to the vault daemon (gatekeeper.py) over loopback TCP.

There is no shell, no filesystem access, and no server source reachable
from the browser -- only this page's observable behavior (the pulse
feed) and the two actions it exposes (plan, strike). Pure standard
library on purpose: no pip install, smallest possible image.

Wire format over the WebSocket at /ws (JSON text frames). Deliberately
plain field names -- the theme lives in the UI copy, not in making the
protocol itself any harder to read than it needs to be:
  server -> client  {"type":"pulse","kind":"OPENS"/"SEALS",
                      "vaultMs":float|null,"yourMs":float}
                     -- vaultMs is relative to this connection's first
                        observed vault timestamp (for measuring the
                        window's width from the SAME clock on both ends
                        of one cycle); yourMs is relative to when this
                        session opened (for measuring the period between
                        cycles from arrival times, immune to any
                        client/server clock offset).
  server -> client  {"type":"log","msg":str}
  server -> client  {"type":"outcome","ok":bool,"flag":str|null,"attempts":int}
  client -> server  {"type":"strike","atMs":float}
                     -- atMs is in the SAME yourMs domain handed out in
                        pulse messages.
"""
import asyncio
import base64
import hashlib
import json
import queue
import socket
import struct
import threading
import time
from pathlib import Path

GATEKEEPER_HOST = "127.0.0.1"
GATEKEEPER_PORT = 9000
BRIDGE_PORT = 8080
STATIC_DIR = (Path(__file__).parent / "static").resolve()

TOKEN_POOL = [f"legacy-badge-{i:02d}" for i in range(8)]

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
}

LEAD_NS = 40_000_000
TAIL_NS = 150_000_000
ROUND_INTERVAL_NS = 1_500_000


# ---------------------------------------------------------------- WS framing

def ws_accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


async def ws_send_frame(writer, opcode: int, payload: bytes, lock: asyncio.Lock):
    frame = bytearray()
    frame.append(0x80 | opcode)
    length = len(payload)
    if length < 126:
        frame.append(length)
    elif length < 65536:
        frame.append(126)
        frame += struct.pack(">H", length)
    else:
        frame.append(127)
        frame += struct.pack(">Q", length)
    frame += payload
    async with lock:
        writer.write(bytes(frame))
        await writer.drain()


async def ws_send_json(writer, obj, lock):
    await ws_send_frame(writer, 0x1, json.dumps(obj).encode(), lock)


async def ws_read_frame(reader):
    hdr = await reader.readexactly(2)
    b0, b1 = hdr[0], hdr[1]
    opcode = b0 & 0x0F
    masked = (b1 & 0x80) != 0
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]
    mask = await reader.readexactly(4) if masked else None
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


# ------------------------------------------------------------ static files

async def handle_static(path: str, writer: asyncio.StreamWriter):
    if path == "/":
        path = "/index.html"
    elif path.startswith("/static/"):
        path = path[len("/static/"):]
        path = "/" + path
    rel = path.lstrip("/")
    file_path = (STATIC_DIR / rel).resolve()
    ok = file_path.is_file() and (file_path == STATIC_DIR or STATIC_DIR in file_path.parents)
    if not ok:
        body = b"not found"
        writer.write(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (len(body), body)
        )
        await writer.drain()
        return
    data = file_path.read_bytes()
    ctype = MIME.get(file_path.suffix, "application/octet-stream")
    header = (
        f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
    ).encode()
    writer.write(header + data)
    await writer.drain()


# ------------------------------------------------------------ gatekeeper IO

PULSE_KIND = {"REBUILD-START": "OPENS", "REBUILD-END": "SEALS"}


async def monitor_relay(writer, send_lock, base_local_ns, state):
    gwriter = None
    try:
        greader, gwriter = await asyncio.open_connection(GATEKEEPER_HOST, GATEKEEPER_PORT)
        gsock = gwriter.get_extra_info("socket")
        if gsock is not None:
            gsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        gwriter.write(b"MONITOR\n")
        await gwriter.drain()
        await ws_send_json(writer, {"type": "log", "msg": "uplink established -- you have eyes on the vault's pulse bus"}, send_lock)

        while True:
            line = await greader.readline()
            if not line:
                break
            local_ns = time.time_ns()
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            raw_kind, _, rest = text.partition(" ")
            kind = PULSE_KIND.get(raw_kind)
            if kind is None:
                continue
            seq_ts = None
            if rest.startswith("seq_ts="):
                try:
                    seq_ts = int(rest.split("=", 1)[1])
                except ValueError:
                    pass
            if seq_ts is not None and state.get("base_server_ns") is None:
                state["base_server_ns"] = seq_ts
            vault_ms = None
            if seq_ts is not None and state.get("base_server_ns") is not None:
                vault_ms = (seq_ts - state["base_server_ns"]) / 1e6
            your_ms = (local_ns - base_local_ns) / 1e6
            await ws_send_json(
                writer,
                {"type": "pulse", "kind": kind, "vaultMs": vault_ms, "yourMs": your_ms},
                send_lock,
            )
    except (asyncio.CancelledError, OSError):
        pass
    finally:
        if gwriter is not None:
            try:
                gwriter.close()
            except OSError:
                pass


def fire_burst_blocking(fire_at_ns: int):
    """Runs in a worker thread: proven busy-wait pacing, ported from the
    reference solver. Precision matters here (sub-ms), which rules out
    asyncio's own sleep/scheduling granularity."""
    sock = socket.create_connection((GATEKEEPER_HOST, GATEKEEPER_PORT))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    replies: "queue.Queue[str]" = queue.Queue()

    def reader():
        f = sock.makefile("r")
        try:
            while True:
                line = f.readline()
                if not line:
                    break
                replies.put(line.strip())
        except OSError:
            pass

    threading.Thread(target=reader, daemon=True).start()

    fire_from_ns = fire_at_ns - LEAD_NS
    fire_until_ns = fire_at_ns + TAIL_NS

    while time.time_ns() < fire_from_ns:
        pass  # busy-wait: needs sub-ms precision, time.sleep() is too coarse here

    payload = "".join(t + "\n" for t in TOKEN_POOL).encode()
    rounds = 0
    next_round_ns = fire_from_ns
    while time.time_ns() < fire_until_ns:
        while time.time_ns() < next_round_ns:
            pass
        try:
            sock.sendall(payload)
        except OSError:
            break
        rounds += 1
        next_round_ns += ROUND_INTERVAL_NS

    flag = None
    deadline = time.time() + 0.3
    expected = max(rounds, 1) * len(TOKEN_POOL)
    seen = 0
    while seen < expected and time.time() < deadline:
        try:
            line = replies.get(timeout=0.05)
        except queue.Empty:
            continue
        seen += 1
        if line.startswith("OK "):
            flag = line[3:]
            break

    try:
        sock.close()
    except OSError:
        pass
    return {"flag": flag, "sent": rounds}


async def run_attempt(fire_at_ns, writer, send_lock, state):
    loop = asyncio.get_running_loop()
    try:
        await ws_send_json(writer, {"type": "log", "msg": "strike launched -- closing on the predicted opening"}, send_lock)
        result = await loop.run_in_executor(None, fire_burst_blocking, fire_at_ns)
        await ws_send_json(
            writer,
            {"type": "outcome", "ok": result["flag"] is not None, "flag": result["flag"], "attempts": result["sent"]},
            send_lock,
        )
    finally:
        state["arm_in_progress"] = False


# ------------------------------------------------------------------ routing

async def handle_ws(reader, writer, headers):
    key = headers.get("sec-websocket-key")
    if not key:
        return
    accept = ws_accept_key(key)
    resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    ).encode()
    writer.write(resp)
    await writer.drain()

    send_lock = asyncio.Lock()
    base_local_ns = time.time_ns()
    state = {"base_server_ns": None, "arm_in_progress": False}

    mtask = asyncio.create_task(monitor_relay(writer, send_lock, base_local_ns, state))
    try:
        while True:
            opcode, payload = await ws_read_frame(reader)
            if opcode == 0x8:  # close
                break
            elif opcode == 0x9:  # ping -> pong
                await ws_send_frame(writer, 0xA, payload, send_lock)
            elif opcode == 0x1:  # text
                try:
                    msg = json.loads(payload.decode(errors="replace"))
                except json.JSONDecodeError:
                    continue
                if msg.get("type") == "strike":
                    if state["arm_in_progress"]:
                        await ws_send_json(writer, {"type": "log", "msg": "hold -- a strike is already in progress"}, send_lock)
                        continue
                    try:
                        at_ms = float(msg["atMs"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    fire_at_ns = base_local_ns + round(at_ms * 1_000_000)
                    state["arm_in_progress"] = True
                    asyncio.create_task(run_attempt(fire_at_ns, writer, send_lock, state))
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        pass
    finally:
        mtask.cancel()


async def handle_conn(reader, writer):
    try:
        request_line = await reader.readline()
        if not request_line:
            return
        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b""):
                break
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.decode(errors="replace").strip().lower()] = v.decode(errors="replace").strip()
        parts = request_line.decode(errors="replace").split()
        if len(parts) < 2:
            return
        _, path, *_ = parts
        if path == "/ws" and headers.get("upgrade", "").lower() == "websocket":
            await handle_ws(reader, writer, headers)
        else:
            await handle_static(path, writer)
    except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def main():
    server = await asyncio.start_server(handle_conn, "0.0.0.0", BRIDGE_PORT)
    print(f"[bridge] listening on 0.0.0.0:{BRIDGE_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
