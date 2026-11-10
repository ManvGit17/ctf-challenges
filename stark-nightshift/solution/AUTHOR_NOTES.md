# Author notes: Stark Nightshift

## Summary

| | |
|---|---|
| Category | Web / Networking |
| Delivery | one web page, one exposed port (8080), no shell for the player |
| Image | `python:3.11-alpine`, standard library only, about 61 MB |

## Architecture

Two processes in one container:

- **`src/gatekeeper.py`**: the vulnerable daemon. Non-atomic badge rotation with a per-boot
  jitter range and period, plus the duty-cycle lockdown. Binds `127.0.0.1:9000` only.
- **`src/bridge.py`**: the only player-facing surface. Hand-rolled HTTP and WebSocket framing
  (no `aiohttp`, no `pip install`). Serves `src/static/` on `GET /`, relays each browser tab's
  `/ws` session to its own `MONITOR` connection, and on a `strike` message opens a fresh
  connection to the daemon and fires the badge pool.

Players never get a raw socket, a shell or the daemon's source. What they see is a themed skin
over the live pulse feed (door "opens"/"seals", a "plan" to write, a "strike" to commit to).

## Design decisions

- **Firing lives in the bridge, not the browser.** Browser JS cannot open raw TCP sockets or
  busy-wait with sub-millisecond precision. The bridge does the mechanical part the same way for
  every player, so the browser only has to do the hard part: reading the feed and predicting the
  window. It also means `yourMs` is the bridge's clock, so there is no client/server clock-sync
  problem on top of the real puzzle.
- **Relative timestamps.** `vaultMs` is relative to the first vault timestamp a session saw and
  `yourMs` to when the session opened. That keeps numbers inside JS `Number` precision (raw epoch
  nanoseconds are not) without precomputing anything the player is supposed to work out.
- **The intro is cosmetic.** The "breach the perimeter" sequence in `playIntro()` gates nothing;
  the WebSocket connects in the background immediately. A real second gate would necessarily be
  shallow with one container and one port, and would dilute the single real vulnerability.
- **No shell.** An earlier version delivered a terminal. Once a player could read the daemon's
  source off disk it folded almost instantly, so the fix was removing the leak and the shell, not
  making the puzzle harder.

## Two bugs to not reintroduce

1. **`TCP_NODELAY` on every socket.** Without it Nagle's algorithm batches these small packets
   and pushes correctly timed guesses past the window's close. It is set in the daemon's
   `handle_client()` and on both bridge sockets to the daemon (`monitor_relay` and
   `fire_burst_blocking`).
2. **No `time.sleep()` for sub-5 ms pacing.** Sleeps of 1-2 ms were observed taking about 10x
   longer in a container. `fire_burst_blocking` busy-waits against absolute `time.time_ns()`
   targets instead, and runs in a worker thread because asyncio scheduling is not tight enough.

## Verification done

- Clean `docker build` on `python:3.11-alpine`.
- In a browser: page loads, intro plays, WebSocket connects, pulses stream into both the chart
  and the table; a hand-computed prediction fired from the console returned the flag on the next
  predicted cycle.
- `solve.py` retrieved the flag on the first predicted window.
- `naive_flood.py` against the daemon: about 35k guesses in 30 s, zero hits.
- The flag is never baked into the image; the daemon reads `/flag.txt` fresh on every successful
  admission.
- Not re-verified behind a reverse proxy that might strip WebSocket upgrades. If the console
  loads but never shows "live", check that first.
