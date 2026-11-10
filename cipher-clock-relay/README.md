# Cipher-Clock Relay: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

The capture you analyse is `relay_dump.pcap`, already in this folder. The demo starts the relay.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the relay on `localhost:8338` |
| `.\demo.ps1 -Port 9338` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-cipher-clock-relay .
docker run -d --name ctf-cipher-clock-relay -p 8338:8338 ctf-cipher-clock-relay
```

Stop it with `docker rm -f ctf-cipher-clock-relay`.

## Talking to the relay

It's a plain TCP line service on port 8338:

- `nc localhost 8338` (Linux/macOS/WSL)
- `ncat localhost 8338` (comes with Nmap on Windows)
- a short Python `socket` script

Each round has a 120 second limit, so don't take forever.

## Tools you'll want

- [Wireshark](https://www.wireshark.org/) or `tshark`

## Files

```
challenge.md        description + ROT13 hints
relay_dump.pcap     the capture
demo.ps1            one-command local launcher
Dockerfile          the relay service (port 8338)
src/                SPOILER: relay source and the script that built the capture
solution/           SPOILER: WRITEUP.md and solve.py
```

## Checking your solve

```bash
python3 solution/solve.py relay_dump.pcap localhost 8338
```
