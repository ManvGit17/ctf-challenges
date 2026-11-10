# Pilgrim's Trace: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

The capture you analyse is `pilgrims_trace.pcap`, already in this folder. The demo only starts
the relay.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the relay on `localhost:9000` |
| `.\demo.ps1 -Port 9100` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the relay container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-pilgrim-relay relay_service
docker run -d --name ctf-pilgrim-relay -p 9000:9000 ctf-pilgrim-relay
```

Stop it with `docker rm -f ctf-pilgrim-relay`.

## Talking to the relay

It's a plain TCP line protocol on port 9000. Use whatever you like:

- `nc localhost 9000` (Linux/macOS/WSL)
- `ncat localhost 9000` (comes with Nmap on Windows)
- a short Python `socket` script, which you will want anyway

## Tools you'll want

- [Wireshark](https://www.wireshark.org/) or `tshark`
- Python 3 (with `scapy` if you like scripting your analysis)

## Files

```
challenge.md          description + ROT13 hints
pilgrims_trace.pcap   the capture
demo.ps1              one-command local launcher
relay_service/        the live service (Dockerfile + relay_server.py, port 9000)
generator/            SPOILER: the script that built the capture
solution/             SPOILER: WRITEUP.md and solve.py
```

## Checking your solve

```bash
pip install scapy
python3 solution/solve.py pilgrims_trace.pcap localhost 9000
```
