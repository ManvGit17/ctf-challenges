# Pilgrim's Trace: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

The challenge has two parts that must agree on the same flag: the capture you analyse and the
relay you talk to. The demo script handles that for you.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

On the first run this:

1. picks a random local flag and keeps it in `.local/` (so restarts reuse the same capture),
2. builds a small generator image and writes `handout/pilgrims_trace.pcap`,
3. builds and starts the relay on `localhost:9000`.

| Command | What it does |
|---|---|
| `.\demo.ps1` | Start the relay (generates the capture on first run) |
| `.\demo.ps1 -Port 9100` | Use a different host port for the relay |
| `.\demo.ps1 -Fresh` | New flag and a brand new capture |
| `.\demo.ps1 -Stop` | Stop and remove the relay container |
| `.\demo.ps1 -Rebuild` | Force fresh image builds |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
FLAG='isfcr{local_test_flag}'
mkdir -p handout

# 1. capture
docker build -t ctf-pilgrim-gen generator
docker run --rm -v "$PWD/handout:/out" ctf-pilgrim-gen --flag "$FLAG" --file /out/pilgrims_trace.pcap > /dev/null

# 2. relay
docker build -t ctf-pilgrim-relay relay_service
docker run -d --name ctf-pilgrim-relay -p 9000:9000 ctf-pilgrim-relay
docker exec ctf-pilgrim-relay sh -c "printf '%s' '$FLAG' > /flag.txt"
```

The generator prints the answer to stdout, which is why it goes to `/dev/null`.

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
challenge.md        description + ROT13 hints
demo.ps1            one-command local launcher
relay_service/      the live service (Dockerfile + relay_server.py, port 9000)
generator/          SPOILER: builds the capture for a given flag
solution/           SPOILER: WRITEUP.md, solve.py, AUTHOR_NOTES.md
```

## Checking your solve

```bash
pip install scapy
python3 solution/solve.py handout/pilgrims_trace.pcap localhost 9000
```
