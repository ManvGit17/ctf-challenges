# The Handshake Skimmer: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

This builds the image (the first build compiles a Go binary and takes a couple of minutes) and
starts the service on <http://localhost:8080>. There's no web page; it's an HTTP API. Start with
`/protocol`.

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the challenge |
| `.\demo.ps1 -Port 8181` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-handshake-skimmer .
docker run -d --name ctf-handshake-skimmer -p 8080:8080 ctf-handshake-skimmer
```

Stop it with `docker rm -f ctf-handshake-skimmer`.

## Good to know

- Every **build** shuffles an internal struct layout, so offsets from someone else's write-up
  won't match your image. `-Rebuild` gives you a new layout.
- Every **container start** picks new session values and timing. Restarting is fine; you just
  redo the live part.
- No extra Docker capabilities are needed. A plain `docker run` works.
- The binary served at `/binary` is a Linux ELF. You only need to analyse it, not run it, so
  Windows is fine.

## Tools you'll want

- Python 3 (`requests`, `pyelftools`, `cryptography` are handy)
- Ghidra, IDA, or anything that reads ELF symbols and DWARF

## Files

```
challenge.md        description + ROT13 hints
PROTOCOL.md         the capture format (public, also served at /protocol)
demo.ps1            one-command local launcher
Dockerfile          builds the daemon (single container, port 8080)
src/                SPOILER: daemon source and the layout shuffler
solution/           SPOILER: WRITEUP.md and solve.py
```

## Checking your solve

```bash
pip install requests pyelftools cryptography
python solution/solve.py http://127.0.0.1:8080
```
