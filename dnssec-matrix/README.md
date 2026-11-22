# DNSSEC Matrix: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

This builds the image and starts the console on <http://localhost:8080>.

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the challenge |
| `.\demo.ps1 -Port 8085` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-dnssec-matrix .
docker run -d --name ctf-dnssec-matrix -p 8080:8080 ctf-dnssec-matrix
```

Then open <http://localhost:8080>. Stop it with `docker rm -f ctf-dnssec-matrix`.

## Files

```
challenge.md        description + ROT13 hints
demo.ps1            one-command local launcher
Dockerfile          the service (single container, port 8080)
src/                SPOILER: server source, page and assets
solution/           SPOILER: WRITEUP.md and solve.py
```

## Checking your solve

```bash
pip install requests
python solution/solve.py http://localhost:8080
```
