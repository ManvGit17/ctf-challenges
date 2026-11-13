# The Impostor Resolver: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

This builds the image and starts the console on <http://localhost:5000>.

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the challenge |
| `.\demo.ps1 -Port 5050` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

On some Windows machines port 5000 is already taken. Use `-Port 5050` if the container won't
start.

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-impostor-resolver .
docker run -d --name ctf-impostor-resolver -p 5000:5000 ctf-impostor-resolver
```

Then open <http://localhost:5000>. Stop it with `docker rm -f ctf-impostor-resolver`.

## Tuning

The server reads a few environment variables. The defaults are what the challenge is meant to
be played with.

| Variable | Default |
|---|---|
| `RACE_WINDOW_MIN_MS` / `RACE_WINDOW_MAX_MS` | `60` / `650` |
| `TARGET_DOMAIN` | `crewmate.ctf` |
| `LEGIT_IP` | `1.2.3.4` |

Pass them with `-e`, for example `docker run -e RACE_WINDOW_MAX_MS=2000 ...`.

## Files

```
challenge.md        description + ROT13 hints
demo.ps1            one-command local launcher
Dockerfile          the service (single container, port 5000)
src/                SPOILER: server source, page and assets
solution/           SPOILER: WRITEUP.md and solve.py
```

## Checking your solve

```bash
pip install requests
python solution/solve.py http://localhost:5000
```
