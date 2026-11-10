# Keyhole: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

This builds the image, starts the service on <http://localhost:1337> and copies the `keyhole` binary to `handout/`.

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the challenge |
| `.\demo.ps1 -Port 8080` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-keyhole .
docker run -d --name ctf-keyhole -p 1337:1337 ctf-keyhole
```

Then open <http://localhost:1337>. Stop it with `docker rm -f ctf-keyhole`.

## How it plays

1. `GET /` shows the instructions page.
2. `GET /keyhole` downloads the checker binary.
3. `POST /api/new` starts a session (cookie `sid`) and returns round 1's base64 ticket.
4. `POST /api/submit` with `{"code": "<12 chars, A-Z 2-9>"}` submits the access code.
5. Two correct rounds in one session return the flag.

Each round has a 300 second deadline and 40 attempts. For quicker local testing you can override
them with environment variables: `-e ROUND_SECONDS=3 -e MAX_ATTEMPTS=3`.

The binary is a Linux ELF. On Windows, run it inside WSL or a Linux container. You can solve the
whole challenge statically in Ghidra/IDA without running it.

## Files

```
challenge.md        description + ROT13 hints
demo.ps1            one-command local launcher
Dockerfile          builds the binary and the HTTP service (single container, port 1337)
src/                SPOILER: source of the binary and the service
solution/           SPOILER: WRITEUP.md, solve.py
```

## Checking your solve

```bash
python3 solution/solve.py http://localhost:1337
```
