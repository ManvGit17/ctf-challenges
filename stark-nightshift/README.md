# Stark Nightshift: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

This builds the image, starts the service on <http://localhost:8080> and puts a random local flag
in the container. Open the URL in a browser; there is no handout file for this one.

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the challenge |
| `.\demo.ps1 -Port 9090` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

If PowerShell refuses to run the script, see the
[player guide](../docs/README.md#powershell-says-running-scripts-is-disabled).

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-stark-nightshift .
docker run -d --name ctf-stark-nightshift -p 8080:8080 ctf-stark-nightshift
docker exec -u root ctf-stark-nightshift sh -c 'echo "pesuctf{local_test_flag}" > /flag.txt'
```

Then open <http://localhost:8080>. Stop it with `docker rm -f ctf-stark-nightshift`.

## Notes

- Everything happens in the browser. The page streams a live feed from the service over a
  WebSocket; you work out a plan from what you see and commit to it.
- Blind flooding is punished by a lockdown that lasts up to 90 seconds, so if the console stops
  responding to your attempts, wait it out.
- Solving it needs a few minutes of watching the feed before the first attempt.

## Files

```
challenge.md        description + ROT13 hints
demo.ps1            one-command local launcher
Dockerfile          builds the service (single container, port 8080)
src/                SPOILER: source of the vault daemon, the web relay and the console
solution/           SPOILER: WRITEUP.md, solve.py, AUTHOR_NOTES.md
```
