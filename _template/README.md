# Challenge Name: running it locally

Read [challenge.md](challenge.md) first for the description and hints. This file only covers
setup.

## One command (Windows, PowerShell)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```powershell
.\demo.ps1
```

| Command | What it does |
|---|---|
| `.\demo.ps1` | Build (if needed) and start the challenge |
| `.\demo.ps1 -Port 8080` | Use a different host port |
| `.\demo.ps1 -Stop` | Stop and remove the container |
| `.\demo.ps1 -Rebuild` | Force a fresh image build |

## Manual setup (Linux / macOS / anything with Docker)

```bash
docker build -t ctf-NAME .
docker run -d --name ctf-NAME -p 1337:1337 ctf-NAME
docker exec -u root ctf-NAME sh -c 'echo "isfcr{local_test_flag}" > /flag.txt'
```

## Files

```
challenge.md        description + ROT13 hints
demo.ps1            one-command local launcher
Dockerfile          the challenge service
src/                SPOILER: challenge source
solution/           SPOILER: WRITEUP.md + solve script
```
