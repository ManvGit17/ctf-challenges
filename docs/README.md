# Player guide

Everything that applies to all challenges in this repo. Each challenge's own `README.md` only
covers what's specific to it.

## What you need

| Tool | Why |
|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Every challenge runs in containers. It must be **running**, not just installed. |
| PowerShell 5.1+ | Runs `demo.ps1`. Already on every Windows 10/11 machine. |
| Git | To clone the repo (or download the ZIP from GitHub instead). |
| Python 3 | Most solve scripts are Python, and you'll probably want it for your own. |

Category-specific tools are listed in each challenge README (Wireshark for forensics,
Ghidra/IDA for reversing, and so on).

## How a demo script works

Every `demo.ps1` follows the same pattern:

1. Checks that Docker is installed and running.
2. Builds the challenge image the first time (later runs reuse it).
3. Starts the container and maps its port to `localhost`.
4. Writes a **random local flag** into the container, the same way a CTF platform injects one.
5. Copies any files you're meant to analyse into the challenge's `handout/` folder.
6. Prints where to connect.

Common switches, supported by every script:

| Switch | Effect |
|---|---|
| *(none)* | Start the challenge |
| `-Port <n>` | Use another host port if the default is busy |
| `-Stop` | Stop and remove the container |
| `-Rebuild` | Rebuild the image from scratch |

Some challenges add more (for example `-Fresh` to regenerate files); their README lists them.

## About the flag

Because you're hosting the challenge yourself, the flag is random each time and is only known
to your container. You *could* `docker exec` in and read `/flag.txt`, but that's like flipping
to the last page of a puzzle book. The flag is only a receipt. The point is the solve path.

You'll know you've solved it when the challenge itself hands you an `isfcr{...}` string through
its intended path. Several challenges contain fake flags on purpose, so a flag-shaped string you
found lying around is probably a trap.

## Fair play

- Read `challenge.md`, not the source. Folders like `src/`, `generator/` and `solution/` exist
  so the challenge can be built, but they contain the answer.
- Use the hints in order. Each one gives away more than the last.
- Attacking the container itself (escaping Docker, reading files from the host) is out of scope.
  Treat the service as a remote box you only reach over the network.

## Troubleshooting

### PowerShell says running scripts is disabled

Windows blocks unsigned scripts by default. Either run it once with a bypass:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo.ps1
```

or allow local scripts for your user (one time):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

If you downloaded the repo as a ZIP, Windows may also mark the files as "from the internet".
Run `Get-ChildItem -Recurse | Unblock-File` inside the folder.

### "Docker is installed but not running"

Start Docker Desktop and wait until it says *Engine running*, then rerun the script.

### "Is port N already in use?"

Something else is on that port. Pick another: `.\demo.ps1 -Port 8080`.

### The build fails while downloading packages

Usually a temporary network hiccup with a package mirror. Run the script again. If it keeps
failing, try `.\demo.ps1 -Rebuild`.

### I'm on Linux or macOS

Every challenge README has a "Manual setup" section with plain `docker` commands. `demo.ps1`
also works with [PowerShell 7](https://github.com/PowerShell/PowerShell) (`pwsh ./demo.ps1`).

### Running a Linux binary on Windows

Use WSL (`wsl ./binary`) or a throwaway container
(`docker run --rm -it -v "${PWD}:/w" -w /w ubuntu bash`).

## Cleaning up

```powershell
.\demo.ps1 -Stop                       # stop one challenge
docker image ls "ctf-*"                # images created by this repo
docker image rm ctf-keyhole            # remove one
```

## For challenge authors: adding a new challenge

1. Copy `_template/` to a new folder named after the challenge (lowercase, hyphens, no
   "challenge" in the name): `keyhole`, `pilgrim-trace`.
2. Fill in `challenge.md`. Encode each hint with ROT13
   (`echo "hint" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`).
3. Put the Dockerfile and sources in the folder, and set the names, ports and handout path at the
   top of `demo.ps1`.
4. Write `solution/WRITEUP.md` and a solve script, and check the solve script works against a
   fresh `demo.ps1` run.
5. Add a row to the challenge table in the root `README.md`.
