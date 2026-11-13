# CTF Challenges

Challenges I've written for CTF events, released here once the event is over so anyone can
play them.

If you're into security, CTFs are one of the best ways to learn it: every challenge is a small,
self-contained puzzle that makes you read code, poke at a binary, dig through a packet capture
or break a bad crypto scheme, then prove it with a flag. You learn far more from solving one
yourself than from reading ten write-ups. So pick a challenge, try it properly, use the hints
when you're stuck, and only open the solution once you've solved it or given it a real shot.

**New challenges get added regularly**, usually soon after they've been used in a CTF. Star or
watch the repo to see them land.

## Challenges

| Challenge | Category | Runs as |
|---|---|---|
| [Keyhole](keyhole/) | Reverse Engineering | HTTP service + Linux binary |
| [Pilgrim's Trace](pilgrim-trace/) | Forensics (network) | PCAP file + TCP relay |
| [Cipher-Clock Relay](cipher-clock-relay/) | Network / Forensics | PCAP file + TCP relay |
| [Stark Nightshift](stark-nightshift/) | Web / Networking | Web console (browser only) |
| [Dead Reckoning](dead-reckoning/) | Forensics / Crypto / OSINT | PNG file (nothing to run) |
| [The Impostor Resolver](impostor-resolver/) | Web / Networking | Web console + your own script |

## Quick start

You need [Git](https://git-scm.com/) and
[Docker Desktop](https://www.docker.com/products/docker-desktop/) (running).

```powershell
git clone https://github.com/ManvGit17/ctf-challenges.git
cd ctf-challenges\keyhole
.\demo.ps1
```

That's it: the script builds the challenge, starts it on your machine and tells you where to
connect. Then open that folder's `challenge.md` and start hacking. `.\demo.ps1 -Stop` shuts it
down.

Not on Windows? Every challenge README also has the plain `docker` commands.

## How each challenge folder is laid out

Every challenge lives in its own folder named after the challenge, and every folder follows the
same layout:

```
<challenge-name>/
  challenge.md     The brief: description, category, flag format, ROT13 hints
  README.md        How to run it locally: the one-command demo and the manual docker steps
  demo.ps1         One-command launcher for Windows PowerShell
  Dockerfile ...   Whatever the challenge needs to run (service source, generators, etc.)
  handout/         Created by some demo.ps1 scripts: files pulled out of the container (not in git)
  solution/        SPOILERS: WRITEUP.md (step-by-step solve path) + solve script
```

| File | Read it when |
|---|---|
| `challenge.md` | First. It's what you'd see on the CTF platform. |
| `README.md` | To get the challenge running. |
| `demo.ps1` | Just run it. |
| `solution/` | After you've solved it, or truly given up. |

Some challenges also have a `src/` or `generator/` folder. Those are needed to build the
challenge but they give the answer away, so treat them like `solution/`.

## Hints

Hints in `challenge.md` are ROT13 encoded, so you can't read them by accident. Paste one into
any ROT13 decoder ([rot13.com](https://rot13.com), [CyberChef](https://gchq.github.io/CyberChef/#recipe=ROT13()),
or `tr 'A-Za-z' 'N-ZA-Mn-za-m'`) when you need a push. They go from gentle to near-direct, so
decode them one at a time.

## Grabbing just one challenge

You don't need the whole repo. Git's sparse checkout fetches a single folder:

```bash
git clone --filter=blob:none --sparse https://github.com/ManvGit17/ctf-challenges.git
cd ctf-challenges
git sparse-checkout set keyhole
```

Want it without the solution sitting right there? Use pattern mode and exclude it:

```bash
git clone --filter=blob:none --no-checkout https://github.com/ManvGit17/ctf-challenges.git
cd ctf-challenges
git sparse-checkout set --no-cone 'keyhole/' '!keyhole/solution/'
git checkout
```

Later, `git sparse-checkout add pilgrim-trace` pulls in another one, and `git pull` picks up
new challenges.

## More help

- [docs/README.md](docs/README.md): the player guide. Prerequisites, how the demo scripts work,
  where the flag lives, fair play, and troubleshooting.
- [_template/](_template/): the skeleton every challenge is built from.

## Feedback

Found a bug, an unintended solution, or a challenge that won't start? Open an issue. Unintended
solves are especially welcome.
