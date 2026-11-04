# Admin notes — Keyhole

## Challenge name
**Keyhole**

## Domain / category
Reverse Engineering

## Difficulty
**Easy-plus** (above a textbook easy crackme, below a medium multi-stage binary). Target solve
time for a player comfortable with a disassembler/Ghidra and basic scripting: roughly 45–90
minutes.

## Points
**200**

---

## Objective description (mysterious, for the platform listing)

> There's a door that only opens for people who already know what's behind it. It doesn't ask
> for a password — it hands you a slip of paper and asks you to prove you can read its own
> handwriting.
>
> It will ask twice, and it never writes the same hand twice.

## Hints (progressive, mysterious — not direct)

**Hint 1 (cheap):**
> The slip of paper isn't the lock. The thing you downloaded is the lock. Read it before you
> write anything back.

**Hint 2 (moderate):**
> Twelve small steps, each one undoing itself if you walk it backwards. The paper tells you
> where you end up — not how you got there. That part's the lock's little secret, and it only
> has three ways of keeping it.

**Hint 3 (expensive, near-direct):**
> If you find something inside the lock that already looks like what you're hunting for,
> look again — it's dressed for the part, not cast for it. Whatever decides the real answer
> cannot be asked for it directly; it has to be walked from the end back to the start, one
> reversible step at a time, and it changes its method every time you knock.

---

## Internal — how the challenge is built

**Type:** Docker, single image/container/port, pure HTTP (no raw TCP).

**Mechanic:** Players download one stripped, statically-linked Linux ELF, `keyhole`, identical
for every player and every session. The web service hands out a fresh, randomized **ticket**
(32 raw bytes, base64-encoded over HTTP) once per round. Running
`./keyhole ticket.bin` (then typing a 12-character code at its prompt) tells you `GRANTED` or
`DENIED` for that ticket. The player must reverse how the binary derives and checks the code,
then do the same math themselves to recover the code the service will accept, submit it over
HTTP, and repeat for a second round before the flag is released.

### Why this resists naive / automated solving
- **No textbook pattern.** It's not a known CVE, not a standard `strcmp`-against-a-constant
  crackme, and not a published algorithm (no AES/known-PRNG the binary itself; the "LCG" uses
  arbitrary hand-picked constants, not glibc's `rand()` values, so pattern-matching on well-known
  magic numbers doesn't shortcut it).
- **Dynamic per-session state.** Every round gets a new random seed, a new transform mode, and a
  freshly generated target — nothing about one session's ticket or code carries over to the next,
  so there is no static "the answer is X" to memorize, publish, or cache. A write-up of a past
  session's code is useless against a new one.
- **Two different transforms, enforced.** The service guarantees round 2's mode differs from
  round 1's, so skimming/guessing from a single observed transform isn't enough — all three
  branches have to actually be read and inverted correctly.
- **A deliberate decoy.** A dead function (never reached by the real check; only reachable via an
  undocumented `--legacy` flag) decodes an XOR-obfuscated string that is shaped exactly like a
  flag (`CNS{...}`). This baits both naive human players and automated "grep the binary for
  flag-shaped strings and submit the first hit" tooling — including LLM-driven solvers that
  pattern-match on `CNS{` — into submitting a confident wrong answer. There is no shortcut that
  skips actually inverting the per-round math; the service only ever returns the real flag by
  reading `/flag.txt` after two correct rounds.
- **Live oracle, not a static file.** The player cannot solve this purely offline from a single
  downloaded artifact — they need the binary (reverse once) plus a live ticket each round
  (dynamic data), and must automate the inversion to beat the per-round timer across two
  differently-keyed, differently-moded rounds.

### Build

```
Dockerfile
  stage 1 (gcc:13-bookworm): gcc -O2 -s -static -o keyhole src/keyhole.c
  stage 2 (python:3.11-slim): copies the stripped binary + src/server.py,
                               touch /flag.txt (platform injects the real value later),
                               runs as unprivileged uid 10001,
                               CMD python3 /app/server.py, EXPOSE 1337
```

- `src/keyhole.c` — the checker (ticket parsing, key schedule, 3 transforms + 1 decoy, GRANTED/DENIED).
  Never shipped as source to players, only as the stripped binary.
- `src/server.py` — stdlib-only Python HTTP service: serves the binary, issues tickets, verifies
  submissions by recomputing the same transform server-side and comparing to the ticket's stored
  target (so the server never needs to remember the plaintext code — same check logic as the
  binary, just reimplemented in Python).

### Deployment facts

- **Type:** Docker, single container, single exposed TCP port (`1337`), single foreground process.
- **Flag handling:** `RUN touch /flag.txt && chmod 644 /flag.txt` in the Dockerfile; the real
  value is injected by the platform at deploy time. `read_flag()` in `server.py` opens and reads
  `/flag.txt` fresh on every successful solve — never cached, never read at startup, never baked
  into the image.
- **Per-player isolation assumed** (one container per player) — in-memory session dict in
  `server.py` is sufficient under that model; no shared/external state needed.
- **No raw sockets / no elevated capabilities** — everything happens over plain HTTP in one
  Python process; the checker binary is only ever executed by the player, never by the server.
- **Resource footprint:** one `python:3.11-slim` process serving a ~1 MB static binary and small
  JSON payloads; negligible CPU/memory, no heavy computation on the server side.

### Tuning

| Parameter | Default | Env override | Where |
|---|---|---|---|
| Rounds | 2 | `ROUNDS` | `src/server.py` |
| Per-round deadline | 300 seconds | `ROUND_SECONDS` | `src/server.py` |
| Max submit attempts per round | 40 | `MAX_ATTEMPTS` | `src/server.py` |
| Session idle TTL | 1200 seconds | `SESSION_TTL` | `src/server.py` |
| Max concurrent sessions | 512 | `MAX_SESSIONS` | `src/server.py` |
| Code length / charset | 12 chars, `A-Z2-9` | — (not env-tunable) | `CODE_LEN` / `CHARSET` |

All five are read via `os.environ.get(...)` with the defaults above, so a deploy never needs to
set them — they only matter for fast local testing (e.g. `-e ROUND_SECONDS=3 -e MAX_ATTEMPTS=3`
to exercise the timeout/attempt-cap paths in seconds instead of minutes).

---

## Internal — step-by-step solution

1. `GET /keyhole` to download the stripped ELF. `file`/`strings` confirm it's a static, stripped
   Linux binary with no obviously useful plaintext beyond usage text, an undocumented `--legacy`
   flag string, and one block of high-entropy bytes.
2. `POST /api/new` (with a cookie jar) to get round 1's ticket. Base64-decode it → 32 bytes.
3. Open the binary in Ghidra/IDA/radare2 (or trace it with gdb). In `main`:
   a. It `fread`s 32 bytes and checks the first 4 against `"KHT1"` → confirms the header layout
      `magic[4] | seed(u32 LE) | mode(u8) | reserved[3] | target[12] | noise[8]`.
   b. Right after, a loop runs exactly 12 times doing `state = state*0x41C64E6D + 0x3039; k[i] =
      state>>24;`, seeded from `seed ^ 0xA53C9D1F`. This is the 12-byte key schedule.
   c. `mode % 3` indexes a 4-entry function pointer table. Decompile indices 0, 1, 2:
      - `t = rol8(c ^ k[i], (i % 7) + 1)`
      - `t = (c + k[i]) ^ (i * 0x1d)` (both mod 256)
      - `t = ror8(c, 3) ^ k[i] ^ k[(i + 5) % 12]`
   d. Index 3 (`legacy_transform`) is a decoy: only reached via an undocumented `--legacy` CLI
      arg, decodes a single-byte-XOR string that reads `CNS{N1CE_TRY_KEEP_REVERSING}`, and always
      denies. It plays no part in the real check — recognizing this (dead from the normal control
      flow, wrong format/source for the real flag) is part of the intended solve, and submitting
      it to `/api/submit` returns `{"status": "wrong"}`.
4. Read the 12 `target` bytes and the `mode` byte from the decoded ticket. Derive the 12-byte key
   schedule from `seed` using the formula from step 3b. Invert whichever of the three transforms
   `mode % 3` selects, byte by byte, to recover the 12-character code (each recovered byte should
   land on `A-Z2-9` — a correctness check on the math):
   - mode 0: `c = ror8(target[i], (i % 7) + 1) ^ k[i]`
   - mode 1: `c = (target[i] ^ (i * 0x1d)) - k[i]  (mod 256)`
   - mode 2: `c = rol8(target[i] ^ k[i] ^ k[(i + 5) % 12], 3)`
5. `POST /api/submit {"code": "<recovered 12 chars>"}`. Correct → response contains round 2's
   ticket (guaranteed a different `mode` than round 1 — repeat steps 3c/4 for whichever mode this
   one uses, since it won't be the same as round 1's).
6. Submit round 2's code. Correct → `{"status": "solved", "flag": "<flag>"}`, read live from
   `/flag.txt` at that moment.
7. `solution/solve.py <base_url>` automates steps 2–6 end to end and (with `--verify-bin`) can
   independently re-check each recovered code against a locally-run copy of the real binary
   before submitting it. `solution/WRITEUP.md` has the full narrative write-up with reversing
   landmarks.
