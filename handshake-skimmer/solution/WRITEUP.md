# The Handshake Skimmer: intended solve path

The daemon (`microtund`) runs an X25519 handshake with itself every 2 to 5 seconds and logs every
handshake to `/capture`. Every so often it also seals the flag with that epoch's session key and
logs the ciphertext. The key itself never hits the wire; it only lives in memory, in a two-slot
ring buffer. The job is to read it out of memory in time.

Endpoints: `/protocol`, `/notes`, `/journal`, `/binary`, `/capture`, `/dump`.

## 1. Get the auth token

`/notes` is ROT13. Decoded, it's some "legacy onboarding notes" with a formula:

```
raw   = bytes.fromhex(session_token)
mac   = hmac_sha256(key=b"microtun-seed-v1", msg=raw)
token = hex(mac)[:20]
```

The `changeme` admin token it also mentions is a dead end (403).

`/journal` is systemd and cron noise with one audit line that matters:

```
... audit[812]: TOKEN_MINT ... session_token=6b8fbc3b9491b6a00485afe2e5d4f09b
```

```python
import hmac, hashlib
print(hmac.new(b"microtun-seed-v1", bytes.fromhex("6b8f..."), hashlib.sha256).hexdigest()[:20])
```

That's the `token=` for `/dump`. The session token changes every time the container starts.

## 2. Find the odd epoch in /capture

`/protocol` documents the framing: `[1B type][8B epoch][8B ts][4B len][payload]`, and says
every epoch produces exactly one `0x01` and one `0x02` frame. Parse the capture and count types.
Every 6 to 10 epochs there's an extra `0x03` frame right after a handshake. That's the epoch
carrying the flag.

## 3. Reverse the binary for the key's address

`/binary` is the running daemon. It's a Go PIE, not stripped, with DWARF intact.

- `main.slots` is a global `[2]sessionSlot`. Epoch `n` lives in slot `n % 2`.
- `sessionSlot` has `Key`, `Nonce`, `EpochID`, `Created` and some padding. Field order and padding
  are shuffled on every build, so read the layout from DWARF, not from someone else's notes.

```python
from elftools.elf.elffile import ELFFile
elf = ELFFile(open("microtund", "rb"))
base = min(s["p_vaddr"] for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
slots = next(s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()
             if s.name == "main.slots") - base
# then walk DWARF for main.sessionSlot: DW_AT_byte_size and the Key member's offset
```

Gotcha: Go links PIEs with a non-zero base vaddr (usually `0x400000`). Subtract the lowest
`PT_LOAD` vaddr from the symbol value to get an offset `/dump` understands.

```
key_offset = slots + (epoch % 2) * struct_size + key_field_offset
```

## 4. Race /dump

```
GET /dump?offset=<hex, no 0x>&len=32&epoch=<id>&token=<token>
```

`/dump` reads the daemon's own memory (`/proc/self/mem`), with limits:

- at most 64 bytes, only inside a mapped region,
- only if `epoch` is still the live occupant of its slot (otherwise 409),
- one request per 2 seconds, and 3 failures (bad token or stale epoch) lock you out for 30 s.

The slot gets overwritten two rotations later, so you have roughly 4 to 10 seconds. Watch
`/capture`, and the moment the `0x03` frame appears, fire one well-formed request. Polling blind
burns your failures and gets you locked out.

## 5. Decrypt

The AEAD scheme isn't in the spec. You get it from the binary (`sealToken`):

- ChaCha20-Poly1305 with the 32-byte key from `/dump`
- nonce = first 4 bytes of the epoch nonce (from that epoch's `0x01` payload) + epoch id as
  8-byte big-endian
- AAD = the raw 21-byte header of that epoch's `0x01` frame

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import struct
nonce = epoch_nonce[:4] + struct.pack(">Q", epoch_id)
print(ChaCha20Poly1305(key).decrypt(nonce, frame03_payload, msg1_header))
```

## What doesn't work

| Attempt | Result |
|---|---|
| analysing `/capture` alone | only public handshake material, never the key |
| `changeme` or a guessed token | 403, counts as a failure |
| `/dump` for a stale or future epoch | 409, counts as a failure |
| `len` over 64, or an address outside mapped memory | 400 |
| hammering `/dump` | 429, then a 30 s lockout |
| offsets from another build | wrong bytes, the layout is shuffled per build |

## Reference solver

```bash
pip install requests pyelftools cryptography
python solve.py http://127.0.0.1:8080
```
