# Keyhole — intended solve path

## 1. Recon

- `GET /` and `GET /keyhole` get you a stripped, statically-linked Linux ELF. No symbols, but
  `file keyhole` shows `statically linked`, and `strings keyhole` turns up a few things worth
  noting (and one that's a trap, see §5):
  - `"keyhole v2.3 - access terminal"`, `"usage: %s <ticket.bin>"`, `"KEYHOLE_DEBUG=1"` — real,
    harmless usage text.
  - `"--legacy"` — an undocumented second argv flag.
  - A short run of high-entropy bytes with no readable string near it — the XOR-obfuscated decoy
    (§5).
- `POST /api/new` (any HTTP client, `curl -c jar.txt -X POST http://host:port/api/new`) returns:
  ```json
  {"round": 1, "total": 2, "ticket": "<base64>", "deadline": 1700000000.0}
  ```
  Base64-decode `ticket` → exactly 32 bytes.

## 2. Ticket format

Running the binary with no args (or reading its early basic blocks in a disassembler) shows it
`fopen`s argv[1], `fread`s 32 bytes into a local buffer, and immediately `memcmp`s the first 4
bytes against the string `"KHT1"`. Laying the 32 bytes out against that check and the sizes the
function later indexes into gives:

```
offset  size  field
0       4     magic "KHT1"
4       4     seed (u32, little-endian)
8       1     mode
9       3     reserved / noise, unused
12      12    target[12]  — compared against the transformed input
24      8     noise, unused
```

## 3. Key schedule

Right after the magic check, the binary runs a tight loop twelve times over a 32-bit local
variable: multiply by a constant, add a constant, take the top byte. In a disassembler this
shows up as a single `imul`/`add` pair inside a loop with the loop counter capped at 12 — easiest
to recognize by setting a breakpoint on it (gdb) and watching the register after each iteration,
or by reading the two 32-bit immediates directly out of the instruction operands:

```c
state = seed ^ 0xA53C9D1F;
for (i = 0; i < 12; i++) {
    state = state * 0x41C64E6D + 0x3039;
    k[i] = (uint8_t)(state >> 24);
}
```

The XOR with `0xA53C9D1F` before the loop starts is easy to miss if you only skim — it's a
separate instruction a few lines before the loop's entry block, not inside it.

## 4. Mode dispatch and the three transforms

The binary reads `ticket.mode % 3` and uses it as an index into a 4-entry array of function
pointers (visible in the disassembly as an indirect `call` through a table in `.rodata`/`.data.rel.ro`,
or in Ghidra as `TABLE[mode](...)`). Only indices 0–2 are ever reachable from the normal flow —
index 3 is the decoy (§5). Decompile each of the three real functions:

- **mode 0:** `rol8(c ^ k[i], (i % 7) + 1)`
- **mode 1:** `(uint8_t)(c + k[i]) ^ (uint8_t)(i * 0x1d)`
- **mode 2:** `ror8(c, 3) ^ k[i] ^ k[(i + 5) % 12]`

(`rol8`/`ror8` are small static helper functions a disassembler will show inlined or as two-line
leaf functions — a shift left/right and an OR.)

Every round's ticket sets a `mode` byte, and the service deliberately never repeats the previous
round's mode — so round 1 and round 2 will use two different transforms. You need to recognize
and invert all three, not just the first one you find.

## 5. The decoy — don't trust the first "flag" you see

`strings keyhole` (or a disassembler's data view) turns up a 28-byte blob of what looks like
noise sitting near a tiny XOR-decode loop and an `fprintf(stderr, "[legacy] %s\n", ...)` call.
Decoding it with a single-byte XOR key (easy to find — the key byte is loaded as an immediate
right next to the loop) gives a string that *looks* like a flag:

```
CNS{N1CE_TRY_KEEP_REVERSING}
```

This function (`legacy_transform`) sits in slot 3 of the dispatch table and is only reachable by
passing `--legacy` as a second argument — and even then, it only prints that string to stderr and
then unconditionally denies. It never participates in the real check (mode is always 0/1/2), and
the decoded text is not a valid flag. It exists to catch anyone who treats "found a CNS{...}-shaped
string in the binary" as the win condition instead of actually solving the per-round math — submitting
it to `/api/submit` just comes back `{"status": "wrong"}`. The real flag only ever comes from
`/flag.txt`, returned by the service after two correct codes.

## 6. Inverting

For each byte `i` of `target`, invert whichever mode the ticket selected:

- **mode 0:** `c = ror8(target[i], (i % 7) + 1) ^ k[i]`
- **mode 1:** `c = (target[i] ^ (i * 0x1d)) - k[i]  (mod 256)`
- **mode 2:** `c = rol8(target[i] ^ k[i] ^ k[(i + 5) % 12], 3)`

Each recovered byte should land exactly on an ASCII character in `A-Z2-9` (the code's charset) —
that's a good self-check that the mode/math was read correctly. Submit the 12-character code via
`/api/submit`. Repeat for round 2 with its own fresh seed/mode/ticket. Two correct rounds in one
session → the flag, read live from `/flag.txt`.

`solve.py` in this directory automates all of the above end to end and optionally cross-checks
each recovered code against the real binary before submitting it.
