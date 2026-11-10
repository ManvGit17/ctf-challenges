# Keyhole: solve path

## 1. Recon

`GET /keyhole` gives a stripped, statically linked Linux ELF. `strings` shows a few things:

- `keyhole v2.3 - access terminal`, `usage: %s <ticket.bin>` and `KEYHOLE_DEBUG=1`. Harmless
  usage text.
- `--legacy`, an undocumented second argument.
- A short run of high-entropy bytes with nothing readable around it. That is the decoy, see
  section 5.

`POST /api/new` (for example `curl -c jar.txt -X POST http://host:port/api/new`) returns:

```json
{"round": 1, "total": 2, "ticket": "<base64>", "deadline": 1700000000.0}
```

The ticket decodes to exactly 32 bytes.

## 2. Ticket format

The binary opens argv[1], reads 32 bytes and compares the first 4 against `KHT1`. Matching the
32 bytes against the sizes the function indexes into gives:

```
offset  size  field
0       4     magic "KHT1"
4       4     seed (u32, little-endian)
8       1     mode
9       3     reserved, unused
12      12    target[12], compared against the transformed input
24      8     noise, unused
```

## 3. Key schedule

After the magic check there is a loop that runs 12 times over a 32-bit variable: multiply, add,
take the top byte. Set a breakpoint in it and watch the register, or read the two immediates off
the instruction operands:

```c
state = seed ^ 0xA53C9D1F;
for (i = 0; i < 12; i++) {
    state = state * 0x41C64E6D + 0x3039;
    k[i] = (uint8_t)(state >> 24);
}
```

The XOR with `0xA53C9D1F` is easy to miss. It sits a few instructions before the loop, not
inside it.

## 4. Mode dispatch

The binary uses `mode % 3` as an index into a table of four function pointers. Slots 0 to 2 are
reachable in normal use. Slot 3 is the decoy. The three real transforms, applied per byte `c` of
the input at position `i`:

- mode 0: `rol8(c ^ k[i], (i % 7) + 1)`
- mode 1: `(uint8_t)(c + k[i]) ^ (uint8_t)(i * 0x1d)`
- mode 2: `ror8(c, 3) ^ k[i] ^ k[(i + 5) % 12]`

The service never repeats the previous round's mode, so the two rounds use different transforms.
You have to recognise and invert all three.

## 5. The decoy

Near a small XOR-decode loop there is a 28-byte blob and an `fprintf(stderr, "[legacy] %s\n", ...)`
call. Decoding it with the single-byte key (loaded as an immediate next to the loop) gives:

```
flag{N1CE_TRY_KEEP_REVERSING}
```

That function (`legacy_transform`) is slot 3 of the table. It is only reachable with `--legacy`,
it only prints that string to stderr, and then it denies. It never takes part in the real check,
and the string is not a flag. Submitting it to `/api/submit` returns `{"status": "wrong"}`. The
real flag only comes back from the service after two correct codes.

## 6. Inverting

For each byte `i` of `target`, undo the mode the ticket selected:

- mode 0: `c = ror8(target[i], (i % 7) + 1) ^ k[i]`
- mode 1: `c = (target[i] ^ (i * 0x1d)) - k[i]  (mod 256)`
- mode 2: `c = rol8(target[i] ^ k[i] ^ k[(i + 5) % 12], 3)`

Every recovered byte should be a character from `A-Z2-9`. If one is not, the mode or the math
was read wrong. Submit the 12 characters to `/api/submit`, then repeat for round 2 with its own
seed, mode and ticket. Two correct rounds in one session return the flag.

`solve.py` does all of this and can check each code against the real binary before submitting.
