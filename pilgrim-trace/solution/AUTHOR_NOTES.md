# Author notes: Pilgrim's Trace

Internal design notes. Spoilers, obviously.

## How the two halves agree

The capture and the relay never talk to each other. Both compute the same access key from the
flag:

```
access_key = sha256("pilgrim-relay:" + flag).hexdigest()[:20]
```

The generator gets the flag via `--flag`; the relay reads it from `/flag.txt` on every
connection. Same flag in, same key out. On a CTF platform the capture is produced by a file
provisioner (`generator/pilgrim_generate_pcap.py`, extension `.pcap`) and the relay is a normal
Docker challenge with the flag injected into `/flag.txt`.

## Anti-shortcut design

Capture:

- The capture never contains the flag, only an access key, so solving stage 1 alone (or
  brute-forcing the XOR) is not enough.
- The access key is 20 hex chars wrapped in random padding: no `isfcr{` prefix to crib-drag.
- Two decoy key/payload pairs on 8443/9999: one from the real server, one from an unrelated
  host. Neither "rare port" nor "pivot on one IP" isolates the real one.
- Non-prime ICMP IP IDs span the full 16-bit range, overlapping the real clue's values.
- No fixed random seed. Decoy keys, channels, hosts and packet order change every generation.

Relay:

- Proof of work before any key attempt.
- `hmac.compare_digest` for the key check (no timing side channel).
- Uniform `ACCESS DENIED`, growing delay, 5 attempts per connection.
- Flag read fresh from `/flag.txt`, never cached or baked into the image.

## Caveats

- The flag prefix `isfcr` came from the original platform's settings, not from either script.
- The generator writes classic libpcap even if you name the file `.pcapng`. Wireshark does not
  care.
- The relay image is `python:3.11-alpine` with no editors. Use `docker exec -it <c> sh` if you
  need to poke around.

## Verification (original deployment)

- 45/45 generated captures solved via the intended path, flag lengths 5 to 46 chars.
- Relay: correct key grants access; wrong then correct recovers; skipped PoW is rejected; five
  wrong attempts close the connection.
- Full loop: a key extracted purely through the forensic chain unlocked the matching flag from a
  live relay container.
