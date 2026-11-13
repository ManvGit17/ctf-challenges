# Dead Reckoning: intended solve path

One PNG, five locks. Each stage's output is the key for the next, so a mistake early on just
gives garbage later instead of a wrong-looking flag.

```
dead_reckoning.png
 A  hidden rows      IDAT holds 320 rows, IHDR says 256 -> squawk -> decrypt trKr -> pcap
 B  TCP reassembly   keep only checksum-valid segments -> telemetry log
 C  OSINT            last NMEA fix (speed 0) -> airport -> ICAO code
 D  RSA              two keys share a prime -> gcd -> session key
 E  final key        HMAC(session_key, ICAO + squawk) -> decrypt tEXt Comment -> flag
```

## A. The image is taller than it says

The file opens fine everywhere as a 512x256 radar scope. Every chunk CRC is valid; nothing is
corrupt. The tell is size: inflate the IDAT yourself and divide by the row length
(`512*3 + 1` bytes with the filter byte). You get 320 rows, not 256.

Viewers stop drawing at the height IHDR declares, so the last 64 rows are never shown. Render the
full buffer as a 512x320 image (or patch the IHDR height and fix its CRC) and you get a "flight
strip" with six hex characters in a blocky font. That's the **squawk**, `B5F067` in this file.

There's also a private chunk, `trKr`. Its body is a `TRKR` + length header followed by data
XORed with a SHA-256 counter-mode keystream keyed by `SHA256(squawk || "trKr")`. Decrypt and
zlib-inflate it to get a pcap.

## B. Two copies of every segment

The pcap has one TCP flow on port 8099 plus background noise. Every chunk of the real stream is
sent twice at the same sequence number: once with a valid TCP checksum (real data) and once,
slightly earlier, with a broken checksum (decoy text).

"Follow TCP Stream" with default settings shows the decoy, which includes the fake flag
`flag{f0ll0w_str3am_lie}`. Turn on TCP checksum validation in Wireshark (or check them in a
script), drop every bad segment, and reassemble by sequence number. The result is the CORVID 451
telemetry log.

## C. Where it stopped

The log is `$GPRMC` / `$GPGGA` NMEA sentences. The track starts fast near one airport (the
origin, a trap) and slows down until the last `$GPRMC` fix reports a ground speed of `000.0`.
Convert that fix from degrees-minutes to decimal and look it up on a map. Here it's
13.6900, 100.7501, which is Bangkok Suvarnabhumi, ICAO **VTBS**.

## D. Two keys, one prime

The same log has a `CORVID GROUND KEY BUNDLE` block: two 1024-bit RSA moduli `N1` and `N2` with
`e = 65537`, a ciphertext under `N1`, and a third "AUX" key with `e = 3`.

The `e = 3` key is the bait. The message under it is small enough to never wrap the modulus, so a
plain integer cube root works, and it gives you a taunt telling you to gcd the real pair.

The real weakness: `N1` and `N2` were generated with a shared prime. `p = gcd(N1, N2)` factors
both, then `d = e^-1 mod (p-1)(q-1)`, decrypt, strip PKCS#1 v1.5 padding, and you have the
16-byte **session key**.

## E. Putting it together

```
key = HMAC-SHA256(session_key, ICAO + squawk)
```

The PNG's `tEXt` `Comment` is base64. Decode it and XOR with the SHA-256 counter-mode keystream
for `key` (nonce `stageE`). The plaintext is `DR01 | 2-byte length | flag | 8-byte tag`, where
the tag is `HMAC(key, "DR01" + flag)[:8]`. If the tag checks out, you have the flag.

## Decoys

| Decoy | Where | What it catches |
|---|---|---|
| LSB text ending in `flag{lsb_r4dar_gh0st}` | visible pixels | running `zsteg` and stopping at the first hit |
| bad-checksum segments with `flag{f0ll0w_str3am_lie}` | the pcap | Follow TCP Stream without validation |
| origin airport at the start of the track | NMEA log | taking the first fix instead of the last |
| `e = 3` AUX key | key bundle | jumping on the famous weak exponent |

The real flag never appears in plaintext anywhere in the file, so `strings | grep flag{` only
finds the decoys.

## Reference solver

```bash
python solve.py ../dead_reckoning.png
```

It imports the parsing helpers from `../generator/generator.py`.
