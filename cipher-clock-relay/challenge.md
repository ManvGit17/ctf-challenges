# Cipher-Clock Relay

| Category | Flag format |
|---|---|
| Network / Forensics | `flag{...}` |

## Description

> Channel 8 went quiet, but the relay behind it still keeps time. It will talk to anyone who can
> keep up.

## What you get

- `relay_dump.pcap`, a packet capture (it sits next to this file).
- A relay on `localhost:8338` (raw TCP) once you run the demo. See [README.md](README.md).

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `N ybhq nafjre vf abg nyjnlf gur gehr bar.`
2. `Gur fvyrapr orgjrra gur abgrf vf cneg bs gur fbat.`
3. `N pybpx gung arire ehaf gur fnzr jnl gjvpr pnaabg or ernq bayl bapr.`
4. `Jung gur erpbeqvat tvirf lbh vf bayl jurer gur qvny fgnegf.`

## Spoilers

- `src/` has the relay source and the script that built the capture. Opening it gives the answer
  away.
- `solution/` has the write-up and a reference solver.
