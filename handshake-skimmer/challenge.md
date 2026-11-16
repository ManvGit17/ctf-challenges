# The Handshake Skimmer

| Category | Flag format |
|---|---|
| Forensics / Reverse Engineering | `flag{...}` |

## Description

> A tunnel daemon shakes hands with itself every few seconds and writes all of it down. Almost
> all of it. One thing it only ever keeps in its head.

## What you get

- An HTTP service on `http://localhost:8080` once you run the demo. See [README.md](README.md).
- `PROTOCOL.md`, the daemon's published capture format (also served at `/protocol`).

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Byq abgrf fgvyy bcra qbbef. Gur ybt erzrzoref jub jnf unaqrq jung.`
2. `Gur fcrp fjrnef rirel ebhaq fbhaqf gur fnzr. Pbhag gurz.`
3. `N qnrzba gung unaqf lbh vgf bja obql pna or ernq yvxr n znc, vs vg xrcg vgf qenjvatf.`
4. `Vg bayl rire erzrzoref gur ynfg gjb. Or gurer orsber vg sbetrgf.`

## Spoilers

- `src/` is the daemon source. Opening it gives the answer away.
- `solution/` has the write-up and a reference solver.
