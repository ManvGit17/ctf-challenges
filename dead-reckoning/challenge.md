# Dead Reckoning

| Category | Flag format |
|---|---|
| Forensics / Crypto / OSINT | `flag{...}` |

## Description

> Freight flight CORVID 451 went dark mid-route. The review board kept one radar screenshot and
> nothing else. Find where it came down, and what it was carrying.

## What you get

- `dead_reckoning.png` (it sits next to this file).

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Lbhe vzntr ivrjre oryvrirf jung gur urnqre gryyf vg. Lbh qba'g unir gb.`
2. `Rirel jbeq ba gur jver jnf frag gjvpr. Bayl bar pbcl jnf fcbxra ubarfgyl.`
3. `Jurer n wbhearl fgnegf vf eneryl jurer vg raqf.`
4. `Gjb xrlf gung jrer arire fhccbfrq gb zrrg fbzrgvzrf funer n frperg naljnl.`

## Spoilers

- `generator/` is the script that built the image, so it shows exactly where everything is
  hidden.
- `solution/` has the write-up and a reference solver.
