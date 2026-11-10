# Keyhole

| Category | Flag format |
|---|---|
| Reverse Engineering | `isfcr{...}` |

## Description

> A door that never asks for a password. It hands you a slip of paper and waits.

## What you get

- A web service on `http://localhost:1337` once you run the demo (see [README.md](README.md)).
- Whatever the service lets you take home. The demo also puts a copy in `handout/`.

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Gur cncre vf bayl n abgr. Jubrire jebgr vg yrsg gurve unaqjevgvat va jung lbh gbbx ubzr.`
2. `Rirel fgebxr pna or gnxra onpx, vs lbh xabj gur cra.`
3. `Gur qbbe arire jevgrf gur fnzr unaq gjvpr, naq vgf frpbaq yvar vf abg vgf svefg.`
4. `Gernfher ylvat arkg gb gur ybpx vf onvg.`

## Spoilers

- `src/` is the source of the binary and the service. Opening it gives the answer away.
- `solution/` has the write-up and a reference solver.
