# The Impostor Resolver

| Category | Flag format |
|---|---|
| Web / Networking | `flag{...}` |

## Description

> The whole crew swears `crewmate.ctf` lives at `1.2.3.4`. You've just vented into Comms.
> Make them believe otherwise.

## What you get

- A ship's console on `http://localhost:5000` once you run the demo. See [README.md](README.md).

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Abobql rire tbg pnhtug ylvat va n ebbz gurl bayl ivfvgrq bapr.`
2. `Gur perjzngr jrnef n pbybhe. Gur gnoyr erzrzoref vg sbe n zbzrag, n irel fubeg zbzrag.`
3. `Jvaavat bar ebbz vf abg jvaavat gur fuvc. Jub gryyf gur perj jurer gb svaq gur perjzngr?`
4. `Svatref ner fybj. Znpuvarf ner abg.`

## Spoilers

- `src/` is the server source. Opening it gives the answer away.
- `solution/` has the write-up and a reference solver.
