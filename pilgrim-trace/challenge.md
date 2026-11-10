# Pilgrim's Trace

| Category | Flag format |
|---|---|
| Forensics (network) | `isfcr{...}` |

## Description

> Everyone on the wire is shouting. Only the quiet ones tell the truth. A relay is waiting for
> whoever heard them.

## What you get

- `pilgrims_trace.pcap`, a packet capture (it sits next to this file).
- A relay on `localhost:9000` (raw TCP) once you run the demo. See [README.md](README.md).

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Ybhq ibvprf ner zveebef. Yvfgra sbe gur bar gung juvfcref.`
2. `Fbzr fgrcf bayl pbhag sbe gubfr jub pbhag gur evtug jnl.`
3. `Guerr geniryyref jrne gur fnzr snpr, ohg bayl bar jnyxf lbhe ebnq.`
4. `Gur xrl vf abg gur gernfher. Fbzrbar vf jnvgvat gb urne vg.`

## Spoilers

- `generator/` is the script that built the capture, so it shows exactly where everything is
  hidden.
- `solution/` has the write-up and a reference solver.
