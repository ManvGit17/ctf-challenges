# Pilgrim's Trace

| Category | Flag format |
|---|---|
| Forensics (network) | `isfcr{...}` |

## Description

> The road through the wire is wide, loud, and paved with a thousand wandering voices. Impatient
> travelers search for quick treasures and find only gilded mirrors. Remember: the river does not
> shout to the sea; it whispers through the silent carrier. Follow the breadcrumbs where the quiet
> protocol marks each step, for shortcuts lead only to illusions, and only the one who walks the
> true path shall earn the pilgrim's key. Present it at the waiting relay to claim the genuine seal.

## What you get

- `handout/pilgrims_trace.pcap`, a packet capture generated just for you by the demo.
- A relay service on `localhost:9000` (raw TCP) that is waiting for something from the capture.

See [README.md](README.md) for how to start both.

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Frrx gur gryrzrgel'f dhvrg juvfcre.`
2. `Vaqvivfvoyr rpubrf uvqr gur cngu.`
3. `Rkpyhfvir ybtvp erirnyf gur raq.`
4. `Gur xrl vf abg gur gernfher - n erynl jnvgf gb urne vg.`

## Spoilers

- `generator/` builds the capture, so it shows exactly where everything is hidden.
- `solution/` has the full write-up and a reference solver.
- `.local/flag.txt` is created by the demo and holds your local flag. Don't open it.
