# Stark Nightshift

| Category | Flag format |
|---|---|
| Web / Networking | `pesuctf{...}` |

## Description

> Somewhere above Manhattan, Stark Industries R&D keeps the Mk-series plasma cannon schematics
> behind a vault door that answers to badge. Word on the street (okay, in a dumpster behind the
> building, in a printed diff nobody shredded) is that the night-shift engineer on rotation pushed
> a "quick fix" to the door's badge-rotation system a few weeks back, to make it easier to debug
> remotely. It now broadcasts its own heartbeat onto the building's internal monitoring network.
> Convenient. Also, apparently, nobody checked whether the rotation itself still swapped badges
> cleanly.
>
> It doesn't.

## What you get

- A web console on `http://localhost:8080` once you run the demo (see [README.md](README.md)).
  Open it in a browser. That's the whole job: no shell, no external tools.
- There is no source code to read and no binary to reverse. Everything you need, you learn by
  watching the live heartbeat feed.

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Rirel ybpx Fgnex'f ratvarref rire ohvyg fgvyy bcraf sbe fbzrbar. Gur onqtr jnf arire gur frperg. Vg'f abg *jung* haybpxf gur qbbe — vg'f *jura* gur qbbe sbetrgf gb purpx.`
2. `Gur urnegorng gryyf lbh fbzrguvat vf nyvir. Bar orng, ba vgf bja, qbrfa'g gryy lbh jura gur arkg bar ynaqf.`
3. `Ol gur gvzr lbh urne gur yngpu pyvpx, vg'f nyernql fuhg. Jungrire lbh'er tbvat gb gel unf gb nyernql or zbivat orsber gur fbhaq rira ernpurf lbh — abg n ernpgvba gb gur orng lbh whfg urneq, ohg n cyna ohvyg sebz frireny orngf orsber vg.`
4. `Gur srrq fcrnxf va gjb ibvprf — bar sebz vafvqr gur inhyg, bar sebz jurerire lbh'er yvfgravat sebz. Gurl qba'g nterr ba gur gvzr. Gung qvfnterrzrag vfa'g n oht sbe lbh gb svk. Bar ibvpr gryyf lbh ubj ybat gur qbbe fgnlf bcra; gur bgure gryyf lbh ubj bsgra vg bcraf — naq gurl qba'g pneel gur fnzr xvaq bs reebe.`
5. `Crccre nyernql synttrq bar "znvagranapr fpevcg" unzzrevat gur onqtr ernqre ng 2 NZ. Qba'g or gur frpbaq anzr ba gung rznvy guernq. N fvatyr, jryy-nvzrq xabpx fbhaqf abguvat yvxr n oernx-va — rira gubhtu, sbe bar oevrs zbzrag, vg qbrf gel zber guna bar onqtr ng bapr.`

## Spoilers

- `src/` is the source of the vault daemon and the web relay. Opening it gives the answer away.
- `solution/` has the full write-up and reference solvers.
