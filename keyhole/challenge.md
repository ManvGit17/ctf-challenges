# Keyhole

| Category | Difficulty | Points | Flag format |
|---|---|---|---|
| Reverse Engineering | Easy+ | 200 | `isfcr{...}` |

## Description

> There's a door that only opens for people who already know what's behind it. It doesn't ask
> for a password. It hands you a slip of paper and asks you to prove you can read its own
> handwriting.
>
> It will ask twice, and it never writes the same hand twice.

## What you get

- A web service on `http://localhost:1337` once you run the demo (see [README.md](README.md)).
- The checker binary `keyhole` (a stripped Linux ELF). You can download it from the service at
  `/keyhole`; the demo also drops a copy in `handout/`.

## Hints

The hints are ROT13 encoded so you don't read one by accident. Decode only what you need, in
order. Any ROT13 decoder works, for example [rot13.com](https://rot13.com) or CyberChef.

1. `Gur fyvc bs cncre vfa'g gur ybpx. Gur guvat lbh qbjaybnqrq vf gur ybpx. Ernq vg orsber lbh jevgr nalguvat onpx.`
2. `Gjryir fznyy fgrcf, rnpu bar haqbvat vgfrys vs lbh jnyx vg onpxjneqf. Gur cncre gryyf lbh jurer lbh raq hc - abg ubj lbh tbg gurer. Gung cneg'f gur ybpx'f yvggyr frperg, naq vg bayl unf guerr jnlf bs xrrcvat vg.`
3. `Vs lbh svaq fbzrguvat vafvqr gur ybpx gung nyernql ybbxf yvxr jung lbh'er uhagvat sbe, ybbx ntnva - vg'f qerffrq sbe gur cneg, abg pnfg sbe vg. Jungrire qrpvqrf gur erny nafjre pnaabg or nfxrq sbe vg qverpgyl; vg unf gb or jnyxrq sebz gur raq onpx gb gur fgneg, bar erirefvoyr fgrc ng n gvzr, naq vg punatrf vgf zrgubq rirel gvzr lbh xabpx.`

## Spoilers

- `src/` is the source of the binary you are supposed to reverse. Opening it gives the answer away.
- `solution/` has the full write-up and a reference solver.
