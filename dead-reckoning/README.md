# Dead Reckoning: running it locally

Read [challenge.md](challenge.md) first for the description and hints.

There is nothing to run. The whole challenge is one file, `dead_reckoning.png`, in this folder.
No Docker, no server, no demo script.

## Tools you'll want

- Python 3 (standard library is enough for every step)
- A hex editor or `pngcheck`
- Wireshark or `tshark`
- A map

## Files

```
challenge.md          description + ROT13 hints
dead_reckoning.png    the challenge file
generator/            SPOILER: the script that built the image
solution/             SPOILER: WRITEUP.md and solve.py
```

## Rebuilding the image

The image in the repo was made with:

```bash
python generator/generator.py --flag 'flag{...}' --out dead_reckoning.png --seed corvid-451
```

Same flag and seed give a byte-identical file. Drop `--seed` for a fresh random variant.

## Checking your solve

```bash
cd solution
python solve.py ../dead_reckoning.png
```
