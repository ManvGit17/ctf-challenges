# Stark Nightshift: intended solve path

There is nothing to read and nothing to reverse. The whole challenge is a timing attack you
work out from a live feed.

## The bug

The vault daemon (`src/gatekeeper.py`) rotates its "stale" badge on a loop, and the rotation is
not atomic:

1. add the stale badge to the set of valid tokens,
2. sleep a random jitter (15-90 ms, range fixed per boot),
3. remove the stale badge,
4. wait out the rest of a 4-7 s interval (also fixed per boot), then repeat.

For the length of that jitter, one badge from a pool of 8 (`legacy-badge-00` ... `07`) is
accepted. Guess it inside the window and the daemon returns the flag. Knowing the pool is no
help on its own; landing a guess inside a window of a few tens of milliseconds is the puzzle.

## What the console shows

The page streams two kinds of pulse over a WebSocket:

- `OPENS`: the window just opened,
- `SEALS`: the window just closed.

Every pulse carries two timestamps:

| Field | Clock | Good for |
|---|---|---|
| `vaultMs` | the daemon's own clock | the **window width** (SEALS minus OPENS of the same cycle) |
| `yourMs` | when the pulse reached your session | the **period** between cycles |

The two clocks disagree, and they carry different kinds of error. Network delay jitters the
arrival time, so `yourMs` is noisy for width but fine for period once you take a median. The
vault clock has no network noise, so it gives an honest width.

## The solve

1. **Watch.** Let 6 or more cycles accumulate.
2. **Fit the period.** Take the deltas between consecutive `OPENS` arrivals (`yourMs`) and use
   the median, which shrugs off one noisy cycle.
3. **Predict.** Extrapolate forward from the last `OPENS`: `next = last + period`, stepping by
   one period until it is in the future. Reacting to a pulse you just saw is too late; the
   window closes before a human or a polling script can answer a single event.
4. **Commit.** Send `{"type":"strike","atMs": next}`. The relay pre-opens its own connection
   and fires a paced burst of all 8 badges across the predicted window.
5. **Read the outcome.** `ACCESS GRANTED` with the flag, or `access denied`. On a miss,
   recompute and aim at a later cycle.

The reference solver does exactly this over the same `/ws` endpoint a browser uses:

```bash
python3 solution/solve.py 127.0.0.1 8080
```

## Why the obvious attacks fail

- **Flooding every badge all the time.** Always `DENY`, and it trips the lockdown. The daemon
  counts rejects in 500 ms slices, and 3 or more slices over 40 rejects in one interval turns
  badge admission off for 45 to 90 seconds. Rotation markers keep firing during a lockdown, so
  the feed still looks normal. About 35k guesses in 30 seconds gets zero hits.
- **Reading the source.** The player only gets a web page. The wire protocol and the badge names
  never reach the browser.
- **Reacting to the latest event.** The window is gone before a human or a polling script can
  answer one pulse. You have to predict from earlier cycles.
- **Repeated blind strikes.** A good strike is one concentrated burst of about 200 ms, which
  trips one slice at most. Many blind misses over many cycles trip enough slices to lock you out.
