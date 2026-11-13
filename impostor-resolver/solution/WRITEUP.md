# The Impostor Resolver: intended solve path

This is the Kaminsky DNS cache-poisoning attack, moved onto HTTP. Real cache poisoning needs
spoofed UDP packets; here the "packets" are JSON and the race is a deadline in milliseconds, but
the logic is the same.

| Real DNS | In the game |
|---|---|
| recursive resolver | the crew (`server.py`) |
| outbound query with txid + source port | a round started by `POST /resolve` |
| sniffing the wire | `GET /egress` (the Admin table) |
| forged response | `POST /inject` |
| racing the real authoritative server | each round's deadline, 60 to 650 ms, random per round |

## 1. Try the obvious thing

Resolving `crewmate.ctf` directly just returns `1.2.3.4`, and the real answer gets cached for a
while (`DIRECT_LOSS_TTL`). You can't race a name the resolver already knows. That's hint 1: you
only get away with lying in a room the crew visits once.

## 2. Start a round on a fresh name

`POST /resolve {"name": "<random>.crewmate.ctf"}`. The resolver hasn't seen that name, so it
sends an upstream query and a round opens.

## 3. Read the round

`GET /egress` lists outstanding queries: `qname`, `txid`, `sport` and time left. The txid and
source port are the "colour" you have to match.

## 4. Forge the reply

`POST /inject` with:

- the same `txid`, `sport` and `qname`,
- flags `qr: true` and `aa: true`,
- an `authority` NS record for `crewmate.ctf` pointing at your nameserver, e.g. `ns.evil.ctf`,
- an `additional` glue A record for that nameserver with your IP, e.g. `6.6.6.6`.

```json
{
  "txid": 41233, "sport": 51022, "qname": "k3j9x0aa1q.crewmate.ctf",
  "flags": {"qr": true, "aa": true},
  "answer":     [{"name": "k3j9x0aa1q.crewmate.ctf", "type": "A",  "data": "6.6.6.6"}],
  "authority":  [{"name": "crewmate.ctf",            "type": "NS", "data": "ns.evil.ctf"}],
  "additional": [{"name": "ns.evil.ctf",             "type": "A",  "data": "6.6.6.6"}]
}
```

A plain A answer for the random name is rejected (`no_delegation`). It would only poison that one
leaf name, which nobody asks for. The point of Kaminsky's attack is that the resolver caches the
delegation from the authority section, so you take over the whole domain.

## 5. Win the race

Each round's window is random between 60 and 650 ms. Clicking through the form by hand, or even
a script that waits a second, arrives `too_late`. But a lost round costs nothing: start another
one on a new random name. Script the resolve, sniff, inject loop and it lands within a few tries
(usually the first one on localhost).

## 6. Cash in

Once the forged delegation is cached, `POST /resolve {"name": "crewmate.ctf"}` resolves to your
IP and the response includes the flag.

## Why the shortcuts fail

| Attempt | Result |
|---|---|
| resolve `crewmate.ctf` directly | real answer, and the name is locked for a while |
| wrong txid or port | `mismatch`, round burned |
| right fields, too slow | `too_late`, round burned |
| missing `qr` / `aa` | `flags` |
| A record only, no authority NS | `no_delegation` |
| NS without glue | `no_glue` |

## Reference solver

```bash
pip install requests
python solve.py http://localhost:5000
```
