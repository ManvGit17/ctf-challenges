#!/usr/bin/env python3
"""
The Impostor Resolver: a DNS cache-poisoning (Kaminsky) challenge over HTTP.

The resolver is a crew that trusts whoever answers first. Match the round's
txid + source port, answer before the real reply arrives, and forge the
delegation (authority NS + glue A), not just one leaf name.

  txid + source port ......... the crewmate's colour you must match
  race window ................ beat the real authoritative reply
  random subdomains .......... unlimited fresh rounds
  NS delegation + glue ....... hijack the whole domain

No UDP and no raw sockets: "packets" are JSON and the race is a deadline in ms.
The flag is read from /flag.txt on every successful solve.
"""

import os
import time
import random
import threading

from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config (all tunable via env vars; defaults chosen so a *scripted* solve wins
# within a handful of rounds while a *human* filling the form always loses the
# race -- that gap is the "you must automate it" difficulty gate).
# ---------------------------------------------------------------------------
TARGET = os.getenv("TARGET_DOMAIN", "crewmate.ctf").lower().rstrip(".")
LEGIT_IP = os.getenv("LEGIT_IP", "1.2.3.4")                 # the real crewmate
# Short enough that a human clicking through the form loses; a script wins.
# Raise both if you host it somewhere with high latency.
WINDOW_MIN_MS = int(os.getenv("RACE_WINDOW_MIN_MS", "60"))
WINDOW_MAX_MS = int(os.getenv("RACE_WINDOW_MAX_MS", "650"))
REQUIRE_AUTHORITY_POISON = os.getenv("REQUIRE_AUTHORITY_POISON", "1") == "1"
DIRECT_LOSS_TTL = int(os.getenv("DIRECT_LOSS_TTL", "45"))    # penalty for querying target directly
NS_CACHE_TTL = int(os.getenv("NS_CACHE_TTL", "3600"))
PORT = int(os.getenv("PORT", "5000"))

FLAG_FILE = os.getenv("FLAG_FILE", "/flag.txt")

# ---------------------------------------------------------------------------
# In-memory state. One container per player, so global state is fine.
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_pending = {}            # qid -> round dict
_qid_counter = [0]
_cache = {
    "ns": None,          # {"ns": <nameserver>, "glue_ip": <ip>} delegation for TARGET
    "ns_expiry": 0.0,    # ms epoch
    "legit_until": 0.0,  # ms epoch; set when a *direct* query loses (soft lockout)
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def now_ms():
    return time.time() * 1000.0


def read_flag():
    """Read the flag fresh on every call."""
    with open(FLAG_FILE, "r") as fh:
        return fh.read().strip()


def parse_int(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def norm(value):
    return str(value or "").strip().lower().rstrip(".")


def is_true(value):
    return value in (1, True, "1", "true", "True")


def target_poisoned_ip():
    """Return the poisoned IP for TARGET if the delegation is poisoned & live, else None."""
    ns = _cache["ns"]
    if ns and now_ms() < _cache["ns_expiry"] and ns["glue_ip"] != LEGIT_IP:
        return ns["glue_ip"]
    return None


def purge_rounds():
    """Drop answered rounds and ones that expired a while ago (keep UI tidy)."""
    t = now_ms()
    for qid in list(_pending.keys()):
        p = _pending[qid]
        if p["answered"] or t > p["deadline"] + 2500:
            del _pending[qid]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", target=TARGET, legit_ip=LEGIT_IP)


@app.route("/config")
def config():
    """Non-secret knobs, handy for the UI and for players reasoning about the race."""
    return jsonify({
        "target": TARGET,
        "legit_ip": LEGIT_IP,
        "race_window_min_ms": WINDOW_MIN_MS,
        "race_window_max_ms": WINDOW_MAX_MS,
        "require_authority_poison": REQUIRE_AUTHORITY_POISON,
    })


@app.route("/resolve", methods=["POST"])
def resolve():
    """Ask the crew (recursive resolver) to resolve a name.

    - TARGET itself: returns the cached result. If the delegation is poisoned,
      it resolves to the Impostor IP and the FLAG is served.
    - a *.TARGET subdomain on a cache miss: starts a ROUND -- the crew sends an
      outbound query with a fresh txid/source port and a real crewmate is now
      racing to Admin (deadline). This is your window to vent in.
    """
    body = request.get_json(force=True, silent=True) or {}
    name = norm(body.get("name"))
    if not name:
        return jsonify({"error": "no name"}), 400

    with _lock:
        purge_rounds()

        if name == TARGET:
            ip = target_poisoned_ip()
            if ip:
                return jsonify({
                    "name": name,
                    "ip": ip,
                    "poisoned": True,
                    "flag": read_flag(),
                    "message": (
                        "VICTORY. {t} now resolves to the Impostor ({ip}). "
                        "The crew voted the Impostor in as a Crewmate. "
                        "The cache is poisoned."
                    ).format(t=name, ip=ip),
                })
            # Not poisoned -> legit answer, and a direct query that loses caches
            # the legit record for a bit (soft lockout -> nudges you to subdomains).
            _cache["legit_until"] = now_ms() + DIRECT_LOSS_TTL * 1000.0
            return jsonify({
                "name": name,
                "ip": LEGIT_IP,
                "poisoned": False,
                "message": (
                    "{t} resolves to the real crewmate ({ip}). Not sus. "
                    "(Querying the target directly just caches the truth -- "
                    "try RANDOM subdomains instead so you get unlimited rounds.)"
                ).format(t=name, ip=LEGIT_IP),
            })

        if name.endswith("." + TARGET):
            ip = target_poisoned_ip()
            if ip:
                return jsonify({
                    "name": name, "ip": ip, "poisoned": True,
                    "message": "Delegation already hijacked -- the whole ship trusts the Impostor.",
                })
            _qid_counter[0] += 1
            qid = _qid_counter[0]
            txid = random.randint(0, 0xFFFF)
            sport = random.randint(20000, 64000)
            window = random.uniform(WINDOW_MIN_MS, WINDOW_MAX_MS)
            t0 = now_ms()
            _pending[qid] = {
                "qid": qid,
                "qname": name,
                "txid": txid,
                "sport": sport,
                "issued_at": t0,
                "deadline": t0 + window,
                "answered": False,
            }
            return jsonify({
                "status": "querying",
                "qid": qid,
                "qname": name,
                "message": (
                    "Round {qid} open for {n}. The crew asked upstream and the REAL "
                    "crewmate is now racing to Admin. Check the Admin table for the "
                    "color (txid + port) and VENT IN before they arrive."
                ).format(qid=qid, n=name),
            })

        return jsonify({"name": name, "ip": None, "message": "Unknown name (NXDOMAIN)."})


@app.route("/egress")
def egress():
    """The Admin table / security tap: shows the crew's outstanding outbound queries
    and the color (txid + source port) each is waiting on. This is your 'sniff'."""
    with _lock:
        purge_rounds()
        t = now_ms()
        rows = []
        for p in _pending.values():
            if p["answered"]:
                continue
            rows.append({
                "qid": p["qid"],
                "qname": p["qname"],
                "txid": p["txid"],
                "txid_hex": "0x{:04x}".format(p["txid"]),
                "sport": p["sport"],
                "remaining_ms": max(0, round(p["deadline"] - t)),
            })
        rows.sort(key=lambda r: r["qid"])
        return jsonify({"pending": rows})


@app.route("/inject", methods=["POST"])
def inject():
    """Vent in: submit a forged DNS response for an open round.

    To poison the whole ship you must:
      * match the round's txid AND source port (from the Admin table),
      * arrive before the real crewmate (inside the race window),
      * look like a real crewmate (flags qr=1, aa=1),
      * and fake the DELEGATION: an AUTHORITY NS record for TARGET plus an
        ADDITIONAL glue A record for that nameserver.
    Faking only the leaf A record poisons one room, not the ship.
    """
    body = request.get_json(force=True, silent=True) or {}
    txid = parse_int(body.get("txid"))
    sport = parse_int(body.get("sport"))
    qname = norm(body.get("qname"))
    flags = body.get("flags") or {}
    answer = body.get("answer") or []
    authority = body.get("authority") or []
    additional = body.get("additional") or []

    with _lock:
        match = None
        for p in _pending.values():
            if p["qname"] == qname and not p["answered"]:
                match = p
                break

        if match is None:
            return jsonify({
                "success": False, "reason": "no_round",
                "message": "No crewmate is out for that name. Call a round first "
                           "(or the real crewmate already reported in -- too late).",
            })

        t = now_ms()
        if t > match["deadline"]:
            match["answered"] = True
            return jsonify({
                "success": False, "reason": "too_late",
                "message": "Too slow -- the REAL crewmate reached Admin first. "
                           "That round is burned. Call a new round.",
            })

        # One shot per round: a wrong guess ejects you and burns the round.
        if txid != match["txid"] or sport != match["sport"]:
            match["answered"] = True
            return jsonify({
                "success": False, "reason": "mismatch",
                "message": "EJECTED. Your color didn't match (wrong txid/port) -- "
                           "that was sus. Read the Admin table for THIS round.",
            })

        if not (is_true(flags.get("qr")) and is_true(flags.get("aa"))):
            match["answered"] = True
            return jsonify({
                "success": False, "reason": "flags",
                "message": "You didn't act like a real crewmate. A valid reply needs "
                           "flags qr=1 (it's a response) and aa=1 (authoritative).",
            })

        if REQUIRE_AUTHORITY_POISON:
            ns_rec = next(
                (r for r in authority
                 if str(r.get("type", "")).upper() == "NS" and norm(r.get("name")) == TARGET),
                None,
            )
            if not ns_rec:
                match["answered"] = True
                return jsonify({
                    "success": False, "reason": "no_delegation",
                    "message": "You faked one room, not the ship. Add an AUTHORITY "
                               "NS record for {t} to hijack the delegation.".format(t=TARGET),
                })
            ns_name = norm(ns_rec.get("data"))
            if not ns_name:
                match["answered"] = True
                return jsonify({
                    "success": False, "reason": "bad_ns",
                    "message": "Your NS record has no nameserver name.",
                })
            glue = next(
                (r for r in additional
                 if str(r.get("type", "")).upper() == "A" and norm(r.get("name")) == ns_name),
                None,
            )
            if not glue:
                match["answered"] = True
                return jsonify({
                    "success": False, "reason": "no_glue",
                    "message": "The crew can't find your nameserver '{n}'. Add an "
                               "ADDITIONAL glue A record for it.".format(n=ns_name),
                })
            glue_ip = str(glue.get("data", "")).strip()
        else:
            a_rec = next((r for r in answer if str(r.get("type", "")).upper() == "A"), None)
            ns_name = "direct"
            glue_ip = str(a_rec.get("data")).strip() if a_rec else LEGIT_IP

        if not glue_ip:
            match["answered"] = True
            return jsonify({"success": False, "reason": "bad_glue",
                            "message": "Your glue A record has no IP."})

        # Success: the forged delegation is accepted (weak bailiwick check = the vuln).
        match["answered"] = True
        _cache["ns"] = {"ns": ns_name, "glue_ip": glue_ip}
        _cache["ns_expiry"] = now_ms() + NS_CACHE_TTL * 1000.0
        poisoned = glue_ip != LEGIT_IP
        msg = ("Impostor vented in and matched the color! The crew cached the "
               "delegation: {t} -> {ns} -> {ip}.").format(t=TARGET, ns=ns_name, ip=glue_ip)
        if poisoned:
            msg += " Now resolve {t} to seal the win.".format(t=TARGET)
        else:
            msg += " ...but that glue points at the real crewmate, so nothing is poisoned."
        return jsonify({"success": True, "poisoned": poisoned, "glue_ip": glue_ip,
                        "ns": ns_name, "message": msg})


@app.route("/cache")
def cache_state():
    with _lock:
        ns = _cache["ns"]
        live = bool(ns) and now_ms() < _cache["ns_expiry"]
        return jsonify({
            "target": TARGET,
            "delegation": (ns if live else None),
            "poisoned": target_poisoned_ip() is not None,
            "resolves_to": (target_poisoned_ip() or LEGIT_IP),
        })


@app.route("/reset", methods=["POST", "GET"])
def reset():
    """Convenience: wipe this player's cache/rounds to start over."""
    with _lock:
        _pending.clear()
        _cache["ns"] = None
        _cache["ns_expiry"] = 0.0
        _cache["legit_until"] = 0.0
    return jsonify({"ok": True, "message": "Ship reset. Cache cleared."})


if __name__ == "__main__":
    print("THE IMPOSTOR RESOLVER starting on 0.0.0.0:{} (target={})".format(PORT, TARGET))
    app.run(host="0.0.0.0", port=PORT, threaded=True)
