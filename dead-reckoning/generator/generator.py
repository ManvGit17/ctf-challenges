#!/usr/bin/env python3
"""
Dead Reckoning: builds dead_reckoning.png for a given flag.

Standard library only. The radar image, the capture and the key bundle are
all made in code.

    python generator.py --flag 'flag{...}' --out dead_reckoning.png [--seed TEXT]

--seed makes the output reproducible. Without it every run gives a different
squawk, route, key bundle and image.

The chain, inside out:
  A  IHDR declares 256 rows, IDAT holds 320. The hidden rows show a 6-char
     squawk, which keys the private trKr chunk (zlib'd pcap).
  B  The pcap's TCP stream has a bad-checksum decoy copy of every segment.
     Only the valid segments rebuild the telemetry log.
  C  The log is an NMEA track. The last fix (speed 0) is the airport -> ICAO.
  D  Two RSA keys in the log share a prime. gcd -> private key -> session key.
     The e=3 key is a decoy.
  E  key = HMAC(session_key, ICAO + squawk) decrypts the tEXt Comment.
"""

import os
import sys
import io
import zlib
import math
import struct
import base64
import hashlib
import hmac
import random

# --------------------------------------------------------------------------
# Tunable parameters (documented in SOLUTION.md)
# --------------------------------------------------------------------------
IMG_W = 512
IMG_H_VIS = 256              # height stored in IHDR (what a viewer paints)
IMG_H_TRUE = 320             # real number of scanlines in IDAT
SQUAWK_LEN = 6               # hex chars painted into the hidden band

# glyph layout inside the hidden band (rows IMG_H_VIS .. IMG_H_TRUE)
GLYPH_SCALE = 6              # pixels per font cell
GLYPH_ORIGIN_X = 48
GLYPH_ORIGIN_Y = IMG_H_VIS + 10
GLYPH_GAP = 12               # horizontal gap between glyphs (pixels)

RSA_PRIME_BITS = 512         # -> 1024-bit moduli
RSA_E = 65537

DR_MAGIC = b"DR01"
STAGE_B_MAGIC = b"DRB1"      # frames the reassembled application payload

DECOY_LSB_TAUNT = (
    b"CORVID// this plane is just surface clutter. the key is not in the "
    b"plain LSB. stop running autostego. fix the frame, then follow the "
    b"track to the ground. flag{lsb_r4dar_gh0st}"
)
DECOY_STREAM_FAKE = b"flag{f0ll0w_str3am_lie}"
DECOY_RSA_TAUNT = b"wrong key. the cube is a decoy. gcd the real pair."

# --------------------------------------------------------------------------
# Real-airport table (ICAO, name, lat, lon).  Picked for unambiguous,
# well-known codes so the OSINT step is lookup-able but not guessable.
# --------------------------------------------------------------------------
AIRPORTS = [
    ("KJFK", "New York JFK",         40.6413, -73.7781),
    ("KLAX", "Los Angeles",          33.9416, -118.4085),
    ("KORD", "Chicago O'Hare",       41.9742, -87.9073),
    ("KATL", "Atlanta",              33.6407, -84.4277),
    ("KSFO", "San Francisco",        37.6213, -122.3790),
    ("KSEA", "Seattle-Tacoma",       47.4502, -122.3088),
    ("KDEN", "Denver",               39.8561, -104.6737),
    ("KMIA", "Miami",                25.7959, -80.2870),
    ("KBOS", "Boston Logan",         42.3656, -71.0096),
    ("KIAD", "Washington Dulles",    38.9531, -77.4565),
    ("EGLL", "London Heathrow",      51.4700, -0.4543),
    ("EGKK", "London Gatwick",       51.1537, -0.1821),
    ("LFPG", "Paris CDG",            49.0097, 2.5479),
    ("EDDF", "Frankfurt",            50.0379, 8.5622),
    ("EHAM", "Amsterdam Schiphol",   52.3105, 4.7683),
    ("LEMD", "Madrid Barajas",       40.4983, -3.5676),
    ("LIRF", "Rome Fiumicino",       41.8003, 12.2389),
    ("LSZH", "Zurich",               47.4647, 8.5492),
    ("LOWW", "Vienna",               48.1103, 16.5697),
    ("EKCH", "Copenhagen",           55.6180, 12.6560),
    ("ESSA", "Stockholm Arlanda",    59.6519, 17.9186),
    ("EIDW", "Dublin",               53.4213, -6.2701),
    ("LTFM", "Istanbul",             41.2753, 28.7519),
    ("UUEE", "Moscow Sheremetyevo",  55.9726, 37.4146),
    ("OMDB", "Dubai",                25.2532, 55.3657),
    ("OTHH", "Doha Hamad",           25.2731, 51.6080),
    ("VIDP", "Delhi",                28.5562, 77.1000),
    ("VABB", "Mumbai",               19.0896, 72.8656),
    ("VOBL", "Bengaluru",            13.1979, 77.7063),
    ("VOMM", "Chennai",              12.9941, 80.1709),
    ("VECC", "Kolkata",              22.6547, 88.4467),
    ("VOHS", "Hyderabad",            17.2403, 78.4294),
    ("VTBS", "Bangkok Suvarnabhumi", 13.6900, 100.7501),
    ("WSSS", "Singapore Changi",     1.3644, 103.9915),
    ("WMKK", "Kuala Lumpur",         2.7456, 101.7099),
    ("WIII", "Jakarta",              -6.1256, 106.6559),
    ("RJTT", "Tokyo Haneda",         35.5494, 139.7798),
    ("RJAA", "Tokyo Narita",         35.7720, 140.3929),
    ("RKSI", "Seoul Incheon",        37.4602, 126.4407),
    ("ZBAA", "Beijing Capital",      40.0799, 116.6031),
    ("ZSPD", "Shanghai Pudong",      31.1443, 121.8083),
    ("VHHH", "Hong Kong",            22.3080, 113.9185),
    ("YSSY", "Sydney",               -33.9399, 151.1753),
    ("YMML", "Melbourne",            -37.6690, 144.8410),
    ("NZAA", "Auckland",             -37.0082, 174.7850),
    ("FACT", "Cape Town",            -33.9715, 18.6021),
    ("FAOR", "Johannesburg",         -26.1392, 28.2460),
    ("SBGR", "Sao Paulo Guarulhos",  -23.4356, -46.4731),
    ("SAEZ", "Buenos Aires Ezeiza",  -34.8222, -58.5358),
    ("SKBO", "Bogota El Dorado",     4.7016, -74.1469),
    ("MMMX", "Mexico City",          19.4363, -99.0721),
    ("CYYZ", "Toronto Pearson",      43.6777, -79.6248),
]

# --------------------------------------------------------------------------
# Small crypto / bit helpers
# --------------------------------------------------------------------------
def _h(*parts):
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()

def _hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def sha256_ctr(key, nbytes, nonce=b""):
    """Simple SHA256-based counter keystream. key may be any length."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += _h(key, nonce, struct.pack(">Q", ctr))
        ctr += 1
    return bytes(out[:nbytes])

def stream_xor(key, data, nonce=b""):
    ks = sha256_ctr(key, len(data), nonce)
    return bytes(a ^ b for a, b in zip(data, ks))

def frame(magic4, payload):
    assert len(magic4) == 4
    return magic4 + struct.pack(">I", len(payload)) + payload

def unframe(magic4, blob):
    if blob[:4] != magic4:
        raise ValueError("bad magic")
    (ln,) = struct.unpack(">I", blob[4:8])
    return blob[8:8 + ln]

def bits_of(data):
    out = []
    for byte in data:
        for b in range(8):
            out.append((byte >> (7 - b)) & 1)
    return out

# --------------------------------------------------------------------------
# RSA (pure-Python, stdlib only) -- shared-prime pair + e=3 decoy
# --------------------------------------------------------------------------
def _is_probable_prime(n, rng, rounds=24):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_prime(bits, rng):
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand, rng):
            return cand

def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = _egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def _invmod(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m

def _i2osp(x, length):
    return x.to_bytes(length, "big")

def _os2ip(b):
    return int.from_bytes(b, "big")

def _pkcs1_pad(msg, k, rng):
    # EME-PKCS1-v1.5: 0x00 0x02 PS 0x00 M, PS has no zero bytes
    pslen = k - len(msg) - 3
    ps = bytearray()
    while len(ps) < pslen:
        b = rng.randrange(1, 256)
        ps.append(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + msg

def _pkcs1_unpad(em):
    if len(em) < 11 or em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("bad PKCS1")
    idx = em.find(b"\x00", 2)
    if idx < 0:
        raise ValueError("no separator")
    return em[idx + 1:]

def build_key_bundle(session_key, rng):
    """Two 1024-bit moduli that share one prime, carrying session_key, plus
    an e=3 cube-root decoy. Returns a text block (ASCII, base64 fields)."""
    p = _gen_prime(RSA_PRIME_BITS, rng)
    q1 = _gen_prime(RSA_PRIME_BITS, rng)
    q2 = _gen_prime(RSA_PRIME_BITS, rng)
    while q1 == q2 or q1 == p or q2 == p:
        q2 = _gen_prime(RSA_PRIME_BITS, rng)
    n1 = p * q1
    n2 = p * q2
    k = (n1.bit_length() + 7) // 8
    em = _pkcs1_pad(session_key, k, rng)
    m = _os2ip(em)
    ct = pow(m, RSA_E, n1)

    # decoy e=3 key: small message so the cube never wraps -> cube root works
    p3 = _gen_prime(RSA_PRIME_BITS, rng)
    q3 = _gen_prime(RSA_PRIME_BITS, rng)
    n3 = p3 * q3
    m3 = _os2ip(DECOY_RSA_TAUNT)
    ct3 = pow(m3, 3)        # integer cube, < n3, no reduction

    def b64(x):
        return base64.b64encode(x).decode()

    lines = [
        "-----CORVID GROUND KEY BUNDLE-----",
        "KEYID: CORVID-451-SESSION",
        "N1: " + b64(_i2osp(n1, k)),
        "N2: " + b64(_i2osp(n2, k)),
        "E: %d" % RSA_E,
        "CT: " + b64(_i2osp(ct, k)),
        "AUX-KEYID: CORVID-451-LEGACY",
        "AUX-N: " + b64(_i2osp(n3, (n3.bit_length() + 7) // 8)),
        "AUX-E: 3",
        "AUX-CT: " + b64(_i2osp(ct3, (ct3.bit_length() + 7) // 8)),
        "-----END BUNDLE-----",
    ]
    return "\n".join(lines).encode()

def recover_session_key(bundle_text):
    """Solver side: gcd(n1,n2) -> factor -> decrypt CT."""
    fields = {}
    for line in bundle_text.replace(b"\r\n", b"\n").split(b"\n"):
        if b":" in line and not line.startswith(b"-----"):
            k, _, v = line.partition(b":")
            fields[k.strip().decode()] = v.strip()
    n1 = _os2ip(base64.b64decode(fields["N1"]))
    n2 = _os2ip(base64.b64decode(fields["N2"]))
    e = int(fields["E"])
    ct = _os2ip(base64.b64decode(fields["CT"]))
    p = math.gcd(n1, n2)
    if p == 1 or p == n1:
        raise ValueError("no shared prime")
    q1 = n1 // p
    phi = (p - 1) * (q1 - 1)
    d = _invmod(e, phi)
    m = pow(ct, d, n1)
    k = (n1.bit_length() + 7) // 8
    em = _i2osp(m, k)
    return _pkcs1_unpad(em)

# --------------------------------------------------------------------------
# NMEA track synthesis  (Stage C: OSINT)
# --------------------------------------------------------------------------
def _nmea_checksum(body):
    c = 0
    for ch in body:
        c ^= ch
    return "%02X" % c

def _nmea_coord(lat, lon):
    ns = "N" if lat >= 0 else "S"
    la = abs(lat)
    dd = int(la)
    mm = (la - dd) * 60.0
    lat_s = "%02d%08.5f" % (dd, mm)
    ew = "E" if lon >= 0 else "W"
    lo = abs(lon)
    dd2 = int(lo)
    mm2 = (lo - dd2) * 60.0
    lon_s = "%03d%08.5f" % (dd2, mm2)
    return lat_s, ns, lon_s, ew

def _nmea_sentence(fields):
    body = ",".join(fields)
    return ("$" + body + "*" + _nmea_checksum(body.encode()) + "\r\n").encode()

def build_nmea_track(origin, dest, rng, npts=18):
    """origin/dest are AIRPORTS rows. Great-circle-ish interpolation; final
    fix is dest with ground speed 0.0 (that is how you know it landed)."""
    _, _, lat0, lon0 = origin
    _, _, lat1, lon1 = dest
    out = bytearray()
    hh, mm, ss = 6, 0, 0
    for i in range(npts):
        t = i / (npts - 1)
        # ease toward destination; tiny wander so it is clearly a real track
        lat = lat0 + (lat1 - lat0) * t + rng.uniform(-0.02, 0.02) * (1 - t)
        lon = lon0 + (lon1 - lon0) * t + rng.uniform(-0.02, 0.02) * (1 - t)
        if i == npts - 1:
            lat, lon = lat1, lon1
        speed = 0.0 if i == npts - 1 else round(420.0 * (1 - t) + 60.0, 1)
        lat_s, ns, lon_s, ew = _nmea_coord(lat, lon)
        tstamp = "%02d%02d%02d.00" % (hh, mm, ss)
        datestamp = "140526"
        status = "A"
        course = "%05.1f" % ((math.degrees(math.atan2(lon1 - lon0, lat1 - lat0))) % 360)
        out += _nmea_sentence(["GPRMC", tstamp, status, lat_s, ns, lon_s, ew,
                               "%05.1f" % speed, course, datestamp, "", ""])
        out += _nmea_sentence(["GPGGA", tstamp, lat_s, ns, lon_s, ew, "1", "08",
                               "0.9", "%.1f" % (max(0.0, (1 - t)) * 11000), "M",
                               "47.0", "M", "", ""])
        ss += 20
        while ss >= 60:
            ss -= 60
            mm += 1
        while mm >= 60:
            mm -= 60
            hh += 1
    return bytes(out)

def nmea_final_fix(track_text):
    """Return (lat, lon) of the last valid RMC fix (speed 0 = on the ground)."""
    last = None
    for line in track_text.replace(b"\r\n", b"\n").split(b"\n"):
        if not line.startswith(b"$GPRMC"):
            continue
        body = line[1:].split(b"*")[0]
        f = body.split(b",")
        if len(f) < 8 or f[2] != b"A":
            continue
        lat_s, ns, lon_s, ew = f[3].decode(), f[4].decode(), f[5].decode(), f[6].decode()
        lat = int(lat_s[:2]) + float(lat_s[2:]) / 60.0
        if ns == "S":
            lat = -lat
        lon = int(lon_s[:3]) + float(lon_s[3:]) / 60.0
        if ew == "W":
            lon = -lon
        last = (lat, lon)
    return last

def _haversine(a, b):
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))

def nearest_airport(latlon):
    best = None
    bestd = 1e18
    for row in AIRPORTS:
        d = _haversine(latlon, (row[2], row[3]))
        if d < bestd:
            bestd, best = d, row
    return best, bestd

# --------------------------------------------------------------------------
# PCAP + TCP reassembly puzzle  (Stage B: NETWORK)
# --------------------------------------------------------------------------
def _ip_checksum(hdr):
    s = 0
    for i in range(0, len(hdr) - 1, 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    if len(hdr) % 2:
        s += hdr[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return (~s) & 0xFFFF

def _ipv4(src, dst, proto, payload, ipid):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ipid, 0, 64, proto, 0,
                      bytes(map(int, src.split("."))),
                      bytes(map(int, dst.split("."))))
    chk = _ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", chk) + hdr[12:]
    return hdr + payload

def _tcp_checksum(src, dst, tcp):
    pseudo = (bytes(map(int, src.split("."))) + bytes(map(int, dst.split("."))) +
              struct.pack(">BBH", 0, 6, len(tcp)))
    return _ip_checksum(pseudo + tcp)

def _tcp(src, dst, sport, dport, seq, ack, flags, payload, force_bad=False):
    off = (5 << 4)
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, off, flags,
                      65535, 0, 0) + payload
    chk = _tcp_checksum(src, dst, tcp)
    if force_bad:
        chk ^= 0xA5A5           # deliberately corrupt the checksum
        if chk == 0:
            chk = 0x1234
    tcp = tcp[:16] + struct.pack(">H", chk) + tcp[18:]
    return tcp

def _eth(payload, ethertype=0x0800):
    return (b"\x52\x54\x00\x12\x34\x56" + b"\x52\x54\x00\x65\x43\x21" +
            struct.pack(">H", ethertype) + payload)

def _pcap_record(ts_us, raw):
    sec = ts_us // 1_000_000
    usec = ts_us % 1_000_000
    return struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw

PCAP_SRC = "10.11.12.5"
PCAP_DST = "10.11.12.80"
PCAP_SPORT = 49200
PCAP_DPORT = 8099

def pcap_build(app_payload, rng):
    """One TCP stream. Good segments (valid checksum) carry app_payload in
    order. Decoy segments carry DECOY_STREAM_FAKE content with BAD checksums
    and overlapping seqs, and arrive earlier -- so a naive follow-stream /
    strings pulls the decoy, a checksum-validating receiver does not."""
    glob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    isn = rng.randint(1 << 20, 1 << 28)

    seg_len = 48
    segments = [app_payload[i:i + seg_len]
                for i in range(0, len(app_payload), seg_len)]

    t = 2_000_000
    # SYN / SYN-ACK / ACK
    records.append((t, _eth(_ipv4(PCAP_SRC, PCAP_DST, 6,
                   _tcp(PCAP_SRC, PCAP_DST, PCAP_SPORT, PCAP_DPORT, isn, 0,
                        0x02, b""), rng.randint(0, 0xFFFF)))))
    t += 1000
    records.append((t, _eth(_ipv4(PCAP_DST, PCAP_SRC, 6,
                   _tcp(PCAP_DST, PCAP_SRC, PCAP_DPORT, PCAP_SPORT, 500, isn + 1,
                        0x12, b""), rng.randint(0, 0xFFFF)))))
    t += 1000
    records.append((t, _eth(_ipv4(PCAP_SRC, PCAP_DST, 6,
                   _tcp(PCAP_SRC, PCAP_DST, PCAP_SPORT, PCAP_DPORT, isn + 1, 501,
                        0x10, b""), rng.randint(0, 0xFFFF)))))

    # decoy fake-flag content, chopped to the SAME seqs as the real stream so
    # it overlaps; emitted with bad checksums and slightly earlier.
    decoy_blob = (b"NMEA-OVERRIDE: landing confirmed. manifest key = "
                  + DECOY_STREAM_FAKE + b" -- transmit to ground. ")
    decoy_blob = (decoy_blob * ((len(app_payload) // len(decoy_blob)) + 1))[:len(app_payload)]
    decoy_segs = [decoy_blob[i:i + seg_len]
                  for i in range(0, len(decoy_blob), seg_len)]

    seq = isn + 1
    for i, seg in enumerate(segments):
        # decoy overlap for this seq range, BAD checksum, arrives first
        if i < len(decoy_segs):
            t += rng.randint(500, 1500)
            bad = _tcp(PCAP_SRC, PCAP_DST, PCAP_SPORT, PCAP_DPORT, seq, 501,
                       0x18, decoy_segs[i], force_bad=True)
            records.append((t, _eth(_ipv4(PCAP_SRC, PCAP_DST, 6, bad,
                                           rng.randint(0, 0xFFFF)))))
        # real segment, GOOD checksum
        t += rng.randint(1500, 4000)
        good = _tcp(PCAP_SRC, PCAP_DST, PCAP_SPORT, PCAP_DPORT, seq, 501,
                    0x18, seg)
        records.append((t, _eth(_ipv4(PCAP_SRC, PCAP_DST, 6, good,
                                       rng.randint(0, 0xFFFF)))))
        # occasional harmless good retransmit (identical data, later)
        if rng.random() < 0.15:
            t += rng.randint(200, 800)
            records.append((t, _eth(_ipv4(PCAP_SRC, PCAP_DST, 6, good,
                                           rng.randint(0, 0xFFFF)))))
        # server ACK
        t += rng.randint(200, 600)
        records.append((t, _eth(_ipv4(PCAP_DST, PCAP_SRC, 6,
                       _tcp(PCAP_DST, PCAP_SRC, PCAP_DPORT, PCAP_SPORT, 501,
                            seq + len(seg), 0x10, b""), rng.randint(0, 0xFFFF)))))
        seq += len(seg)

    # unrelated background noise (benign-looking, no secrets)
    for j in range(40):
        t += rng.randint(1000, 30000)
        noise = b"GET /ads-b/feed/%d HTTP/1.1\r\nHost: flightfeed.example\r\n\r\n" % j
        records.append((t, _eth(_ipv4("192.168.50.%d" % (10 + j % 40),
                       "198.51.100.%d" % (5 + j % 50), 6,
                       _tcp("192.168.50.%d" % (10 + j % 40), "198.51.100.%d" % (5 + j % 50),
                            51000 + j, 80, 1000 + j * 7, 1, 0x18, noise),
                       rng.randint(0, 0xFFFF)))))

    records.sort(key=lambda r: r[0])
    out = bytearray(glob)
    for ts_us, raw in records:
        out += _pcap_record(ts_us, raw)
    return bytes(out)

def _parse_pcap_records(pcap_bytes):
    off = 24
    while off + 16 <= len(pcap_bytes):
        sec, usec, incl, orig = struct.unpack("<IIII", pcap_bytes[off:off + 16])
        rec = pcap_bytes[off + 16:off + 16 + incl]
        off += 16 + incl
        yield (sec * 1_000_000 + usec, rec)

def pcap_reassemble(pcap_bytes):
    """Correct receiver: keep only TCP segments of the target flow with a
    VALID TCP checksum, order by seq, first copy of each seq range wins."""
    segs = []  # (ts, seq, payload)
    for ts, rec in _parse_pcap_records(pcap_bytes):
        if len(rec) < 14 + 20 or rec[12:14] != b"\x08\x00":
            continue
        ihl = (rec[14] & 0x0F) * 4
        if rec[23] != 6:   # TCP
            continue
        ip = rec[14:]
        src = ".".join(str(x) for x in ip[12:16])
        dst = ".".join(str(x) for x in ip[16:20])
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
        if not (src == PCAP_SRC and dst == PCAP_DST and
                sport == PCAP_SPORT and dport == PCAP_DPORT):
            continue
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if not payload:
            continue
        # validate TCP checksum
        chk_field = struct.unpack(">H", tcp[16:18])[0]
        tcp_zero = tcp[:16] + b"\x00\x00" + tcp[18:]
        if _tcp_checksum(src, dst, tcp_zero) != chk_field:
            continue  # bad checksum -> drop (this is where decoys die)
        segs.append((ts, seq, bytes(payload)))

    segs.sort(key=lambda s: (s[1], s[0]))   # by seq, then time
    assembled = {}
    for ts, seq, payload in segs:
        if seq not in assembled:            # first copy wins
            assembled[seq] = payload
    out = bytearray()
    for seq in sorted(assembled):
        out += assembled[seq]
    return bytes(out)

# --------------------------------------------------------------------------
# PNG  (color type 2 = RGB, 8-bit) with the oversized-IDAT layer trick
# --------------------------------------------------------------------------
# Every chunk's CRC in this file is correct for the bytes it actually holds
# -- it is a 100% valid PNG that opens in any viewer. The trick is that the
# IDAT's inflated scanline data is LONGER than width*h_vis*3 + h_vis bytes:
# a standard decoder reads exactly h_vis scanlines and simply stops, never
# noticing (or erroring on) the extra, already-decompressed rows sitting
# unread at the end of the same zlib stream. Recovering them just takes
# inflating the IDAT yourself and comparing its length against the declared
# canvas -- no "fixing" a lie, just reading past where a casual viewer quit.
PNG_SIG = b"\x89PNG\r\n\x1a\n"

def _png_chunk(ctype, data):
    return (struct.pack(">I", len(data)) + ctype + data +
            struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))

def _ihdr_body(width, height):
    return struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)

def png_build(width, h_vis, h_true, raw_rgb_true, text_chunks, extra_chunks=()):
    """Build a fully valid RGB PNG whose IHDR declares h_vis rows (every
    ordinary viewer renders exactly this many) while the IDAT actually
    inflates to h_true >= h_vis scanlines. raw_rgb_true has length
    width*h_true*3."""
    ihdr = _ihdr_body(width, h_vis)

    scan = bytearray()
    stride = width * 3
    for y in range(h_true):
        scan.append(0)  # filter: None
        scan += raw_rgb_true[y * stride:(y + 1) * stride]
    idat = zlib.compress(bytes(scan), 9)

    out = bytearray(PNG_SIG)
    out += _png_chunk(b"IHDR", ihdr)
    for kw, tx in text_chunks:
        out += _png_chunk(b"tEXt", kw + b"\x00" + tx)
    for ctype, body in extra_chunks:
        out += _png_chunk(ctype, body)
    out += _png_chunk(b"IDAT", idat)
    out += _png_chunk(b"IEND", b"")
    return bytes(out)

def png_parse(data):
    """Return (width, h_vis, h_true, raw_rgb bytearray covering ALL h_true
    rows, {keyword: text}, {ctype: body}). h_vis is what IHDR declares (what
    a normal viewer paints); h_true is recovered by inflating the full IDAT
    and dividing its length by the per-scanline stride -- the Stage-A step."""
    assert data[:8] == PNG_SIG, "not a PNG"
    off = 8
    width = h_vis = 0
    idat = bytearray()
    texts = {}
    chunks = {}
    while off < len(data):
        (ln,) = struct.unpack(">I", data[off:off + 4])
        ctype = data[off + 4:off + 8]
        body = data[off + 8:off + 8 + ln]
        off += 12 + ln
        if ctype == b"IHDR":
            width, h_vis = struct.unpack(">II", body[:8])
        elif ctype == b"tEXt":
            kw, _, tx = body.partition(b"\x00")
            texts[kw] = tx
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            pass
        else:
            chunks[ctype] = body

    scan = zlib.decompress(bytes(idat))
    stride = width * 3
    h_true = len(scan) // (stride + 1)   # more rows decoded than IHDR declares
    raw = bytearray()
    for y in range(h_true):
        base = y * (stride + 1)
        raw += scan[base + 1:base + 1 + stride]
    return width, h_vis, h_true, raw, texts, chunks

# --------------------------------------------------------------------------
# 5x7 hex font: paint SQUAWK into the hidden band; read it back by sampling
# --------------------------------------------------------------------------
_HEXFONT = {
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    "3": ["11111", "00010", "00100", "00010", "00001", "10001", "01110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["01110", "10000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
}
_FONT_ROWS = 7
_FONT_COLS = 5

def _glyph_x0(ci):
    return GLYPH_ORIGIN_X + ci * (_FONT_COLS * GLYPH_SCALE + GLYPH_GAP)

def paint_flight_strip(raw, width, squawk):
    """Paint the hidden band: a dim label row plus the SQUAWK in big glyphs."""
    def setpx(x, y, rgb):
        if 0 <= x < width:
            i = (y * width + x) * 3
            raw[i], raw[i + 1], raw[i + 2] = rgb
    # dim background wash for the band so glyphs read clearly
    for y in range(IMG_H_VIS, IMG_H_TRUE):
        for x in range(width):
            i = (y * width + x) * 3
            raw[i] = 6
            raw[i + 1] = 14
            raw[i + 2] = 10
    # glyphs in bright amber (radar-strip look)
    for ci, ch in enumerate(squawk):
        glyph = _HEXFONT[ch]
        x0 = _glyph_x0(ci)
        for r in range(_FONT_ROWS):
            for c in range(_FONT_COLS):
                if glyph[r][c] == "1":
                    for dy in range(GLYPH_SCALE):
                        for dx in range(GLYPH_SCALE):
                            setpx(x0 + c * GLYPH_SCALE + dx,
                                  GLYPH_ORIGIN_Y + r * GLYPH_SCALE + dy,
                                  (250, 196, 70))

def read_flight_strip(raw, width, nchars=SQUAWK_LEN):
    """Sample the centre of each font cell; template-match to a hex glyph."""
    def lum(x, y):
        i = (y * width + x) * 3
        return 0.299 * raw[i] + 0.587 * raw[i + 1] + 0.114 * raw[i + 2]
    keys = list(_HEXFONT.keys())
    out = []
    for ci in range(nchars):
        x0 = _glyph_x0(ci)
        mat = []
        for r in range(_FONT_ROWS):
            row = []
            for c in range(_FONT_COLS):
                cx = x0 + c * GLYPH_SCALE + GLYPH_SCALE // 2
                cy = GLYPH_ORIGIN_Y + r * GLYPH_SCALE + GLYPH_SCALE // 2
                row.append(1 if lum(cx, cy) > 120 else 0)
            mat.append(row)
        best, bestd = "0", 10 ** 9
        for key in keys:
            g = _HEXFONT[key]
            d = sum(1 for r in range(_FONT_ROWS) for c in range(_FONT_COLS)
                    if mat[r][c] != (1 if g[r][c] == "1" else 0))
            if d < bestd:
                bestd, best = d, key
        out.append(best)
    return "".join(out)

# --------------------------------------------------------------------------
# Plain-LSB decoy (Stage A red herring)
# --------------------------------------------------------------------------
def plain_lsb_embed(raw, message, limit_bytes):
    bits = bits_of(message)
    for i, bit in enumerate(bits):
        if i >= limit_bytes:
            break
        raw[i] = (raw[i] & 0xFE) | bit
    return len(bits)

def plain_lsb_read(raw, nbytes):
    bits = [raw[i] & 1 for i in range(nbytes * 8)]
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in range(8):
            v = (v << 1) | bits[i + b]
        out.append(v)
    return bytes(out)

# --------------------------------------------------------------------------
# Procedural radar-scope cover image (visible rows)
# --------------------------------------------------------------------------
def make_cover(width, h_true, r_seed):
    """A PPI radar scope: dark green phosphor, range rings, a sweep wedge,
    scattered blips and a track line. Hidden band rows are left for the
    flight strip (overwritten later)."""
    rnd = random.Random(int.from_bytes(_h(r_seed, b"img")[:8], "big"))
    raw = bytearray(width * h_true * 3)
    cx, cy = width // 2, IMG_H_VIS // 2
    maxr = min(cx, cy) - 6
    rings = [int(maxr * f) for f in (0.3, 0.55, 0.8, 1.0)]
    sweep = rnd.uniform(0, 2 * math.pi)
    blips = [(rnd.randint(20, width - 20), rnd.randint(20, IMG_H_VIS - 20))
             for _ in range(rnd.randint(14, 22))]
    for y in range(IMG_H_VIS):
        for x in range(width):
            dx, dy = x - cx, y - cy
            dist = math.hypot(dx, dy)
            g = 10 + 6 * math.sin(x * 0.03) * math.cos(y * 0.03)
            r = g * 0.2
            b = g * 0.4
            # range rings
            for rr in rings:
                if abs(dist - rr) < 1.2:
                    g += 70
            # radial grid lines
            ang = math.atan2(dy, dx)
            if dist < maxr and abs((ang % (math.pi / 6))) < 0.015:
                g += 30
            # sweep wedge (brightening trail)
            da = (ang - sweep) % (2 * math.pi)
            if dist < maxr and da < 0.6:
                k = (0.6 - da) / 0.6
                g += 120 * k
                b += 20 * k
            n = rnd.randint(0, 16)
            i = (y * width + x) * 3
            raw[i] = max(0, min(255, int(r + n)))
            raw[i + 1] = max(0, min(255, int(g + n)))
            raw[i + 2] = max(0, min(255, int(b + n)))
    # blips
    for (bx, by) in blips:
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                if dx * dx + dy * dy <= 4:
                    x, y = bx + dx, by + dy
                    if 0 <= x < width and 0 <= y < IMG_H_VIS:
                        i = (y * width + x) * 3
                        raw[i + 1] = min(255, raw[i + 1] + 120)
    return raw

# --------------------------------------------------------------------------
# Top-level generation
# --------------------------------------------------------------------------
def generate(flag_bytes, seed=None):
    flag_bytes = flag_bytes.strip()
    R = seed if seed is not None else os.urandom(16)
    rng = random.Random(int.from_bytes(_h(R, b"build")[:8], "big"))

    # --- secrets derived from the seed ---
    squawk = hashlib.sha256(R + b"squawk").hexdigest()[:SQUAWK_LEN].upper()
    session_key = _h(R + b"session")[:16]

    # pick origin + destination airports (distinct, far apart)
    oi = rng.randrange(len(AIRPORTS))
    di = rng.randrange(len(AIRPORTS))
    while di == oi or _haversine((AIRPORTS[oi][2], AIRPORTS[oi][3]),
                                 (AIRPORTS[di][2], AIRPORTS[di][3])) < 800:
        di = rng.randrange(len(AIRPORTS))
    origin, dest = AIRPORTS[oi], AIRPORTS[di]
    icao = dest[0]

    # --- Stage C/D application payload (telemetry log + key bundle) ---
    track = build_nmea_track(origin, dest, rng)
    bundle = build_key_bundle(session_key, rng)
    app_payload = (b"CORVID 451 TELEMETRY DOWNLINK // decoded ADS-B + GPS log\n"
                   b"----------------------------------------------------\n"
                   + track +
                   b"\n" + bundle + b"\n"
                   b"----------------------------------------------------\n"
                   b"END OF STREAM\n")
    app_framed = frame(STAGE_B_MAGIC, app_payload)

    # --- Stage B: build the pcap reassembly puzzle ---
    pcap = pcap_build(app_framed, rng)

    # --- Stage A: encrypt the pcap into the private trKr chunk (keyed by SQUAWK)
    trkr_key = _h(squawk.encode(), b"trKr")
    trkr_body = frame(b"TRKR", stream_xor(trkr_key, zlib.compress(pcap, 9)))

    # --- Stage E: flag block keyed by session_key + ICAO + SQUAWK ---
    key = _hmac(session_key, icao.encode() + squawk.encode())
    tag = _hmac(key, DR_MAGIC + flag_bytes)[:8]
    core = DR_MAGIC + struct.pack(">H", len(flag_bytes)) + flag_bytes + tag
    ct_e = stream_xor(key, core, nonce=b"stageE")
    comment_b64 = base64.b64encode(ct_e)

    # --- cover image + flight strip + plain-LSB decoy ---
    raw = make_cover(IMG_W, IMG_H_TRUE, R)
    paint_flight_strip(raw, IMG_W, squawk)
    # decoy LSB only in the visible region (leave the hidden band glyphs clean)
    plain_lsb_embed(raw, DECOY_LSB_TAUNT, IMG_W * IMG_H_VIS * 3)

    texts = [
        (b"Software", b"CorvidScope 2.6 (incident export)"),
        (b"Comment", comment_b64),
        (b"Notice", b"Corvid incident review. The transponder stopped; the GPS "
                    b"did not."),
    ]
    extra = [(b"trKr", trkr_body)]
    png = png_build(IMG_W, IMG_H_VIS, IMG_H_TRUE, bytes(raw), texts, extra)
    return png


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--flag", required=True)
    ap.add_argument("--out", default="dead_reckoning.png")
    ap.add_argument("--seed", help="any text; same seed + flag = same file")
    a = ap.parse_args()
    seed = hashlib.sha256(a.seed.encode()).digest()[:16] if a.seed else None
    data = generate(a.flag.encode(), seed=seed)
    with open(a.out, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (a.out, len(data)))


if __name__ == "__main__":
    main()
