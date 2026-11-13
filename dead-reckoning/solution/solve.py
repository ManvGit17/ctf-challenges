#!/usr/bin/env python3
"""
Reference solver for Dead Reckoning. Works from the .png alone.

  A  IDAT inflates to more rows than IHDR declares; read the squawk from the
     hidden rows, then decrypt + inflate the trKr chunk -> pcap.
  B  Rebuild the TCP stream from checksum-valid segments only.
  C  Last NMEA fix with speed 0 -> nearest airport -> ICAO.
  D  gcd(N1, N2) -> private key -> session key.
  E  HMAC(session_key, ICAO + squawk) decrypts the tEXt Comment.

Usage:
    python solve.py ../dead_reckoning.png

It reuses the parsing helpers from ../generator/generator.py.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "generator"))
import generator as g  # noqa: E402


def solve(data, verbose=True):
    def say(*a):
        if verbose:
            print(*a)

    # ---- Stage A -----------------------------------------------------
    width, h_vis, h_true, raw, texts, chunks = g.png_parse(data)
    say("[A] PNG %dx%d declared, but IDAT inflates to %d rows -- %d hidden"
        % (width, h_vis, h_true, h_true - h_vis))
    squawk = g.read_flight_strip(raw, width)
    say("[A] SQUAWK (read from hidden flight-strip glyphs) = %s" % squawk)

    trkr_key = g._h(squawk.encode(), b"trKr")
    trkr_body = chunks.get(b"trKr")
    if trkr_body is None:
        raise ValueError("Stage A: no trKr chunk found")
    enc = g.unframe(b"TRKR", trkr_body)          # magic/length header is plaintext
    comp = g.stream_xor(trkr_key, enc)           # only the payload is encrypted
    pcap = g.zlib.decompress(comp)
    say("[A] decrypted+inflated trKr -> pcap (%d bytes)" % len(pcap))

    # ---- Stage B -------------------------------------------------------
    app_framed = g.pcap_reassemble(pcap)
    app_payload = g.unframe(g.STAGE_B_MAGIC, app_framed)
    say("[B] reassembled application stream (%d bytes, checksum-validated)" % len(app_payload))

    # ---- Stage C ---------------------------------------------------------
    fix = g.nmea_final_fix(app_payload)
    if fix is None:
        raise ValueError("Stage C: no NMEA fix found")
    airport, dist_km = g.nearest_airport(fix)
    icao = airport[0]
    say("[C] final GPS fix %.4f,%.4f -> nearest airport %s (%s), %.1f km" %
        (fix[0], fix[1], icao, airport[1], dist_km))

    # ---- Stage D ---------------------------------------------------------
    i0 = app_payload.find(b"-----CORVID GROUND KEY BUNDLE-----")
    i1 = app_payload.find(b"-----END BUNDLE-----") + len(b"-----END BUNDLE-----")
    bundle = app_payload[i0:i1]
    session_key = g.recover_session_key(bundle)
    say("[D] gcd(N1,N2) factored the shared prime -> session_key=%s" % session_key.hex())

    # ---- Stage E ---------------------------------------------------------
    key = g._hmac(session_key, icao.encode() + squawk.encode())
    comment_b64 = texts.get(b"Comment")
    if comment_b64 is None:
        raise ValueError("Stage E: no Comment tEXt chunk")
    ct_e = base64.b64decode(comment_b64)
    core = g.stream_xor(key, ct_e, nonce=b"stageE")
    if core[:4] != g.DR_MAGIC:
        raise ValueError("Stage E: wrong key (bad magic) (check squawk, ICAO, session key)")
    (ln,) = g.struct.unpack(">H", core[4:6])
    flag = core[6:6 + ln]
    tag = core[6 + ln:6 + ln + 8]
    expect = g._hmac(key, g.DR_MAGIC + flag)[:8]
    if tag != expect:
        raise ValueError("Stage E: integrity tag mismatch")
    say("[E] integrity OK")
    return flag.decode("latin1")


def main(argv):
    if len(argv) < 2:
        raise SystemExit("usage: python solve.py <dead_reckoning.png>")
    with open(argv[1], "rb") as f:
        data = f.read()
    flag = solve(data, verbose=True)
    print("\nFLAG:", flag)


if __name__ == "__main__":
    main(sys.argv)
