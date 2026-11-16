#!/usr/bin/env python3
"""
Reference solver for The Handshake Skimmer. Follows the intended path:

  1. Fetch /journal + /notes, derive the forensics API auth token.
  2. Fetch /binary, RE it (DWARF) for the sessionSlot struct layout and the
     main.slots symbol address.
  3. Poll /capture, parse frames per PROTOCOL.md, and watch for the
     structural anomaly (a 0x03 frame) that marks the token-carrying epoch.
  4. Race GET /dump for that epoch's slot before the next rotation.
  5. Re-derive the (RE'd, undocumented) nonce/AAD construction and decrypt.

Usage:
    pip install requests pyelftools cryptography
    python solve.py [BASE_URL]        # default http://127.0.0.1:8080
"""
import codecs
import hashlib
import hmac
import os
import re
import struct
import sys
import tempfile
import time

import requests
from elftools.elf.elffile import ELFFile
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

KDF_KEY = b"microtun-seed-v1"


def step(msg):
    print(f"[*] {msg}", flush=True)


def derive_auth_token():
    journal = requests.get(f"{BASE_URL}/journal", timeout=10).text
    token = re.search(r"session_token=([0-9a-f]+)", journal).group(1)

    notes_rot13 = requests.get(f"{BASE_URL}/notes", timeout=10).text
    notes = codecs.decode(notes_rot13, "rot13")
    step("decoded /notes:\n" + notes)

    raw = bytes.fromhex(token)
    mac = hmac.new(KDF_KEY, raw, hashlib.sha256).hexdigest()
    auth_token = mac[:20]
    step(f"session_token={token} -> derived auth token={auth_token}")
    return auth_token


def re_binary(local_path):
    with open(local_path, "rb") as f:
        elf = ELFFile(f)
        # PIE binaries still commonly link with a non-zero base vaddr (Go
        # defaults to 0x400000 for the first PT_LOAD). The /dump endpoint
        # computes the runtime address as (lowest mapped segment address) +
        # offset, so the offset we hand it must be normalized against that
        # same first segment's *link-time* vaddr, not treated as if the
        # image links at 0.
        first_load_vaddr = min(
            seg["p_vaddr"] for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"
        )

        symtab = elf.get_section_by_name(".symtab")
        slots_addr = None
        for sym in symtab.iter_symbols():
            if sym.name == "main.slots":
                slots_addr = sym["st_value"] - first_load_vaddr
        assert slots_addr is not None, "main.slots symbol not found"

        dwarfinfo = elf.get_dwarf_info()
        sessionSlot_die = None
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_structure_type":
                    name = DIE.attributes.get("DW_AT_name")
                    if name and name.value == b"main.sessionSlot":
                        sessionSlot_die = DIE
        assert sessionSlot_die is not None, "sessionSlot struct not found"

        struct_size = sessionSlot_die.attributes["DW_AT_byte_size"].value
        key_offset = None
        for child in sessionSlot_die.iter_children():
            if child.tag == "DW_TAG_member":
                fname = child.attributes["DW_AT_name"].value.decode()
                if fname == "Key":
                    key_offset = child.attributes["DW_AT_data_member_location"].value
        assert key_offset is not None, "Key field not found"

    step(f"RE: main.slots={hex(slots_addr)} struct_size={struct_size} key_offset={key_offset}")
    return slots_addr, struct_size, key_offset


FRAME_HDR = 21


def parse_frames(buf):
    frames = []
    off = 0
    while off + FRAME_HDR <= len(buf):
        ftype = buf[off]
        epoch_id = struct.unpack(">Q", buf[off + 1:off + 9])[0]
        ts = struct.unpack(">Q", buf[off + 9:off + 17])[0]
        plen = struct.unpack(">I", buf[off + 17:off + 21])[0]
        start = off + FRAME_HDR
        end = start + plen
        if end > len(buf):
            break
        payload = buf[start:end]
        header = buf[off:start]
        frames.append((ftype, epoch_id, ts, payload, header))
        off = end
    return frames, off


def try_dump(offset_hex, epoch_id, auth_token):
    r = requests.get(f"{BASE_URL}/dump", params={
        "offset": offset_hex, "len": 32, "epoch": epoch_id, "token": auth_token,
    }, timeout=10)
    if r.status_code == 200 and len(r.content) == 32:
        return r.content, None
    return None, f"[{r.status_code}] {r.text.strip()}"


def main():
    auth_token = derive_auth_token()

    step(f"downloading daemon binary from {BASE_URL}/binary")
    binary_bytes = requests.get(f"{BASE_URL}/binary", timeout=30).content
    bin_path = os.path.join(tempfile.gettempdir(), "microtund_dl")
    with open(bin_path, "wb") as f:
        f.write(binary_bytes)
    slots_addr, struct_size, key_offset = re_binary(bin_path)

    step("watching /capture for the structural anomaly (a 0x03 frame)...")
    hdr1_by_epoch = {}
    nonce_by_epoch = {}

    # Baseline read: anything already in capture.bin before we started
    # watching is history, not a live opportunity -- its key slot may
    # already be long overwritten. We only race anomalies that appear
    # *after* this point.
    buf = requests.get(f"{BASE_URL}/capture", timeout=10).content
    baseline_frames, _ = parse_frames(buf)
    for ftype, epoch_id, ts, payload, header in baseline_frames:
        if ftype == 0x01:
            hdr1_by_epoch[epoch_id] = header
            nonce_by_epoch[epoch_id] = payload[32:48]
    seen_frames = len(baseline_frames)
    step(f"baseline: {seen_frames} frames already logged before this run; "
         f"now watching live for a fresh anomaly")

    session_key = None
    target_epoch = None
    token_payload = None
    overall_deadline = time.time() + 180

    while time.time() < overall_deadline and session_key is None:
        # 1. wait for the next fresh 0x03 frame
        fresh_epoch = None
        fresh_payload = None
        while time.time() < overall_deadline:
            buf = requests.get(f"{BASE_URL}/capture", timeout=10).content
            frames, _ = parse_frames(buf)
            if len(frames) > seen_frames:
                new_frames = frames[seen_frames:]
                seen_frames = len(frames)
                for ftype, epoch_id, ts, payload, header in new_frames:
                    if ftype == 0x01:
                        hdr1_by_epoch[epoch_id] = header
                        nonce_by_epoch[epoch_id] = payload[32:48]  # pubA(32)|nonce(16)|tag(16)
                    elif ftype == 0x03 and fresh_epoch is None:
                        fresh_epoch = epoch_id
                        fresh_payload = payload
                        step(f"anomaly found: 0x03 frame at epoch {epoch_id} "
                             f"(normal epochs only ever emit 0x01/0x02)")
                if fresh_epoch is not None:
                    break
            time.sleep(0.2)

        if fresh_epoch is None:
            break  # overall timeout

        target_epoch = fresh_epoch
        token_payload = fresh_payload
        slot = target_epoch % 2
        key_addr = slots_addr + slot * struct_size + key_offset
        step(f"target epoch={target_epoch} -> slot {slot} -> Key RVA {hex(key_addr)}")

        # 2. race /dump for this occurrence only -- if we lose the race (or
        # hit the lockout) we go back to watching for the *next* occurrence
        # rather than hammering a stale epoch id forever.
        step("racing /dump for the live key before the next rotation overwrites it...")
        this_race_deadline = time.time() + 8
        attempts = 0
        while time.time() < this_race_deadline:
            data, err = try_dump(format(key_addr, "x"), target_epoch, auth_token)
            attempts += 1
            if data is not None:
                session_key = data
                step(f"/dump succeeded on attempt {attempts}: got 32-byte key")
                break
            step(f"attempt {attempts}: {err}")
            time.sleep(0.3)

        if session_key is None:
            step("missed this occurrence's window -- waiting for the next one")

    assert session_key is not None, "lost the race repeatedly -- key was overwritten before a valid dump"

    epoch_nonce = nonce_by_epoch[target_epoch]
    aad = hdr1_by_epoch[target_epoch]
    nonce = epoch_nonce[0:4] + struct.pack(">Q", target_epoch)

    aead = ChaCha20Poly1305(session_key)
    plaintext = aead.decrypt(nonce, token_payload, aad)
    print()
    print("=" * 60)
    print("FLAG:", plaintext.decode())
    print("=" * 60)


if __name__ == "__main__":
    main()
