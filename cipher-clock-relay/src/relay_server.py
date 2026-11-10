#!/usr/bin/env python3
"""
Cipher-Clock Relay. Raw TCP line service on port 8338.

On connect it announces a clock drift (0-25, random per connection). The rotation in force for
that connection is (BASE_ROTATION + drift) % 26. It then sends ROUNDS random 8-letter tokens and
expects each one back Caesar-rotated by that amount. After the last round it prints the flag.
"""
import random
import socket
import string
import sys
import threading

HOST = "0.0.0.0"
PORT = 8338
FLAG_PATH = "/flag.txt"
TIMEOUT = 120.0
ROUNDS = 3
ALPHABET = string.ascii_uppercase

# The same number is hidden in the capture, in the gaps between the sync packets.
BASE_ROTATION = 17


def caesar(text, shift):
    out = []
    for ch in text:
        if ch in ALPHABET:
            out.append(ALPHABET[(ALPHABET.index(ch) + shift) % 26])
        else:
            out.append(ch)
    return "".join(out)


def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    try:
        drift = random.randint(0, 25)
        shift = (BASE_ROTATION + drift) % 26
        banner = (
            "Connected to Cipher-Clock Relay.\n"
            f"Clock drift: {drift}\n"
            f"Complete {ROUNDS} rounds, {int(TIMEOUT)}s each, to receive your flag.\n"
        )
        conn.sendall(banner.encode())
        for round_idx in range(1, ROUNDS + 1):
            token = "".join(random.choices(ALPHABET, k=8))
            conn.sendall(f"[Round {round_idx}/{ROUNDS}] Rotate this: {token}\n".encode())
            try:
                data = conn.recv(1024)
            except socket.timeout:
                conn.sendall(b"Timeout. Connection closed.\n")
                return
            if not data:
                return
            reply = data.strip().decode(errors="replace").upper()
            if reply != caesar(token, shift):
                conn.sendall(b"Incorrect response. Connection closed.\n")
                return
            if round_idx < ROUNDS:
                conn.sendall(b"Correct.\n")
        with open(FLAG_PATH) as f:
            flag = f.read().strip()
        conn.sendall(("Correct. Flag: " + flag + "\n").encode())
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"relay listening on {HOST}:{PORT}", file=sys.stderr)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
