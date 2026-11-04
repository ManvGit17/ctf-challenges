import hashlib
import hmac
import secrets
import socket
import socketserver
import time

PORT = 9000
FLAG_PATH = "/flag.txt"
POW_PREFIX = "0000"
MAX_ATTEMPTS = 5
IDLE_TIMEOUT = 60


def derive_access_key(flag):
    digest = hashlib.sha256(f"pilgrim-relay:{flag}".encode()).hexdigest()
    return digest[:20]


def read_flag():
    with open(FLAG_PATH, "r") as f:
        return f.read().strip()


def check_pow(nonce, solution):
    candidate = hashlib.sha256((nonce + solution).encode()).hexdigest()
    return candidate.startswith(POW_PREFIX)


class RelayHandler(socketserver.StreamRequestHandler):
    timeout = IDLE_TIMEOUT

    def send(self, text=""):
        self.wfile.write((text + "\n").encode())

    def recv_line(self):
        self.request.settimeout(IDLE_TIMEOUT)
        line = self.rfile.readline()
        if not line:
            return None
        return line.decode(errors="replace").strip()

    def handle(self):
        try:
            self.send("=" * 50)
            self.send("PILGRIM'S TRACE -- RELAY STATION")
            self.send("=" * 50)
            self.send()

            nonce = secrets.token_hex(8)
            self.send("Relay handshake required.")
            self.send(f'Find S such that sha256("{nonce}" + S) starts with "{POW_PREFIX}".')
            self.send("Submit S:")
            solution = self.recv_line()
            if solution is None or not check_pow(nonce, solution):
                self.send("Handshake failed.")
                return
            self.send("Handshake accepted.")
            self.send()

            flag = read_flag()
            expected_key = derive_access_key(flag)

            attempts = 0
            while attempts < MAX_ATTEMPTS:
                attempts += 1
                self.send("Enter access key:")
                key = self.recv_line()
                if key is None:
                    return
                if hmac.compare_digest(key.strip(), expected_key):
                    self.send()
                    self.send("ACCESS GRANTED")
                    self.send(f"Flag: {flag}")
                    return
                time.sleep(min(attempts * 1.5, 6))
                self.send("ACCESS DENIED")

            self.send("Too many attempts. Closing connection.")
        except (socket.timeout, ConnectionError):
            return
        except Exception:
            return


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    with ThreadedServer(("0.0.0.0", PORT), RelayHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
