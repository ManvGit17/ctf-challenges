#!/usr/bin/env python3
import argparse
import hashlib
import random
import string
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap

DECOYS = [
    {"protocol": "http", "payload": b"HTTP/1.1 200 OK\r\n\r\nflag{d0wnl04d_m0r3_r4m_plz_2026}", "src": "192.168.1.51", "dst": "192.168.1.100", "sport": 80, "dport_range": (40000, 60000)},
    {"protocol": "dns", "qname": "flag{d0m41n_n4m3_c4ch3_p01s0n_f4k3}.corp.local", "src": "192.168.1.52", "dst": "192.168.1.1"},
    {"protocol": "ftp", "payload": b"220 (vsFTPd 3.0.3)\nUSER anonymous\n331 Please specify the password.\nPASS guest\n230 Login successful.\nTYPE I\n200 Switching to Binary mode.\nRETR secret.txt\n150 Opening BINARY mode data connection for secret.txt (70 bytes).\nflag{cl34rt3xt_ftp_1s_4_tr4p_l0l}\n226 Transfer complete.\n", "src": "192.168.1.53", "dst": "192.168.1.101", "sport": 21, "dport_range": (40000, 60000)},
    {"protocol": "smtp", "payload": b"220 smtp.example.com ESMTP Postfix\nHELO student\n250 Hello\nMAIL FROM:<tester@example.com>\n250 Ok\nRCPT TO:<victim@example.com>\n250 Ok\nDATA\n354 End data with <CR><LF>.<CR><LF>\nHello, your secret is flag{sm7p_f4k3_fl4g_2026}\n.\n250 Ok: queued as 12345\nQUIT\n221 Bye\n", "src": "192.168.1.54", "dst": "192.168.1.102", "sport": 25, "dport_range": (40000, 60000)},
    {"protocol": "smb", "payload": b"flag{sm_b_f4k3_2026}", "src": "192.168.1.55", "dst": "192.168.1.103"},
    {"protocol": "ntp", "payload": b"\x1c" + b"flag{ntp_f4k3_2026}" + b"\x00" * 48, "src": "192.168.1.56", "dst": "192.168.1.104", "sport": 123, "dport_range": (40000, 60000)},
    {"protocol": "dns_txt", "qname": "example.com", "txt": "flag{dns_txt_f4k3_2026}", "src": "192.168.1.57", "dst": "192.168.1.1"},
    {"protocol": "http_get", "payload": b"GET /flag{g37_f4k3_url_2026} HTTP/1.1\r\nHost: example.com\r\n\r\n", "src": "192.168.1.58", "dst": "192.168.1.105", "sport": 80, "dport_range": (40000, 60000)},
    {"protocol": "tls", "payload": b"\x16\x03\x01" + b"flag{tls_f4k3_2026}" + b"\x00" * 30, "src": "192.168.1.59", "dst": "192.168.1.106", "sport": 443, "dport_range": (40000, 60000)},
    {"protocol": "icmp_unreach", "payload": b"flag{icmp_unreach_f4k3_2026}", "src": "192.168.1.60", "dst": "192.168.1.1"},
]

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]

SERVER_IP = "192.168.1.200"
CLIENT_IP = "192.168.1.105"

KEY_CHARSET = string.ascii_lowercase + string.digits + "_"


def random_key(length=12):
    return "".join(random.choices(KEY_CHARSET, k=length)).encode()


def random_hex(length=20):
    return "".join(random.choices("0123456789abcdef", k=length))


def derive_access_key(flag):
    digest = hashlib.sha256(f"pilgrim-relay:{flag}".encode()).hexdigest()
    return digest[:20]


def random_channel(exclude):
    while True:
        code = random.randint(0, 9999)
        if code not in exclude:
            return code


def build_noise(count):
    packets = []
    for i in range(count):
        src_ip = f"192.168.1.{random.randint(10, 200)}"
        if i % 4 == 0:
            pkt = IP(src=src_ip, dst="192.168.1.255") / UDP(sport=random.randint(1024, 65535), dport=random.choice([67, 68, 137])) / Raw(load=b"noise")
        elif i % 4 == 1:
            pkt = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=random.randint(1024, 65535), dport=random.choice([22, 443, 8080]), flags="S")
        elif i % 4 == 2:
            pkt = IP(src=src_ip, dst="192.168.1.1") / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(qd=DNSQR(qname=f"host-{i}.internal.net"))
        else:
            pkt = IP(src=src_ip, dst="192.168.1.1") / ICMP(type=8, seq=random.randint(100, 9000)) / Raw(load=b"ping")
        packets.append(pkt)
    return packets


def build_decoys():
    packets = []
    for dec in DECOYS:
        proto = dec["protocol"]
        if proto in ("http", "ftp", "smtp", "http_get", "tls"):
            pkt = IP(src=dec["src"], dst=dec["dst"]) / TCP(sport=dec["sport"], dport=random.randint(*dec["dport_range"]), flags="PA") / Raw(load=dec["payload"])
        elif proto == "dns":
            pkt = IP(src=dec["src"], dst=dec["dst"]) / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(qd=DNSQR(qname=dec["qname"]))
        elif proto == "smb":
            pkt = IP(src=dec["src"], dst=dec["dst"]) / TCP(sport=445, dport=445, flags="PA") / Raw(load=dec["payload"])
        elif proto == "ntp":
            pkt = IP(src=dec["src"], dst=dec["dst"]) / UDP(sport=dec.get("sport", random.randint(40000, 60000)), dport=123) / Raw(load=dec["payload"])
        elif proto == "dns_txt":
            pkt = IP(src=dec["src"], dst=dec["dst"]) / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(qd=DNSQR(qname=dec["qname"]), an=DNSRR(rrname=dec["qname"], type="TXT", rdata=dec["txt"]))
        elif proto == "icmp_unreach":
            pkt = IP(src=dec["src"], dst=dec["dst"]) / ICMP(type=3) / Raw(load=dec["payload"])
        else:
            continue
        packets.append(pkt)
    return packets


def build_mqtt_packet():
    payload = (
        b"\x30\x4e\x00\x0f/system/beaconWaypoint 1: Seek the Echo where "
        b"sequence numbers belong only to the primes (2..29)."
    )
    return IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=1883, dport=49152, flags="PA") / Raw(load=payload)


def build_icmp_train(channel_code):
    clue = f"PORT8443/CHANNEL{channel_code:04d}".encode()
    chunk_size = 2
    packets = []
    prime_idx = 0
    for seq in range(1, 35):
        if seq in PRIMES:
            chunk = clue[prime_idx * chunk_size:(prime_idx + 1) * chunk_size]
            ip_id = int.from_bytes(chunk, "big")
            prime_idx += 1
        else:
            ip_id = random.randint(0, 65535)
        pkt = IP(src=CLIENT_IP, dst="192.168.1.1", id=ip_id) / ICMP(type=8, seq=seq) / Raw(load=b"DiagnosticPingData")
        packets.append(pkt)
    return packets


def build_vault_banner(src_ip, dst_ip, sport, dport, key, channel_code):
    channel = f"{channel_code:04d}".encode()
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"X-Vault-Key: " + key + b"\r\n"
        b"X-Vault-Channel: " + channel + b"\r\n"
        b"X-Vault-Target: UDP/9999 Payload Blocks\r\n\r\n"
        b"Session bound to channel " + channel + b"."
    )
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=payload)


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_udp_flag_packets(src_ip, sport, key, message):
    prefix_salt = bytes(random.randint(0, 255) for _ in range(random.randint(6, 18)))
    suffix_salt = bytes(random.randint(0, 255) for _ in range(random.randint(6, 18)))
    salted = prefix_salt + message.encode() + suffix_salt
    encrypted = xor_bytes(salted, key)

    total = len(encrypted)
    base, remainder = divmod(total, 4)
    sizes = [base + (1 if i < remainder else 0) for i in range(4)]

    packets = []
    offset = 0
    for size in sizes:
        part = encrypted[offset:offset + size]
        offset += size
        pkt = IP(src=src_ip, dst="192.168.1.255") / UDP(sport=sport, dport=9999) / Raw(load=part)
        packets.append(pkt)
    return packets


def interleave(conversations):
    positions = [0] * len(conversations)
    result = []
    total = sum(len(c) for c in conversations)
    while len(result) < total:
        available = [i for i, c in enumerate(conversations) if positions[i] < len(c)]
        selected = random.choice(available)
        result.append(conversations[selected][positions[selected]])
        positions[selected] += 1
    return result


def generate(flag, output):
    access_key = derive_access_key(flag)

    real_key = b"k3y_tr4c3_99"
    real_channel = random_channel(exclude=set())
    decoy_channels = []
    for _ in range(2):
        decoy_channels.append(random_channel(exclude=set(decoy_channels) | {real_channel}))
    decoy_keys = [random_key() for _ in range(2)]
    decoy_access_keys = [random_hex(20) for _ in range(2)]

    decoy_host_a, decoy_host_b = random.sample(range(210, 250), 2)
    decoy_host_a = f"192.168.1.{decoy_host_a}"
    decoy_host_b = f"192.168.1.{decoy_host_b}"

    real_banner = build_vault_banner(SERVER_IP, CLIENT_IP, 8443, 51234, real_key, real_channel)
    decoy1_banner = build_vault_banner(SERVER_IP, CLIENT_IP, 8443, 51235, decoy_keys[0], decoy_channels[0])
    decoy2_banner = build_vault_banner(decoy_host_a, decoy_host_b, 8443, 51236, decoy_keys[1], decoy_channels[1])

    real_udp = build_udp_flag_packets(SERVER_IP, 9999, real_key, access_key)
    decoy1_udp = build_udp_flag_packets(SERVER_IP, 9998, decoy_keys[0], decoy_access_keys[0])
    decoy2_udp = build_udp_flag_packets(decoy_host_a, 9999, decoy_keys[1], decoy_access_keys[1])

    other_packets = (
        build_noise(150)
        + build_decoys()
        + [build_mqtt_packet()]
        + build_icmp_train(real_channel)
        + [real_banner, decoy1_banner, decoy2_banner]
    )

    conversations = [[p] for p in other_packets] + [real_udp, decoy1_udp, decoy2_udp]
    packets = interleave(conversations)

    wrpcap(output, packets)
    print(f"Created: {output}")
    print(f"Flag: {flag}")
    print(f"Access key: {access_key}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flag", required=True)
    parser.add_argument("--file", required=True)
    args = parser.parse_args()
    generate(args.flag, args.file)


if __name__ == "__main__":
    main()
