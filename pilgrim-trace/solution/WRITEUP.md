# Pilgrim's Trace: intended solve path

The capture is a few hundred packets of noise plus ten decoy "flags" in obvious places (HTTP,
DNS, FTP, SMTP, SMB, NTP, TLS, ICMP unreachable...). All of them are fake. The real path is a
chain of five steps, each one telling you where to look next.

## 1. MQTT: the first waypoint

Filter `tcp.port == 1883`. There is a single MQTT PUBLISH on topic `/system/beacon`:

```
Waypoint 1: Seek the Echo where sequence numbers belong only to the primes (2..29).
```

"Echo" means ICMP echo request; the filter is prime sequence numbers.

## 2. ICMP: prime echoes

Filter `icmp.type == 8 && icmp.seq <= 29`. There are 34 echo requests with seq 1..34 from
the same host. Keep the 10 whose sequence number is prime (2, 3, 5, 7, 11, 13, 17, 19, 23, 29).
The payload is boring (`DiagnosticPingData`). The data is in the **IP ID** field: each one holds
two ASCII bytes. In sequence order they spell:

```
PORT8443/CHANNELnnnn
```

The non-prime echoes have random IP IDs across the full 16-bit range, so sorting by value does
not help. You have to apply the prime filter.

## 3. TCP/8443: pick the right vault banner

Filter `tcp.srcport == 8443`. There are three HTTP-style banners, each with an `X-Vault-Key`
and an `X-Vault-Channel`. Only the one whose channel matches `nnnn` from step 2 is real; the
other two are decoys with plausible keys (one even comes from the same server IP).

## 4. UDP/9999: XOR the right cluster

Filter `udp`. There are three clusters of four packets heading to the broadcast address,
interleaved with everything else. Group them by sender (`ip.src` + `udp.srcport`), join each
cluster's payloads in capture order, and XOR with the key from step 3 (repeating key).

The right cluster decodes to random padding around a 20-character lowercase hex string. That is
the **access key**, not the flag. The padding means there is no fixed prefix to crib-drag
against.

## 5. The relay

Connect to the relay on port 9000. It asks for a small proof of work:

```
Find S such that sha256("<nonce>" + S) starts with "0000".
```

Brute force `S` over integers (a few seconds in Python), send it, then send the access key.
The relay answers `ACCESS GRANTED` and prints the flag.

Wrong keys get a uniform `ACCESS DENIED` with a growing delay, and five misses close the
connection, so guessing is not practical.

## Reference solver

`solve.py` in this folder does all of the above:

```bash
pip install scapy
python3 solve.py ../pilgrims_trace.pcap localhost 9000
```
