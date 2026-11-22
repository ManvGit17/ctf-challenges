# DNSSEC Matrix: intended solve path

In DNSSEC, NSEC3 records provide authenticated denial of existence without leaking
plain domain names via zone walking. Instead, they store salted, iterated SHA-1 hashes
of the next domain in the canonical order.

In this challenge, the diagnostic portal simulates a deterministic NSEC3 zone walking
walkthrough across 5 chained hops.

## 1. Initial query

Start by querying the entry node:

```json
POST /api/query
{"domain": "start.matrix.ctf", "qtype": "TXT"}
```

The response returns:

```
Welcome. Query a nonexistent name at *.wild.start.matrix.ctf to find the path.
```

## 2. Triggering the NSEC3 denial

Querying a nonexistent subdomain under the wildcard boundary returns an NXDOMAIN with
an authority section containing NSEC3 parameters:

```json
POST /api/query
{"domain": "probe.wild.start.matrix.ctf", "qtype": "A"}
```

The server returns:

```json
{
  "status": "NXDOMAIN",
  "authority": [
    {
      "record": "wild.start.matrix.ctf. 300 IN NSEC3 1 0 100 -",
      "diagnostic_hint_salt": "init_salt_42",
      "iterations": 100,
      "hash_algo": "SHA-1"
    }
  ]
}
```

## 3. Walking the chain

The next valid node is computed deterministically by concatenating the current node name
with the salt, then applying SHA-1 repeatedly for the given number of iterations:

```python
def compute_next(node, salt, iters):
    curr = (node + salt).encode()
    for _ in range(iters):
        curr = hashlib.sha1(curr).digest()
    return curr.hex()
```

Starting from `start`:
1. `start` + `init_salt_42` (100 iters) -> Node 1
2. Node 1 + `node_alpha_x` (250 iters) -> Node 2
3. Node 2 + `crypto_bridge_99` (500 iters) -> Node 3
4. Node 3 + `almost_there_sec` (750 iters) -> Node 4
5. Node 4 + `final_hop_1337` (1000 iters) -> Node 5

## 4. Retrieving the flag

Once the final node hash is reached, querying its TXT record retrieves the flag:

```json
POST /api/query
{"domain": "<node5_hash>.matrix.ctf", "qtype": "TXT"}
```

Response:
```
flag{dn553c_n53c3_w1ldc4rd_w4lk3r}
```

## Why shortcuts fail

- Guessing domain hashes directly is infeasible due to the iteration counts and unknown salt sequence.
- Querying random names outside `*.wild.<node>.matrix.ctf` returns plain NXDOMAIN with no authority hints.
- Querying non-TXT records at the final node returns an empty answer set.

## Reference solver

```bash
pip install requests
python solve.py http://localhost:8080
```
