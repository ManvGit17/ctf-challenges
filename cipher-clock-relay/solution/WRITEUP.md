# Cipher-Clock Relay: solve path

The capture holds two encodings and only one of them matters. The live relay holds a second
number that you need to combine with it.

## 1. The decoy

Filter `icmp`. There is one echo request whose IP ID is `0x3139`, which reads as the ASCII
characters `19`. That looks like a rotation amount, and it is a trap: the relay rejects it in
round 1. It is the same shape as the real answer on purpose, so the only way to rule it out is to
test it.

## 2. The real constant

Filter `udp.port == 7331`. Three packets with the payload `sync` and nothing else worth reading.
The information is in their timestamps. Take the two gaps between them, in tenths of a second:

- 0.1 s gives 1
- 0.7 s gives 7

Read in order that is **17**, the base rotation. `frame.time_delta_displayed` in Wireshark shows
the gaps directly.

## 3. The live half

Connect to the relay:

```
Connected to Cipher-Clock Relay.
Clock drift: 19
Complete 3 rounds, 120s each, to receive your flag.
[Round 1/3] Rotate this: KQOKHXIK
```

The drift is random for every connection. The rotation in force is `(17 + drift) % 26`. With a
drift of 19 that is 36 % 26 = 10.

For each of the 3 rounds, Caesar-shift the 8-letter token forward by that amount and send it
back. After round 3 the relay prints the flag. Reconnecting rolls a new drift, so a rotation
worked out once is useless on the next connection.

With `tr`, a shift of 10 looks like this:

```bash
echo KQOKHXIK | tr 'A-Z' 'K-ZA-J'
```

## Solver

`solve.py` reads the gaps out of the capture, connects, applies the drift and answers the rounds:

```bash
python3 solve.py ../relay_dump.pcap localhost 8338
```
