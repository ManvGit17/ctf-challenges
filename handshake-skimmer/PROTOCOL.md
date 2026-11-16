# microtun wire format (PROTOCOL.md)

`microtund` is a small tunnel daemon that performs a self-contained handshake
with itself on a fixed cadence and logs everything it sends/receives to
`/var/log/microtun/capture.bin` for audit purposes.

This document describes the **on-disk capture framing only**. It does not
describe the cryptographic handshake construction, key derivation, or the
AEAD nonce/associated-data scheme used inside the payloads. Those are not
part of this spec and are intentionally left for you to determine from the
binary itself if you need them.

## capture.bin framing

The file is a flat, back-to-back sequence of frames. There is no file header.
Each frame has this fixed layout:

```
offset  size  field
0       1     frame_type   (uint8)
1       8     epoch_id     (uint64, big-endian)
9       8     timestamp    (uint64, big-endian, unix seconds)
17      4     payload_len  (uint32, big-endian)
21      N     payload      (N = payload_len bytes)
```

Total frame size on disk = `21 + payload_len` bytes. Frames are written in
the order they occur; there is no padding or alignment between frames.

### Known frame_type values

| value | meaning                                                          |
|-------|-------------------------------------------------------------------|
| 0x01  | handshake message 1 (initiator -> responder)                      |
| 0x02  | handshake message 2 (responder -> initiator)                      |
| 0x03  | AEAD-sealed application data, opaque to this spec                  |

Every rotation epoch produces exactly one `0x01` frame followed by exactly
one `0x02` frame. Anything else you observe in the capture is not accounted
for by this spec.

## epoch_id

`epoch_id` is a monotonically increasing counter starting at 0 at daemon
boot, incremented once per handshake/rotation. It has no other structure.

## What this document deliberately does not cover

- The handshake message body layout (beyond total frame length).
- Key derivation (KDF, salts, info strings).
- AEAD algorithm, nonce construction, or associated data for any payload.
- In-memory data structures, their layout, or their lifetime.

If you need any of the above, you'll need to get it from the binary.
