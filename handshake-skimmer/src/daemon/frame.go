package main

import (
	"encoding/binary"
	"io"
)

const (
	frameTypeMsg1 byte = 0x01
	frameTypeMsg2 byte = 0x02
	frameTypeData byte = 0x03
)

// frameHeader builds the 21-byte capture.bin frame header described in
// PROTOCOL.md: [1B type][8B epoch_id][8B ts][4B payload_len].
func frameHeader(frameType byte, epochID uint64, ts int64, payloadLen uint32) []byte {
	h := make([]byte, 21)
	h[0] = frameType
	binary.BigEndian.PutUint64(h[1:9], epochID)
	binary.BigEndian.PutUint64(h[9:17], uint64(ts))
	binary.BigEndian.PutUint32(h[17:21], payloadLen)
	return h
}

// writeFrame appends one frame to the capture stream and returns the raw
// header bytes that were written (some header instances double as AEAD
// associated data for the caller).
func writeFrame(w io.Writer, frameType byte, epochID uint64, ts int64, payload []byte) ([]byte, error) {
	h := frameHeader(frameType, epochID, ts, uint32(len(payload)))
	if _, err := w.Write(h); err != nil {
		return nil, err
	}
	if _, err := w.Write(payload); err != nil {
		return nil, err
	}
	return h, nil
}
