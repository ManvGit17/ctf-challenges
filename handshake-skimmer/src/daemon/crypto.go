package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func newEphemeral() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// blake2sTag returns a keyed BLAKE2s digest truncated to size bytes.
func blake2sTag(key, msg []byte, size int) []byte {
	h, err := blake2s.New256(key)
	if err != nil {
		// blake2s.New256 only errors on oversized keys; our keys are fixed size.
		panic(err)
	}
	h.Write(msg)
	sum := h.Sum(nil)
	return sum[:size]
}

// deriveSessionKey computes the per-epoch session key from the X25519
// shared secret, the public epoch nonce (used as HKDF salt) and the epoch
// id (folded into the HKDF info string). Not documented in PROTOCOL.md.
func deriveSessionKey(shared, epochNonce []byte, epochID uint64) []byte {
	info := make([]byte, 0, len("microtun-v1")+8)
	info = append(info, []byte("microtun-v1")...)
	var idBuf [8]byte
	binary.BigEndian.PutUint64(idBuf[:], epochID)
	info = append(info, idBuf[:]...)

	r := hkdf.New(sha256.New, shared, epochNonce, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(err)
	}
	return key
}

// sealToken encrypts plaintext under a nonce/AAD construction that is
// intentionally undocumented outside this source file: nonce is the first
// 4 bytes of the epoch nonce concatenated with the big-endian epoch id (12
// bytes total), and the associated data is the raw wire header of that
// epoch's handshake-message-1 frame.
func sealToken(key, epochNonce []byte, epochID uint64, aad, plaintext []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce[0:4], epochNonce[0:4])
	binary.BigEndian.PutUint64(nonce[4:12], epochID)
	return aead.Seal(nil, nonce, plaintext, aad)
}
