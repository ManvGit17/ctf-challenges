package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	captureFile = "/var/log/microtun/capture.bin"
	flagFile    = "/flag.txt"
)

// seededRand returns a math/rand source seeded from crypto/rand, used only
// for non-secret scheduling decisions (jitter timing, which epoch modulus
// carries the token). None of this randomness ever touches key material.
func seededRand() *mrand.Rand {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	seed := int64(binary.BigEndian.Uint64(b))
	return mrand.New(mrand.NewSource(seed))
}

// tryReadFlag reads /flag.txt fresh each time. If it can't be read, this
// epoch's token frame is skipped instead of sealing a placeholder.
func tryReadFlag() (string, bool) {
	b, err := os.ReadFile(flagFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "microtund: warning: flag not readable this epoch:", err)
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func randInterval(r *mrand.Rand) time.Duration {
	// 2s - 5s jitter, redrawn every rotation.
	ms := 2000 + r.Intn(3000)
	return time.Duration(ms) * time.Millisecond
}

func runRotationLoop(slots *slotState) {
	f, err := os.OpenFile(captureFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	r := seededRand()

	// Per-deployment randomization: which rotation modulus/offset carries
	// the token frame this run.
	tokenMod := uint64(6 + r.Intn(5)) // 6..10
	tokenOff := uint64(r.Intn(int(tokenMod)))

	var epoch uint64
	for {
		epochNonce := make([]byte, 16)
		if _, err := rand.Read(epochNonce); err != nil {
			panic(err)
		}

		privA, err := newEphemeral()
		if err != nil {
			panic(err)
		}
		privB, err := newEphemeral()
		if err != nil {
			panic(err)
		}
		pubA := privA.PublicKey().Bytes()
		pubB := privB.PublicKey().Bytes()

		shared, err := privA.ECDH(privB.PublicKey())
		if err != nil {
			panic(err)
		}

		ts := time.Now().Unix()

		tag1 := blake2sTag(epochNonce, pubA, 16)
		msg1 := bytes.Join([][]byte{pubA, epochNonce, tag1}, nil)
		hdr1, err := writeFrame(f, frameTypeMsg1, epoch, ts, msg1)
		if err != nil {
			panic(err)
		}

		sessionKey := deriveSessionKey(shared, epochNonce, epoch)

		confirmMsg := bytes.Join([][]byte{epochNonce, pubA, pubB}, nil)
		confirmTag := blake2sTag(sessionKey, confirmMsg, 32)
		msg2 := bytes.Join([][]byte{pubB, confirmTag}, nil)
		if _, err := writeFrame(f, frameTypeMsg2, epoch, ts, msg2); err != nil {
			panic(err)
		}

		slot := slotForEpoch(epoch)
		copy(slot.Key[:], sessionKey)
		copy(slot.Nonce[:], epochNonce)
		slot.EpochID = epoch
		slot.Created = time.Now().UnixNano()
		flipActive(int32(epoch % 2))

		slots.update(int(epoch%2), epoch)

		if epoch%tokenMod == tokenOff {
			if flag, ok := tryReadFlag(); ok {
				ciphertext := sealToken(sessionKey, epochNonce, epoch, hdr1, []byte(flag))
				if _, err := writeFrame(f, frameTypeData, epoch, ts, ciphertext); err != nil {
					panic(err)
				}
			}
		}

		if err := f.Sync(); err != nil {
			panic(err)
		}

		epoch++
		time.Sleep(randInterval(r))
	}
}

func main() {
	sessionToken := generateSessionToken()
	authToken := computeAuthToken(sessionToken)
	journal := buildJournal(sessionToken, seededRand())

	// Debug line for whoever runs the container (docker logs). Not reachable
	// over HTTP; solvers derive the token from /journal + /notes.
	fmt.Fprintln(os.Stderr, "microtund: this instance's auth token:", authToken)

	slots := newSlotState()
	go runRotationLoop(slots)

	srv := newServer(authToken, journal, slots)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("microtund: listening on :%s", port)
	if err := http.ListenAndServe(":"+port, srv.routes()); err != nil {
		log.Fatal(err)
	}
}
