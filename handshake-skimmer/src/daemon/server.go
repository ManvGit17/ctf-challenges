package main

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strconv"
)

const protocolFile = "/etc/microtun/PROTOCOL.md"

const indexText = `microtun forensics API

Available routes:
  GET /protocol   - wire framing spec
  GET /journal    - partial system log
  GET /notes      - onboarding notes
  GET /binary     - the running daemon binary
  GET /capture    - live wire-traffic capture
  GET /dump       - forensics endpoint (needs offset, len, epoch, token)
`

type server struct {
	authToken   string
	journalText string
	slots       *slotState
	dump        *dumpState
}

func newServer(authToken, journalText string, slots *slotState) *server {
	return &server{
		authToken:   authToken,
		journalText: journalText,
		slots:       slots,
		dump:        &dumpState{},
	}
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// "/" is a subtree pattern in net/http's ServeMux, so without this
	// check it would also catch any unregistered path (typos, probes).
	// Only serve the landing text for the exact root; everything else
	// still 404s normally.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(indexText))
	})

	mux.HandleFunc("/protocol", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, protocolFile)
	})

	mux.HandleFunc("/journal", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(s.journalText))
	})

	mux.HandleFunc("/notes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(kdfNotes()))
	})

	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		exe, err := os.Executable()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.ServeFile(w, r, exe)
	})

	mux.HandleFunc("/capture", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, captureFile)
	})

	mux.HandleFunc("/dump", s.handleDump)

	return mux
}

// handleDump validates the auth token, the epoch, and the offset/len bounds, rate-limits and
// locks out on repeated bad guesses, then reads this process's OWN memory
// (never another process's -- no special capability needed or possible to
// misuse). Deliberately does NOT take any lock around the actual pread of
// the key bytes -- only the small bookkeeping above is synchronized -- so
// the read still genuinely races the rotation goroutine's next overwrite.
func (s *server) handleDump(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	offset, err := strconv.ParseUint(q.Get("offset"), 16, 64)
	if err != nil {
		http.Error(w, "bad offset", http.StatusBadRequest)
		return
	}
	length, err := strconv.Atoi(q.Get("len"))
	if err != nil || length <= 0 || length > maxDumpLen {
		http.Error(w, "bad length", http.StatusBadRequest)
		return
	}
	epoch, err := strconv.ParseUint(q.Get("epoch"), 10, 64)
	if err != nil {
		http.Error(w, "bad epoch", http.StatusBadRequest)
		return
	}
	token := q.Get("token")

	if allowed, msg := s.dump.tryRequest(); !allowed {
		http.Error(w, msg, http.StatusTooManyRequests)
		return
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) != 1 {
		msg := s.dump.recordFailure()
		http.Error(w, "invalid token -- "+msg, http.StatusForbidden)
		return
	}

	if !s.slots.check(epoch) {
		msg := s.dump.recordFailure()
		http.Error(w, "epoch mismatch, no live key at that epoch -- "+msg, http.StatusConflict)
		return
	}

	base, err := selfLoadBase()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	addr := base + offset
	if addr < base {
		http.Error(w, "offset overflow", http.StatusBadRequest)
		return
	}
	ok, err := validateRange(addr, length)
	if err != nil || !ok {
		http.Error(w, "offset/len not within a readable region", http.StatusBadRequest)
		return
	}

	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer mem.Close()

	buf := make([]byte, length)
	n, err := mem.ReadAt(buf, int64(addr))
	if err != nil || n != length {
		http.Error(w, "short read", http.StatusInternalServerError)
		return
	}

	s.dump.recordSuccess()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(buf)
}
