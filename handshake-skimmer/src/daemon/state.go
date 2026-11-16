package main

import (
	"fmt"
	"sync"
	"time"
)

// slotState tracks which epoch currently occupies each of the two reused
// key slots. Shared between the rotation goroutine (writer) and the HTTP
// dump handler (reader).
type slotState struct {
	mu    sync.Mutex
	epoch [2]uint64
}

func newSlotState() *slotState {
	return &slotState{epoch: [2]uint64{^uint64(0), ^uint64(0)}}
}

func (s *slotState) update(idx int, epoch uint64) {
	s.mu.Lock()
	s.epoch[idx] = epoch
	s.mu.Unlock()
}

func (s *slotState) check(epoch uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch[epoch%2] == epoch
}

const (
	maxDumpLen      = 64
	rateLimitWindow = 2 * time.Second
	failLimit       = 3
	lockoutDuration = 30 * time.Second
)

// dumpState rate-limits and locks out the /dump endpoint.
type dumpState struct {
	mu           sync.Mutex
	lastReq      time.Time
	failCount    int
	lockoutUntil time.Time
}

func (d *dumpState) tryRequest() (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if now.Before(d.lockoutUntil) {
		return false, fmt.Sprintf("locked out, retry in %ds", int(d.lockoutUntil.Sub(now).Seconds())+1)
	}
	if now.Sub(d.lastReq) < rateLimitWindow {
		return false, fmt.Sprintf("rate limited, retry in %ds", int(rateLimitWindow.Seconds()))
	}
	d.lastReq = now
	return true, ""
}

func (d *dumpState) recordFailure() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failCount++
	if d.failCount >= failLimit {
		d.lockoutUntil = time.Now().Add(lockoutDuration)
		d.failCount = 0
		return fmt.Sprintf("too many failed attempts -- locked out %ds", int(lockoutDuration.Seconds()))
	}
	return "try again"
}

func (d *dumpState) recordSuccess() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failCount = 0
}
