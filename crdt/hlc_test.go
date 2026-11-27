/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package crdt

import (
	"errors"
	"testing"
	"time"
)

// storedStamp packs (wall, logical) the way this package has always written
// its stamps (wall<<16 | logical), standing in for a stamp read back from a
// store: an LWW entry's HLC, a sequence op or a delta watermark.
func storedStamp(wallMs uint64, logical uint16) uint64 {
	return wallMs<<16 | uint64(logical)
}

func nowMs() uint64 { return uint64(time.Now().UnixMilli()) }

// TestUpdateOutrunsARemoteAtTheCounterLimit: a remote stamp whose 16-bit
// counter is full must still be followed by a greater local stamp. Adding one
// to a full uint16 counter drops it to 0 and returns a stamp below the remote,
// so a write that causally follows the remote would lose to it under the
// highest-HLC-wins merge.
func TestUpdateOutrunsARemoteAtTheCounterLimit(t *testing.T) {
	h := NewHLC("node-a")
	remote := storedStamp(nowMs()+30_000, 0xFFFF)
	got, err := h.Update(remote)
	if err != nil {
		t.Fatalf("Update(remote 30s ahead): %v", err)
	}
	if got <= remote {
		t.Fatalf("Update(remote with a full counter) = %d (wall %d, logical %d), must exceed %d", got, got>>16, got&0xFFFF, remote)
	}
	if next := h.Now(); next <= got {
		t.Fatalf("Now after Update = %d, must exceed %d", next, got)
	}
}

// TestUpdateRefusesARemoteBeyondMaxDrift: a remote more than MaxDrift ahead is
// refused and does not move the clock.
func TestUpdateRefusesARemoteBeyondMaxDrift(t *testing.T) {
	h := NewHLC("node-a")
	before := h.Now()
	remote := storedStamp(nowMs()+uint64((2*MaxDrift).Milliseconds()), 0)
	if _, err := h.Update(remote); !errors.Is(err, ErrClockDrift) {
		t.Fatalf("Update(remote 2*MaxDrift ahead): err = %v, want ErrClockDrift", err)
	}
	if next := h.Now(); next >= remote || next <= before {
		t.Fatalf("Now after a refused Update = %d: must stay below the refused remote %d and above %d", next, remote, before)
	}
}

// TestUpdateOutrunsARemoteJustInsideMaxDrift: the latest remote Update
// accepts is folded into the clock, so the stamp returned exceeds it.
func TestUpdateOutrunsARemoteJustInsideMaxDrift(t *testing.T) {
	h := NewHLC("node-a")
	remote := storedStamp(nowMs()+uint64((MaxDrift-time.Second).Milliseconds()), 5)
	got, err := h.Update(remote)
	if err != nil {
		t.Fatalf("Update(remote just inside MaxDrift): %v", err)
	}
	if got <= remote {
		t.Fatalf("Update = %d, must exceed the accepted remote %d", got, remote)
	}
}

// TestStoredStampsKeepTheirOrder: stamps written in this package's packed
// format read back with their wall and counter in the clock's high and low
// bits, and a clock that has seen the latest of them stamps above every one.
func TestStoredStampsKeepTheirOrder(t *testing.T) {
	w := nowMs() - 5_000
	stored := []uint64{storedStamp(w, 0), storedStamp(w, 1), storedStamp(w, 0xFFFF), storedStamp(w+1, 0)}
	for i := 1; i < len(stored); i++ {
		if stored[i] <= stored[i-1] {
			t.Fatalf("stored stamps out of order at %d", i)
		}
	}
	h := NewHLC("node-a")
	for _, s := range stored {
		if _, err := h.Update(s); err != nil {
			t.Fatalf("Update(stored %d): %v", s, err)
		}
	}
	got := h.Now()
	if got>>16 < w+1 {
		t.Fatalf("Now = %d (wall %d): must be at or after the stored stamps' wall %d", got, got>>16, w+1)
	}
	for _, s := range stored {
		if got <= s {
			t.Fatalf("Now = %d after the stored stamps, must exceed %d", got, s)
		}
	}
}

// TestAStoredStampIsTheClocksFormat: a stored stamp's wall and counter are the
// clock's own, so the stamp after one read back from a store, 20 seconds
// ahead with counter 7, is that same wall with counter 8.
func TestAStoredStampIsTheClocksFormat(t *testing.T) {
	h := NewHLC("node-a")
	w := nowMs() + 20_000
	got, err := h.Update(storedStamp(w, 7))
	if err != nil {
		t.Fatalf("Update(stored stamp 20s ahead): %v", err)
	}
	if got>>16 != w || got&0xFFFF != 8 {
		t.Fatalf("Update(stored wall %d, counter 7) = wall %d, counter %d; want wall %d, counter 8", w, got>>16, got&0xFFFF, w)
	}
}
