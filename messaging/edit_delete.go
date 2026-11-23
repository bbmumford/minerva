/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Edit / Delete helpers.
 *
 * The core mutation paths live on Conversation (Edit and Delete). This
 * file provides read-side helpers — resolving the latest version of a
 * message, listing the full edit chain, and checking whether a message
 * has been tombstoned. They are pulled out here to keep conversation.go
 * focused on transport and CRDT bookkeeping.
 */
package messaging

import (
	"sort"
)

// versionBeats reports whether candidate should replace current when
// resolving the "latest" version of a message chain. The ordering is:
//
//  1. Later SentAt wins.
//  2. On equal SentAt, an edit (EditOf != "") beats an original — the
//     edit is by construction created after its target, so treating it
//     as strictly later is correct even when the wall-clock delta was
//     below the host OS's timer resolution (Windows ~15.6ms, macOS/Linux
//     usually finer but not guaranteed). This eliminates the classic
//     "TestGroup_Edit flake" where Send + Edit landed in the same
//     time.Now() tick.
//  3. On equal SentAt AND both are edits (or both are originals), fall
//     back to MessageID lex order. UUIDv7 embeds the ms timestamp in its
//     leading bytes so ID order is itself a stable causal tiebreak
//     across nodes, independent of map iteration order.
//
// The function is deliberately commutative-safe: versionBeats(a, b)
// returning true implies versionBeats(b, a) is false (barring the
// impossible all-equal case).
func versionBeats(candidate, current *Message) bool {
	if candidate.SentAt.After(current.SentAt) {
		return true
	}
	if current.SentAt.After(candidate.SentAt) {
		return false
	}
	// Equal SentAt — tiebreak on edit-ness, then on ID.
	candIsEdit := candidate.EditOf != ""
	curIsEdit := current.EditOf != ""
	if candIsEdit != curIsEdit {
		return candIsEdit // edit beats original
	}
	return candidate.ID > current.ID
}

// LatestVersion returns the most recent non-tombstoned version of msgID.
// If msgID is itself an edit, the chain is walked to the root first.
// Returns (nil, false) if the original has been deleted or never seen.
func (c *Conversation) LatestVersion(msgID MessageID) (*Message, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	root := c.rootOfLocked(msgID)
	if c.tombstones[root] {
		return nil, false
	}

	candidates := []*Message{c.log[root]}
	for _, editID := range c.edits[root] {
		if m, ok := c.log[editID]; ok && !m.Deleted {
			candidates = append(candidates, m)
		}
	}

	var best *Message
	for _, m := range candidates {
		if m == nil {
			continue
		}
		if best == nil || versionBeats(m, best) {
			best = m
		}
	}
	if best == nil {
		return nil, false
	}
	cp := *best
	return &cp, true
}

// EditChain returns every version of msgID (original + all edits) ordered
// by SentAt ascending. Deleted / tombstone markers are excluded.
func (c *Conversation) EditChain(msgID MessageID) []Message {
	c.mu.RLock()
	defer c.mu.RUnlock()

	root := c.rootOfLocked(msgID)
	out := []Message{}
	if m, ok := c.log[root]; ok && !m.Deleted {
		out = append(out, *m)
	}
	for _, editID := range c.edits[root] {
		if m, ok := c.log[editID]; ok && !m.Deleted {
			out = append(out, *m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SentAt.Equal(out[j].SentAt) {
			// Equal SentAt: originals sort before edits (so chain reads
			// orig -> edit1 -> edit2), and identical edit-status ties
			// break on ID lex order for determinism.
			iIsEdit := out[i].EditOf != ""
			jIsEdit := out[j].EditOf != ""
			if iIsEdit != jIsEdit {
				return !iIsEdit // original first
			}
			return out[i].ID < out[j].ID
		}
		return out[i].SentAt.Before(out[j].SentAt)
	})
	return out
}

// IsDeleted reports whether msgID (or its root original, if msgID is an
// edit) has been tombstoned.
func (c *Conversation) IsDeleted(msgID MessageID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tombstones[c.rootOfLocked(msgID)]
}

// rootOfLocked walks EditOf until it finds an original. Caller must hold
// c.mu (read or write).
func (c *Conversation) rootOfLocked(msgID MessageID) MessageID {
	cur := msgID
	// Bound the loop so a pathological cycle can't hang us.
	for i := 0; i < 128; i++ {
		m, ok := c.log[cur]
		if !ok {
			return cur
		}
		if m.EditOf == "" {
			return cur
		}
		cur = m.EditOf
	}
	return cur
}
