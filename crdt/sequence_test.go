/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package crdt

import (
	"testing"
)

func TestSequenceInsert(t *testing.T) {
	clock := NewHLC("node-a")
	seq := NewSequence(clock, "node-a")

	// Insert characters one by one to form "abc".
	seq.Insert(0, 'a')
	seq.Insert(1, 'b')
	seq.Insert(2, 'c')

	if got := seq.Text(); got != "abc" {
		t.Errorf("expected %q, got %q", "abc", got)
	}
	if got := seq.Length(); got != 3 {
		t.Errorf("expected length 3, got %d", got)
	}

	// Insert at the beginning.
	seq.Insert(0, 'z')
	if got := seq.Text(); got != "zabc" {
		t.Errorf("expected %q, got %q", "zabc", got)
	}

	// Insert in the middle.
	seq.Insert(2, 'x')
	if got := seq.Text(); got != "zaxbc" {
		t.Errorf("expected %q, got %q", "zaxbc", got)
	}
}

func TestSequenceDelete(t *testing.T) {
	clock := NewHLC("node-a")
	seq := NewSequence(clock, "node-a")

	seq.Insert(0, 'h')
	seq.Insert(1, 'e')
	seq.Insert(2, 'l')
	seq.Insert(3, 'l')
	seq.Insert(4, 'o')

	if got := seq.Text(); got != "hello" {
		t.Fatalf("setup: expected %q, got %q", "hello", got)
	}

	// Delete the middle character 'l' at position 2.
	op := seq.Delete(2)
	if op == nil {
		t.Fatal("Delete returned nil op")
	}
	if got := seq.Text(); got != "helo" {
		t.Errorf("after delete pos 2: expected %q, got %q", "helo", got)
	}

	// Delete the first character.
	op = seq.Delete(0)
	if op == nil {
		t.Fatal("Delete returned nil op")
	}
	if got := seq.Text(); got != "elo" {
		t.Errorf("after delete pos 0: expected %q, got %q", "elo", got)
	}

	// Delete the last character.
	op = seq.Delete(seq.Length() - 1)
	if op == nil {
		t.Fatal("Delete returned nil op")
	}
	if got := seq.Text(); got != "el" {
		t.Errorf("after delete last: expected %q, got %q", "el", got)
	}

	// Delete out of range returns nil.
	op = seq.Delete(100)
	if op != nil {
		t.Errorf("Delete out of range should return nil, got %+v", op)
	}
	op = seq.Delete(-1)
	if op != nil {
		t.Errorf("Delete negative index should return nil, got %+v", op)
	}
}

func TestSequenceConcurrentInsert(t *testing.T) {
	// Two nodes insert at the same position concurrently.
	// The RGA merge must produce the same result on both replicas.
	clockA := NewHLC("node-a")
	clockB := NewHLC("node-b")
	seqA := NewSequence(clockA, "node-a")
	seqB := NewSequence(clockB, "node-b")

	// Both start with "ac" — insert 'a' then 'c'.
	opA1 := seqA.Insert(0, 'a')
	opA2 := seqA.Insert(1, 'c')

	if err := seqB.Merge(opA1); err != nil {
		t.Fatalf("seqB merge opA1: %v", err)
	}
	if err := seqB.Merge(opA2); err != nil {
		t.Fatalf("seqB merge opA2: %v", err)
	}

	// Both replicas should now have "ac".
	if got := seqA.Text(); got != "ac" {
		t.Fatalf("seqA setup: expected %q, got %q", "ac", got)
	}
	if got := seqB.Text(); got != "ac" {
		t.Fatalf("seqB setup: expected %q, got %q", "ac", got)
	}

	// Node A inserts 'x' at position 1 (between 'a' and 'c').
	opAx := seqA.Insert(1, 'x')
	// Node B inserts 'y' at position 1 (between 'a' and 'c').
	opBy := seqB.Insert(1, 'y')

	// Cross-merge: apply each other's operations.
	if err := seqA.Merge(opBy); err != nil {
		t.Fatalf("seqA merge opBy: %v", err)
	}
	if err := seqB.Merge(opAx); err != nil {
		t.Fatalf("seqB merge opAx: %v", err)
	}

	// Both replicas must converge to the same text.
	textA := seqA.Text()
	textB := seqB.Text()
	if textA != textB {
		t.Errorf("replicas diverged: seqA=%q, seqB=%q", textA, textB)
	}

	// The text should contain all four characters.
	if len(textA) != 4 {
		t.Errorf("expected 4 characters, got %d: %q", len(textA), textA)
	}

	// 'a' should be first, 'c' should be last.
	runes := []rune(textA)
	if runes[0] != 'a' {
		t.Errorf("expected first char 'a', got %q", string(runes[0]))
	}
	if runes[len(runes)-1] != 'c' {
		t.Errorf("expected last char 'c', got %q", string(runes[len(runes)-1]))
	}
}

func TestSequenceText(t *testing.T) {
	clock := NewHLC("node-a")
	seq := NewSequence(clock, "node-a")

	// Empty sequence.
	if got := seq.Text(); got != "" {
		t.Errorf("empty sequence: expected %q, got %q", "", got)
	}
	if got := seq.Length(); got != 0 {
		t.Errorf("empty sequence: expected length 0, got %d", got)
	}

	// Build "Hello, World!" character by character.
	text := "Hello, World!"
	for i, ch := range text {
		seq.Insert(i, ch)
	}

	if got := seq.Text(); got != text {
		t.Errorf("expected %q, got %q", text, got)
	}
	if got := seq.Length(); got != len(text) {
		t.Errorf("expected length %d, got %d", len(text), got)
	}

	// Delete everything.
	for seq.Length() > 0 {
		seq.Delete(0)
	}
	if got := seq.Text(); got != "" {
		t.Errorf("after deleting all: expected %q, got %q", "", got)
	}
}

func TestSequenceMerge(t *testing.T) {
	clockA := NewHLC("node-a")
	clockB := NewHLC("node-b")
	seqA := NewSequence(clockA, "node-a")
	seqB := NewSequence(clockB, "node-b")

	// Node A types "cat".
	ops := make([]*SeqOp, 0, 3)
	ops = append(ops, seqA.Insert(0, 'c'))
	ops = append(ops, seqA.Insert(1, 'a'))
	ops = append(ops, seqA.Insert(2, 't'))

	// Merge all ops into node B.
	for i, op := range ops {
		if err := seqB.Merge(op); err != nil {
			t.Fatalf("merge op %d: %v", i, err)
		}
	}

	if got := seqB.Text(); got != "cat" {
		t.Errorf("seqB after merge: expected %q, got %q", "cat", got)
	}

	// Node B deletes 'a' (position 1) and the op is merged into A.
	delOp := seqB.Delete(1)
	if delOp == nil {
		t.Fatal("seqB delete returned nil")
	}
	if err := seqA.Merge(delOp); err != nil {
		t.Fatalf("seqA merge delete: %v", err)
	}

	if got := seqA.Text(); got != "ct" {
		t.Errorf("seqA after merge delete: expected %q, got %q", "ct", got)
	}
	if got := seqB.Text(); got != "ct" {
		t.Errorf("seqB after delete: expected %q, got %q", "ct", got)
	}

	// Idempotent: re-merging the same insert ops should not error or duplicate.
	for i, op := range ops {
		if err := seqB.Merge(op); err != nil {
			t.Errorf("idempotent re-merge op %d: %v", i, err)
		}
	}
	if got := seqB.Text(); got != "ct" {
		t.Errorf("seqB after idempotent re-merge: expected %q, got %q", "ct", got)
	}

	// Merging a delete for a non-existent node should return an error.
	badOp := &SeqOp{
		Type:   SeqOpDelete,
		NodeID: "nonexistent-node-id",
		HLC:    clockA.Now(),
	}
	if err := seqA.Merge(badOp); err != ErrSeqNodeNotFound {
		t.Errorf("expected ErrSeqNodeNotFound, got %v", err)
	}

	// Merging an insert with a non-existent left parent should return an error.
	badInsert := &SeqOp{
		Type:   SeqOpInsert,
		NodeID: "new-node-123",
		Value:  'z',
		LeftID: "nonexistent-left-parent",
		HLC:    clockA.Now(),
	}
	if err := seqA.Merge(badInsert); err != ErrSeqNodeNotFound {
		t.Errorf("expected ErrSeqNodeNotFound, got %v", err)
	}
}
