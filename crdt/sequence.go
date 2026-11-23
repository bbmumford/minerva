/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Sequence CRDT — Replicated Growable Array (RGA).
 *
 * Each character is a node in a tree. The root is a sentinel with no value.
 * Insert places a new node as a child of the node to its left (the "left
 * parent"). Children of the same parent are ordered by descending HLC, which
 * gives last-writer-wins semantics for concurrent inserts at the same position.
 * Delete marks a node as tombstoned (soft delete).
 *
 * The tree is flattened to a string via pre-order DFS: visit a node, then its
 * children in order. This is the RGA linearisation.
 */
package crdt

import (
	"errors"
	"sort"
	"sync"
)

const (
	// SeqOpInsert is an insert operation.
	SeqOpInsert = iota
	// SeqOpDelete is a delete (tombstone) operation.
	SeqOpDelete
)

var (
	// ErrSeqPositionOutOfRange is returned for out-of-bounds positions.
	ErrSeqPositionOutOfRange = errors.New("sequence: position out of range")
	// ErrSeqNodeNotFound is returned when a referenced node does not exist.
	ErrSeqNodeNotFound = errors.New("sequence: node not found")
	// ErrSeqDuplicateNode is returned when merging a node that already exists.
	ErrSeqDuplicateNode = errors.New("sequence: duplicate node ID")
)

// seqNode is a single character in the RGA tree.
type seqNode struct {
	ID       string
	Value    rune
	Left     *seqNode   // parent (left neighbour at insert time)
	Children []*seqNode // children ordered by descending HLC
	Deleted  bool
	hlc      uint64 // HLC timestamp for ordering
}

// SeqOp represents a single insert or delete operation on the sequence.
type SeqOp struct {
	Type   int    `json:"type"`
	NodeID string `json:"nodeId"`
	Value  rune   `json:"value,omitempty"`
	LeftID string `json:"leftId"`
	HLC    uint64 `json:"hlc"`
}

// Sequence is an RGA CRDT for collaborative text editing.
// It supports Insert, Delete, and Merge operations with causal ordering via HLC.
type Sequence struct {
	mu      sync.RWMutex
	root    *seqNode            // sentinel root
	nodeMap map[string]*seqNode // ID -> node for O(1) lookup
	clock   *HLC
	nodeID  string
}

// NewSequence creates a new empty sequence with the given clock and node ID.
func NewSequence(clock *HLC, nodeID string) *Sequence {
	root := &seqNode{
		ID:       "__root__",
		Children: make([]*seqNode, 0),
	}
	return &Sequence{
		root:    root,
		nodeMap: map[string]*seqNode{"__root__": root},
		clock:   clock,
		nodeID:  nodeID,
	}
}

// Insert inserts a character at the given position (0-based index into visible text).
// Returns the operation that can be sent to peers via Merge.
func (s *Sequence) Insert(pos int, char rune) *SeqOp {
	s.mu.Lock()
	defer s.mu.Unlock()

	hlc := s.clock.Now()

	// Find the node to the left of the insertion point.
	leftNode := s.nodeAtPosition(pos)

	id := s.generateID(hlc)
	node := &seqNode{
		ID:       id,
		Value:    char,
		Left:     leftNode,
		Children: make([]*seqNode, 0),
		hlc:      hlc,
	}

	s.nodeMap[id] = node
	s.insertChild(leftNode, node)

	return &SeqOp{
		Type:   SeqOpInsert,
		NodeID: id,
		Value:  char,
		LeftID: leftNode.ID,
		HLC:    hlc,
	}
}

// Delete tombstones the character at the given position (0-based index into visible text).
// Returns the operation that can be sent to peers via Merge.
func (s *Sequence) Delete(pos int) *SeqOp {
	s.mu.Lock()
	defer s.mu.Unlock()

	visible := s.visibleNodes()
	if pos < 0 || pos >= len(visible) {
		return nil
	}

	node := visible[pos]
	node.Deleted = true

	hlc := s.clock.Now()
	return &SeqOp{
		Type:   SeqOpDelete,
		NodeID: node.ID,
		HLC:    hlc,
	}
}

// Text returns the current visible text as a string.
func (s *Sequence) Text() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var runes []rune
	s.walk(s.root, func(n *seqNode) {
		if n != s.root && !n.Deleted {
			runes = append(runes, n.Value)
		}
	})
	return string(runes)
}

// Length returns the number of visible characters.
func (s *Sequence) Length() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	s.walk(s.root, func(n *seqNode) {
		if n != s.root && !n.Deleted {
			count++
		}
	})
	return count
}

// Merge applies a remote operation into the local sequence.
// For inserts, the node is placed as a child of its left parent, ordered by HLC.
// For deletes, the referenced node is tombstoned.
func (s *Sequence) Merge(op *SeqOp) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update HLC with remote timestamp.
	if _, err := s.clock.Update(op.HLC); err != nil {
		return err
	}

	switch op.Type {
	case SeqOpInsert:
		return s.mergeInsert(op)
	case SeqOpDelete:
		return s.mergeDelete(op)
	default:
		return errors.New("sequence: unknown operation type")
	}
}

// mergeInsert handles a remote insert operation.
func (s *Sequence) mergeInsert(op *SeqOp) error {
	// Idempotent: skip if already present.
	if _, exists := s.nodeMap[op.NodeID]; exists {
		return nil
	}

	leftNode, ok := s.nodeMap[op.LeftID]
	if !ok {
		return ErrSeqNodeNotFound
	}

	node := &seqNode{
		ID:       op.NodeID,
		Value:    op.Value,
		Left:     leftNode,
		Children: make([]*seqNode, 0),
		hlc:      op.HLC,
	}

	s.nodeMap[op.NodeID] = node
	s.insertChild(leftNode, node)
	return nil
}

// mergeDelete handles a remote delete operation.
func (s *Sequence) mergeDelete(op *SeqOp) error {
	node, ok := s.nodeMap[op.NodeID]
	if !ok {
		return ErrSeqNodeNotFound
	}
	node.Deleted = true
	return nil
}

// insertChild adds a node as a child of parent, maintaining descending HLC order.
// Higher HLC = earlier in children list = appears first in linearisation.
func (s *Sequence) insertChild(parent, node *seqNode) {
	i := 0
	for i < len(parent.Children) {
		if node.hlc > parent.Children[i].hlc {
			break
		}
		if node.hlc == parent.Children[i].hlc && node.ID > parent.Children[i].ID {
			break
		}
		i++
	}
	parent.Children = append(parent.Children, nil)
	copy(parent.Children[i+1:], parent.Children[i:])
	parent.Children[i] = node
}

// nodeAtPosition returns the node at or before the given visible position.
// Position 0 returns root (insert before first char), position N returns
// the Nth visible node (insert after it).
func (s *Sequence) nodeAtPosition(pos int) *seqNode {
	if pos <= 0 {
		return s.root
	}
	visible := s.visibleNodes()
	if pos > len(visible) {
		pos = len(visible)
	}
	if pos == 0 {
		return s.root
	}
	return visible[pos-1]
}

// visibleNodes returns all non-deleted, non-root nodes in DFS order.
func (s *Sequence) visibleNodes() []*seqNode {
	var nodes []*seqNode
	s.walk(s.root, func(n *seqNode) {
		if n != s.root && !n.Deleted {
			nodes = append(nodes, n)
		}
	})
	return nodes
}

// walk does a pre-order DFS of the tree. For each node, visit it, then
// recurse into children. This gives the RGA linearisation.
func (s *Sequence) walk(node *seqNode, fn func(*seqNode)) {
	fn(node)
	for _, child := range node.Children {
		s.walk(child, fn)
	}
}

// generateID creates a unique node ID from the HLC and node ID.
func (s *Sequence) generateID(hlc uint64) string {
	// Use a format that includes HLC and nodeID for global uniqueness.
	buf := make([]byte, 0, len(s.nodeID)+20)
	buf = append(buf, s.nodeID...)
	buf = append(buf, ':')
	// Append HLC as hex.
	h := hlc
	var hexBuf [16]byte
	for i := 15; i >= 0; i-- {
		d := h & 0xf
		if d < 10 {
			hexBuf[i] = byte('0' + d)
		} else {
			hexBuf[i] = byte('a' + d - 10)
		}
		h >>= 4
	}
	buf = append(buf, hexBuf[:]...)
	return string(buf)
}

// DeltaSince returns all operations with HLC strictly greater than the given
// watermark, sorted by ascending HLC. This is used by delta-sync to send only
// the operations a peer has not yet seen.
func (s *Sequence) DeltaSince(watermark uint64) []*SeqOp {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ops []*SeqOp
	for _, node := range s.nodeMap {
		if node == s.root {
			continue
		}
		if node.hlc <= watermark {
			continue
		}

		op := &SeqOp{
			NodeID: node.ID,
			Value:  node.Value,
			HLC:    node.hlc,
		}

		if node.Deleted {
			op.Type = SeqOpDelete
		} else {
			op.Type = SeqOpInsert
			if node.Left != nil {
				op.LeftID = node.Left.ID
			}
		}

		ops = append(ops, op)
	}

	// Sort by ascending HLC for causal ordering.
	sort.Slice(ops, func(i, j int) bool {
		return ops[i].HLC < ops[j].HLC
	})

	return ops
}
