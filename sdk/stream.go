/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package sdk

import (
	"context"
	"sync"

	"github.com/ORBTR/aether"
)

// Stream wraps an Aether stream with a named application channel.
// Applications open named streams to specific peers for structured communication.
type Stream struct {
	// Name is the application-level channel name (e.g. "chat", "file-transfer").
	Name string

	// PeerID is the remote peer this stream is connected to.
	PeerID string

	mu     sync.Mutex
	raw    aether.Stream
	closed bool
}

// NewStream wraps an existing Aether stream with application metadata.
func NewStream(name string, peerID string, raw aether.Stream) *Stream {
	return &Stream{
		Name:   name,
		PeerID: peerID,
		raw:    raw,
	}
}

// Send writes data to the stream. Returns ErrStreamClosed if the stream has been closed.
func (s *Stream) Send(ctx context.Context, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStreamClosed
	}
	return s.raw.Send(ctx, data)
}

// Receive reads the next message from the stream. Blocks until data arrives or ctx expires.
func (s *Stream) Receive(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStreamClosed
	}
	s.mu.Unlock()
	return s.raw.Receive(ctx)
}

// Close shuts down the stream. Safe to call multiple times.
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.raw.Close()
}

// IsClosed returns whether the stream has been closed.
func (s *Stream) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
