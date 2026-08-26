/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package sdk

import (
	"context"

	"github.com/bbmumford/minerva/identity"
)

// StreamHandler handles a single inbound stream from a peer.
//
// Minerva spawns a dedicated goroutine per inbound stream and invokes
// HandleStream there. The handler owns the *Stream until it returns, at
// which point Minerva closes the stream. Returning nil means "handled
// successfully"; returning a non-nil error is logged but does not tear
// down the session (so one bad fetch does not kill the peer).
//
// The ctx is derived from the Node's run context — handlers MUST respect
// cancellation so shutdown is prompt.
type StreamHandler interface {
	HandleStream(ctx context.Context, peerID identity.PeerID, stream *Stream) error
}

// StreamHandlerFunc adapts an ordinary function to the StreamHandler
// interface.
type StreamHandlerFunc func(ctx context.Context, peerID identity.PeerID, stream *Stream) error

// HandleStream satisfies StreamHandler.
func (f StreamHandlerFunc) HandleStream(ctx context.Context, peerID identity.PeerID, stream *Stream) error {
	return f(ctx, peerID, stream)
}
