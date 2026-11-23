/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package sdk

import "errors"

var (
	ErrNotStarted     = errors.New("minerva: node not started")
	ErrAlreadyStarted = errors.New("minerva: node already started")
	ErrPeerNotFound   = errors.New("minerva: peer not found")
	ErrStreamClosed   = errors.New("minerva: stream closed")
	ErrStoreNotReady  = errors.New("minerva: store not ready")
)
