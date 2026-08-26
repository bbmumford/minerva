/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
