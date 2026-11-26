/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Content-addressed WASM loader — works on all platforms.
 */
package wasmcid

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WASMLoader fetches WASM binaries from content-addressed gateways and
// verifies them against their CID before returning.
type WASMLoader struct {
	gateways   []string
	httpClient *http.Client
}

// NewWASMLoader creates a loader that tries each gateway in order.
// Gateways are URL prefixes; the CID is appended as a path segment.
// For example, a gateway "https://cdn.example.com/wasm/" with CID "abc123"
// resolves to "https://cdn.example.com/wasm/abc123".
func NewWASMLoader(gateways []string) *WASMLoader {
	return &WASMLoader{
		gateways: gateways,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Load fetches a WASM binary by CID, trying each gateway in order.
// The binary is verified against the CID before being returned.
func (l *WASMLoader) Load(ctx context.Context, cid string) ([]byte, error) {
	if len(l.gateways) == 0 {
		return nil, fmt.Errorf("wasmcid: no gateways configured")
	}

	var lastErr error
	for _, gw := range l.gateways {
		url := gw + cid
		data, err := l.fetchAndVerify(ctx, url, cid)
		if err != nil {
			lastErr = fmt.Errorf("gateway %s: %w", gw, err)
			continue
		}
		return data, nil
	}
	return nil, fmt.Errorf("wasmcid: all gateways failed; last error: %w", lastErr)
}

// LoadFromURL fetches a WASM binary from an explicit URL and verifies it
// against the expected CID.
func (l *WASMLoader) LoadFromURL(ctx context.Context, url, expectedCID string) ([]byte, error) {
	return l.fetchAndVerify(ctx, url, expectedCID)
}

// fetchAndVerify performs the HTTP GET and CID verification.
func (l *WASMLoader) fetchAndVerify(ctx context.Context, url, expectedCID string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("wasmcid: create request: %w", err)
	}

	resp, err := l.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wasmcid: fetch %s: %w", url, err)
	}
	// The body is read whole and its digest checked, or its error returned;
	// a close error after that changes nothing the caller gets.
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wasmcid: fetch %s: HTTP %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("wasmcid: read body from %s: %w", url, err)
	}

	if err := VerifyWASM(data, expectedCID); err != nil {
		return nil, err
	}

	return data, nil
}
