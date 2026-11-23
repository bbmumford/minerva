//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// browser_ws.go — pure net.Conn wrapper over a browser-native
// WebSocket. This is what the aether adapter USED to own as
// BrowserWSSession in aether/adapter/ws_browser.go, now moved here
// per the browser-transport-architecture plan (§4.1: browser-specific
// substrates live with the WASM app that uses them, not in the
// generic aether package).
//
// After the move, the wrapper exposes ONLY net.Conn. The full
// aether.Session layer (OpenStream, flow control, scheduler) is
// provided uniformly by adapter.NewNoiseSession, which accepts any
// net.Conn that delivers plaintext Aether frames — exactly what a
// WebSocket-over-TLS does (no Noise layered on top; TLS already
// handles encryption between browser and relay).

package main

import (
	"errors"
	"net"
	"sync"
	"syscall/js"
	"time"
)

// browserWS is a net.Conn over a browser WebSocket. Close idempotent.
type browserWS struct {
	ws        js.Value
	inbox     chan []byte
	readBuf   []byte
	closed    chan struct{}
	closeOnce sync.Once
	openCh    chan struct{}
	openOnce  sync.Once

	deadlineMu sync.Mutex
	deadline   time.Time

	onMessageFn js.Func
	onOpenFn    js.Func
	onCloseFn   js.Func
	onErrorFn   js.Func
}

// dialBrowserWS opens a browser WebSocket to url and returns a net.Conn
// once the socket's "open" event fires (or timeoutMs elapses).
func dialBrowserWS(url string, timeoutMs int) (*browserWS, error) {
	ws := js.Global().Get("WebSocket").New(url)
	ws.Set("binaryType", "arraybuffer")

	bw := &browserWS{
		ws:     ws,
		inbox:  make(chan []byte, 64),
		closed: make(chan struct{}),
		openCh: make(chan struct{}),
	}

	bw.onMessageFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		data := args[0].Get("data")
		arr := js.Global().Get("Uint8Array").New(data)
		buf := make([]byte, arr.Get("length").Int())
		js.CopyBytesToGo(buf, arr)
		select {
		case bw.inbox <- buf:
		case <-bw.closed:
		}
		return nil
	})
	ws.Call("addEventListener", "message", bw.onMessageFn)

	bw.onOpenFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		bw.openOnce.Do(func() { close(bw.openCh) })
		return nil
	})
	ws.Call("addEventListener", "open", bw.onOpenFn)

	bw.onCloseFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		bw.closeOnce.Do(func() { close(bw.closed) })
		return nil
	})
	ws.Call("addEventListener", "close", bw.onCloseFn)

	bw.onErrorFn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		bw.closeOnce.Do(func() { close(bw.closed) })
		return nil
	})
	ws.Call("addEventListener", "error", bw.onErrorFn)

	if timeoutMs <= 0 {
		timeoutMs = 10000
	}
	select {
	case <-bw.openCh:
		return bw, nil
	case <-bw.closed:
		return nil, errors.New("browser_ws: closed before open")
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		_ = bw.Close()
		return nil, errors.New("browser_ws: open timeout")
	}
}

func (c *browserWS) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		c.deadlineMu.Lock()
		dl := c.deadline
		c.deadlineMu.Unlock()
		var deadlineCh <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, errors.New("browser_ws: read deadline exceeded")
			}
			t := time.NewTimer(d)
			defer t.Stop()
			deadlineCh = t.C
		}
		select {
		case data, ok := <-c.inbox:
			if !ok {
				return 0, net.ErrClosed
			}
			c.readBuf = data
		case <-c.closed:
			return 0, net.ErrClosed
		case <-deadlineCh:
			return 0, errors.New("browser_ws: read deadline exceeded")
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *browserWS) Write(p []byte) (int, error) {
	buf := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(buf, p)
	c.ws.Call("send", buf.Get("buffer"))
	return len(p), nil
}

func (c *browserWS) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	c.ws.Call("close")
	c.onMessageFn.Release()
	c.onOpenFn.Release()
	c.onCloseFn.Release()
	c.onErrorFn.Release()
	return nil
}

func (c *browserWS) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *browserWS) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *browserWS) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.deadline = t
	c.deadlineMu.Unlock()
	return nil
}
func (c *browserWS) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *browserWS) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
