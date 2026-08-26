package relay

import (
	"context"
	"errors"
	"sync"

	"github.com/ORBTR/aether"
	"github.com/ORBTR/aether/websocket"
)

// Client manages a connection to a relay server via WebSocket.
// The relay provides bootstrap connectivity for peers that cannot
// establish direct connections (NAT traversal, browser WASM, etc.).
type Client struct {
	mu           sync.Mutex
	url          string
	transport    *websocket.WebsocketTransport
	conn         aether.Connection
	onDisconnect func(url string)
	closed       bool
}

// NewClient creates a relay client targeting the given WebSocket URL.
// The transport is used to dial the WebSocket connection and establish
// an Aether session.
func NewClient(url string, transport *websocket.WebsocketTransport) *Client {
	return &Client{
		url:       url,
		transport: transport,
	}
}

// Dial connects to the relay and establishes an Aether connection.
// The relay URL is dialed via the WebSocket transport.
func (c *Client) Dial(ctx context.Context) (aether.Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("relay: client is closed")
	}

	if c.transport == nil {
		return nil, errors.New("relay: WebSocket transport not configured")
	}

	// If we already have a live connection, return it.
	if c.conn != nil {
		return c.conn, nil
	}

	// Dial the relay via the WebSocket transport. The relay NodeID is
	// not known ahead of time (it's a bootstrap relay), so we use an
	// empty NodeID — the transport authenticates via signed headers.
	target := aether.Target{
		Address:  c.url,
		Protocol: aether.ProtoWebSocket,
	}
	conn, err := c.transport.Dial(ctx, target)
	if err != nil {
		return nil, err
	}

	// Store the connection.
	c.conn = conn

	// Wire disconnect handler.
	conn.OnClose(func() {
		c.mu.Lock()
		c.conn = nil
		handler := c.onDisconnect
		c.mu.Unlock()

		if handler != nil {
			handler(c.url)
		}
	})

	return conn, nil
}

// Reconnect closes any existing connection and re-dials the relay.
func (c *Client) Reconnect(ctx context.Context) (aether.Connection, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("relay: client is closed")
	}
	// Close existing connection if any.
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.mu.Unlock()

	return c.Dial(ctx)
}

// Connected returns whether the client has an active relay connection.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Close shuts down the relay connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	return nil
}

// CurrentRelay returns the URL of the relay this client is connected to.
func (c *Client) CurrentRelay() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.url
}

// OnDisconnect registers a handler that is called when the relay connection drops.
func (c *Client) OnDisconnect(handler func(url string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDisconnect = handler
}
