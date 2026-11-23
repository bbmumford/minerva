/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package sdk

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/ORBTR/aether"
	"github.com/bbmumford/minerva/discovery"
	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/minerva/persistence"
	pmem "github.com/bbmumford/minerva/persistence/memory"
	"github.com/bbmumford/whisper"
)

// stopTimeout bounds how long Node.Stop will wait for in-flight
// per-session accept-loop goroutines and stream handlers to drain before
// logging a warning and returning. Handlers that ignore ctx cancellation
// will still be counted here so shutdown never hangs the process.
const stopTimeout = 5 * time.Second

// LifecycleHook is a pluggable subsystem that wants to start and stop with the
// Node. External packages (such as gossip.SyncManager, which imports sdk and
// therefore cannot be imported from here) register themselves via
// Node.AddLifecycleHook so that Start/Stop invoke them automatically.
type LifecycleHook interface {
	Start(ctx context.Context) error
	Stop() error
}

// Node is the central Minerva type. It manages identity, peer connections,
// CRDT state, and gossip synchronisation. Applications interact with the P2P
// network exclusively through Node.
type Node struct {
	config      NodeConfig
	peerManager *PeerManager
	eventBus    *EventBus
	store       *Store

	// identity holds the Ed25519 keypair for this node.
	identity *identity.Keypair
	// peerID is derived from the public key.
	peerID identity.PeerID
	// persistence is the backing store for state (memory by default).
	persistence persistence.Store

	// transport is the underlying Aether session (nil until Start).
	transport aether.Session

	// whisperEngine is the gossip broadcast engine (nil until wired).
	whisperEngine *whisper.Engine
	// ownsEngine indicates whether Stop() should call whisperEngine.Stop().
	ownsEngine bool

	// sessions maps peer IDs to active Aether sessions.
	sessions map[string]aether.Session
	// sessionCancels tracks the per-session accept-loop cancel funcs so
	// UnregisterSession / Stop can tear them down.
	sessionCancels map[string]context.CancelFunc
	// sessionLoops counts in-flight accept-loop goroutines so Stop can
	// wait for them to drain.
	sessionLoops sync.WaitGroup

	// streamHandlers is the set of OnStream-registered handlers keyed by
	// Aether stream ID. Protected by streamMu.
	streamMu       sync.RWMutex
	streamHandlers map[uint64]StreamHandler

	// discoverer merges all configured peer-discovery mechanisms.
	discoverer    *discovery.MultiDiscoverer
	discoveryDone chan struct{}

	// hooks are subsystems registered via AddLifecycleHook.
	hooks        []LifecycleHook
	startedHooks []LifecycleHook // tracks hooks whose Start succeeded, for reverse Stop.

	mu      sync.RWMutex
	started bool
	cancel  context.CancelFunc
}

// NewNode creates a Minerva node with functional options applied over defaults.
// Does not start networking — call Start() for that.
func NewNode(opts ...NodeOption) *Node {
	n := &Node{
		config:   DefaultConfig(),
		eventBus: NewEventBus(),
		store:    NewStore(),
	}
	for _, opt := range opts {
		opt(n)
	}
	n.peerManager = NewPeerManager(n.config.MaxPeers)
	return n
}

// AddLifecycleHook registers a subsystem whose Start/Stop should be driven by
// the Node. Hooks are started after the node's own subsystems and stopped in
// reverse order during Stop. If the node is already started, the hook is
// started immediately.
func (n *Node) AddLifecycleHook(hook LifecycleHook) error {
	if hook == nil {
		return fmt.Errorf("minerva: nil lifecycle hook")
	}
	n.mu.Lock()
	n.hooks = append(n.hooks, hook)
	started := n.started
	n.mu.Unlock()

	if !started {
		return nil
	}
	// Already running — start the hook against the node's context.
	n.mu.RLock()
	cancel := n.cancel
	n.mu.RUnlock()
	if cancel == nil {
		return nil
	}
	// We reconstruct a background context; the hook will be cancelled via its
	// own Stop() call at shutdown since we cannot re-derive the node context.
	if err := hook.Start(context.Background()); err != nil {
		return fmt.Errorf("minerva: start lifecycle hook: %w", err)
	}
	n.mu.Lock()
	n.startedHooks = append(n.startedHooks, hook)
	n.mu.Unlock()
	return nil
}

// Start initialises the node: loads identity, brings up configured discovery
// mechanisms, starts the Whisper engine (if one was wired with SetWhisperEngine
// but not yet started — ownership is external), and runs all registered
// lifecycle hooks (gossip SyncManager, etc.).
func (n *Node) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return ErrAlreadyStarted
	}

	// --- Persistence -------------------------------------------------------
	if n.persistence == nil {
		n.persistence = pmem.New()
	}

	// --- Identity ----------------------------------------------------------
	hasKey, err := n.persistence.HasKeypair()
	if err != nil {
		n.mu.Unlock()
		return fmt.Errorf("minerva: check keypair: %w", err)
	}
	if hasKey {
		kp, err := n.persistence.LoadKeypair(nil)
		if err != nil {
			n.mu.Unlock()
			return fmt.Errorf("minerva: load keypair: %w", err)
		}
		n.identity = kp
	} else {
		kp, err := identity.Generate()
		if err != nil {
			n.mu.Unlock()
			return fmt.Errorf("minerva: generate keypair: %w", err)
		}
		n.identity = kp
		if err := n.persistence.SaveKeypair(kp, nil); err != nil {
			n.mu.Unlock()
			return fmt.Errorf("minerva: save keypair: %w", err)
		}
	}

	n.peerID = identity.PeerIDFromPublicKey(n.identity.PublicKey)
	n.sessions = make(map[string]aether.Session)
	n.sessionCancels = make(map[string]context.CancelFunc)

	// Derive the node's context for all background goroutines.
	runCtx, cancel := context.WithCancel(ctx)
	n.cancel = cancel

	// Snapshot hooks under the same lock so we can release it before running
	// any Start that may itself acquire n.mu (e.g. via SDK accessors).
	hooks := append([]LifecycleHook(nil), n.hooks...)
	n.started = true
	n.mu.Unlock()

	// --- Discovery ---------------------------------------------------------
	var discoverers []discovery.Discoverer

	if n.config.EnableMDNS {
		port := parseListenPort(n.config.ListenAddress)
		discoverers = append(discoverers, discovery.NewMDNSDiscoverer(string(n.peerID), port))
	}

	if n.config.DNSBootstrapDomain != "" {
		discoverers = append(discoverers, discovery.NewDNSDiscoverer(n.config.DNSBootstrapDomain))
	}

	// PEX discovery — enabled only when the caller asked for it AND a Whisper
	// engine constructed with whisper.WithPEX has been wired via
	// SetWhisperEngine / SetWhisperEngineOwned. The engine's PEXManager()
	// accessor returns nil when PEX wasn't configured at construction time;
	// we treat that as a config error (log + continue) rather than a crash.
	if n.config.EnablePEX {
		n.mu.RLock()
		engine := n.whisperEngine
		n.mu.RUnlock()
		if engine == nil {
			log.Printf("minerva: EnablePEX set but no Whisper engine wired — skipping PEX discovery")
		} else if pexMgr := engine.PEXManager(); pexMgr == nil {
			log.Printf("minerva: EnablePEX set but Whisper engine was not constructed with WithPEX — skipping PEX discovery")
		} else {
			discoverers = append(discoverers, discovery.NewPEXDiscoverer(pexMgr))
		}
	}

	if len(discoverers) > 0 {
		n.mu.Lock()
		n.discoverer = discovery.NewMultiDiscoverer(discoverers...)
		n.discoveryDone = make(chan struct{})
		done := n.discoveryDone
		disc := n.discoverer
		n.mu.Unlock()

		var pubkey [32]byte
		copy(pubkey[:], n.identity.PublicKey)
		self := discovery.PeerAddress{
			PeerID:    n.peerID,
			Pubkey:    pubkey,
			Timestamp: nowUnix(),
		}
		// Advertise is best-effort — log and continue.
		if err := disc.Advertise(runCtx, self); err != nil {
			log.Printf("minerva: discovery advertise: %v", err)
		}

		go n.runDiscoveryLoop(runCtx, disc, done)
	}

	// --- Lifecycle hooks ---------------------------------------------------
	// Start hooks in registration order. On failure, stop already-started
	// hooks in reverse and unwind node state.
	started := make([]LifecycleHook, 0, len(hooks))
	for _, hook := range hooks {
		if err := hook.Start(runCtx); err != nil {
			// Reverse-stop previously started hooks.
			for i := len(started) - 1; i >= 0; i-- {
				_ = started[i].Stop()
			}
			cancel()
			n.mu.Lock()
			n.started = false
			n.cancel = nil
			n.mu.Unlock()
			return fmt.Errorf("minerva: start hook: %w", err)
		}
		started = append(started, hook)
	}
	n.mu.Lock()
	n.startedHooks = started
	n.mu.Unlock()

	log.Printf("minerva: node started (peerID=%s, app=%s, relays=%d, maxPeers=%d, discoverers=%d, hooks=%d)",
		n.peerID.Short(), n.config.AppID, len(n.config.BootstrapRelays), n.config.MaxPeers,
		len(discoverers), len(hooks))
	return nil
}

// runDiscoveryLoop consumes peer addresses from the MultiDiscoverer and feeds
// them into the PeerManager. Runs until the context is cancelled.
func (n *Node) runDiscoveryLoop(ctx context.Context, disc *discovery.MultiDiscoverer, done chan<- struct{}) {
	defer close(done)
	ch := disc.Discover(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case pa, ok := <-ch:
			if !ok {
				return
			}
			n.ingestDiscoveredPeer(pa)
		}
	}
}

// ingestDiscoveredPeer promotes a discovered address into the PeerManager
// (or updates an existing record). Peers are added in the Discovered state.
func (n *Node) ingestDiscoveredPeer(pa discovery.PeerAddress) {
	peerID := string(pa.PeerID)
	if peerID == "" || peerID == string(n.peerID) {
		return
	}
	existing := n.peerManager.Get(peerID)
	if existing != nil {
		existing.Addresses = mergeAddresses(existing.Addresses, pa.Addresses)
		return
	}
	peer := &Peer{
		ID:        peerID,
		PublicKey: pa.Pubkey,
		State:     PeerStateDiscovered,
		Addresses: pa.Addresses,
	}
	n.peerManager.Add(peer)
}

// Stop gracefully shuts down the node — stops hooks in reverse, cancels
// discovery, stops the Whisper engine if owned, and closes persistence.
func (n *Node) Stop() error {
	n.mu.Lock()
	if !n.started {
		n.mu.Unlock()
		return ErrNotStarted
	}
	hooks := n.startedHooks
	n.startedHooks = nil
	cancel := n.cancel
	discoveryDone := n.discoveryDone
	engine := n.whisperEngine
	ownsEngine := n.ownsEngine
	store := n.persistence
	// Drain per-session accept-loop cancels under the lock so we don't
	// race a concurrent RegisterSession.
	sessionCancels := n.sessionCancels
	n.sessionCancels = nil
	n.started = false
	n.cancel = nil
	n.mu.Unlock()

	// Cancel every per-session accept-loop so their goroutines exit
	// before we try to Wait below.
	for _, c := range sessionCancels {
		if c != nil {
			c()
		}
	}
	// Bounded wait so a handler that ignores ctx cancellation cannot
	// hang the whole shutdown path forever. We still cancel everything
	// above; this timeout just caps the join window.
	loopsDone := make(chan struct{})
	go func() {
		n.sessionLoops.Wait()
		close(loopsDone)
	}()
	select {
	case <-loopsDone:
		// clean drain
	case <-time.After(stopTimeout):
		log.Printf("minerva: Stop exceeded %s waiting for accept-loop / handler drain; continuing shutdown", stopTimeout)
	}

	var firstErr error

	// Stop hooks in reverse (e.g. gossip SyncManager before anything else).
	for i := len(hooks) - 1; i >= 0; i-- {
		if err := hooks[i].Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("minerva: stop hook: %w", err)
		}
	}

	// Cancel discovery and wait for the loop to drain.
	if cancel != nil {
		cancel()
	}
	if discoveryDone != nil {
		<-discoveryDone
	}

	// Stop Whisper engine only if the Node owns it.
	if engine != nil && ownsEngine {
		engine.Stop()
	}

	// Flush/close persistence last so in-flight hook writes are captured.
	if store != nil {
		if err := store.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("minerva: close persistence: %w", err)
		}
	}

	log.Println("minerva: node stopped")
	return firstErr
}

// Peers returns the PeerManager for inspecting connected peers.
func (n *Node) Peers() *PeerManager {
	return n.peerManager
}

// Store returns the CRDT store for reading/writing shared state.
func (n *Node) Store() *Store {
	return n.store
}

// Events returns the EventBus for subscribing to node events.
func (n *Node) Events() *EventBus {
	return n.eventBus
}

// OnPeerConnect is a convenience that delegates to the EventBus.
func (n *Node) OnPeerConnect(handler func(Peer)) {
	n.eventBus.OnPeerConnect(handler)
}

// OnPeerDisconnect is a convenience that delegates to the EventBus.
func (n *Node) OnPeerDisconnect(handler func(peerID string)) {
	n.eventBus.OnPeerDisconnect(handler)
}

// OnStateChange is a convenience that delegates to the EventBus.
func (n *Node) OnStateChange(collection string, handler func(key string, value []byte)) {
	n.eventBus.OnStateChange(collection, handler)
}

// Started reports whether the node is currently running.
func (n *Node) Started() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.started
}

// PeerID returns the node's identity-derived peer ID.
func (n *Node) PeerID() identity.PeerID {
	return n.peerID
}

// Identity returns the node's Ed25519 keypair.
func (n *Node) Identity() *identity.Keypair {
	return n.identity
}

// Broadcast publishes data to a Whisper topic. Requires a whisper engine to be wired.
func (n *Node) Broadcast(topic string, data []byte) error {
	n.mu.RLock()
	engine := n.whisperEngine
	started := n.started
	n.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	if engine == nil {
		return ErrNotStarted
	}
	return engine.Publish(topic, data)
}

// StreamConfig configures a named application stream to a peer.
type StreamConfig struct {
	// Name is the application-level channel name (e.g. "chat", "file-transfer").
	Name string
	// StreamID is the Aether stream identifier (>= 100 for application streams).
	StreamID uint64
	// Reliability configures the delivery guarantee.
	Reliability aether.Reliability
}

// OpenStreamTo opens a named application stream to a specific peer by peer ID.
// Returns ErrPeerNotFound if no active Aether session exists for that peer.
func (n *Node) OpenStreamTo(ctx context.Context, peerID string, config StreamConfig) (*Stream, error) {
	n.mu.RLock()
	started := n.started
	session := n.sessions[peerID]
	n.mu.RUnlock()
	if !started {
		return nil, ErrNotStarted
	}
	if session == nil {
		return nil, ErrPeerNotFound
	}

	streamID := config.StreamID
	if streamID == 0 {
		streamID = 100
	}
	reliability := config.Reliability
	if reliability == 0 {
		reliability = aether.ReliableOrdered
	}

	raw, err := session.OpenStream(ctx, aether.StreamConfig{
		StreamID:    streamID,
		Reliability: reliability,
		Priority:    128,
	})
	if err != nil {
		return nil, fmt.Errorf("minerva: open stream to %s: %w", peerID, err)
	}

	return NewStream(config.Name, peerID, raw), nil
}

// SetWhisperEngine wires a Whisper engine for broadcast. Called during setup.
// By default the Node does NOT take ownership — the caller is responsible for
// stopping the engine. Use SetWhisperEngineOwned to transfer ownership.
func (n *Node) SetWhisperEngine(engine *whisper.Engine) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.whisperEngine = engine
	n.ownsEngine = false
}

// SetWhisperEngineOwned wires a Whisper engine and transfers ownership so that
// Node.Stop() calls engine.Stop().
func (n *Node) SetWhisperEngineOwned(engine *whisper.Engine) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.whisperEngine = engine
	n.ownsEngine = true
}

// WhisperEngine returns the wired Whisper engine (may be nil).
func (n *Node) WhisperEngine() *whisper.Engine {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.whisperEngine
}

// RegisterSession registers an active Aether session for a peer and
// starts a dedicated accept-loop goroutine that dispatches inbound
// streams to registered handlers (see OnStream). The loop runs until
// the session's AcceptStream returns an error (peer disconnect / close)
// or UnregisterSession / Stop cancels it.
//
// Registering a session twice for the same peer replaces the first and
// cancels its accept-loop.
//
// Node MUST be started (see Start) before RegisterSession is called —
// calling it pre-Start returns ErrNotStarted. This avoids a leak window
// where Start would overwrite the sessions / sessionCancels maps (losing
// the pre-Start registration) while the accept-loop goroutine keeps
// running against the orphaned state.
func (n *Node) RegisterSession(peerID string, session aether.Session) error {
	n.mu.Lock()
	if !n.started {
		n.mu.Unlock()
		return ErrNotStarted
	}
	// If we already have a loop for this peer, cancel it before replacing.
	if prev, ok := n.sessionCancels[peerID]; ok && prev != nil {
		prev()
		delete(n.sessionCancels, peerID)
	}
	if n.sessions == nil {
		n.sessions = make(map[string]aether.Session)
	}
	if n.sessionCancels == nil {
		n.sessionCancels = make(map[string]context.CancelFunc)
	}
	n.sessions[peerID] = session

	// Accept-loop ctx is a standalone cancellable derived from Background
	// — we track the cancel in sessionCancels so Stop() / UnregisterSession
	// can tear it down explicitly without depending on the node's
	// run-context lifetime.
	loopCtx, cancel := context.WithCancel(context.Background())
	n.sessionCancels[peerID] = cancel
	n.sessionLoops.Add(1)
	n.mu.Unlock()

	go n.runSessionAcceptLoop(loopCtx, peerID, session)
	return nil
}

// UnregisterSession removes a peer's Aether session and cancels its
// accept-loop (if any). Safe to call for a peer that was never registered.
func (n *Node) UnregisterSession(peerID string) {
	n.mu.Lock()
	delete(n.sessions, peerID)
	cancel, ok := n.sessionCancels[peerID]
	if ok {
		delete(n.sessionCancels, peerID)
	}
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// runSessionAcceptLoop drains inbound streams from one session and
// dispatches each to the handler registered for its StreamID. Streams
// with no registered handler are closed immediately so the peer is not
// kept waiting.
//
// A panic in raw.Config(), NewStream, or any of the pre-dispatch
// bookkeeping is recovered so one bad inbound stream cannot terminate
// the whole accept loop (which would silently kill dispatch for every
// future stream on this peer's session).
func (n *Node) runSessionAcceptLoop(ctx context.Context, peerID string, session aether.Session) {
	defer n.sessionLoops.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("minerva: accept loop panicked for peer=%s: %v\n%s", peerID, r, debug.Stack())
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if session.IsClosed() {
			return
		}
		raw, err := session.AcceptStream(ctx)
		if err != nil {
			// Peer closed the session, ctx cancelled, or a transient
			// error. The session is already marked closed in the
			// first two cases; we exit in all cases because once
			// AcceptStream has returned an error the session can no
			// longer produce new streams.
			return
		}
		streamID := raw.Config().StreamID

		n.streamMu.RLock()
		handler := n.streamHandlers[streamID]
		n.streamMu.RUnlock()

		if handler == nil {
			// No registered handler — close the stream so the peer
			// observes a prompt teardown rather than a silent hang.
			log.Printf("minerva: no handler for inbound stream id=%d peer=%s — closing", streamID, peerID)
			_ = raw.Close()
			continue
		}

		// Wrap the raw aether.Stream in minerva's *Stream for the
		// handler so we surface the same surface consumers already
		// use (plutus/blob.AetherStream, etc.).
		wrapped := NewStream(fmt.Sprintf("inbound:%d", streamID), peerID, raw)
		n.sessionLoops.Add(1)
		go func(pid string, sid uint64, s *Stream, h StreamHandler) {
			defer n.sessionLoops.Done()
			defer func() {
				if err := s.Close(); err != nil {
					log.Printf("minerva: close inbound stream peer=%s: %v", pid, err)
				}
			}()
			// A panicking handler MUST NOT take down the accept
			// loop — we log + stack trace here and let the
			// accept loop keep dispatching subsequent streams.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("minerva: stream handler panicked for streamID=%d peer=%s: %v\n%s",
						sid, pid, r, debug.Stack())
				}
			}()
			if err := h.HandleStream(ctx, identity.PeerID(pid), s); err != nil {
				log.Printf("minerva: stream handler peer=%s stream=%d: %v", pid, sid, err)
			}
		}(peerID, streamID, wrapped, handler)
	}
}

// HandlerForStream returns the handler currently registered for the
// given Aether StreamID, or nil. Primarily useful for tests that want
// to drive a handler directly without going through a live session.
func (n *Node) HandlerForStream(streamID uint64) StreamHandler {
	n.streamMu.RLock()
	defer n.streamMu.RUnlock()
	return n.streamHandlers[streamID]
}

// OnStream registers a handler for inbound streams with the given Aether
// StreamID. Passing a nil handler removes the registration.
//
// Registering a handler while one already exists replaces the previous
// handler and logs a warning — in-flight stream goroutines continue to
// use the previously-captured reference until they return.
//
// Thread-safe; callable before or after Start.
func (n *Node) OnStream(streamID uint64, handler StreamHandler) {
	n.streamMu.Lock()
	defer n.streamMu.Unlock()
	if n.streamHandlers == nil {
		n.streamHandlers = make(map[uint64]StreamHandler)
	}
	if handler == nil {
		delete(n.streamHandlers, streamID)
		return
	}
	if _, exists := n.streamHandlers[streamID]; exists {
		log.Printf("minerva: OnStream replacing handler for stream id=%d", streamID)
	}
	n.streamHandlers[streamID] = handler
}

// Persistence returns the backing persistence store.
func (n *Node) Persistence() persistence.Store {
	return n.persistence
}

// --- helpers -------------------------------------------------------------

// parseListenPort extracts the port from a "host:port" listen address. Returns
// 0 if the address is empty or unparseable (mDNS will still function with
// port=0 for pure advertisement/discovery).
func parseListenPort(listen string) int {
	if listen == "" {
		return 0
	}
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return p
}

// mergeAddresses unions two address lists preserving order of the first.
func mergeAddresses(existing, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]string, 0, len(existing)+len(incoming))
	for _, a := range existing {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, a := range incoming {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

// nowUnix returns the current unix timestamp. Wrapped for testability.
var nowUnix = func() int64 { return time.Now().Unix() }
