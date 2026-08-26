# Minerva — Decentralised P2P Web Platform

*High-Performance WebAssembly Applications Running at the Edge*

```
go get github.com/bbmumford/minerva
```

**Related:** [Aether](https://github.com/ORBTR/aether) (wire protocol) · [Ledger](https://github.com/bbmumford/ledger) (state directory) · [Mercury](https://github.com/bbmumford/mercury) (marketplace)

---

## API Docs

Generated API reference (pkgsite) for each tagged release is published to GitHub Pages:

- Latest: https://aether-protocol.github.io/minerva/github.com/aether-protocol/minerva/
- Published by `.github/workflows/docs.yml` on every `v*` tag.

---

## Executive Summary

**Minerva** is a next-generation decentralised web platform where applications compile to WebAssembly (WASM) and execute entirely within users' browsers. Unlike traditional web apps that rely on central servers for computation, Minerva apps run as local, high-performance nodes in a peer-to-peer network. Content is content-addressed and distributed via IPFS or similar protocols, allowing anyone to host application code from any web server while all users access the same shared state.

**Core Innovation:** *Serverless without servers.* The web server becomes a dumb pipe for static WASM binaries. The browser becomes the application runtime. The network becomes the database.

---

## 1. The Problem with Current Decentralised Platforms

| Platform | Limitation |
|----------|-----------|
| **OpenBazaar** | Requires native client installation; Electron-based; centralization creep |
| **IPFS Apps** | Static content only; no shared mutable state between users |
| **Holochain** | Requires native runtime installation; high barrier to entry |
| **Secure Scuttlebutt** | Limited to social use cases; JavaScript performance constraints |
| **Traditional Web3 dApps** | Depend on blockchain RPC nodes; gas fees; scalability limits |

**Minerva eliminates these trade-offs** by combining WebAssembly's near-native performance with browser-native P2P networking, creating truly serverless applications that require zero installation and zero blockchain fees.

---

## 2. Architecture Overview

```
+-------------------------------------------------------------+
|                    USER BROWSER LAYER                        |
|  +-------------+  +-------------+  +---------------------+  |
|  | Minerva   |  |  WebAssembly|  |   P2P Networking    |  |
|  |   Runtime   |  |    VM       |  |  (Aether Protocol)  |  |
|  |  (Go/Rust)  |  |  (Sandbox)  |  |                     |  |
|  +------+------+  +------+------+  +----------+----------+  |
|         |                |                    |              |
|         +----------------+--------------------+              |
|                      Local-First Execution                   |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 CONTENT DISTRIBUTION LAYER                   |
|    Any Static Host (GitHub Pages, Neocities, Self-Hosted)   |
|         v                v                v                  |
|    [WASM Binary]    [WASM Binary]    [WASM Binary]          |
|    (Content-ID:     (Content-ID:     (Content-ID:           |
|     QmXyz123...)      QmAbc456...)      QmDef789...)        |
|                                                              |
|         All identical via content-addressing (IPFS)         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  STATE SYNCHRONIZATION LAYER                 |
|                                                              |
|   +----------+    +----------+    +----------+              |
|   |  User A  |<-->|  User B  |<-->|  User C  |              |
|   |  (Node)  |    |  (Node)  |    |  (Node)  |              |
|   +----+-----+    +----+-----+    +----+-----+              |
|        |               |               |                    |
|        +---------------+---------------+                    |
|                        |                                    |
|              +---------+---------+                          |
|              |   CRDT / Gossip   |                          |
|              |   Protocol        |                          |
|              | (Shared Mutable   |                          |
|              |      State)       |                          |
|              +-------------------+                          |
+-------------------------------------------------------------+
```

**Transport Layer:** All peer-to-peer communication uses the **Aether protocol** -- a custom wire protocol providing stream multiplexing, reliability, congestion control, and encryption. Aether replaces WebRTC/libp2p with a purpose-built transport that supports Noise-UDP, WebSocket, QUIC, and WASM targets.

**Platform Layer:** Minerva builds on Aether to provide identity, CRDTs, persistence, peer discovery, and a developer SDK. Applications only interact with Minerva -- Aether is an internal transport detail.

---

## 3. Technical Stack

### 3.1 Runtime Language: Go -> WebAssembly

While Rust is the conventional choice for WASM, **Go offers unique advantages** for Minerva:

| Feature | Benefit |
|---------|---------|
| **TinyGo Compiler** | Produces small WASM binaries (~10-100KB vs Go's standard 2MB+) |
| **Goroutines in WASM** | Lightweight concurrency model maps well to browser event loops |
| **Standard Library** | Rich networking, crypto, and encoding packages compile to WASM |
| **Developer Experience** | Simple syntax, fast compilation, excellent debugging |
| **Existing Transport** | Aether protocol already implemented in Go, compiles to WASM |

**Alternative:** Rust with `wasm-bindgen` for maximum performance-critical paths.

### 3.2 Core Components

#### Minerva Runtime (Browser-Based)

```go
// Conceptual Go/WASM runtime structure
package minerva

type Node struct {
    Identity    *CryptoIdentity      // Self-sovereign ED25519 keypair
    Network     *AetherTransport     // Aether streams (WS in browser, Noise-UDP/WS/QUIC native)
    Storage     *LocalStore          // IndexedDB wrapper
    Consensus   *CRDTManager         // State synchronization engine
    App         *WASMModule          // User application logic
}

func (n *Node) Initialize(config NodeConfig) error {
    // 1. Generate/load cryptographic identity
    // 2. Establish Aether connections via relay bootstrap
    // 3. Discover peers via gossip + PEX
    // 4. Load application WASM module
    // 5. Sync state with connected peers
}
```

#### Application Structure

Minerva applications are **WASM modules** with specific exported functions:

```go
// Example: Decentralised marketplace app (Mercury)
package main

import "github.com/minerva/sdk"

//export initialize
func initialize() {
    // Called on app load
    sdk.RegisterHandler("listing:create", handleNewListing)
    sdk.RegisterHandler("listing:purchase", handlePurchase)
}

//export handleStateUpdate
func handleStateUpdate(delta []byte) {
    // Process CRDT state delta from peers
    // Update local UI via DOM bindings
}

//export queryLocalState
func queryLocalState(query []byte) []byte {
    // Respond to UI queries for local data
    return executeQuery(query)
}
```

#### State Synchronization: CRDTs over Gossip

Instead of blockchain or central servers, Minerva uses **Conflict-free Replicated Data Types** for shared mutable state:

- **Operation-based CRDTs**: Small, efficient updates propagate via gossip
- **Delta-state CRDTs**: Bandwidth-efficient synchronization for large datasets
- **Causal consistency**: Preserves happens-before relationships without global consensus

**Example:** A marketplace listing is a CRDT map. When User A updates the price, the delta propagates to connected peers via Aether gossip streams. If User B updates simultaneously, the CRDT merge function resolves the conflict deterministically.

---

## 4. The "Host From Anywhere" Model

### Content Addressing

Applications are identified by **Content Identifiers (CIDs)**, not URLs:

```
Traditional:  https://amazon.com/marketplace
Minerva:    minerva://QmXyz123.../marketplace
              (resolves via IPFS/any gateway)
```

### Hosting Flexibility

| Host Type | Role | Example |
|-----------|------|---------|
| **IPFS Node** | Primary distribution | `ipfs.io/ipfs/QmXyz...` |
| **Static Web Host** | Fallback/Caching | GitHub Pages, Netlify |
| **Self-Hosted** | Personal control | Raspberry Pi + Nginx |
| **Aether Relay** | Initial peer discovery | Any WS relay (stateless byte proxy) |

**Key Insight:** Because the WASM binary is content-addressed, it doesn't matter which server delivers it. The browser verifies the hash before execution. A malicious host cannot serve modified code without detection.

---

## 5. Security Model

### WebAssembly Sandbox

- **Memory isolation**: Apps cannot access host memory outside their linear memory
- **Capability-based**: No filesystem, network, or DOM access without explicit imports
- **Deterministic execution**: Same input always produces same output

### Identity & Trust

```go
type Identity struct {
    PublicKey   [32]byte        // ED25519 verification key
    Petname     string          // User-chosen display name
    Reputation  *CRDTCounter    // Decentralized reputation score
    Capabilities []Capability   // What this identity is allowed to do
}
```

- **Self-sovereign**: Users generate keys locally; no registration servers
- **Web of Trust**: Reputation propagates via social graph
- **Capability Tokens**: Fine-grained permissions for app-specific actions

---

## 6. Performance Characteristics

| Metric | Traditional Web App | Minerva (Go/WASM) | Native App |
|--------|---------------------|----------------------|------------|
| **Cold Start** | 1-3s (network dependent) | 0.5-1s (WASM compile) | Instant |
| **Runtime Speed** | JavaScript interpreted/JIT | Near-native (WASM) | Native |
| **Memory Usage** | High (V8 overhead) | Low (linear memory) | Low |
| **Network Resilience** | None (server required) | Full P2P operation | N/A |
| **Scalability** | Server-bottlenecked | User-device scalable | N/A |

**The "Minerva Effect":** As more users join a Minerva application, performance improves. Popular content is cached by more peers, reducing load times. Computation is parallelized across user devices.

---

## 7. Use Cases

### 7.1 Decentralised Marketplace (Mercury)

Mercury is a commerce protocol built on Minerva. It is one application -- the marketplace.

- **Listings**: CRDT documents replicated across seller and interested buyers
- **Escrow**: Programmatic escrow adapters per chain (no blockchain dependency for Minerva itself)
- **Reputation**: Local-first ratings aggregated via CRDT counters
- **Messaging**: Ephemeral P2P chat between buyer/seller via Aether streams

### 7.2 Collaborative Document Editing

- **Real-time sync**: CRDT text editor (like Yjs or Automerge)
- **Offline-first**: Edit locally, sync when peers are available
- **Version history**: Append-only log of all changes
- **Access control**: Capability-based sharing (grant read/write per document)

### 7.3 Social Network

- **Feeds**: Append-only logs per user
- **Media**: IPFS-stored images/video referenced by CID
- **Interactions**: Likes/comments as CRDT counters
- **Moderation**: Client-side filtering based on web-of-trust

### 7.4 Decentralised Game Worlds

- **Game State**: CRDT world state synchronized between players
- **Assets**: WASM-compiled game logic + IPFS-stored assets
- **Persistence**: World state persisted via user pinning or Filecoin

---

## 8. Comparison with Existing Solutions

| Feature | Minerva | Holochain | SSB | IPFS+JS | OpenBazaar |
|---------|-----------|-----------|-----|---------|------------|
| **Browser-Native** | Yes | No (native only) | Limited (JS) | Yes | No (native only) |
| **Installation Required** | No | Yes | Optional | No | Yes |
| **WASM Performance** | Yes | Yes | No | No | No |
| **Mutable State** | CRDTs | DHT | Logs | Static | Centralized |
| **True P2P** | Aether | libp2p | Gossip | Gateway | libp2p |
| **Language Options** | Go/Rust | Rust | JS | Any | Go/Python |

---

## 9. Implementation Roadmap

### Phase 1: Aether Transport + Minerva Core Runtime (Months 1-6)
- [ ] Aether WASM module (transport layer compiled to WebAssembly)
- [ ] Aether WebSocket adapter for browser-to-relay connections
- [ ] Minerva CRDT library (LWW-Map, OR-Set, G-Counter, PN-Counter)
- [ ] Minerva IndexedDB storage layer for persistence
- [ ] Minerva identity and cryptography primitives (Ed25519)
- [ ] Minerva peer discovery (gossip, PEX, relay bootstrap)

### Phase 2: Developer SDK (Months 6-12)
- [ ] Minerva SDK for building decentralised apps
- [ ] DOM binding utilities (WASM-to-JS interop)
- [ ] State management abstractions (CRDT wrappers)
- [ ] CLI tool for building and deploying to IPFS
- [ ] Example applications (chat, todo list, Mercury marketplace)

### Phase 3: Ecosystem (Months 12-18)
- [ ] Reputation system implementation
- [ ] Incentivised storage integration (Filecoin/Storj)
- [ ] Mobile browser support (Aether handles NAT via relay)
- [ ] Application registry/discovery protocol
- [ ] Governance framework for protocol evolution

---

## 10. Technical Challenges & Mitigations

| Challenge | Mitigation Strategy |
|-----------|---------------------|
| **NAT Traversal** | Aether handles NAT via Noise-UDP + relay; browsers connect through WS relays |
| **Browser Storage Limits** | Implement tiered storage (hot: IndexedDB, warm: IPFS, cold: Filecoin) |
| **WASM Binary Size** | TinyGo compilation; aggressive tree-shaking; streaming compilation |
| **Initial Peer Discovery** | Bootstrap via DNS TXT records; fallback to Aether relays |
| **Malicious Code in WASM** | Sandboxing + capability model; community auditing of popular apps |
| **State Bloat** | CRDT garbage collection; archival to cold storage; sharding |

---

## 11. Vision Statement

> *"Minerva returns the web to its original vision: a decentralised network of peers where anyone can publish, anyone can connect, and no central authority controls the flow of information. By compiling to WebAssembly and running at the edge -- in users' browsers -- we eliminate the distinction between client and server, between user and host. The result is a web that is faster, more resilient, and truly owned by its users."*

---

## 12. Call to Action

**For Developers:**
- Minerva is ideal for Go developers interested in P2P systems and WebAssembly
- Rust developers can contribute performance-critical runtime components
- JavaScript/TypeScript developers can build UI layers that interface with WASM cores

**For Users:**
- Experience applications that work offline, load instantly, and respect privacy
- Own your data and identity without trusting centralised platforms
- Host applications from anywhere -- even a GitHub Pages site

**For the Ecosystem:**
- Minerva is not a company; it's an open protocol
- No tokens, no ICO, no central foundation
- Governance via the applications built on top of it

---

## Appendix A: Example Application Code

**Decentralised Todo List (Go/WASM on Minerva):**

```go
package main

import (
    "github.com/minerva/sdk"
    "github.com/minerva/crdt"
)

type Todo struct {
    ID      string
    Text    string
    Done    bool
    Owner   sdk.Identity
}

var (
    store   *crdt.LWWMap[string, Todo]
    node    *sdk.Node
)

func main() {
    // Initialize Minerva node
    node = sdk.NewNode()

    // Create CRDT map for todos
    store = crdt.NewLWWMap[string, Todo]()

    // Register sync handler
    node.OnPeerConnect(func(peer sdk.Peer) {
        // Send current state delta to new peer
        delta := store.Delta()
        peer.Send("todos:sync", delta)
    })

    node.OnMessage("todos:sync", func(from sdk.Peer, delta []byte) {
        // Merge remote state into local
        store.Merge(delta)
        updateUI()
    })

    // Start node (connects via Aether transport)
    node.Start()
}

//export addTodo
func addTodo(text string) {
    todo := Todo{
        ID:    node.NewID(),
        Text:  text,
        Done:  false,
        Owner: node.Identity(),
    }
    store.Set(todo.ID, todo)
    broadcastDelta()
}

//export toggleTodo
func toggleTodo(id string) {
    if todo, ok := store.Get(id); ok {
        todo.Done = !todo.Done
        store.Set(id, todo)
        broadcastDelta()
    }
}

func broadcastDelta() {
    delta := store.Delta()
    node.Broadcast("todos:sync", delta)
}

func updateUI() {
    // Called by SDK when state changes
    // Triggers JS callback to update DOM
    sdk.JS.Call("updateTodoList", store.Values())
}
```

---

## Appendix B: Glossary

- **Aether**: Wire protocol providing stream multiplexing, reliability, and encryption
- **CID**: Content Identifier (IPFS hash)
- **CRDT**: Conflict-free Replicated Data Type
- **Minerva**: Decentralised P2P web platform (this project)
- **LWW**: Last-Write-Wins (CRDT variant)
- **Mercury**: Decentralised marketplace built on Minerva
- **NAT**: Network Address Translation (firewall traversal)
- **SSB**: Secure Scuttlebutt (decentralised social protocol)
- **TinyGo**: Go compiler for small binaries/WebAssembly
- **WASM**: WebAssembly (binary instruction format)

---

*Document Version: 2.0*
*Concept Date: April 2026*
*License: CC0 (Public Domain)*
