# Minerva Developer Guide

Build decentralised, peer-to-peer web applications with no servers.

---

## What Minerva Does

Minerva is a **headless state engine** that runs in the browser via WebAssembly. It handles:
- **CRDT state sync** — conflict-free data types that merge automatically across peers
- **Peer discovery** — find other users running the same app via gossip, DNS, or relay
- **Identity** — Ed25519 keypairs, mnemonic backup, device delegation
- **Persistence** — IndexedDB (browser) or SQLite (native) — survives page refresh
- **Encryption** — end-to-end via Aether wire protocol

**You build the UI.** Minerva doesn't render anything — it's a state engine your frontend talks to.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  YOUR FRONTEND                          │
│  (HTML/CSS + any JS framework)          │
│  React, Vue, Svelte, vanilla JS, etc.   │
└──────────────────┬──────────────────────┘
                   │ minerva.js API calls
┌──────────────────┴──────────────────────┐
│  minerva.js                           │
│  Developer-friendly JS wrapper          │
│  MinervaNode, CRDTCollection classes  │
└──────────────────┬──────────────────────┘
                   │ window.Minerva.* bridge
┌──────────────────┴──────────────────────┐
│  minerva.wasm                         │
│  Go compiled to WebAssembly             │
│  CRDTs • Gossip • Identity • Crypto     │
│  Aether transport • Whisper engine      │
└─────────────────────────────────────────┘
```

Your frontend is completely separate from the WASM. You can use any framework, any CSS library, any build tool. The WASM is a black box that syncs state.

---

## Quick Start

### 1. Install the CLI

```bash
go install github.com/aether-protocol/minerva/cmd/hos@latest
```

### 2. Create a New App

```bash
min init my-app
cd my-app
```

This creates:

```
my-app/
├── go.mod              # Go module (imports minerva SDK)
├── wasm/
│   └── main.go         # WASM entry point (registers your CRDT collections)
├── dist/               # Build output (created by `min build`)
├── index.html          # Your frontend (edit this)
└── README.md
```

### 3. Define Your State (Go)

Edit `wasm/main.go` — this is where you register your CRDT collections:

```go
//go:build js && wasm

package main

import (
    "fmt"
    "syscall/js"
    "github.com/aether-protocol/minerva/sdk"
)

func main() {
    // The Minerva JS bridge handles node creation and CRDT access.
    // Your Go code here can register custom handlers or extend the SDK.

    fmt.Println("[MY-APP] WASM loaded")
    select {} // keep alive
}
```

For most apps, you don't need to modify `main.go` — the JS bridge (`minerva.js`) handles everything. You only edit Go code if you need custom server-side logic in the WASM.

### 4. Build Your Frontend (HTML/JS)

Edit `index.html` — this is your app:

```html
<!DOCTYPE html>
<html>
<head>
    <title>My P2P App</title>
    <script src="wasm_exec.js"></script>
    <script src="minerva.js"></script>
</head>
<body>
    <div id="app">
        <h1>My P2P App</h1>
        <input id="input" placeholder="Add item...">
        <button onclick="addItem()">Add</button>
        <ul id="list"></ul>
        <p>Connected peers: <span id="peers">0</span></p>
    </div>

    <script>
    let node;
    let items;

    async function init() {
        // Initialize WASM
        await initMinerva('app.wasm');

        // Create a Minerva node
        node = new MinervaNode({
            appId: 'my-app',
            relays: ['wss://relay.example.com']
        });
        await node.start();

        // Create a CRDT collection (LWW-Map: last-write-wins key-value store)
        items = node.store.lwwMap('items');

        // Listen for remote changes
        items.onChange((key, value) => {
            renderItems();
        });

        // Listen for peer events
        node.onPeerConnect((peer) => {
            document.getElementById('peers').textContent = node.peers.length;
        });
        node.onPeerDisconnect((peerID) => {
            document.getElementById('peers').textContent = node.peers.length;
        });

        // Initial render
        renderItems();
    }

    async function addItem() {
        const input = document.getElementById('input');
        const id = crypto.randomUUID();
        await items.set(id, { title: input.value, done: false, createdAt: Date.now() });
        input.value = '';
        renderItems();
    }

    async function renderItems() {
        const all = await items.all();
        const list = document.getElementById('list');
        list.innerHTML = '';
        for (const [key, value] of all) {
            const li = document.createElement('li');
            li.textContent = value.title;
            list.appendChild(li);
        }
    }

    init();
    </script>
</body>
</html>
```

### 5. Build and Run

```bash
# Build WASM + copy runtime files to dist/
min build

# Start dev server with live reload
min dev
# → Open http://localhost:8080
```

### 6. Test P2P Sync

1. Open `http://localhost:8080` in two browser tabs
2. Add an item in Tab A
3. It appears in Tab B automatically (via gossip sync)

### 7. Publish

```bash
# Copy dist/ to a deployment directory + compute CID
min publish ./release/

# Verify a WASM binary's integrity
min verify release/app.wasm
```

Deploy the `release/` directory to any static host (GitHub Pages, Netlify, Vercel, IPFS, your own server). No backend required.

---

## CRDT Types

| Type | Use Case | Example |
|---|---|---|
| **LWW-Map** | Key-value store (last write wins) | Todo items, user profiles, settings |
| **LWW-Register** | Single value (last write wins) | Document title, room name |
| **OR-Set** | Set with add/remove (add wins on conflict) | Chat messages, tags, members |
| **G-Counter** | Grow-only counter | View counts, likes |
| **PN-Counter** | Increment/decrement counter | Inventory, vote tallies |
| **Sequence** | Ordered text (collaborative editing) | Documents, code, notes |

### Usage Examples

```javascript
// Key-value store
const settings = node.store.lwwMap('settings');
await settings.set('theme', 'dark');
const theme = await settings.get('theme'); // 'dark'

// Set (add/remove)
const tags = node.store.orSet('tags');
await tags.set('important', true);   // add
await tags.delete('important');       // remove

// Counter
const likes = node.store.gCounter('likes');
await likes.set('increment', 1);     // increment by 1
const count = await likes.get('value'); // total across all peers

// Collaborative text
const doc = node.store.sequence('document');
await doc.set('insert', { pos: 0, char: 'H' });
```

---

## App Isolation

Each app runs in its own isolated gossip network:

- **`appId`** scopes all gossip topics — `my-todo-app` never sees data from `my-chat-app`
- **Relay servers are shared** — the relay is a dumb byte pipe, it doesn't know what app is running
- **Identity is per-app** — each app gets its own keypair (or you can share one across apps)
- **Persistence is per-app** — IndexedDB databases are scoped by appId
- **Peers are per-app** — you only discover peers running the same app

This means:
- Your todo app doesn't relay data for someone else's chat app
- A vulnerability in one app can't access another app's data
- Each app is a self-contained P2P network

---

## CLI Reference

```
min — CLI toolchain for Minerva P2P WASM apps

Commands:
  min init <app-name>      Scaffold a new app (go.mod, wasm/, index.html)
  min build                Compile Go to WASM, copy runtime files to dist/
  min dev                  Build + serve on localhost:8080 with live reload
  min publish <dir>        Compute CID, copy dist/ to target directory
  min verify <path>        Print SHA-256 CID of a WASM file
  min help                 Show help
```

### `min init`

Creates a new app directory with:
- `go.mod` — Go module importing the Minerva SDK
- `wasm/main.go` — WASM entry point (minimal, extend as needed)
- `index.html` — HTML shell with WASM loading boilerplate
- `README.md` — Getting started instructions

### `min build`

1. Runs `GOOS=js GOARCH=wasm go build -o dist/app.wasm ./wasm/`
2. Copies `wasm_exec.js` (Go WASM runtime) to `dist/`
3. Copies `minerva.js` (SDK wrapper) to `dist/`
4. Prints binary size

### `min dev`

1. Runs `min build`
2. Starts HTTP server on `localhost:8080` serving `dist/`
3. Watches `.go` files every 2 seconds
4. Rebuilds WASM on change (refresh browser to pick up)

### `min publish`

1. Reads `dist/app.wasm`
2. Computes SHA-256 content hash (CID)
3. Copies all files from `dist/` to the target directory
4. Writes `app.wasm.cid` file for verification

### `min verify`

Reads a WASM file and prints its SHA-256 CID. Use to verify a downloaded binary matches the expected hash from the app's manifest.

---

## Using with Frontend Frameworks

Minerva works with any frontend framework. The WASM is loaded once, then your framework talks to it via `minerva.js`.

### React

```jsx
import { useEffect, useState } from 'react';

function App() {
    const [node, setNode] = useState(null);
    const [items, setItems] = useState(new Map());

    useEffect(() => {
        async function init() {
            await initMinerva('/app.wasm');
            const n = new MinervaNode({ appId: 'react-app', relays: ['wss://...'] });
            await n.start();
            setNode(n);

            const collection = n.store.lwwMap('items');
            collection.onChange(() => {
                collection.all().then(setItems);
            });
            collection.all().then(setItems);
        }
        init();
        return () => node?.stop();
    }, []);

    return <div>{[...items].map(([k, v]) => <div key={k}>{v.title}</div>)}</div>;
}
```

### Vue

```vue
<script setup>
import { ref, onMounted, onUnmounted } from 'vue';

const items = ref(new Map());
let node;

onMounted(async () => {
    await initMinerva('/app.wasm');
    node = new MinervaNode({ appId: 'vue-app', relays: ['wss://...'] });
    await node.start();

    const collection = node.store.lwwMap('items');
    collection.onChange(() => collection.all().then(r => items.value = r));
    items.value = await collection.all();
});

onUnmounted(() => node?.stop());
</script>
```

### Svelte

```svelte
<script>
let items = new Map();
let node;

async function init() {
    await initMinerva('/app.wasm');
    node = new MinervaNode({ appId: 'svelte-app', relays: ['wss://...'] });
    await node.start();

    const collection = node.store.lwwMap('items');
    collection.onChange(async () => { items = await collection.all(); });
    items = await collection.all();
}

init();
</script>
```

---

## Relay Servers

Minerva apps need at least one relay server for peers to discover each other. A relay is a simple WebSocket server that forwards encrypted bytes — it cannot read your data.

You can run your own relay, use a public relay, or both:

```javascript
const node = new MinervaNode({
    appId: 'my-app',
    relays: [
        'wss://relay.my-company.com',    // your own
        'wss://relay.minerva.dev',      // public fallback
    ]
});
```

Once peers discover each other via the relay, they establish direct connections (WebRTC, Noise-UDP) and the relay is no longer in the data path.

---

## Identity & Security

- **Keypairs** are Ed25519, generated locally, private key never leaves the device
- **Mnemonic backup** — 24-word BIP39 phrase for key recovery
- **Device delegation** — master key can delegate to per-device keys with capabilities and expiry
- **Key revocation** — propagated via gossip, revoked keys are rejected at merge time
- **Web-of-trust** — transitive reputation scoring for community auditing
- **All CRDT deltas are signed** — peers reject unsigned or forged state changes
- **Transport encryption** — ChaCha20-Poly1305 per-frame AEAD via Aether

---

## Offline-First

Minerva apps work offline by default:

1. State is persisted to IndexedDB (browser) on every change
2. When you go offline, the app continues working with local state
3. When you come back online, gossip sync reconciles with peers
4. CRDT merge functions ensure conflicts are resolved automatically
5. No data loss, no merge conflicts, no manual intervention

---

## FAQ

**Q: Do I need Go to build Minerva apps?**
A: Yes — the WASM binary is compiled from Go. But you write your UI in HTML/JS with any framework.

**Q: How big is the WASM binary?**
A: ~3-4 MB (standard Go), ~500 KB (TinyGo). Gzipped: ~1 MB / ~200 KB.

**Q: Can I use TypeScript?**
A: Yes — for your frontend. The `minerva.js` wrapper has TypeScript-friendly APIs. Type definitions can be generated.

**Q: Is there a size limit on CRDT collections?**
A: Practical limit is browser memory. For large datasets, use sharding (H25) to partition across gossip topics.

**Q: Can peers communicate directly without a relay?**
A: Yes — once discovered, peers use WebRTC or Noise-UDP for direct connections. The relay is only for initial discovery and NAT traversal.

**Q: Is my data encrypted?**
A: Transport is always encrypted (Aether AEAD). Application-level E2E encryption is available via the identity package.
