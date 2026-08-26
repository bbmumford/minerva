# Minerva Chat — P2P Messenger

A peer-to-peer chat application demonstrating real-time messaging, presence tracking, and message history using Minerva CRDTs.

## Features

- Send and receive messages in real-time between browser tabs
- OR-Set CRDT for messages (messages can be deleted but not edited — conflict-free)
- LWW-Map CRDT for presence (last-seen timestamps per peer)
- Peer list sidebar with online/stale/offline indicators
- Message history survives page reload (persisted via IndexedDB when available)
- No central server for data — all state lives in the CRDT mesh

## Build

1. Build the WASM binary from the repository root:

```bash
cd ../../wasm
GOOS=js GOARCH=wasm go build -o minerva.wasm .
```

2. Copy the Go WASM support file (if not already present):

```bash
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" ../../wasm/wasm_exec.js
```

## Run

Serve the repository root with any static HTTP server. The HTML references the WASM files via relative paths (`../../wasm/`).

Using Python:

```bash
cd ../..
python3 -m http.server 8080
```

Using Node.js (`npx serve`):

```bash
cd ../..
npx serve -l 8080
```

Then open [http://localhost:8080/examples/chat/](http://localhost:8080/examples/chat/) in your browser.

## Test Sync

1. Open the chat in two browser tabs.
2. Send a message in tab A — it should appear in tab B within seconds.
3. The peer list should show both tabs as connected peers.
4. Refresh tab B — message history should be preserved.
5. Close tab B — its presence indicator in tab A should change to stale/offline after ~30 seconds.

## How It Works

- **Messages** are stored in an OR-Set CRDT collection named `messages`. Each message has a UUID key and JSON value: `{ from: peerID, text: string, timestamp: number }`.
- **Presence** is stored in an LWW-Map CRDT collection named `presence`. Each peer writes its own entry with a `lastSeen` timestamp every 15 seconds.
- The Minerva gossip protocol syncs both collections across all connected peers automatically.
- Messages use OR-Set semantics: if two peers send different messages concurrently, both are kept. Deletes are tracked via tombstones.
- Presence uses LWW-Map semantics: the latest heartbeat always wins, giving an accurate last-seen time.
