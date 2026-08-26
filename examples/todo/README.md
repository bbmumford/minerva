# Minerva Todo — Decentralised P2P Todo List

A complete peer-to-peer todo list that syncs in real-time between browser tabs using Minerva's LWW-Map CRDT.

## Features

- Create, toggle (done/undone), and delete todos
- Real-time sync between browser tabs via Minerva gossip
- Shows connected peer count
- No server required for data storage — all state lives in the CRDT mesh

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

Then open [http://localhost:8080/examples/todo/](http://localhost:8080/examples/todo/) in your browser.

## Test Sync

1. Open the todo app in two browser tabs.
2. Add a todo in tab A — it should appear in tab B within seconds.
3. Toggle a todo in tab B — it should update in tab A.
4. Close tab B, add a todo in tab A, reopen tab B — the new todo should sync.

## How It Works

- Each todo is stored as a key-value entry in an LWW-Map CRDT collection named `todos`.
- Keys are UUIDs, values are JSON: `{ title: string, done: boolean, createdAt: number }`.
- The Minerva gossip protocol automatically syncs state between all connected peers.
- Conflicts are resolved by last-write-wins semantics using hybrid logical clocks.
