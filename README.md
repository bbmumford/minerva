# minerva

minerva is a Go toolkit for peer-to-peer applications that keep shared state
without a central server. A node (`sdk`) joins peers it finds over DNS, mDNS,
peer exchange and relays, keeps named collections as CRDTs (counters,
last-writer-wins registers and maps, observed-remove sets, sequences), and
spreads their deltas over whisper gossip with per-peer hybrid-logical-clock
watermarks. Around that it supplies identities (key pairs, recovery
mnemonics, passkeys, delegated device keys and revocation), end-to-end
encrypted messaging, tiered persistence (memory, JSON files, IndexedDB), a
content cache, an application registry with signed manifests and audit
verdicts, governance proposals, and a loader that checks a WebAssembly module
against its content id.

```sh
go get github.com/bbmumford/minerva
```

## Use

```go
n := sdk.NewNode(
	sdk.WithAppID("my-app"),
	sdk.WithPersistencePath(dir),
)
if err := n.Start(ctx); err != nil {
	return err
}
defer n.Stop()

_ = n.Store().Register("todos", sdk.CRDTLWWMap)
peers := n.Peers()
```

`sdk.DefaultConfig` gives a `NodeConfig` (listen address, bootstrap relays and
peers, a DNS bootstrap domain, mDNS and peer exchange switches, the gossip
interval, the tombstone lifetime, the peer limit) for `WithConfig`.
`SetWhisperEngine` wires the whisper engine that carries the gossip, and
`OpenStreamTo` opens a stream to one peer over aether.

## Packages

| Path | What it holds |
|---|---|
| `sdk` | `NodeConfig` and the node: peers, the peer manager, stores and streams; the API an application starts from |
| `crdt` | the CRDTs (G-Counter, PN-Counter, LWW register and map, OR-Set, sequence), the hybrid logical clock and tombstone sweeping |
| `gossip` | CRDT delta sync over per-peer HLC watermarks, rumor push, sharding and topics |
| `identity` | key pairs and recovery mnemonics, passkeys for each platform, delegated device keys, revocation and trust |
| `messaging` | end-to-end encrypted conversations (ratchet, sender keys), attachments, receipts, presence, edits and deletes; see [its README](messaging/README.md) |
| `discovery` | peer discovery over DNS SRV, mDNS, peer exchange and relays |
| `relay` | the relay client, relay authentication and relay selection |
| `persistence` | the `Store` interface, a tiered store, and memory, file and IndexedDB backends |
| `cache` | an LRU cache for content-addressed blobs |
| `registry` | app manifests and community audit verdicts |
| `governance` | proposals and their lifecycle |
| `wasmcid` | the content-addressed WASM loader and its verification |
| `wasm`, `wasm/cmd` | the browser build and its JavaScript bridge |
| `cmd/min` | the `min` command: scaffold, develop and build a Minerva WASM application |
| `examples` | chat, editor, game and todo applications |
| `docs/GUIDE.md` | the developer guide |

The `examples` programs build for js/wasm and only load the packages; they do
not run an application yet.

## Dependencies

- `github.com/ORBTR/aether` (with `adapter`, `discovery`, `websocket`): the
  node's sessions and streams.
- `github.com/bbmumford/whisper`: the gossip engine (`gossip.CRDTStateStore`
  is its `StateStore`).
- `github.com/bbmumford/ledger`: `crdt` and `persistence` use its record and
  blob types.
- `golang.org/x/crypto`, `golang.org/x/sys` and `google.golang.org/protobuf`.
- `go.mod` replaces aether, whisper and ledger with the sibling checkouts
  `../aether`, `../whisper` and `../ledger`.

## Used by

Importers in the ORBTR estate:

- `github.com/bbmumford/mercury` (`sdk`, `crdt`, `identity`, `messaging`,
  `persistence/file`): the marketplace is built on a minerva node.

## Platforms and build

`identity` uses cgo for the platform passkey stores on macOS and Linux and has
a cgo-free build for every other case; `persistence/file` and the mDNS and DNS
discoverers build everywhere but js, and `persistence/indexeddb` and the DNS
over HTTPS discoverer only for js/wasm. The `sdk` package does not build for
js/wasm at this commit: `sdk/node.go` calls `discovery.NewMDNSDiscoverer` and
`discovery.NewDNSDiscoverer`, which have no js build. The module's `go`
directive is 1.25.0. Releases are cut by release-please from conventional
commits, and each tag publishes the API reference to the repository's GitHub
Pages site (`.github/workflows/docs.yml`).

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code. The developer guide is [docs/GUIDE.md](docs/GUIDE.md).
