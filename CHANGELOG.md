# Changelog

## [0.1.0](https://github.com/bbmumford/minerva/compare/v0.0.1...v0.1.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* a device-key certificate signs each capability with its length under a domain tag, and verifies only within its validity window

### Bug Fixes

* a device-key certificate signs each capability with its length under a domain tag, and verifies only within its validity window ([1cceafa](https://github.com/bbmumford/minerva/commit/1cceafadef77fc4051ab525a39a07c2a6fe250b8))
* crdt's HLC takes its stamps from swarm's HLC, so a stamp after a full counter is greater than the one before ([04ee212](https://github.com/bbmumford/minerva/commit/04ee212438ff40b5b88acb0bb19ec05fa58298c2))
* go.mod requires the released aether and ledger and keeps no replace of a sibling directory, so a checkout of this repository alone builds ([502861f](https://github.com/bbmumford/minerva/commit/502861fb2a558c07b9e0c2adb0aa8a32227dd650))
* go.mod requires whisper v0.0.19, so the module builds read-only ([06d1979](https://github.com/bbmumford/minerva/commit/06d1979da78047e20e218292a739020ddf04e265))
* gossip.proto names this module's go_package and gossip.pb.go is regenerated, so loading the gossip package no longer panics ([6ae3d3c](https://github.com/bbmumford/minerva/commit/6ae3d3c623a511c6e807c627960e32c86a4325f3))
* **gossip:** the gossip contract's field names are lowerCamelCase ([2903ee9](https://github.com/bbmumford/minerva/commit/2903ee99a26021022c5487e24968bc1fdce67c72))
* SyncManager registers no CRDT collection as a StatefulMerge topic while its store holds no records, and the store refuses what it cannot merge ([aa0a2bb](https://github.com/bbmumford/minerva/commit/aa0a2bbfa3be842639b07164d14a00a651d67f53))
* the js/wasm build starts the browser's own discoverers ([a72e8cc](https://github.com/bbmumford/minerva/commit/a72e8cccca01424f4acda78971c54aabc72eaef0))
* the passkey delegate holds an ASAuthorization, the CRDT state store answers whisper's current StateStore, and the module carries a go.sum ([53bcfa3](https://github.com/bbmumford/minerva/commit/53bcfa30369de54e40dcbf7f6ed2b0e4d9916580))
