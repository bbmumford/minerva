<!--
Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
Queries: licensing@hstles.com
-->

# Minerva Messaging

**The canonical messaging SDK for apps on the Minerva stack.**

> Related: [Aether](https://github.com/ORBTR/aether) (wire protocol) · [Whisper](https://github.com/aether-protocol/whisper) (topic transport) · [Ledger](https://github.com/bbmumford/ledger) (state directory) · [Mercury](https://github.com/bbmumford/mercury) (marketplace, first consumer)

---

## 1. Overview

`minerva/messaging` is the single, unified messaging front-door for every application built on the Minerva stack — Mercury today, future marketplace / collaboration / social apps tomorrow. It exposes one `Messenger` type that owns every chat-form capability the protocol supports: direct 1:1, group, broadcast, presence, receipts, attachments, edits, deletes, and store-and-forward relay.

There is no separate "direct chat" vs. "group chat" primitive. A `Conversation` with exactly 2 members **is** the direct-chat primitive — it simply upgrades its encryption to the double-ratchet path when both peers advertise `v1-ratchet`, otherwise it uses the same sender-key scheme a 3+ member Conversation uses. One type, one API, one authentication path, graceful downgrade when peers lack a capability.

---

## 2. Capability matrix

| #  | Capability                              | Type / method                                                          | Underlying primitive                                                | Status |
|----|-----------------------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------|--------|
| 1  | Direct 1-to-1 encrypted chat            | 2-member `Conversation`                                                | Double-ratchet (v1) or sender-key fallback                          | Yes    |
| 2  | Group messaging (N &ge; 3)              | N-member `Conversation`                                                | Sender-key encryption + ORSet membership                            | Yes    |
| 3  | Broadcast channels (1 &rarr; many)      | `Broadcast` (publisher) / `SubscribeBroadcast` (consumer)              | Signed records over Whisper `BroadcastOnly` topic                   | Yes    |
| 4  | Persistent history                      | `Conversation.History(since)`                                          | CRDT-backed `Sequence` + per-message log                            | Yes    |
| 5  | Signed sender auth                      | Every record signed Ed25519                                            | Author identity key                                                 | Yes    |
| 6  | Forward secrecy                         | Double-ratchet (2-member only)                                         | X25519 DH ratchet + HKDF chain + ChaCha20-Poly1305 AEAD             | Yes    |
| 7  | Message edit                            | `Conversation.Edit(msgID, newBody)`                                    | `EditOf` chain + `LatestVersion()` resolver                         | Yes    |
| 8  | Message delete (gossipable tombstone)   | `Conversation.Delete(msgID)`                                           | ORSet tombstone + `IsDeleted()`                                     | Yes    |
| 9  | File / blob attachments                 | `Messenger.Attach(ctx, content, mime, filename)`                       | Per-attachment ChaCha20 key + CID + `BlobStore`                     | Yes    |
| 10 | Typing indicators / presence            | `PresenceChannel`                                                      | LWW-Register with TTL heartbeat                                     | Yes    |
| 11 | Read receipts / delivery acks           | `ReceiptChannel`                                                       | Signed receipts in ORSet                                            | Yes    |
| 12 | Store-and-forward relay for offline     | `MessageRelay` via `Messenger.EnableRelay(role)`                       | Ring-buffer per recipient + Whisper replay on peer-online           | Yes    |
| 13 | OTR-style deniability                   | &mdash;                                                                | &mdash;                                                             | **No — out of scope; cost &gt; benefit for this protocol** |

---

## 3. Capability advertisement

Peers advertise which wire features they speak as part of their signed profile gossip. The Messenger keeps a per-peer map and consults it on every Send so it can pick the richest commonly-supported path and gracefully degrade otherwise.

### Capability constants

| Constant                  | Value              | What it gates |
|---------------------------|--------------------|---------------|
| `CapabilityV1Ratchet`     | `"v1-ratchet"`     | Double-ratchet in 2-member conversations. Absent &rArr; sender-key. |
| `CapabilityV2Attachments` | `"v2-attachments"` | `Attach` / `FetchAttachment` via the mesh `BlobStore`. |
| `CapabilityV3Relay`       | `"v3-relay"`       | Store-and-forward buffering for offline peers. |
| `CapabilityV4Edit`        | `"v4-edit"`        | `EditOf` resolution (reader-side opt-in). |
| `CapabilityV5Delete`      | `"v5-delete"`      | Tombstone honouring (reader-side opt-in). |
| `CapabilityV6Presence`    | `"v6-presence"`    | Presence / typing LWW channel. |
| `CapabilityV7Receipts`    | `"v7-receipts"`    | Signed read-receipt channel. |

### API

```go
// Tell the world we speak v1-ratchet (application layer re-emits in profile gossip).
m.AdvertiseCapability(messaging.CapabilityV1Ratchet, true)

// Record that a remote peer advertised a capability (called by the profile-ingest
// path when a signed profile arrives).
m.ObservePeerCapability(peerID, messaging.CapabilityV1Ratchet, true)

// Query before using the feature.
if m.SupportsFeature(peerID, messaging.CapabilityV1Ratchet) {
    m.BootstrapRatchet(peerID, peerIdentityPub, true /* initiator */)
}
```

### Automatic downgrade / upgrade

- **Downgrade** — `Conversation.Send` inspects `shouldUseRatchet(remoteMembers)` on every send. If the peer has not advertised `v1-ratchet`, or no ratchet session has been bootstrapped, encryption falls back to the sender-key path for that send. No half-ratcheted state is ever committed.
- **Upgrade** — When decrypting an inbound ciphertext tagged with `ciphertextVersionRatchet` (`0x01`), the Messenger calls `observeRatchetMessage(peer)` which flips that peer's `v1-ratchet` flag to `true`. A peer that silently drops the flag in its gossiped profile is still recognised once a single ratchet ciphertext lands.
- **3+ member conversations** always route through sender-key regardless of flags — the double-ratchet does not generalise cleanly to multi-party.

---

## 4. Getting started

```go
import (
    "context"
    "time"

    "github.com/aether-protocol/minerva/messaging"
)

// 1. Construct a Messenger.
m, err := messaging.NewMessenger(identity, transport)
if err != nil { /* ... */ }
defer m.Close()

// 2. Open a direct conversation (a 2-member group IS the direct primitive).
conv, err := m.OpenConversation(
    messaging.ChannelID("direct:"+peerIDHex),
    []messaging.PeerID{peerID},
)

// 3. Advertise ratchet capability + bootstrap if peer also has it.
m.AdvertiseCapability(messaging.CapabilityV1Ratchet, true)
if m.SupportsFeature(peerID, messaging.CapabilityV1Ratchet) {
    _, _ = m.BootstrapRatchet(peerID, peerIdentityPub, true /* initiator */)
}

// 4. Send.
msg, err := conv.Send(ctx, []byte("Hello"))

// 5. Receive.
unsubscribe := conv.Subscribe(func(incoming messaging.Message) {
    body, err := conv.DecryptBody(&incoming)
    _ = body
    _ = err
})
defer unsubscribe()

// 6. Edit.
_, _ = conv.Edit(ctx, msg.ID, []byte("Hello (edited)"))

// 7. Delete (gossipable tombstone).
_ = conv.Delete(ctx, msg.ID)

// 8. Attach a file. Attach uploads the encrypted blob and returns a reference;
//    MarshalAttachmentBody packs a text caption + the attachment into a message body.
att, err := m.Attach(ctx, fileBytes, "image/png", "photo.png")
body, _ := messaging.MarshalAttachmentBody("", []messaging.Attachment{*att})
_, _ = conv.SendKind(ctx, body, messaging.KindAttachment, "" /* replyTo */, "" /* editOf */)

// 9. Presence / typing indicator.
presence, _ := m.Presence(conv.ID(), 30*time.Second)
_ = presence.SetState(ctx, messaging.StateTyping)

// 10. Read receipts.
receipts, _ := m.Receipts(conv.ID())
_ = receipts.MarkRead(ctx, msg.ID)

// 11. Broadcast — e.g. a seller announcing shipping updates to all subscribers.
bcast, _ := m.OpenBroadcast(messaging.ChannelID("seller-updates:" + sellerID))
_, _ = bcast.Publish(ctx, []byte("Order shipped"))
```

> `OpenBroadcast` returns a publisher-owned handle; peers read the same channel via `m.SubscribeBroadcast(id, publisherPeerID)`.

---

## 5. Transport abstraction

The package is **decoupled from any specific wire**. Everything flows through the `Transport` interface, which exposes just `Publish`, `Subscribe`, and lifecycle methods against a `ChannelID`. Two concrete implementations ship:

| Transport         | Use                               | Notes |
|-------------------|-----------------------------------|-------|
| `LocalBus`        | Unit / integration tests          | In-process channel fan-out; no network, no crypto costs. Used in every `*_test.go` file in this package. |
| `WhisperTransport`| Production                        | Sits on top of the Whisper topic bus — `BroadcastOnly` mode for `Broadcast`, standard gossip for `Conversation` / presence / receipts. |

Because the Messenger only ever speaks `Transport`, swapping Whisper for a different topic layer (or plugging a mock for fuzz testing) is a one-line change.

---

## 6. CRDTs used

All conflict resolution lives in `minerva/crdt` — this package is strictly a consumer.

| CRDT           | Package file             | Where it appears in messaging                                 |
|----------------|--------------------------|---------------------------------------------------------------|
| `LWW-Register` | `crdt/lww_register.go`   | Presence state per peer (typing / online / away)              |
| `ORSet`        | `crdt/orset.go`          | Conversation membership, receipts, message tombstones         |
| `Sequence`     | `crdt/sequence.go`       | Ordered message log + edit chains                             |
| `HLC`          | `crdt/hlc.go`            | Hybrid-logical-clock for causal ordering of every op          |
| `GCounter`, `PNCounter` | `crdt/gcounter.go`, `crdt/pncounter.go` | Not used directly by messaging — available for apps (reactions, like counts). |

---

## 7. Persistence

Messaging records persist through Minerva's `Store` interface: file, IndexedDB, in-memory, or a tiered backend all satisfy the same shape. No backend lock-in.

Attachments persist through a `BlobStore` (see `attachments.go`), which is deliberately identical to `ledger.ContextBlobStore` — any implementation satisfying one satisfies the other. Blobs are:

1. Encrypted at rest with a **per-attachment** ChaCha20-Poly1305 key.
2. Content-addressed by the hash of the ciphertext (`EncryptedCID`) for mesh fetch.
3. Hash-stamped with the plaintext digest (`CID`) for dedupe.

The key itself rides inside the end-to-end encrypted Message body, so the blob store never sees plaintext and only intended recipients can decrypt. See [`_OTHER/mercury/encryption-model.md`](../../../_OTHER/mercury/encryption-model.md) §5 and [`rotation-guide.md`](../../../_OTHER/mercury/rotation-guide.md) for the full key-management story.

---

## 8. Observability

Minerva intentionally does **not** import any specific tracing package. Consumers wire their own telemetry via a narrow hook:

```go
// Mercury (or any app) registers at SDK init.
messaging.SetMessageSentHook(func(ctx context.Context) {
    myTracer.Counter("messaging.sent").Add(ctx, 1)
})
```

The hook fires exactly once per successful `Conversation.Send` or `Broadcast.Publish`. Passing `nil` clears it. `MessagingSentCount` in Mercury's existing OTel setup is the canonical consumer; any app can shadow it.

---

## 9. Explicitly NOT supported

| Not supported                                             | Why |
|-----------------------------------------------------------|-----|
| OTR-style repudiation / deniability                       | Complex protocol surface, niche audience, conflicts with the signed-record story every other capability depends on. |
| Post-compromise group security beyond sender-key rotation | MLS-style continuous group key agreement is a major scope addition. Sender-key rotation (triggered on membership change and on a periodic schedule) covers the common "member left, rotate the key" case. |

See [`_OTHER/mercury/roadmap.md`](../../../_OTHER/mercury/roadmap.md) for the longer-term security-feature backlog.

---

## 10. Versioning

- Wire-format changes that break interop **always** come with a new capability version. Old peers simply never see the flag and keep using the previous version.
- New peers negotiate the **highest commonly-supported** version on a per-peer basis via `SupportsFeature`.
- The version byte on every encrypted body (`ciphertextVersionSenderKey = 0x00`, `ciphertextVersionRatchet = 0x01`) lets the decrypt path pick the right branch without advance negotiation, which is what makes the automatic-upgrade flow in &sect;3 possible.

Adding a new capability is a three-step patch:

1. Add a `CapabilityVxName` constant in `sdk.go`.
2. Gate the new behaviour behind `SupportsFeature(peer, CapabilityVxName)`.
3. Have the application layer emit the flag in its profile gossip when the local build supports it.

No centrally-managed version registry — peers discover each other's capability set live.

---

## License

See the repository `LICENSE`. Copyright &copy; 2026 HSTLES / ORBTR Pty Ltd.
