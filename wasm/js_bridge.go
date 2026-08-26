//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall/js"

	"github.com/bbmumford/minerva/crdt"
	"github.com/bbmumford/minerva/identity"
	"github.com/bbmumford/minerva/sdk"
)

// handleCounter provides monotonically increasing handle IDs for node and
// collection instances exposed to JavaScript.
var handleCounter atomic.Uint64

// nodeEntry holds a node instance alongside its keypair and per-collection
// CRDT data structures.
type nodeEntry struct {
	node     *sdk.Node
	keypair  *identity.Keypair
	peerID   identity.PeerID
	hlc      *crdt.HLC
	cancel   context.CancelFunc
	colMu    sync.RWMutex
	colByID  map[uint64]*collectionEntry // handle -> collection
	colByNam map[string]*collectionEntry // name   -> collection
}

// collectionEntry wraps an LWWMap instance that backs a registered collection.
type collectionEntry struct {
	handle   uint64
	name     string
	crdtType sdk.CRDTType
	lwwMap   *crdt.LWWMap
}

var (
	nodesMu sync.RWMutex
	nodes   = make(map[uint64]*nodeEntry)
)

// nextHandle returns a unique non-zero handle.
func nextHandle() uint64 {
	return handleCounter.Add(1)
}

// registerAll exposes the Minerva API as window.Minerva in the browser.
func registerAll() {
	minerva := map[string]interface{}{
		"createNode":         js.FuncOf(jsCreateNode),
		"startNode":          js.FuncOf(jsStartNode),
		"stopNode":           js.FuncOf(jsStopNode),
		"registerCollection": js.FuncOf(jsRegisterCollection),
		"storeGet":           js.FuncOf(jsStoreGet),
		"storeSet":           js.FuncOf(jsStoreSet),
		"storeDelete":        js.FuncOf(jsStoreDelete),
		"storeAll":           js.FuncOf(jsStoreAll),
		"broadcast":          js.FuncOf(jsBroadcast),
		"onPeerConnect":      js.FuncOf(jsOnPeerConnect),
		"onPeerDisconnect":   js.FuncOf(jsOnPeerDisconnect),
		"onStateChange":      js.FuncOf(jsOnStateChange),
		"getPeerID":          js.FuncOf(jsGetPeerID),
		"exportIdentity":     js.FuncOf(jsExportIdentity),
		"importIdentity":     js.FuncOf(jsImportIdentity),
	}
	js.Global().Set("Minerva", js.ValueOf(minerva))
}

// ---------------------------------------------------------------------------
// Promise wrapper
// ---------------------------------------------------------------------------

// promiseWrapper creates a JS Promise that executes fn on a goroutine.
// The returned value is resolved with the result or rejected with the error.
func promiseWrapper(fn func() (interface{}, error)) interface{} {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			result, err := fn()
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(result)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// getNode retrieves a nodeEntry by handle, returning an error if not found.
func getNode(handle uint64) (*nodeEntry, error) {
	nodesMu.RLock()
	defer nodesMu.RUnlock()
	ne, ok := nodes[handle]
	if !ok {
		return nil, fmt.Errorf("minerva: node handle %d not found", handle)
	}
	return ne, nil
}

// getCollection retrieves a collectionEntry from a node by handle.
func getCollection(ne *nodeEntry, colHandle uint64) (*collectionEntry, error) {
	ne.colMu.RLock()
	defer ne.colMu.RUnlock()
	ce, ok := ne.colByID[colHandle]
	if !ok {
		return nil, fmt.Errorf("minerva: collection handle %d not found", colHandle)
	}
	return ce, nil
}

// getCollectionByName retrieves a collectionEntry from a node by name.
func getCollectionByName(ne *nodeEntry, name string) (*collectionEntry, error) {
	ne.colMu.RLock()
	defer ne.colMu.RUnlock()
	ce, ok := ne.colByNam[name]
	if !ok {
		return nil, fmt.Errorf("minerva: collection %q not found", name)
	}
	return ce, nil
}

// parseCRDTType converts a JS string to an sdk.CRDTType.
func parseCRDTType(s string) (sdk.CRDTType, error) {
	switch s {
	case "lww_register":
		return sdk.TypeLWWRegister, nil
	case "lww_map":
		return sdk.TypeLWWMap, nil
	case "or_set":
		return sdk.TypeORSet, nil
	case "g_counter":
		return sdk.TypeGCounter, nil
	case "pn_counter":
		return sdk.TypePNCounter, nil
	default:
		return 0, fmt.Errorf("minerva: unknown CRDT type %q", s)
	}
}

// goBytes copies a JS Uint8Array into a Go byte slice.
func goBytes(v js.Value) []byte {
	length := v.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, v)
	return buf
}

// jsUint8Array copies a Go byte slice into a new JS Uint8Array.
func jsUint8Array(data []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(arr, data)
	return arr
}

// ---------------------------------------------------------------------------
// jsCreateNode — parse config from JS object, create node, return handle
// ---------------------------------------------------------------------------

func jsCreateNode(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		var opts []sdk.NodeOption

		// Parse config if provided.
		if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
			cfg := args[0]

			if v := cfg.Get("appId"); !v.IsUndefined() && !v.IsNull() {
				opts = append(opts, sdk.WithAppID(v.String()))
			}
			if v := cfg.Get("maxPeers"); !v.IsUndefined() && !v.IsNull() {
				opts = append(opts, sdk.WithMaxPeers(v.Int()))
			}
			if v := cfg.Get("persistencePath"); !v.IsUndefined() && !v.IsNull() {
				opts = append(opts, sdk.WithPersistencePath(v.String()))
			}
			if v := cfg.Get("identityPath"); !v.IsUndefined() && !v.IsNull() {
				opts = append(opts, sdk.WithIdentityPath(v.String()))
			}

			// Bootstrap relays: array of strings.
			if v := cfg.Get("relays"); !v.IsUndefined() && !v.IsNull() {
				length := v.Get("length").Int()
				for i := range length {
					opts = append(opts, sdk.WithRelay(v.Index(i).String()))
				}
			}
		}

		node := sdk.NewNode(opts...)

		// Generate a keypair for this node.
		kp, err := identity.Generate()
		if err != nil {
			return nil, fmt.Errorf("minerva: generate keypair: %w", err)
		}
		peerID := identity.PeerIDFromPublicKey(kp.PublicKey)
		hlc := crdt.NewHLC(string(peerID))

		handle := nextHandle()

		ne := &nodeEntry{
			node:     node,
			keypair:  kp,
			peerID:   peerID,
			hlc:      hlc,
			colByID:  make(map[uint64]*collectionEntry),
			colByNam: make(map[string]*collectionEntry),
		}

		nodesMu.Lock()
		nodes[handle] = ne
		nodesMu.Unlock()

		return js.ValueOf(float64(handle)), nil
	})
}

// ---------------------------------------------------------------------------
// jsStartNode — start the node (returns Promise)
// ---------------------------------------------------------------------------

func jsStartNode(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("minerva: startNode requires a node handle")
		}
		handle := uint64(args[0].Float())
		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithCancel(context.Background())
		ne.cancel = cancel

		if err := ne.node.Start(ctx); err != nil {
			cancel()
			return nil, err
		}
		return js.Undefined(), nil
	})
}

// ---------------------------------------------------------------------------
// jsStopNode — stop the node (returns Promise)
// ---------------------------------------------------------------------------

func jsStopNode(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("minerva: stopNode requires a node handle")
		}
		handle := uint64(args[0].Float())
		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}

		if ne.cancel != nil {
			ne.cancel()
		}

		if err := ne.node.Stop(); err != nil {
			return nil, err
		}

		// Remove from handle map so resources can be collected.
		nodesMu.Lock()
		delete(nodes, handle)
		nodesMu.Unlock()

		return js.Undefined(), nil
	})
}

// ---------------------------------------------------------------------------
// jsRegisterCollection — register a named CRDT collection on a node
// Args: (nodeHandle, name, crdtTypeString) -> Promise<collectionHandle>
// ---------------------------------------------------------------------------

func jsRegisterCollection(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("minerva: registerCollection requires (nodeHandle, name, crdtType)")
		}
		handle := uint64(args[0].Float())
		name := args[1].String()
		crdtTypeStr := args[2].String()

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}

		crdtType, err := parseCRDTType(crdtTypeStr)
		if err != nil {
			return nil, err
		}

		// Register in the SDK store (metadata).
		if err := ne.node.Store().Register(name, crdtType); err != nil {
			return nil, err
		}

		ne.colMu.Lock()
		defer ne.colMu.Unlock()

		// Return existing handle if already registered.
		if existing, ok := ne.colByNam[name]; ok {
			return js.ValueOf(float64(existing.handle)), nil
		}

		// Create the backing LWWMap for key-value operations.
		lwwMap := crdt.NewLWWMap(name, string(ne.peerID), ne.hlc)

		colHandle := nextHandle()
		ce := &collectionEntry{
			handle:   colHandle,
			name:     name,
			crdtType: crdtType,
			lwwMap:   lwwMap,
		}
		ne.colByID[colHandle] = ce
		ne.colByNam[name] = ce

		return js.ValueOf(float64(colHandle)), nil
	})
}

// ---------------------------------------------------------------------------
// jsStoreGet — get a value by key from a collection
// Args: (nodeHandle, collectionName, key) -> Promise<Uint8Array|null>
// ---------------------------------------------------------------------------

func jsStoreGet(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("minerva: storeGet requires (nodeHandle, collectionName, key)")
		}
		handle := uint64(args[0].Float())
		colName := args[1].String()
		key := args[2].String()

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}
		ce, err := getCollectionByName(ne, colName)
		if err != nil {
			return nil, err
		}

		value, ok := ce.lwwMap.Get(key)
		if !ok {
			return js.Null(), nil
		}

		return jsUint8Array(value), nil
	})
}

// ---------------------------------------------------------------------------
// jsStoreSet — set a key-value pair in a collection
// Args: (nodeHandle, collectionName, key, Uint8Array) -> Promise<void>
// ---------------------------------------------------------------------------

func jsStoreSet(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 4 {
			return nil, fmt.Errorf("minerva: storeSet requires (nodeHandle, collectionName, key, value)")
		}
		handle := uint64(args[0].Float())
		colName := args[1].String()
		key := args[2].String()
		value := goBytes(args[3])

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}
		ce, err := getCollectionByName(ne, colName)
		if err != nil {
			return nil, err
		}

		ce.lwwMap.Set(key, value)

		// Emit a state-change event so listeners are notified.
		ne.node.Events().Emit(sdk.Event{
			Type:       sdk.EventStateChange,
			Collection: ce.name,
			Key:        key,
			Value:      value,
		})

		return js.Undefined(), nil
	})
}

// ---------------------------------------------------------------------------
// jsStoreDelete — delete a key from a collection
// Args: (nodeHandle, collectionName, key) -> Promise<void>
// ---------------------------------------------------------------------------

func jsStoreDelete(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("minerva: storeDelete requires (nodeHandle, collectionName, key)")
		}
		handle := uint64(args[0].Float())
		colName := args[1].String()
		key := args[2].String()

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}
		ce, err := getCollectionByName(ne, colName)
		if err != nil {
			return nil, err
		}

		ce.lwwMap.Delete(key)

		// Emit a state-change event for the deletion.
		ne.node.Events().Emit(sdk.Event{
			Type:       sdk.EventStateChange,
			Collection: ce.name,
			Key:        key,
			Value:      nil,
		})

		return js.Undefined(), nil
	})
}

// ---------------------------------------------------------------------------
// jsStoreAll — return all entries in a collection as a JS Map
// Args: (nodeHandle, collectionName) -> Promise<Map<string, Uint8Array>>
// ---------------------------------------------------------------------------

func jsStoreAll(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("minerva: storeAll requires (nodeHandle, collectionName)")
		}
		handle := uint64(args[0].Float())
		colName := args[1].String()

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}
		ce, err := getCollectionByName(ne, colName)
		if err != nil {
			return nil, err
		}

		entries := ce.lwwMap.All()

		// Build a JS Map.
		jsMap := js.Global().Get("Map").New()
		for k, v := range entries {
			jsMap.Call("set", k, jsUint8Array(v))
		}

		return jsMap, nil
	})
}

// ---------------------------------------------------------------------------
// jsBroadcast — broadcast a message to all peers on a topic
// Args: (nodeHandle, topic, Uint8Array) -> Promise<void>
//
// Serialises the broadcast as a JSON envelope and emits a state-change event
// on the node's event bus. When gossip sync is wired, the SyncManager picks
// this up and pushes it to peers.
// ---------------------------------------------------------------------------

func jsBroadcast(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("minerva: broadcast requires (nodeHandle, topic, data)")
		}
		handle := uint64(args[0].Float())
		topic := args[1].String()
		data := goBytes(args[2])

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}

		if !ne.node.Started() {
			return nil, fmt.Errorf("minerva: node not started")
		}

		// Wrap in a JSON envelope for peer consumption.
		envelope := struct {
			Topic  string `json:"topic"`
			PeerID string `json:"peerId"`
			Data   []byte `json:"data"`
		}{
			Topic:  topic,
			PeerID: string(ne.peerID),
			Data:   data,
		}

		payload, err := json.Marshal(envelope)
		if err != nil {
			return nil, fmt.Errorf("minerva: marshal broadcast: %w", err)
		}

		// Emit on the event bus — gossip sync picks this up for network delivery.
		ne.node.Events().Emit(sdk.Event{
			Type:       sdk.EventStateChange,
			Collection: topic,
			Key:        "__broadcast__",
			Value:      payload,
		})

		return js.Undefined(), nil
	})
}

// ---------------------------------------------------------------------------
// jsOnPeerConnect — register a JS callback for peer connect events
// Args: (nodeHandle, callback) -> void
// ---------------------------------------------------------------------------

func jsOnPeerConnect(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.Undefined()
	}
	handle := uint64(args[0].Float())
	callback := args[1]

	ne, err := getNode(handle)
	if err != nil {
		return js.Undefined()
	}

	ne.node.OnPeerConnect(func(peer sdk.Peer) {
		peerObj := map[string]interface{}{
			"id":      peer.ID,
			"petname": peer.Petname,
			"state":   peer.State.String(),
			"rttMs":   peer.RTTMs(),
		}
		callback.Invoke(js.ValueOf(peerObj))
	})

	return js.Undefined()
}

// ---------------------------------------------------------------------------
// jsOnPeerDisconnect — register a JS callback for peer disconnect events
// Args: (nodeHandle, callback) -> void
// ---------------------------------------------------------------------------

func jsOnPeerDisconnect(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.Undefined()
	}
	handle := uint64(args[0].Float())
	callback := args[1]

	ne, err := getNode(handle)
	if err != nil {
		return js.Undefined()
	}

	ne.node.OnPeerDisconnect(func(peerID string) {
		callback.Invoke(peerID)
	})

	return js.Undefined()
}

// ---------------------------------------------------------------------------
// jsOnStateChange — register a JS callback for collection state changes
// Args: (nodeHandle, collectionName, callback) -> void
// ---------------------------------------------------------------------------

func jsOnStateChange(_ js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return js.Undefined()
	}
	handle := uint64(args[0].Float())
	collection := args[1].String()
	callback := args[2]

	ne, err := getNode(handle)
	if err != nil {
		return js.Undefined()
	}

	ne.node.OnStateChange(collection, func(key string, value []byte) {
		var jsVal js.Value
		if value != nil {
			jsVal = jsUint8Array(value)
		} else {
			jsVal = js.Null()
		}
		callback.Invoke(key, jsVal)
	})

	return js.Undefined()
}

// ---------------------------------------------------------------------------
// jsGetPeerID — return the node's peer ID string
// Args: (nodeHandle) -> string
// ---------------------------------------------------------------------------

func jsGetPeerID(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.Null()
	}
	handle := uint64(args[0].Float())

	ne, err := getNode(handle)
	if err != nil {
		return js.Null()
	}

	return js.ValueOf(string(ne.peerID))
}

// ---------------------------------------------------------------------------
// jsExportIdentity — export the node's identity as a 24-word mnemonic
// Args: (nodeHandle) -> Promise<string>
// ---------------------------------------------------------------------------

func jsExportIdentity(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("minerva: exportIdentity requires a node handle")
		}
		handle := uint64(args[0].Float())

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}

		mnemonic, err := identity.ToMnemonic(ne.keypair)
		if err != nil {
			return nil, fmt.Errorf("minerva: export identity: %w", err)
		}

		return js.ValueOf(mnemonic), nil
	})
}

// ---------------------------------------------------------------------------
// jsImportIdentity — import an identity from a 24-word mnemonic and replace
// the node's current keypair.
// Args: (nodeHandle, mnemonic) -> Promise<string> (new peer ID)
// ---------------------------------------------------------------------------

func jsImportIdentity(_ js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("minerva: importIdentity requires (nodeHandle, mnemonic)")
		}
		handle := uint64(args[0].Float())
		mnemonic := args[1].String()

		ne, err := getNode(handle)
		if err != nil {
			return nil, err
		}

		if ne.node.Started() {
			return nil, fmt.Errorf("minerva: cannot import identity while node is running")
		}

		kp, err := identity.FromMnemonic(mnemonic)
		if err != nil {
			return nil, fmt.Errorf("minerva: import identity: %w", err)
		}

		newPeerID := identity.PeerIDFromPublicKey(kp.PublicKey)
		ne.keypair = kp
		ne.peerID = newPeerID
		ne.hlc = crdt.NewHLC(string(newPeerID))

		return js.ValueOf(string(newPeerID)), nil
	})
}
