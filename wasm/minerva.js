/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * Minerva P2P SDK — JavaScript wrapper over WASM bridge.
 *
 * Usage:
 *   <script src="wasm_exec.js"></script>
 *   <script src="minerva.js"></script>
 *   <script>
 *     const node = new MinervaNode({ appId: 'my-app', relays: ['wss://relay.example.com'] });
 *     await node.start();
 *     const todos = node.store.lwwMap('todos');
 *     await todos.set('item-1', new TextEncoder().encode(JSON.stringify({ title: 'Buy milk' })));
 *   </script>
 *
 * The WASM bridge exposes window.Minerva with these functions:
 *   createNode(configJSON) -> handle (int)
 *   startNode(handle) -> Promise<void>
 *   stopNode(handle) -> Promise<void>
 *   getPeerID(handle) -> string
 *   registerCollection(handle, name, crdtType) -> Promise<void>
 *   storeGet(handle, collection, key) -> Promise<Uint8Array|null>
 *   storeSet(handle, collection, key, value) -> Promise<void>
 *   storeDelete(handle, collection, key) -> Promise<void>
 *   storeAll(handle, collection) -> Promise<string> (JSON array of {key, value})
 *   broadcast(handle, topic, data) -> Promise<void>
 *   onPeerConnect(handle, callback)
 *   onPeerDisconnect(handle, callback)
 *   onStateChange(handle, collection, callback)
 */

'use strict';

// CRDT type constants — match sdk.CRDTType values in Go.
var CRDT_TYPE_LWW_REGISTER = 1;
var CRDT_TYPE_LWW_MAP = 2;
var CRDT_TYPE_OR_SET = 3;
var CRDT_TYPE_G_COUNTER = 4;
var CRDT_TYPE_PN_COUNTER = 5;

/**
 * Encode a value to Uint8Array for CRDT storage.
 * Accepts Uint8Array (passthrough), ArrayBuffer, string, or any JSON-serialisable object.
 */
function _encodeValue(value) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (typeof value === 'string') {
        return new TextEncoder().encode(value);
    }
    // Anything else: JSON-encode to bytes.
    return new TextEncoder().encode(JSON.stringify(value));
}

/**
 * Decode a Uint8Array back to bytes. Returns null for null/undefined.
 */
function _decodeValue(raw) {
    if (raw == null) {
        return null;
    }
    if (raw instanceof Uint8Array) {
        return raw;
    }
    // The bridge may return a plain array of numbers; convert it.
    if (Array.isArray(raw)) {
        return new Uint8Array(raw);
    }
    return raw;
}

/**
 * Wait for the WASM bridge to be ready. The Go WASM binary sets
 * window.Minerva once RegisterAll() completes. This polls until
 * it appears or a timeout is reached.
 */
function _waitForBridge(timeoutMs) {
    timeoutMs = timeoutMs || 10000;
    return new Promise(function (resolve, reject) {
        var start = Date.now();
        function check() {
            if (typeof Minerva !== 'undefined' && Minerva && typeof Minerva.createNode === 'function') {
                resolve();
                return;
            }
            if (Date.now() - start > timeoutMs) {
                reject(new Error('Minerva WASM bridge did not initialise within ' + timeoutMs + 'ms'));
                return;
            }
            setTimeout(check, 50);
        }
        check();
    });
}

// ---------------------------------------------------------------------------
// CRDTCollection
// ---------------------------------------------------------------------------

/**
 * CRDTCollection wraps a single named CRDT collection on a Minerva node.
 * All mutations are async because they cross the JS-WASM boundary.
 *
 * @param {number} nodeHandle - Internal handle returned by createNode.
 * @param {string} name - Collection name.
 * @param {number} crdtType - One of the CRDT_TYPE_* constants.
 */
function CRDTCollection(nodeHandle, name, crdtType) {
    this._nodeHandle = nodeHandle;
    this._name = name;
    this._crdtType = crdtType;
    this._registered = false;
    this._changeCallbacks = [];
}

/**
 * Ensure the collection is registered with the WASM bridge.
 * Idempotent — safe to call multiple times.
 */
CRDTCollection.prototype._ensureRegistered = function () {
    if (this._registered) {
        return Promise.resolve();
    }
    var self = this;
    return Promise.resolve(Minerva.registerCollection(this._nodeHandle, this._name, this._crdtType))
        .then(function () {
            self._registered = true;
        });
};

/**
 * Get a value by key. Returns a Uint8Array or null if the key does not exist.
 *
 * @param {string} key
 * @returns {Promise<Uint8Array|null>}
 */
CRDTCollection.prototype.get = function (key) {
    var self = this;
    return this._ensureRegistered().then(function () {
        return Promise.resolve(Minerva.storeGet(self._nodeHandle, self._name, key));
    }).then(function (raw) {
        return _decodeValue(raw);
    });
};

/**
 * Set a key to a value. Accepts Uint8Array, string, or any JSON-serialisable object.
 *
 * @param {string} key
 * @param {Uint8Array|string|object} value
 * @returns {Promise<void>}
 */
CRDTCollection.prototype.set = function (key, value) {
    var self = this;
    var encoded = _encodeValue(value);
    return this._ensureRegistered().then(function () {
        return Promise.resolve(Minerva.storeSet(self._nodeHandle, self._name, key, encoded));
    });
};

/**
 * Delete a key (tombstone).
 *
 * @param {string} key
 * @returns {Promise<void>}
 */
CRDTCollection.prototype.delete = function (key) {
    var self = this;
    return this._ensureRegistered().then(function () {
        return Promise.resolve(Minerva.storeDelete(self._nodeHandle, self._name, key));
    });
};

/**
 * Return all entries as an array of {key: string, value: Uint8Array}.
 *
 * @returns {Promise<Array<{key: string, value: Uint8Array}>>}
 */
CRDTCollection.prototype.all = function () {
    var self = this;
    return this._ensureRegistered().then(function () {
        return Promise.resolve(Minerva.storeAll(self._nodeHandle, self._name));
    }).then(function (raw) {
        // The bridge returns JSON: [{key, value(base64 or array)}]
        var entries;
        if (typeof raw === 'string') {
            try {
                entries = JSON.parse(raw);
            } catch (_) {
                entries = [];
            }
        } else if (Array.isArray(raw)) {
            entries = raw;
        } else {
            entries = [];
        }
        return entries.map(function (entry) {
            var val = entry.value;
            if (typeof val === 'string') {
                // base64 decode
                var bin = atob(val);
                var bytes = new Uint8Array(bin.length);
                for (var i = 0; i < bin.length; i++) {
                    bytes[i] = bin.charCodeAt(i);
                }
                val = bytes;
            } else {
                val = _decodeValue(val);
            }
            return { key: entry.key, value: val };
        });
    });
};

/**
 * Register a callback that fires whenever this collection changes.
 * The callback receives (key: string, value: Uint8Array).
 *
 * @param {function(string, Uint8Array): void} callback
 */
CRDTCollection.prototype.onChange = function (callback) {
    this._changeCallbacks.push(callback);
};

/**
 * Internal: dispatch a change event to registered callbacks.
 */
CRDTCollection.prototype._dispatchChange = function (key, value) {
    var decoded = _decodeValue(value);
    for (var i = 0; i < this._changeCallbacks.length; i++) {
        try {
            this._changeCallbacks[i](key, decoded);
        } catch (e) {
            console.error('Minerva: onChange callback error:', e);
        }
    }
};

// ---------------------------------------------------------------------------
// MinervaStore
// ---------------------------------------------------------------------------

/**
 * MinervaStore is the collection factory for a Minerva node.
 *
 * @param {number} nodeHandle
 */
function MinervaStore(nodeHandle) {
    this._nodeHandle = nodeHandle;
    this._collections = {};
}

/**
 * Get or create an LWW-Map collection.
 * @param {string} name
 * @returns {CRDTCollection}
 */
MinervaStore.prototype.lwwMap = function (name) {
    return this._getOrCreate(name, CRDT_TYPE_LWW_MAP);
};

/**
 * Get or create an OR-Set collection.
 * @param {string} name
 * @returns {CRDTCollection}
 */
MinervaStore.prototype.orSet = function (name) {
    return this._getOrCreate(name, CRDT_TYPE_OR_SET);
};

/**
 * Get or create a G-Counter collection.
 * @param {string} name
 * @returns {CRDTCollection}
 */
MinervaStore.prototype.gCounter = function (name) {
    return this._getOrCreate(name, CRDT_TYPE_G_COUNTER);
};

/**
 * Get or create a PN-Counter collection.
 * @param {string} name
 * @returns {CRDTCollection}
 */
MinervaStore.prototype.pnCounter = function (name) {
    return this._getOrCreate(name, CRDT_TYPE_PN_COUNTER);
};

/**
 * Get or create an LWW-Register collection.
 * @param {string} name
 * @returns {CRDTCollection}
 */
MinervaStore.prototype.lwwRegister = function (name) {
    return this._getOrCreate(name, CRDT_TYPE_LWW_REGISTER);
};

/**
 * Internal: return cached collection or create a new one.
 */
MinervaStore.prototype._getOrCreate = function (name, crdtType) {
    var cacheKey = name + ':' + crdtType;
    if (this._collections[cacheKey]) {
        return this._collections[cacheKey];
    }
    var col = new CRDTCollection(this._nodeHandle, name, crdtType);
    this._collections[cacheKey] = col;
    return col;
};

/**
 * Internal: look up a collection by name (any type) for event dispatch.
 */
MinervaStore.prototype._findByName = function (name) {
    var results = [];
    var keys = Object.keys(this._collections);
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].indexOf(name + ':') === 0) {
            results.push(this._collections[keys[i]]);
        }
    }
    return results;
};

// ---------------------------------------------------------------------------
// MinervaNode
// ---------------------------------------------------------------------------

/**
 * MinervaNode is the main entry point for the Minerva P2P SDK.
 *
 * @param {object} config
 * @param {string} config.appId - Application namespace.
 * @param {string[]} [config.relays] - Bootstrap relay WebSocket URLs.
 * @param {string[]} [config.peers] - Bootstrap peer addresses.
 * @param {string} [config.dnsBootstrap] - DNS bootstrap domain.
 * @param {string} [config.identityPath] - Path for identity persistence.
 * @param {string} [config.persistencePath] - Path for state persistence.
 * @param {boolean} [config.enableMDNS] - Enable mDNS discovery.
 * @param {boolean} [config.enablePEX] - Enable peer exchange (default true).
 * @param {number} [config.gossipIntervalMs] - Gossip interval in milliseconds.
 * @param {number} [config.tombstoneTTLMs] - Tombstone TTL in milliseconds.
 * @param {number} [config.maxPeers] - Maximum peer connections.
 */
function MinervaNode(config) {
    if (!config || !config.appId) {
        throw new Error('MinervaNode: config.appId is required');
    }
    this._config = {
        appId: config.appId,
        relays: config.relays || [],
        peers: config.peers || [],
        dnsBootstrap: config.dnsBootstrap || '',
        identityPath: config.identityPath || '',
        persistencePath: config.persistencePath || '',
        enableMDNS: !!config.enableMDNS,
        enablePEX: config.enablePEX !== false,
        gossipIntervalMs: config.gossipIntervalMs || 30000,
        tombstoneTTLMs: config.tombstoneTTLMs || 86400000,
        maxPeers: config.maxPeers || 50,
    };
    this._handle = null;
    this._store = null;
    this._started = false;
    this._peerConnectCallbacks = [];
    this._peerDisconnectCallbacks = [];
}

/**
 * Start the Minerva node. Initialises the WASM bridge, creates the
 * underlying Go node, connects to bootstrap relays, and begins discovery.
 *
 * @returns {Promise<void>}
 */
MinervaNode.prototype.start = function () {
    var self = this;
    return _waitForBridge().then(function () {
        // Create node via WASM bridge.
        var configJSON = JSON.stringify({
            appId: self._config.appId,
            bootstrapRelays: self._config.relays,
            bootstrapPeers: self._config.peers,
            dnsBootstrapDomain: self._config.dnsBootstrap,
            identityPath: self._config.identityPath,
            persistencePath: self._config.persistencePath,
            enableMDNS: self._config.enableMDNS,
            enablePEX: self._config.enablePEX,
            gossipIntervalMs: self._config.gossipIntervalMs,
            tombstoneTTLMs: self._config.tombstoneTTLMs,
            maxPeers: self._config.maxPeers,
        });
        self._handle = Minerva.createNode(configJSON);
        self._store = new MinervaStore(self._handle);

        // Register event handlers on the WASM side.
        Minerva.onPeerConnect(self._handle, function (peerJSON) {
            var peer;
            try {
                peer = typeof peerJSON === 'string' ? JSON.parse(peerJSON) : peerJSON;
            } catch (_) {
                peer = { id: String(peerJSON) };
            }
            for (var i = 0; i < self._peerConnectCallbacks.length; i++) {
                try {
                    self._peerConnectCallbacks[i](peer);
                } catch (e) {
                    console.error('Minerva: onPeerConnect callback error:', e);
                }
            }
        });

        Minerva.onPeerDisconnect(self._handle, function (peerID) {
            var id = typeof peerID === 'string' ? peerID : String(peerID);
            for (var i = 0; i < self._peerDisconnectCallbacks.length; i++) {
                try {
                    self._peerDisconnectCallbacks[i](id);
                } catch (e) {
                    console.error('Minerva: onPeerDisconnect callback error:', e);
                }
            }
        });

        // Start the node.
        return Promise.resolve(Minerva.startNode(self._handle));
    }).then(function () {
        self._started = true;
    });
};

/**
 * Stop the node gracefully. Closes peer connections, flushes persistence.
 *
 * @returns {Promise<void>}
 */
MinervaNode.prototype.stop = function () {
    var self = this;
    if (!this._started || this._handle == null) {
        return Promise.resolve();
    }
    return Promise.resolve(Minerva.stopNode(this._handle)).then(function () {
        self._started = false;
    });
};

/**
 * The CRDT store for this node.
 * @type {MinervaStore}
 */
Object.defineProperty(MinervaNode.prototype, 'store', {
    get: function () {
        return this._store;
    }
});

/**
 * The local peer ID (hex-encoded public key prefix).
 * @type {string}
 */
Object.defineProperty(MinervaNode.prototype, 'peerID', {
    get: function () {
        if (this._handle == null) {
            return '';
        }
        return Minerva.getPeerID(this._handle);
    }
});

/**
 * List of connected peers as an array of peer info objects.
 * Delegates to the WASM bridge's getPeers if available, otherwise
 * returns an empty array.
 * @type {Array<{id: string, state: string, lastSeen: string}>}
 */
Object.defineProperty(MinervaNode.prototype, 'peers', {
    get: function () {
        if (this._handle == null) {
            return [];
        }
        if (typeof Minerva.getPeers === 'function') {
            var raw = Minerva.getPeers(this._handle);
            if (typeof raw === 'string') {
                try {
                    return JSON.parse(raw);
                } catch (_) {
                    return [];
                }
            }
            if (Array.isArray(raw)) {
                return raw;
            }
        }
        return [];
    }
});

/**
 * Register a callback invoked when a new peer connects.
 *
 * @param {function(object): void} callback - Receives peer info object.
 */
MinervaNode.prototype.onPeerConnect = function (callback) {
    this._peerConnectCallbacks.push(callback);
};

/**
 * Register a callback invoked when a peer disconnects.
 *
 * @param {function(string): void} callback - Receives peer ID.
 */
MinervaNode.prototype.onPeerDisconnect = function (callback) {
    this._peerDisconnectCallbacks.push(callback);
};

/**
 * Register a callback invoked when a CRDT collection changes.
 * Wires into the WASM bridge's onStateChange for the given collection,
 * and also dispatches to any CRDTCollection onChange listeners.
 *
 * @param {string} collection - Collection name.
 * @param {function(string, Uint8Array): void} callback - Receives (key, value).
 */
MinervaNode.prototype.onStateChange = function (collection, callback) {
    var self = this;
    if (this._handle != null) {
        Minerva.onStateChange(this._handle, collection, function (key, value) {
            var decoded = _decodeValue(value);
            try {
                callback(key, decoded);
            } catch (e) {
                console.error('Minerva: onStateChange callback error:', e);
            }
            // Also dispatch to any CRDTCollection onChange listeners for this collection.
            if (self._store) {
                var cols = self._store._findByName(collection);
                for (var i = 0; i < cols.length; i++) {
                    cols[i]._dispatchChange(key, value);
                }
            }
        });
    }
};

/**
 * Broadcast data to all connected peers on a topic.
 *
 * @param {string} topic - The topic/channel name.
 * @param {Uint8Array|string|object} data - Data to broadcast.
 * @returns {Promise<void>}
 */
MinervaNode.prototype.broadcast = function (topic, data) {
    if (this._handle == null) {
        return Promise.reject(new Error('MinervaNode: not started'));
    }
    var encoded = _encodeValue(data);
    return Promise.resolve(Minerva.broadcast(this._handle, topic, encoded));
};

// ---------------------------------------------------------------------------
// initMinerva — WASM loader helper
// ---------------------------------------------------------------------------

/**
 * Load the Minerva WASM binary and initialise the bridge.
 * Requires wasm_exec.js to be loaded first (provides the Go class).
 *
 * @param {string} wasmUrl - URL to the minerva.wasm binary.
 * @returns {Promise<{MinervaNode, MinervaStore, CRDTCollection}>}
 */
function initMinerva(wasmUrl) {
    if (typeof Go === 'undefined') {
        return Promise.reject(new Error('initMinerva: wasm_exec.js must be loaded first (Go class not found)'));
    }
    var go = new Go();
    var instantiate;
    if (typeof WebAssembly.instantiateStreaming === 'function') {
        instantiate = WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject);
    } else {
        // Fallback for environments without streaming compilation.
        instantiate = fetch(wasmUrl)
            .then(function (resp) { return resp.arrayBuffer(); })
            .then(function (buf) { return WebAssembly.instantiate(buf, go.importObject); });
    }
    return instantiate.then(function (result) {
        // go.run() starts the Go program. It sets up window.Minerva
        // and then blocks forever (select{}).
        go.run(result.instance);
        // Wait for the bridge to register its globals.
        return _waitForBridge();
    }).then(function () {
        return {
            MinervaNode: MinervaNode,
            MinervaStore: MinervaStore,
            CRDTCollection: CRDTCollection,
        };
    });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        MinervaNode: MinervaNode,
        MinervaStore: MinervaStore,
        CRDTCollection: CRDTCollection,
        initMinerva: initMinerva,
    };
}
if (typeof window !== 'undefined') {
    window.MinervaNode = MinervaNode;
    window.MinervaStore = MinervaStore;
    window.CRDTCollection = CRDTCollection;
    window.initMinerva = initMinerva;
}
