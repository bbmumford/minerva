/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package sdk

import "sync"

// CRDTType identifies the CRDT algorithm for a collection.
type CRDTType int

const (
	TypeLWWRegister CRDTType = iota + 1
	TypeLWWMap
	TypeORSet
	TypeGCounter
	TypePNCounter
)

// String returns the human-readable name of a CRDT type.
func (ct CRDTType) String() string {
	switch ct {
	case TypeLWWRegister:
		return "lww_register"
	case TypeLWWMap:
		return "lww_map"
	case TypeORSet:
		return "or_set"
	case TypeGCounter:
		return "g_counter"
	case TypePNCounter:
		return "pn_counter"
	default:
		return "unknown"
	}
}

// CollectionMeta describes a registered CRDT collection.
type CollectionMeta struct {
	Name     string
	CRDTType CRDTType
}

// Store is the application-facing CRDT state registry.
// Applications register named collections with a CRDT type. The Store manages
// creation, lookup, and lifecycle of CRDT collections.
type Store struct {
	mu          sync.RWMutex
	collections map[string]*CollectionMeta
}

// NewStore creates an empty Store.
func NewStore() *Store {
	return &Store{
		collections: make(map[string]*CollectionMeta),
	}
}

// Register creates a new CRDT collection with the given name and type.
// Returns ErrStoreNotReady if a collection with the same name already exists
// with a different type.
func (s *Store) Register(name string, crdtType CRDTType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.collections[name]; ok {
		if existing.CRDTType != crdtType {
			return ErrStoreNotReady
		}
		return nil // already registered with same type
	}
	s.collections[name] = &CollectionMeta{
		Name:     name,
		CRDTType: crdtType,
	}
	return nil
}

// Get returns the metadata for a named collection, or nil if not registered.
func (s *Store) Get(name string) *CollectionMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.collections[name]
}

// All returns a snapshot of all registered collections.
func (s *Store) All() []CollectionMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]CollectionMeta, 0, len(s.collections))
	for _, c := range s.collections {
		result = append(result, *c)
	}
	return result
}
