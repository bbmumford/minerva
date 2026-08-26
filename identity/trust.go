package identity

import (
	"sync"
)

// TrustGraph implements a web-of-trust reputation system with transitive trust
// that decays over hops. Trust levels are in the range [0.0, 1.0].
type TrustGraph struct {
	mu      sync.RWMutex
	edges   map[string]map[string]float64 // from -> to -> trust level
	maxHops int
	decay   float64 // per-hop multiplicative decay factor
}

// NewTrustGraph creates a new TrustGraph with default settings (maxHops=3, decay=0.5).
func NewTrustGraph() *TrustGraph {
	return &TrustGraph{
		edges:   make(map[string]map[string]float64),
		maxHops: 3,
		decay:   0.5,
	}
}

// SetTrust sets a direct trust level from one identity to another.
// Level is clamped to [0.0, 1.0]. A level of 0 removes the edge.
func (g *TrustGraph) SetTrust(from, to string, level float64) {
	if level < 0 {
		level = 0
	}
	if level > 1 {
		level = 1
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if level == 0 {
		if m, ok := g.edges[from]; ok {
			delete(m, to)
			if len(m) == 0 {
				delete(g.edges, from)
			}
		}
		return
	}

	m, ok := g.edges[from]
	if !ok {
		m = make(map[string]float64)
		g.edges[from] = m
	}
	m[to] = level
}

// DirectTrust returns the direct trust level from one identity to another.
// Returns 0 if no direct trust edge exists.
func (g *TrustGraph) DirectTrust(from, to string) float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if m, ok := g.edges[from]; ok {
		return m[to]
	}
	return 0
}

// Trust computes transitive trust from one identity to another using BFS.
// Trust decays by the decay factor at each hop. The maximum trust across
// all discovered paths (up to maxHops) is returned.
func (g *TrustGraph) Trust(from, to string) float64 {
	if from == to {
		return 1.0
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// BFS: each entry is (node, accumulated trust level)
	type entry struct {
		node  string
		trust float64
		hops  int
	}

	visited := make(map[string]bool)
	visited[from] = true

	queue := []entry{{node: from, trust: 1.0, hops: 0}}
	best := 0.0

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		neighbors, ok := g.edges[cur.node]
		if !ok {
			continue
		}

		for neighbor, directLevel := range neighbors {
			// Trust along this edge = accumulated trust * direct level * decay
			hopTrust := cur.trust * directLevel * g.decay

			if neighbor == to {
				if hopTrust > best {
					best = hopTrust
				}
				// Don't continue BFS through the target.
				continue
			}

			if visited[neighbor] {
				continue
			}

			nextHops := cur.hops + 1
			if nextHops >= g.maxHops {
				continue
			}

			visited[neighbor] = true
			queue = append(queue, entry{node: neighbor, trust: hopTrust, hops: nextHops})
		}
	}

	return best
}

// IsTrusted returns true if the transitive trust from one identity to another
// meets or exceeds the given threshold.
func (g *TrustGraph) IsTrusted(from, to string, threshold float64) bool {
	return g.Trust(from, to) >= threshold
}

// RemoveTrust removes all direct trust from one identity to another.
func (g *TrustGraph) RemoveTrust(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if m, ok := g.edges[from]; ok {
		delete(m, to)
		if len(m) == 0 {
			delete(g.edges, from)
		}
	}
}
