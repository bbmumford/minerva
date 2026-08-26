package identity

import (
	"math"
	"testing"
)

func approxEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}

func TestDirectTrust(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("alice", "bob", 0.8)

	if v := g.DirectTrust("alice", "bob"); v != 0.8 {
		t.Fatalf("expected 0.8, got %f", v)
	}
	if v := g.DirectTrust("bob", "alice"); v != 0.0 {
		t.Fatalf("expected 0.0, got %f", v)
	}
	if v := g.DirectTrust("alice", "unknown"); v != 0.0 {
		t.Fatalf("expected 0.0, got %f", v)
	}
}

func TestTransitiveTrust(t *testing.T) {
	g := NewTrustGraph()
	// alice -> bob (0.8), bob -> carol (0.9)
	g.SetTrust("alice", "bob", 0.8)
	g.SetTrust("bob", "carol", 0.9)

	// alice -> bob: 1.0 * 0.8 * 0.5 = 0.4
	trust := g.Trust("alice", "bob")
	if !approxEqual(trust, 0.4, 0.001) {
		t.Fatalf("expected ~0.4, got %f", trust)
	}

	// alice -> carol: 1.0 * 0.8 * 0.5 (at bob) * 0.9 * 0.5 (at carol) = 0.18
	trust = g.Trust("alice", "carol")
	if !approxEqual(trust, 0.18, 0.001) {
		t.Fatalf("expected ~0.18, got %f", trust)
	}
}

func TestSelfTrust(t *testing.T) {
	g := NewTrustGraph()
	if v := g.Trust("alice", "alice"); v != 1.0 {
		t.Fatalf("self trust should be 1.0, got %f", v)
	}
}

func TestMaxHops(t *testing.T) {
	g := NewTrustGraph()
	// Chain: a -> b -> c -> d -> e (4 hops to reach e)
	g.SetTrust("a", "b", 1.0)
	g.SetTrust("b", "c", 1.0)
	g.SetTrust("c", "d", 1.0)
	g.SetTrust("d", "e", 1.0)

	// With maxHops=3, we can reach d (3 hops) but not e (4 hops).
	if trust := g.Trust("a", "d"); trust == 0 {
		t.Fatal("should reach d within 3 hops")
	}
	if trust := g.Trust("a", "e"); trust != 0 {
		t.Fatalf("should not reach e (4 hops), got %f", trust)
	}
}

func TestCycleHandling(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("a", "b", 0.8)
	g.SetTrust("b", "c", 0.9)
	g.SetTrust("c", "a", 0.7) // cycle

	// Should not infinite loop.
	trust := g.Trust("a", "c")
	if trust == 0 {
		t.Fatal("should have transitive trust to c")
	}
}

func TestIsTrusted(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("alice", "bob", 0.8)

	// Direct trust with decay: 0.8 * 0.5 = 0.4
	if !g.IsTrusted("alice", "bob", 0.3) {
		t.Fatal("should be trusted at threshold 0.3")
	}
	if g.IsTrusted("alice", "bob", 0.5) {
		t.Fatal("should not be trusted at threshold 0.5")
	}
}

func TestRemoveTrust(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("alice", "bob", 0.8)
	g.RemoveTrust("alice", "bob")

	if v := g.DirectTrust("alice", "bob"); v != 0 {
		t.Fatalf("expected 0 after removal, got %f", v)
	}
}

func TestSetTrustZeroRemoves(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("alice", "bob", 0.8)
	g.SetTrust("alice", "bob", 0)

	if v := g.DirectTrust("alice", "bob"); v != 0 {
		t.Fatalf("expected 0 after setting to 0, got %f", v)
	}
}

func TestSetTrustClamping(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("a", "b", 2.0)
	if v := g.DirectTrust("a", "b"); v != 1.0 {
		t.Fatalf("expected clamped to 1.0, got %f", v)
	}
	g.SetTrust("a", "c", -0.5)
	if v := g.DirectTrust("a", "c"); v != 0.0 {
		t.Fatalf("expected clamped to 0.0, got %f", v)
	}
}

func TestMultiplePaths(t *testing.T) {
	g := NewTrustGraph()
	// Two paths from a to c:
	// a -> b (1.0) -> c (1.0): 1.0 * 1.0 * 0.5 * 1.0 * 0.5 = 0.25
	// a -> c (0.5) direct: 1.0 * 0.5 * 0.5 = 0.25
	g.SetTrust("a", "b", 1.0)
	g.SetTrust("b", "c", 1.0)
	g.SetTrust("a", "c", 0.5)

	trust := g.Trust("a", "c")
	// Best path should be max(0.25, 0.25) = 0.25
	if !approxEqual(trust, 0.25, 0.001) {
		t.Fatalf("expected ~0.25, got %f", trust)
	}
}

func TestNoTrustPath(t *testing.T) {
	g := NewTrustGraph()
	g.SetTrust("a", "b", 0.8)

	if trust := g.Trust("a", "c"); trust != 0 {
		t.Fatalf("expected 0 for unreachable node, got %f", trust)
	}
	if trust := g.Trust("unknown1", "unknown2"); trust != 0 {
		t.Fatalf("expected 0 for unknown nodes, got %f", trust)
	}
}
