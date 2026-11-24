//go:build !js

package sdk

import (
	"testing"

	"github.com/bbmumford/minerva/discovery"
)

// A native node starts mDNS when asked and DNS SRV lookups of a named
// bootstrap domain, and neither when not asked.
func TestPlatformDiscoverersNative(t *testing.T) {
	got := platformDiscoverers(NodeConfig{EnableMDNS: true, DNSBootstrapDomain: "example.com", ListenAddress: ":4001"}, "peer")
	if len(got) != 2 {
		t.Fatalf("got %d discoverers, want mDNS and DNS", len(got))
	}
	if _, ok := got[0].(*discovery.MDNSDiscoverer); !ok {
		t.Fatalf("first discoverer is %T, want *discovery.MDNSDiscoverer", got[0])
	}
	if _, ok := got[1].(*discovery.DNSDiscoverer); !ok {
		t.Fatalf("second discoverer is %T, want *discovery.DNSDiscoverer", got[1])
	}
	if none := platformDiscoverers(NodeConfig{}, "peer"); len(none) != 0 {
		t.Fatalf("got %d discoverers for a config asking for none", len(none))
	}
}
