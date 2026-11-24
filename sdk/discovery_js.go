//go:build js && wasm

package sdk

import (
	"log"

	"github.com/bbmumford/minerva/discovery"
)

// platformDiscoverers answers the discoverers a browser node starts from its
// config, before PEX. A browser can neither send multicast nor reach a DNS
// resolver, so EnableMDNS is reported and skipped, and DNSBootstrapDomain is
// looked up over DNS-over-HTTPS (discovery.DoHDiscoverer). Node.Start calls
// it; the native build has its own (discovery_native.go).
func platformDiscoverers(cfg NodeConfig, _ string) []discovery.Discoverer {
	var out []discovery.Discoverer
	if cfg.EnableMDNS {
		log.Printf("minerva/sdk: EnableMDNS has no effect in a browser node: mDNS needs multicast")
	}
	if cfg.DNSBootstrapDomain != "" {
		out = append(out, discovery.NewDoHDiscoverer(cfg.DNSBootstrapDomain))
	}
	return out
}
