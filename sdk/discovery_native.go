//go:build !js

package sdk

import "github.com/bbmumford/minerva/discovery"

// platformDiscoverers answers the discoverers a native node starts from its
// config, before PEX: mDNS on the local network when EnableMDNS is set, and
// DNS SRV lookups of DNSBootstrapDomain when one is named. Node.Start calls
// it; the browser build has its own (discovery_js.go), because mDNS and the
// native DNS resolver do not exist under js/wasm.
func platformDiscoverers(cfg NodeConfig, selfID string) []discovery.Discoverer {
	var out []discovery.Discoverer
	if cfg.EnableMDNS {
		out = append(out, discovery.NewMDNSDiscoverer(selfID, parseListenPort(cfg.ListenAddress)))
	}
	if cfg.DNSBootstrapDomain != "" {
		out = append(out, discovery.NewDNSDiscoverer(cfg.DNSBootstrapDomain))
	}
	return out
}
