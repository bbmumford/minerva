package relay

import "errors"

// SelectRelay picks a relay from the provided list.
// For now, returns the first available relay URL.
// Future: latency-based ranking, geographic proximity, load balancing.
func SelectRelay(relays []string) (string, error) {
	if len(relays) == 0 {
		return "", errors.New("relay: no relays provided")
	}
	return relays[0], nil
}
