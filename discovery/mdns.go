//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bbmumford/minerva/identity"
)

const (
	// mdnsMulticastAddr is the standard mDNS multicast group.
	mdnsMulticastAddr = "224.0.0.251:5353"

	// mdnsDefaultServiceType is the default mDNS service type for Minerva.
	mdnsDefaultServiceType = "_minerva._tcp.local."

	// mdnsQueryInterval is how often the discover loop queries for peers.
	mdnsQueryInterval = 10 * time.Second

	// mdnsMaxResponseSize is the maximum UDP packet size for mDNS responses.
	mdnsMaxResponseSize = 4096

	// mdnsTTLDefault is the default TTL for mDNS SRV records in seconds.
	mdnsTTLDefault = 120
)

// MDNSDiscoverer discovers peers on the local network via mDNS multicast UDP.
// It queries for SRV records matching the configured service type and
// advertises this node's presence by responding to mDNS queries.
type MDNSDiscoverer struct {
	serviceType string // e.g., "_minerva._tcp.local."
	selfID      string
	port        int
	mu          sync.Mutex
	discovered  map[string]PeerAddress
}

// NewMDNSDiscoverer creates a new mDNS-based local network discoverer.
// selfID is the local node's identity string, port is the mesh listen port.
func NewMDNSDiscoverer(selfID string, port int) *MDNSDiscoverer {
	return &MDNSDiscoverer{
		serviceType: mdnsDefaultServiceType,
		selfID:      selfID,
		port:        port,
		discovered:  make(map[string]PeerAddress),
	}
}

// Discover returns a channel that emits PeerAddress entries for peers found
// via mDNS on the local network. The loop queries every 10 seconds until
// the context is cancelled. The channel is closed when the context ends.
func (d *MDNSDiscoverer) Discover(ctx context.Context) <-chan PeerAddress {
	ch := make(chan PeerAddress, 16)

	go func() {
		defer close(ch)

		// Open a multicast listener for mDNS responses.
		listenAddr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		if err != nil {
			return
		}
		conn, err := net.ListenUDP("udp4", listenAddr)
		if err != nil {
			return
		}
		defer conn.Close()

		// Set up a background reader that processes mDNS responses.
		responseCh := make(chan mdnsResponse, 32)
		go d.readResponses(ctx, conn, responseCh)

		// Initial query + periodic re-query.
		d.sendQuery(conn)

		ticker := time.NewTicker(mdnsQueryInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case resp := <-responseCh:
				pa := d.processResponse(resp)
				if pa == nil {
					continue
				}
				select {
				case ch <- *pa:
				case <-ctx.Done():
					return
				}
			case <-ticker.C:
				d.sendQuery(conn)
			}
		}
	}()

	return ch
}

// Advertise announces this node's presence on the local network via mDNS.
// It listens for mDNS queries on the multicast group and responds with
// SRV records containing this node's identity and address. Blocks until
// the context is cancelled.
func (d *MDNSDiscoverer) Advertise(ctx context.Context, self PeerAddress) error {
	mcastAddr, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return fmt.Errorf("mdns: resolve multicast addr: %w", err)
	}

	listenAddr, err := net.ResolveUDPAddr("udp4", ":5353")
	if err != nil {
		return fmt.Errorf("mdns: resolve listen addr: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, mcastAddr)
	if err != nil {
		// Fallback: try binding without multicast (e.g., in containers).
		conn2, err2 := net.ListenUDP("udp4", listenAddr)
		if err2 != nil {
			return fmt.Errorf("mdns: listen multicast: %w (fallback: %w)", err, err2)
		}
		conn = conn2
	}

	go func() {
		defer conn.Close()

		buf := make([]byte, mdnsMaxResponseSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			if n < 12 {
				continue // too short for DNS header
			}

			// Parse only enough to check if it is a query for our service type.
			if !d.isQueryForService(buf[:n]) {
				continue
			}

			// Build and send a response with our SRV + TXT records.
			response := d.buildResponse(self)
			_, _ = conn.WriteToUDP(response, remoteAddr)
		}
	}()

	return nil
}

// mdnsResponse holds a parsed mDNS response with peer information.
type mdnsResponse struct {
	peerID    string
	host      string
	port      int
	addresses []string
	timestamp int64
}

// readResponses reads mDNS UDP responses and parses out peer information.
func (d *MDNSDiscoverer) readResponses(ctx context.Context, conn *net.UDPConn, ch chan<- mdnsResponse) {
	buf := make([]byte, mdnsMaxResponseSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if n < 12 {
			continue // too short for DNS header
		}

		resp, ok := d.parseResponse(buf[:n])
		if !ok {
			continue
		}

		select {
		case ch <- resp:
		case <-ctx.Done():
			return
		}
	}
}

// sendQuery sends an mDNS query for the configured service type.
func (d *MDNSDiscoverer) sendQuery(conn *net.UDPConn) {
	mcastAddr, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return
	}

	query := d.buildQuery()
	_, _ = conn.WriteToUDP(query, mcastAddr)
}

// processResponse converts an mdnsResponse into a PeerAddress, deduplicating
// against previously discovered peers. Returns nil if the peer is already known
// with the same or newer timestamp, or if it is the local node.
func (d *MDNSDiscoverer) processResponse(resp mdnsResponse) *PeerAddress {
	if resp.peerID == d.selfID {
		return nil // ignore self
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if existing, ok := d.discovered[resp.peerID]; ok {
		if existing.Timestamp >= resp.timestamp {
			return nil // already have this or newer
		}
	}

	addrs := resp.addresses
	if len(addrs) == 0 && resp.host != "" {
		addrs = []string{fmt.Sprintf("%s:%d", resp.host, resp.port)}
	}

	pa := PeerAddress{
		PeerID:    identity.PeerID(resp.peerID),
		Addresses: addrs,
		Timestamp: resp.timestamp,
	}
	d.discovered[resp.peerID] = pa
	return &pa
}

// buildQuery builds a minimal mDNS query packet for the service type.
// DNS wire format: Header (12 bytes) + Question section.
func (d *MDNSDiscoverer) buildQuery() []byte {
	var buf []byte

	// DNS Header: ID=0, Flags=0 (standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT = 1
	buf = append(buf, header...)

	// Question: service type name, QTYPE=SRV (33), QCLASS=IN (1)
	buf = append(buf, encodeDNSName(d.serviceType)...)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], 33)  // SRV
	binary.BigEndian.PutUint16(qtype[2:4], 1)   // IN
	buf = append(buf, qtype...)

	return buf
}

// buildResponse builds an mDNS response packet advertising this node.
// The response includes an SRV record and a TXT record with the peer ID.
func (d *MDNSDiscoverer) buildResponse(self PeerAddress) []byte {
	var buf []byte

	// DNS Header: ID=0, Flags=0x8400 (response, authoritative), QDCOUNT=0, ANCOUNT=2
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[2:4], 0x8400) // QR=1, AA=1
	binary.BigEndian.PutUint16(header[6:8], 2)      // ANCOUNT = 2 (SRV + TXT)
	buf = append(buf, header...)

	// Answer 1: SRV record for our service.
	srvName := encodeDNSName(d.serviceType)
	buf = append(buf, srvName...)
	srvHeader := make([]byte, 10)
	binary.BigEndian.PutUint16(srvHeader[0:2], 33) // TYPE=SRV
	binary.BigEndian.PutUint16(srvHeader[2:4], 1)  // CLASS=IN
	binary.BigEndian.PutUint32(srvHeader[4:8], mdnsTTLDefault)
	buf = append(buf, srvHeader...)

	// SRV RDATA: Priority(2) + Weight(2) + Port(2) + Target(variable)
	hostname := d.selfID + ".local."
	targetName := encodeDNSName(hostname)
	srvRdata := make([]byte, 6, 6+len(targetName))
	binary.BigEndian.PutUint16(srvRdata[0:2], 0)              // priority
	binary.BigEndian.PutUint16(srvRdata[2:4], 0)              // weight
	binary.BigEndian.PutUint16(srvRdata[4:6], uint16(d.port)) // port
	srvRdata = append(srvRdata, targetName...)

	// RDLENGTH
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(srvRdata)))
	buf = append(buf, rdlen...)
	buf = append(buf, srvRdata...)

	// Answer 2: TXT record with peer metadata.
	buf = append(buf, srvName...)
	txtHeader := make([]byte, 10)
	binary.BigEndian.PutUint16(txtHeader[0:2], 16) // TYPE=TXT
	binary.BigEndian.PutUint16(txtHeader[2:4], 1)  // CLASS=IN
	binary.BigEndian.PutUint32(txtHeader[4:8], mdnsTTLDefault)
	buf = append(buf, txtHeader...)

	// TXT RDATA: length-prefixed strings with peer metadata.
	var txtRdata []byte
	peerIDStr := "peer_id=" + string(self.PeerID)
	txtRdata = append(txtRdata, byte(len(peerIDStr)))
	txtRdata = append(txtRdata, []byte(peerIDStr)...)

	addrStr := "addrs=" + strings.Join(self.Addresses, ",")
	txtRdata = append(txtRdata, byte(len(addrStr)))
	txtRdata = append(txtRdata, []byte(addrStr)...)

	tsStr := fmt.Sprintf("ts=%d", self.Timestamp)
	txtRdata = append(txtRdata, byte(len(tsStr)))
	txtRdata = append(txtRdata, []byte(tsStr)...)

	txtRdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(txtRdlen, uint16(len(txtRdata)))
	buf = append(buf, txtRdlen...)
	buf = append(buf, txtRdata...)

	return buf
}

// isQueryForService checks if a DNS packet is a query containing our service type.
func (d *MDNSDiscoverer) isQueryForService(pkt []byte) bool {
	if len(pkt) < 12 {
		return false
	}

	// Check QR bit = 0 (query).
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 != 0 {
		return false // response, not query
	}

	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount == 0 {
		return false
	}

	// Parse the first question name and check if it matches our service type.
	name, _ := decodeDNSName(pkt, 12)
	return strings.EqualFold(name, d.serviceType)
}

// parseResponse extracts peer information from an mDNS response packet.
func (d *MDNSDiscoverer) parseResponse(pkt []byte) (mdnsResponse, bool) {
	if len(pkt) < 12 {
		return mdnsResponse{}, false
	}

	// Check QR bit = 1 (response).
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 == 0 {
		return mdnsResponse{}, false // query, not response
	}

	ancount := binary.BigEndian.Uint16(pkt[6:8])
	if ancount == 0 {
		return mdnsResponse{}, false
	}

	var resp mdnsResponse
	foundSRV := false

	// Skip question section.
	offset := 12
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	for i := 0; i < int(qdcount); i++ {
		_, newOffset := decodeDNSName(pkt, offset)
		if newOffset <= offset || newOffset+4 > len(pkt) {
			return mdnsResponse{}, false
		}
		offset = newOffset + 4 // skip QTYPE + QCLASS
	}

	// Parse answer records.
	for i := 0; i < int(ancount); i++ {
		if offset >= len(pkt) {
			break
		}

		_, nameEnd := decodeDNSName(pkt, offset)
		if nameEnd <= offset || nameEnd+10 > len(pkt) {
			break
		}

		rtype := binary.BigEndian.Uint16(pkt[nameEnd : nameEnd+2])
		rdlen := binary.BigEndian.Uint16(pkt[nameEnd+8 : nameEnd+10])
		rdataStart := nameEnd + 10

		if rdataStart+int(rdlen) > len(pkt) {
			break
		}

		switch rtype {
		case 33: // SRV
			if rdlen >= 6 {
				resp.port = int(binary.BigEndian.Uint16(pkt[rdataStart+4 : rdataStart+6]))
				target, _ := decodeDNSName(pkt, rdataStart+6)
				// Extract hostname from target (strip .local. suffix).
				resp.host = strings.TrimSuffix(target, ".local.")
				resp.host = strings.TrimSuffix(resp.host, ".")
				foundSRV = true
			}

		case 16: // TXT
			d.parseTXTRdata(pkt[rdataStart:rdataStart+int(rdlen)], &resp)
		}

		offset = rdataStart + int(rdlen)
	}

	if !foundSRV {
		return mdnsResponse{}, false
	}

	// If we got a peer_id from TXT, use it; otherwise use the SRV target hostname.
	if resp.peerID == "" && resp.host != "" {
		resp.peerID = resp.host
	}

	if resp.peerID == "" {
		return mdnsResponse{}, false
	}

	return resp, true
}

// parseTXTRdata extracts key=value pairs from DNS TXT record RDATA.
func (d *MDNSDiscoverer) parseTXTRdata(rdata []byte, resp *mdnsResponse) {
	offset := 0
	for offset < len(rdata) {
		txtLen := int(rdata[offset])
		offset++
		if offset+txtLen > len(rdata) {
			break
		}

		txt := string(rdata[offset : offset+txtLen])
		offset += txtLen

		eqIdx := strings.IndexByte(txt, '=')
		if eqIdx < 0 {
			continue
		}
		key := txt[:eqIdx]
		value := txt[eqIdx+1:]

		switch key {
		case "peer_id":
			resp.peerID = value
		case "addrs":
			if value != "" {
				resp.addresses = strings.Split(value, ",")
			}
		case "ts":
			var ts int64
			fmt.Sscanf(value, "%d", &ts)
			resp.timestamp = ts
		}
	}
}

// encodeDNSName encodes a domain name into DNS wire format.
// "example.local." -> [7]example[5]local[0]
func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label
	return buf
}

// decodeDNSName decodes a DNS wire-format name starting at offset.
// Returns the decoded name and the offset immediately after the name.
// Handles pointer compression (0xC0 prefix).
func decodeDNSName(pkt []byte, offset int) (string, int) {
	var labels []string
	jumped := false
	returnOffset := 0
	maxJumps := 10 // prevent infinite loops from malformed packets

	for jumps := 0; offset < len(pkt) && jumps < maxJumps; jumps++ {
		length := int(pkt[offset])

		if length == 0 {
			if !jumped {
				returnOffset = offset + 1
			}
			break
		}

		// Pointer compression: two high bits set.
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				break
			}
			if !jumped {
				returnOffset = offset + 2
				jumped = true
			}
			pointer := int(binary.BigEndian.Uint16(pkt[offset:offset+2])) & 0x3FFF
			offset = pointer
			continue
		}

		offset++
		if offset+length > len(pkt) {
			break
		}
		labels = append(labels, string(pkt[offset:offset+length]))
		offset += length
	}

	if !jumped {
		returnOffset = offset
	}

	name := strings.Join(labels, ".") + "."
	return name, returnOffset
}
