/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package proto

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

// The generated descriptor must decode: the package's init builds it, so a
// descriptor whose length prefixes disagree with its bytes panics every
// binary importing minerva's gossip package. It names this module's import
// path, and a GossipEnvelope survives a round trip through the wire form.
func TestGossipDescriptorDecodesAndNamesThisModule(t *testing.T) {
	opts, ok := File_gossip_proto_gossip_proto.Options().(*descriptorpb.FileOptions)
	if !ok || opts.GetGoPackage() != "github.com/bbmumford/minerva/gossip/proto" {
		t.Fatalf("go_package = %q, want github.com/bbmumford/minerva/gossip/proto", opts.GetGoPackage())
	}

	in := &GossipEnvelope{AppId: "app", SenderId: "node", Fingerprint: 7, Deltas: []*CRDTDelta{{Collection: "c", Key: "k", Value: []byte("v"), Hlc: 3}}}
	data, err := proto.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out GossipEnvelope
	if err := proto.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !proto.Equal(in, &out) {
		t.Fatalf("round trip changed the envelope: %v", &out)
	}
}
