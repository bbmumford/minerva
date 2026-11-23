/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 *
 * ecdh.go — Ed25519 -> X25519 converters and ECDH shared-secret helper
 * for the double-ratchet and related messaging primitives. These routines
 * are package-internal (lowercase) on purpose; Minerva exposes the
 * ratchet API at a higher level and callers should not depend on the
 * raw X25519 byte-mangling.
 *
 * The implementation mirrors mercury/messaging/encrypt.go so the two
 * packages stay wire-compatible during the Session A -> C migration; the
 * Mercury copy will be removed in Session C once its callers migrate.
 */
package messaging

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// ed25519PublicToX25519 converts an Ed25519 public key to the corresponding
// X25519 public key using the standard birational map from the Edwards
// curve to the Montgomery curve.
func ed25519PublicToX25519(edPub ed25519.PublicKey) (*[32]byte, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("messaging: invalid Ed25519 public key size %d", len(edPub))
	}
	var edPubBytes [32]byte
	copy(edPubBytes[:], edPub)
	return edwardsToMontgomeryPub(&edPubBytes)
}

// ed25519PrivateToX25519 converts an Ed25519 private key to the clamped
// X25519 private scalar. The Ed25519 private key is the 32-byte seed
// followed by the 32-byte public key; the X25519 private key is the
// RFC 7748 clamped first half of SHA-512(seed).
func ed25519PrivateToX25519(edPriv ed25519.PrivateKey) (*[32]byte, error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("messaging: invalid Ed25519 private key size %d", len(edPriv))
	}
	h := sha512.Sum512(edPriv[:ed25519.SeedSize])
	var x25519Priv [32]byte
	copy(x25519Priv[:], h[:32])
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64
	return &x25519Priv, nil
}

// sharedSecret computes the X25519 ECDH shared secret between our
// Ed25519 private key and the peer's Ed25519 public key. Package-internal:
// the exported form lives on the higher-level ratchet / identity API.
func sharedSecret(ourPriv ed25519.PrivateKey, theirPub ed25519.PublicKey) ([]byte, error) {
	ourX, err := ed25519PrivateToX25519(ourPriv)
	if err != nil {
		return nil, err
	}
	theirX, err := ed25519PublicToX25519(theirPub)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(ourX[:], theirX[:])
	if err != nil {
		return nil, fmt.Errorf("messaging: X25519 ECDH failed: %w", err)
	}
	return shared, nil
}

// hexDecodePeerID decodes a PeerID back to a 32-byte Ed25519 public key.
// Returns an error if the string is not valid lowercase hex or is the
// wrong length. Thin wrapper so call sites outside types.go can reuse
// the conversion without re-implementing it.
func hexDecodePeerID(p PeerID) ([]byte, error) {
	return peerIDFromHex(p)
}

// --- Ed25519 -> X25519 birational map --------------------------------------
//
// Montgomery u = (1 + y) / (1 - y) mod p, where p = 2^255 - 19 and y is the
// little-endian encoding of the Ed25519 y-coordinate (the Ed25519 public
// key bytes, with the x-sign bit in the top bit of the last byte; that
// bit is ignored by the map).

func edwardsToMontgomeryPub(edPub *[32]byte) (*[32]byte, error) {
	y := new(fieldElement)
	feFromBytes(y, edPub)

	var num fieldElement
	feAdd(&num, &feOne, y)

	var den fieldElement
	feSub(&den, &feOne, y)

	var denInv fieldElement
	feInverse(&denInv, &den)

	var u fieldElement
	feMul(&u, &num, &denInv)

	var result [32]byte
	feToBytes(&result, &u)
	return &result, nil
}

// --- GF(2^255-19) field arithmetic -----------------------------------------
//
// 5-limb, 51-bit representation. Sufficient for the birational map; no
// side-channel guarantees are claimed (timing-sensitive conversions should
// use curve25519 directly on the private-scalar path, which they do).

type fieldElement [5]uint64

var feOne = fieldElement{1, 0, 0, 0, 0}

func feFromBytes(fe *fieldElement, b *[32]byte) {
	fe[0] = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6]&0x07)<<48
	fe[1] = uint64(b[6])>>3 | uint64(b[7])<<5 | uint64(b[8])<<13 | uint64(b[9])<<21 |
		uint64(b[10])<<29 | uint64(b[11])<<37 | uint64(b[12]&0x3f)<<45
	fe[2] = uint64(b[12])>>6 | uint64(b[13])<<2 | uint64(b[14])<<10 | uint64(b[15])<<18 |
		uint64(b[16])<<26 | uint64(b[17])<<34 | uint64(b[18])<<42 | uint64(b[19]&0x01)<<50
	fe[3] = uint64(b[19])>>1 | uint64(b[20])<<7 | uint64(b[21])<<15 | uint64(b[22])<<23 |
		uint64(b[23])<<31 | uint64(b[24])<<39 | uint64(b[25]&0x0f)<<47
	fe[4] = uint64(b[25])>>4 | uint64(b[26])<<4 | uint64(b[27])<<12 | uint64(b[28])<<20 |
		uint64(b[29])<<28 | uint64(b[30])<<36 | uint64(b[31]&0x7f)<<44
}

func feToBytes(b *[32]byte, fe *fieldElement) {
	var t fieldElement
	copy(t[:], fe[:])
	feReduce(&t)

	b[0] = byte(t[0])
	b[1] = byte(t[0] >> 8)
	b[2] = byte(t[0] >> 16)
	b[3] = byte(t[0] >> 24)
	b[4] = byte(t[0] >> 32)
	b[5] = byte(t[0] >> 40)
	b[6] = byte(t[0]>>48) | byte(t[1]<<3)
	b[7] = byte(t[1] >> 5)
	b[8] = byte(t[1] >> 13)
	b[9] = byte(t[1] >> 21)
	b[10] = byte(t[1] >> 29)
	b[11] = byte(t[1] >> 37)
	b[12] = byte(t[1]>>45) | byte(t[2]<<6)
	b[13] = byte(t[2] >> 2)
	b[14] = byte(t[2] >> 10)
	b[15] = byte(t[2] >> 18)
	b[16] = byte(t[2] >> 26)
	b[17] = byte(t[2] >> 34)
	b[18] = byte(t[2] >> 42)
	b[19] = byte(t[2]>>50) | byte(t[3]<<1)
	b[20] = byte(t[3] >> 7)
	b[21] = byte(t[3] >> 15)
	b[22] = byte(t[3] >> 23)
	b[23] = byte(t[3] >> 31)
	b[24] = byte(t[3] >> 39)
	b[25] = byte(t[3]>>47) | byte(t[4]<<4)
	b[26] = byte(t[4] >> 4)
	b[27] = byte(t[4] >> 12)
	b[28] = byte(t[4] >> 20)
	b[29] = byte(t[4] >> 28)
	b[30] = byte(t[4] >> 36)
	b[31] = byte(t[4] >> 44)
}

const mask51 = (1 << 51) - 1

func feReduce(fe *fieldElement) {
	for i := 0; i < 4; i++ {
		fe[i+1] += fe[i] >> 51
		fe[i] &= mask51
	}
	fe[0] += 19 * (fe[4] >> 51)
	fe[4] &= mask51

	for i := 0; i < 4; i++ {
		fe[i+1] += fe[i] >> 51
		fe[i] &= mask51
	}
	fe[0] += 19 * (fe[4] >> 51)
	fe[4] &= mask51
}

func feAdd(out, a, b *fieldElement) {
	for i := range out {
		out[i] = a[i] + b[i]
	}
}

func feSub(out, a, b *fieldElement) {
	out[0] = a[0] + (2*((1<<51)-1) - 2*18) - b[0]
	for i := 1; i < 5; i++ {
		out[i] = a[i] + 2*((1<<51)-1) - b[i]
	}
	feReduce(out)
}

func feMul(out, a, b *fieldElement) {
	var s [5]uint128

	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			idx := i + j
			product := mul64(a[i], b[j])
			if idx >= 5 {
				product = mul64x19(product)
				idx -= 5
			}
			s[idx] = add128(s[idx], product)
		}
	}

	for i := range out {
		out[i] = s[i].lo & mask51
		if i < 4 {
			s[i+1] = add128(s[i+1], uint128{lo: s[i].lo>>51 | s[i].hi<<13})
		} else {
			carry := s[i].lo>>51 | s[i].hi<<13
			out[0] += carry * 19
		}
	}
	feReduce(out)
}

func feSquare(out, a *fieldElement) {
	feMul(out, a, a)
}

// feInverse computes the modular inverse using Fermat's little theorem:
// a^(p-2) mod p, where p-2 = 2^255 - 21.
func feInverse(out, a *fieldElement) {
	var t0, t1, t2, t3 fieldElement

	feSquare(&t0, a)
	feSquare(&t1, &t0)
	feSquare(&t1, &t1)
	feMul(&t1, a, &t1)
	feMul(&t0, &t0, &t1)
	feSquare(&t2, &t0)
	feMul(&t1, &t1, &t2)
	feSquare(&t2, &t1)
	for i := 0; i < 4; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t2, &t1)
	feSquare(&t2, &t1)
	for i := 0; i < 9; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t2, &t2, &t1)
	feSquare(&t3, &t2)
	for i := 0; i < 19; i++ {
		feSquare(&t3, &t3)
	}
	feMul(&t2, &t3, &t2)
	feSquare(&t2, &t2)
	for i := 0; i < 9; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t2, &t1)
	feSquare(&t2, &t1)
	for i := 0; i < 49; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t2, &t2, &t1)
	feSquare(&t3, &t2)
	for i := 0; i < 99; i++ {
		feSquare(&t3, &t3)
	}
	feMul(&t2, &t3, &t2)
	feSquare(&t2, &t2)
	for i := 0; i < 49; i++ {
		feSquare(&t2, &t2)
	}
	feMul(&t1, &t2, &t1)
	feSquare(&t1, &t1)
	feSquare(&t1, &t1)
	feSquare(&t1, &t1)
	feSquare(&t1, &t1)
	feSquare(&t1, &t1)
	feMul(out, &t1, &t0)
}

// uint128 is a 128-bit unsigned integer for intermediate multiplication
// results in the field multiplication routine.
type uint128 struct {
	lo, hi uint64
}

func mul64(a, b uint64) uint128 {
	aLo := a & 0xFFFFFFFF
	aHi := a >> 32
	bLo := b & 0xFFFFFFFF
	bHi := b >> 32

	ll := aLo * bLo
	lh := aLo * bHi
	hl := aHi * bLo
	hh := aHi * bHi

	mid := lh + (ll >> 32)
	mid += hl

	var carry uint64
	if mid < hl {
		carry = 1
	}

	return uint128{
		lo: (mid << 32) | (ll & 0xFFFFFFFF),
		hi: hh + (mid >> 32) + (carry << 32),
	}
}

func mul64x19(v uint128) uint128 {
	loProduct := mul64(v.lo, 19)
	hiProduct := v.hi * 19
	return uint128{
		lo: loProduct.lo,
		hi: loProduct.hi + hiProduct,
	}
}

func add128(a, b uint128) uint128 {
	lo := a.lo + b.lo
	var carry uint64
	if lo < a.lo {
		carry = 1
	}
	return uint128{
		lo: lo,
		hi: a.hi + b.hi + carry,
	}
}
