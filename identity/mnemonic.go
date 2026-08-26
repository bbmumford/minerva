package identity

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// ToMnemonic converts a keypair's private key seed (32 bytes) to a 24-word mnemonic.
// Uses a 2048-word list with BIP39-style bit packing.
// 256 bits of entropy + 8-bit checksum = 264 bits = 24 * 11-bit indices.
func ToMnemonic(kp *Keypair) (string, error) {
	if kp == nil {
		return "", errors.New("identity: keypair is nil")
	}
	seed := kp.Seed()
	if len(seed) != 32 {
		return "", fmt.Errorf("identity: expected 32-byte seed, got %d", len(seed))
	}

	checksum := sha256.Sum256(seed)

	// Combine seed (32 bytes) + first checksum byte = 33 bytes = 264 bits
	data := make([]byte, 33)
	copy(data, seed)
	data[32] = checksum[0]

	words := make([]string, 24)
	for i := range 24 {
		idx := extract11Bits(data, i*11)
		words[i] = wordlist[idx]
	}

	return strings.Join(words, " "), nil
}

// FromMnemonic reconstructs a keypair from a 24-word mnemonic.
func FromMnemonic(mnemonic string) (*Keypair, error) {
	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		return nil, fmt.Errorf("identity: mnemonic must be 24 words, got %d", len(words))
	}

	lookup := make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		lookup[w] = i
	}

	// Reconstruct the 264-bit stream (33 bytes).
	data := make([]byte, 33)
	for i, word := range words {
		idx, ok := lookup[strings.ToLower(word)]
		if !ok {
			return nil, fmt.Errorf("identity: unknown mnemonic word %q at position %d", word, i)
		}
		write11Bits(data, i*11, idx)
	}

	seed := data[:32]

	// Verify checksum.
	checksum := sha256.Sum256(seed)
	if data[32] != checksum[0] {
		return nil, errors.New("identity: mnemonic checksum mismatch")
	}

	return FromSeed(seed)
}

// extract11Bits reads an 11-bit value starting at the given bit offset.
func extract11Bits(data []byte, bitOffset int) int {
	// We need up to 3 bytes to span 11 bits.
	byteIdx := bitOffset / 8
	shift := bitOffset % 8

	// Collect enough bits from up to 3 bytes into a uint32.
	var val uint32
	val = uint32(data[byteIdx]) << 16
	if byteIdx+1 < len(data) {
		val |= uint32(data[byteIdx+1]) << 8
	}
	if byteIdx+2 < len(data) {
		val |= uint32(data[byteIdx+2])
	}

	// The 11 bits we want start at position (24 - 11 - shift) from the right.
	return int((val >> uint(24-11-shift)) & 0x7FF)
}

// write11Bits writes an 11-bit value at the given bit offset.
func write11Bits(data []byte, bitOffset int, value int) {
	for bit := 0; bit < 11; bit++ {
		if value&(1<<(10-bit)) != 0 {
			byteIdx := (bitOffset + bit) / 8
			bitIdx := 7 - (bitOffset+bit)%8
			data[byteIdx] |= 1 << uint(bitIdx)
		}
	}
}
