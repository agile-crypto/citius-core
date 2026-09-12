package provider

import (
	"sort"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// Capability names one of the optional interfaces a Backend may implement
// (Signer, Cipher, Macer, Hasher, Randomizer, KeyEstablisher).
type Capability string

const (
	CapabilitySign         Capability = "sign"
	CapabilityCipher       Capability = "cipher"
	CapabilityMac          Capability = "mac"
	CapabilityHash         Capability = "hash"
	CapabilityRandom       Capability = "random"
	CapabilityKeyEstablish Capability = "key_establish"
)

// HasCapability reports whether backend implements the capability
// This is the one place the Signer/Cipher/Macer/Hasher/Randomizer/
// KeyEstablisher type assertions live — callers that need to check a
// capability should call this instead of asserting the interface directly.
func HasCapability(b Backend, c Capability) bool {
	switch c {
	case CapabilitySign:
		_, ok := b.(Signer)
		return ok
	case CapabilityCipher:
		_, ok := b.(Cipher)
		return ok
	case CapabilityMac:
		_, ok := b.(Macer)
		return ok
	case CapabilityHash:
		_, ok := b.(Hasher)
		return ok
	case CapabilityRandom:
		_, ok := b.(Randomizer)
		return ok
	case CapabilityKeyEstablish:
		_, ok := b.(KeyEstablisher)
		return ok
	default:
		return false
	}
}

// CapabilityForOperation maps a catalog CryptoOperation to the Backend
// capability that serves it, mirroring the Backend interface split exactly.
// ok is false for key-lifecycle operations (CREATE_KEY, ROTATE_KEY, ...) and
// dual-function operations (DIGEST_ENCRYPT, SIGN_ENCRYPT, ...) — neither is
// served by an optional capability interface.
func CapabilityForOperation(op types.CryptoOperation) (Capability, bool) {
	switch op {
	case types.CryptoOperation_CRYPTO_OPERATION_SIGN,
		types.CryptoOperation_CRYPTO_OPERATION_VERIFY,
		types.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN,
		types.CryptoOperation_CRYPTO_OPERATION_DIGEST_VERIFY:
		return CapabilitySign, true
	case types.CryptoOperation_CRYPTO_OPERATION_ENCRYPT,
		types.CryptoOperation_CRYPTO_OPERATION_DECRYPT:
		return CapabilityCipher, true
	case types.CryptoOperation_CRYPTO_OPERATION_GENERATE_MAC,
		types.CryptoOperation_CRYPTO_OPERATION_VERIFY_MAC:
		return CapabilityMac, true
	case types.CryptoOperation_CRYPTO_OPERATION_DIGEST:
		return CapabilityHash, true
	case types.CryptoOperation_CRYPTO_OPERATION_GENERATE_RANDOM,
		types.CryptoOperation_CRYPTO_OPERATION_SEED_RANDOM:
		return CapabilityRandom, true
	case types.CryptoOperation_CRYPTO_OPERATION_WRAP_KEY,
		types.CryptoOperation_CRYPTO_OPERATION_UNWRAP_KEY,
		types.CryptoOperation_CRYPTO_OPERATION_DERIVE_KEY,
		types.CryptoOperation_CRYPTO_OPERATION_KEY_AGREEMENT,
		types.CryptoOperation_CRYPTO_OPERATION_ENCAPSULATE,
		types.CryptoOperation_CRYPTO_OPERATION_DECAPSULATE:
		return CapabilityKeyEstablish, true
	default:
		return "", false
	}
}

// RequiredCapabilities returns the deduplicated, sorted set of capabilities
// needed to serve every operation across every scope in caps.
//
// A template is not guaranteed to need only one capability
// so this returns a slice rather than a single
// value, even though every template in the current catalog happens to
// collapse to exactly one.
func RequiredCapabilities(caps []*types.ScopedCapabilities) []Capability {
	seen := make(map[Capability]bool)
	for _, sc := range caps {
		for _, op := range sc.GetOperations() {
			if c, ok := CapabilityForOperation(op); ok {
				seen[c] = true
			}
		}
	}
	out := make([]Capability, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
