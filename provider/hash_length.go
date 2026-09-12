package provider

import (
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// DigestLengthForHash returns the fixed output length in bytes for h, and
// whether h has a fixed length at all.
//
// ok is false for HASH_ALGORITHM_UNSPECIFIED, HASH_ALGORITHM_OTHER (caller
// must use hash_algorithm_oid instead), and the SHAKE XOFs (SHAKE128/256
// produce caller-selected output lengths, not a fixed one) — none of these
// have a single correct length to check a digest against.
//
// This is provider-agnostic: SHA-256 is always 32 bytes regardless of which
// provider computed it, so the mapping lives here rather than being
// duplicated per provider.
func DigestLengthForHash(h types.HashAlgorithm) (length int, ok bool) {
	switch h {
	case types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		types.HashAlgorithm_HASH_ALGORITHM_SHA512_256,
		types.HashAlgorithm_HASH_ALGORITHM_SHA3_256,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_256,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE2S_256,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE3,
		types.HashAlgorithm_HASH_ALGORITHM_GOST_R3411_94,
		types.HashAlgorithm_HASH_ALGORITHM_GOST_R3411_2012_256:
		return 32, true
	case types.HashAlgorithm_HASH_ALGORITHM_SHA384,
		types.HashAlgorithm_HASH_ALGORITHM_SHA3_384,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_384:
		return 48, true
	case types.HashAlgorithm_HASH_ALGORITHM_SHA512,
		types.HashAlgorithm_HASH_ALGORITHM_SHA3_512,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_512,
		types.HashAlgorithm_HASH_ALGORITHM_GOST_R3411_2012_512:
		return 64, true
	case types.HashAlgorithm_HASH_ALGORITHM_SHA224,
		types.HashAlgorithm_HASH_ALGORITHM_SHA512_224,
		types.HashAlgorithm_HASH_ALGORITHM_SHA3_224,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE2S_224:
		return 28, true
	case types.HashAlgorithm_HASH_ALGORITHM_BLAKE2S_160,
		types.HashAlgorithm_HASH_ALGORITHM_SHA1: //nolint:staticcheck // deprecated hash still needs a length for legacy digest validation
		return 20, true
	case types.HashAlgorithm_HASH_ALGORITHM_MD5: //nolint:staticcheck // deprecated hash still needs a length for legacy digest validation
		return 16, true
	default:
		// HASH_ALGORITHM_UNSPECIFIED, HASH_ALGORITHM_OTHER, HASH_ALGORITHM_SHAKE128/256.
		return 0, false
	}
}
