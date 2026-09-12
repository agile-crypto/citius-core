package provider_test

import (
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
)

func TestDigestLengthForHash(t *testing.T) {
	tests := []struct {
		name       string
		h          types.HashAlgorithm
		wantLength int
		wantOK     bool
	}{
		{"SHA256", types.HashAlgorithm_HASH_ALGORITHM_SHA256, 32, true},
		{"SHA384", types.HashAlgorithm_HASH_ALGORITHM_SHA384, 48, true},
		{"SHA512", types.HashAlgorithm_HASH_ALGORITHM_SHA512, 64, true},
		{"SHA224", types.HashAlgorithm_HASH_ALGORITHM_SHA224, 28, true},
		{"SHA512_256", types.HashAlgorithm_HASH_ALGORITHM_SHA512_256, 32, true},
		{"SHA512_224", types.HashAlgorithm_HASH_ALGORITHM_SHA512_224, 28, true},
		{"SHA3_256", types.HashAlgorithm_HASH_ALGORITHM_SHA3_256, 32, true},
		{"SHA3_384", types.HashAlgorithm_HASH_ALGORITHM_SHA3_384, 48, true},
		{"SHA3_512", types.HashAlgorithm_HASH_ALGORITHM_SHA3_512, 64, true},
		{"SHA3_224", types.HashAlgorithm_HASH_ALGORITHM_SHA3_224, 28, true},
		{"BLAKE2B_256", types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_256, 32, true},
		{"BLAKE2B_384", types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_384, 48, true},
		{"BLAKE2B_512", types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_512, 64, true},
		{"BLAKE2S_256", types.HashAlgorithm_HASH_ALGORITHM_BLAKE2S_256, 32, true},
		{"BLAKE2S_160", types.HashAlgorithm_HASH_ALGORITHM_BLAKE2S_160, 20, true},
		{"BLAKE2S_224", types.HashAlgorithm_HASH_ALGORITHM_BLAKE2S_224, 28, true},
		{"BLAKE3", types.HashAlgorithm_HASH_ALGORITHM_BLAKE3, 32, true},
		{"GOST_R3411_94", types.HashAlgorithm_HASH_ALGORITHM_GOST_R3411_94, 32, true},
		{"GOST_R3411_2012_256", types.HashAlgorithm_HASH_ALGORITHM_GOST_R3411_2012_256, 32, true},
		{"GOST_R3411_2012_512", types.HashAlgorithm_HASH_ALGORITHM_GOST_R3411_2012_512, 64, true},
		{"SHA1 (deprecated, still checkable)", types.HashAlgorithm_HASH_ALGORITHM_SHA1, 20, true}, //nolint:staticcheck // deprecated value under intentional test
		{"MD5 (deprecated, still checkable)", types.HashAlgorithm_HASH_ALGORITHM_MD5, 16, true},   //nolint:staticcheck // deprecated value under intentional test
		{"UNSPECIFIED has no fixed length", types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, 0, false},
		{"OTHER has no fixed length", types.HashAlgorithm_HASH_ALGORITHM_OTHER, 0, false},
		{"SHAKE128 is a variable-length XOF", types.HashAlgorithm_HASH_ALGORITHM_SHAKE128, 0, false},
		{"SHAKE256 is a variable-length XOF", types.HashAlgorithm_HASH_ALGORITHM_SHAKE256, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLength, gotOK := provider.DigestLengthForHash(tt.h)
			if gotOK != tt.wantOK {
				t.Errorf("ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotOK && gotLength != tt.wantLength {
				t.Errorf("length = %d, want %d", gotLength, tt.wantLength)
			}
		})
	}
}
