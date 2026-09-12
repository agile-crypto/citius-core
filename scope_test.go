package core

import (
	"slices"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/stretchr/testify/require"
)

func TestScope_AllScopesCanBeConvertedToString(t *testing.T) {
	for s := ScopeUnknown + 1; s < scopeMax; s++ {
		require.NotEqual(t, "unknown", s.String(), "Scope %d does not have a string representation", s)
	}
}

func TestScope_AllScopesHaveAProtoRepresentation(t *testing.T) {
	for s := ScopeUnknown + 1; s < scopeMax; s++ {
		p := s.ToProto()
		require.NotNil(t, p, "Scope %d does not have a proto representation", s)
	}
}

func TestScope_AllScopesCanBeObtainedFormSomeProtoScope(t *testing.T) {
	ls := []struct {
		name        string
		protoMap    map[int32]string
		skipValues  []int32
		protoScopFn func(int32) any
	}{
		{
			name:        "SignatureScope",
			protoMap:    types.SignatureScope_name,
			skipValues:  []int32{int32(types.SignatureScope_SIGNATURE_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.SignatureScope(i) },
		},
		{
			name:        "AeadScope",
			protoMap:    types.AeadScope_name,
			skipValues:  []int32{int32(types.AeadScope_AEAD_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.AeadScope(i) },
		},
		{
			name:        "MacScope",
			protoMap:    types.MacScope_name,
			skipValues:  []int32{int32(types.MacScope_MAC_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.MacScope(i) },
		},
		{
			name:        "KemScope",
			protoMap:    types.KemScope_name,
			skipValues:  []int32{int32(types.KemScope_KEM_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.KemScope(i) },
		},
		{
			name:        "KeyAgreementScope",
			protoMap:    types.KeyAgreementScope_name,
			skipValues:  []int32{int32(types.KeyAgreementScope_KEY_AGREEMENT_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.KeyAgreementScope(i) },
		},
		{
			name:        "KdfScope",
			protoMap:    types.KdfScope_name,
			skipValues:  []int32{int32(types.KdfScope_KDF_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.KdfScope(i) },
		},
		{
			name:        "HashScope",
			protoMap:    types.HashScope_name,
			skipValues:  []int32{int32(types.HashScope_HASH_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.HashScope(i) },
		},
		{
			name:        "KeyWrappingScope",
			protoMap:    types.KeyWrappingScope_name,
			skipValues:  []int32{int32(types.KeyWrappingScope_KEY_WRAPPING_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.KeyWrappingScope(i) },
		},
		{
			name:        "SymmetricCipherScope",
			protoMap:    types.SymmetricCipherScope_name,
			skipValues:  []int32{int32(types.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.SymmetricCipherScope(i) },
		},
		{
			name:        "DiskEncryptionScope",
			protoMap:    types.DiskEncryptionScope_name,
			skipValues:  []int32{int32(types.DiskEncryptionScope_DISK_ENCRYPTION_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.DiskEncryptionScope(i) },
		},
		{
			name:        "GenericSecretScope",
			protoMap:    types.GenericSecretScope_name,
			skipValues:  []int32{int32(types.GenericSecretScope_GENERIC_SECRET_SCOPE_UNSPECIFIED)},
			protoScopFn: func(i int32) any { return types.GenericSecretScope(i) },
		},
	}
	collectedScopes := make(map[Scope]bool)
	for _, l := range ls {
		for k, v := range l.protoMap {
			if slices.Contains(l.skipValues, k) {
				continue
			}
			protoScope := l.protoScopFn(k)
			s, ok := ScopeFromProto(protoScope)
			require.True(t, ok, "Failed to obtain scope from proto scope %v", v)
			collectedScopes[s] = true
		}
	}
	for s := ScopeUnknown + 1; s < scopeMax; s++ {
		require.Contains(t, collectedScopes, s, "Scope %d cannot be obtained from any proto scope", s)
		_, ok := collectedScopes[s]
		require.True(t, ok, "Scope %d cannot be obtained from any proto scope", s)
	}
}
