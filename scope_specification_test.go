package core

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/stretchr/testify/require"
)

// extractScopeSpecFields returns (Security, AdditionalProperties) from any ScopeSpec variant.
func extractScopeSpecFields(s *types.ScopeSpecification) (any, *types.UniversalSecurityProperties, map[string]string) {
	switch v := s.ScopeSpec.(type) {
	case *types.ScopeSpecification_Aead:
		return v.Aead.Scope, v.Aead.Security, v.Aead.AdditionalProperties
	case *types.ScopeSpecification_DiskEncryption:
		return v.DiskEncryption.Scope, v.DiskEncryption.Security, v.DiskEncryption.AdditionalProperties
	case *types.ScopeSpecification_GenericSecret:
		return v.GenericSecret.Scope, v.GenericSecret.Security, v.GenericSecret.AdditionalProperties
	case *types.ScopeSpecification_KeyAgreement:
		return v.KeyAgreement.Scope, v.KeyAgreement.Security, v.KeyAgreement.AdditionalProperties
	case *types.ScopeSpecification_Hash:
		return v.Hash.Scope, v.Hash.Security, v.Hash.AdditionalProperties
	case *types.ScopeSpecification_Kdf:
		return v.Kdf.Scope, v.Kdf.Security, v.Kdf.AdditionalProperties
	case *types.ScopeSpecification_Kem:
		return v.Kem.Scope, v.Kem.Security, v.Kem.AdditionalProperties
	case *types.ScopeSpecification_KeyWrapping:
		return v.KeyWrapping.Scope, v.KeyWrapping.Security, v.KeyWrapping.AdditionalProperties
	case *types.ScopeSpecification_Mac:
		return v.Mac.Scope, v.Mac.Security, v.Mac.AdditionalProperties
	case *types.ScopeSpecification_Signature:
		return v.Signature.Scope, v.Signature.Security, v.Signature.AdditionalProperties
	case *types.ScopeSpecification_SymmetricCipher:
		return v.SymmetricCipher.Scope, v.SymmetricCipher.Security, v.SymmetricCipher.AdditionalProperties
	default:
		return nil, nil, nil
	}
}
func TestScopeSpecification_Completeness(t *testing.T) {
	tc := []struct {
		name            string
		securityProps   *SecurityProperties
		additionalProps map[string]string
	}{
		{
			name:            "no options",
			securityProps:   nil,
			additionalProps: nil,
		},
		{
			name: "only security properties",
			securityProps: &SecurityProperties{
				SecurityStrength: 128,
				SecurityLevel:    types.NistSecurityLevel_NIST_SECURITY_LEVEL_1,
				QuantumSafe:      false,
			},
			additionalProps: nil,
		},
		{
			name:            "only additional properties",
			securityProps:   nil,
			additionalProps: map[string]string{"vendor": "example"},
		},
		{
			name: "both security and additional properties",
			securityProps: &SecurityProperties{
				SecurityStrength: 256,
				SecurityLevel:    types.NistSecurityLevel_NIST_SECURITY_LEVEL_3,
				QuantumSafe:      true,
			},
			additionalProps: map[string]string{"vendor": "example"},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			for _, s := range ListScopes() {
				scopeSpec, err := NewScopeSpecification(ctx, s, tt.securityProps, nil, tt.additionalProps)
				require.NoError(t, err, "Error creating scope specification for scope %v: %v", s.String(), err)
				spec, err := scopeSpec.ToProto(ctx)
				require.NoError(t, err, "Error converting scope specification to proto for scope %v: %v", s.String(), err)
				require.NotNil(t, spec, "Scope specification for scope %v is nil", s.String())
				pScope, security, additional := extractScopeSpecFields(spec)
				require.NotNil(t, pScope, "Scope field is nil for scope %v", s.String())
				require.Equal(t, s.ToProto(), pScope, "Scope does not match for scope %v", s.String())
				require.Equal(t, tt.securityProps.ToProto(), security)
				require.Equal(t, tt.additionalProps, additional)
			}
		})
	}
}

func TestScopeSpecification_SignatureOptions(t *testing.T) {
	s := ScopeSignatureStandard
	props := &SecurityProperties{
		SecurityStrength: 256,
	}
	ctx := context.Background()
	primitiveProps, err := NewPrimitiveSpecificProperties(
		ctx,
		WithNonMalleable(),
		WithDeterministic(),
	)
	require.NoError(t, err, "Error creating primitive specific properties")
	additionalProps := map[string]string{"vendor": "example"}
	scopeSpec, err := NewScopeSpecification(ctx, s, props, primitiveProps, additionalProps)
	require.NoError(t, err, "Error creating scope specification for scope %v: %v", s.String(), err)
	spec, err := scopeSpec.ToProto(ctx)
	require.NoError(t, err, "Error converting scope specification to proto for scope %v: %v", s.String(), err)

	sigSpec, ok := spec.ScopeSpec.(*types.ScopeSpecification_Signature)
	require.True(t, ok, "Scope specification is not a signature scope specification")
	require.Equal(t, sigSpec.Signature.Security, props.ToProto(), "Security properties do not match")
	require.NotNil(t, sigSpec.Signature.NonMalleable, "Non-malleability option is nil")
	require.True(t, *sigSpec.Signature.NonMalleable, "Non-malleability option is false")
	require.NotNil(t, sigSpec.Signature.Deterministic, "Deterministic option is nil")
	require.True(t, *sigSpec.Signature.Deterministic, "Deterministic option is false")
	require.Equal(t, sigSpec.Signature.AdditionalProperties["vendor"], "example", "Additional properties do not match")
}

func TestScopeSpecification_AcceptedDigestHashesRoundTrip(t *testing.T) {
	ctx := context.Background()
	hashes := []types.HashAlgorithm{types.HashAlgorithm_HASH_ALGORITHM_SHA384, types.HashAlgorithm_HASH_ALGORITHM_SHA512}
	spec := (&ScopeSpecification{Scope: ScopeSignaturePrehashed}).WithAcceptedDigestHashes(hashes)

	data, err := spec.Serialize(ctx)
	require.NoError(t, err)
	got := &ScopeSpecification{}
	require.NoError(t, got.Deserialize(ctx, data))
	require.Equal(t, ScopeSignaturePrehashed, got.Scope)
	require.Equal(t, hashes, got.AcceptedDigestHashes(), "order is the preference and must survive a round trip")

	// WithAcceptedDigestHashes keeps other signature properties and never
	// mutates its receiver or the caller's slice.
	base := &ScopeSpecification{Scope: ScopeSignaturePrehashed, PrimitiveSpecificProps: &SignatureProperties{Deterministic: true}}
	narrowed := base.WithAcceptedDigestHashes(hashes)
	hashes[0] = types.HashAlgorithm_HASH_ALGORITHM_SHA256
	require.Nil(t, base.AcceptedDigestHashes())
	require.True(t, narrowed.PrimitiveSpecificProps.(*SignatureProperties).Deterministic)
	require.Equal(t, types.HashAlgorithm_HASH_ALGORITHM_SHA384, narrowed.AcceptedDigestHashes()[0])

	require.Nil(t, (&ScopeSpecification{Scope: ScopeSignatureStandard}).AcceptedDigestHashes())
	require.True(t, ScopeSignaturePrehashedWithContext.IsPrehashed())
	require.False(t, ScopeSignatureWithContext.IsPrehashed())
}

// A spec that carries only digest hashes must not claim deterministic=false or
// non_malleable=false: reading a key would then contradict its template
// (e.g. ed25519ph is both). False properties stay unset; true ones are kept.
func TestScopeSpecification_ToProtoLeavesFalseSignaturePropertiesUnset(t *testing.T) {
	ctx := context.Background()
	hashes := []types.HashAlgorithm{types.HashAlgorithm_HASH_ALGORITHM_SHA512}

	p, err := (&ScopeSpecification{Scope: ScopeSignaturePrehashed}).WithAcceptedDigestHashes(hashes).ToProto(ctx)
	require.NoError(t, err)
	sig := p.GetSignature()
	require.Nil(t, sig.Deterministic)
	require.Nil(t, sig.NonMalleable)
	require.Equal(t, hashes, sig.GetAcceptedDigestHashes())

	p, err = (&ScopeSpecification{
		Scope:                  ScopeSignaturePrehashed,
		PrimitiveSpecificProps: &SignatureProperties{Deterministic: true, AcceptedDigestHashes: hashes},
	}).ToProto(ctx)
	require.NoError(t, err)
	require.True(t, p.GetSignature().GetDeterministic())
	require.Nil(t, p.GetSignature().NonMalleable)
}

func TestScopeSpecification_AEADOptions(t *testing.T) {
	s := ScopeAeadStandard
	props := &SecurityProperties{
		SecurityStrength: 128,
	}
	ctx := context.Background()
	primitiveProps, err := NewPrimitiveSpecificProperties(ctx, WithNonceMisuseResistance())
	require.NoError(t, err, "Error creating primitive specific properties")
	additionalProps := map[string]string{"vendor": "example"}
	scopeSpec, err := NewScopeSpecification(ctx, s, props, primitiveProps, additionalProps)
	require.NoError(t, err, "Error creating scope specification for scope %v: %v", s.String(), err)
	spec, err := scopeSpec.ToProto(ctx)
	require.NoError(t, err, "Error converting scope specification to proto for scope %v: %v", s.String(), err)
	aeadSpec, ok := spec.ScopeSpec.(*types.ScopeSpecification_Aead)
	require.True(t, ok, "Scope specification is not an AEAD scope specification")
	require.Equal(t, aeadSpec.Aead.Security, props.ToProto(), "Security properties do not match")
	require.NotNil(t, aeadSpec.Aead.NonceMisuseResistant, "Nonce misuse resistance option is nil")
	require.True(t, *aeadSpec.Aead.NonceMisuseResistant, "Nonce misuse resistance option is false")
	require.Equal(t, aeadSpec.Aead.AdditionalProperties["vendor"], "example", "Additional properties do not match")
}

func TestScopeSpecification_KeyAgreementOptions(t *testing.T) {
	s := ScopeKeyAgreementStandard
	props := &SecurityProperties{
		SecurityStrength: 192,
	}
	ctx := context.Background()
	primitiveProps, err := NewPrimitiveSpecificProperties(ctx, WithForwardSecrecy())
	require.NoError(t, err, "Error creating primitive specific properties")
	additionalProps := map[string]string{"vendor": "example"}
	scopeSpec, err := NewScopeSpecification(ctx, s, props, primitiveProps, additionalProps)
	require.NoError(t, err, "Error creating scope specification for scope %v: %v", s.String(), err)
	spec, err := scopeSpec.ToProto(ctx)
	require.NoError(t, err, "Error converting scope specification to proto for scope %v: %v", s.String(), err)
	kaSpec, ok := spec.ScopeSpec.(*types.ScopeSpecification_KeyAgreement)
	require.True(t, ok, "Scope specification is not a key agreement scope specification")
	require.Equal(t, kaSpec.KeyAgreement.Security, props.ToProto(), "Security properties do not match")
	require.NotNil(t, kaSpec.KeyAgreement.ForwardSecrecy, "Forward secrecy option is nil")
	require.True(t, *kaSpec.KeyAgreement.ForwardSecrecy, "Forward secrecy option is false")
	require.Equal(t, kaSpec.KeyAgreement.AdditionalProperties["vendor"], "example", "Additional properties do not match")
}

func TestScopeSpecification_KDFOptions(t *testing.T) {
	s := ScopeKdfPassword
	props := &SecurityProperties{
		SecurityStrength: 256,
	}
	ctx := context.Background()
	primitiveProps, err := NewPrimitiveSpecificProperties(ctx, WithMemoryHard())
	require.NoError(t, err, "Error creating primitive specific properties")
	additionalProps := map[string]string{"vendor": "example"}
	scopeSpec, err := NewScopeSpecification(ctx, s, props, primitiveProps, additionalProps)
	require.NoError(t, err, "Error creating scope specification for scope %v: %v", s.String(), err)
	spec, err := scopeSpec.ToProto(ctx)
	require.NoError(t, err, "Error converting scope specification to proto for scope %v: %v", s.String(), err)
	kdfSpec, ok := spec.ScopeSpec.(*types.ScopeSpecification_Kdf)
	require.True(t, ok, "Scope specification is not a KDF scope specification")
	require.Equal(t, kdfSpec.Kdf.Security, props.ToProto(), "Security properties do not match")
	require.NotNil(t, kdfSpec.Kdf.MemoryHard, "Memory-hard option is nil")
	require.True(t, *kdfSpec.Kdf.MemoryHard, "Memory-hard option is false")
	require.Equal(t, kdfSpec.Kdf.AdditionalProperties["vendor"], "example", "Additional properties do not match")
}
