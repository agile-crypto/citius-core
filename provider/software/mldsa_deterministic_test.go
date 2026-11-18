package software_test

import (
	"bytes"
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// ML-DSA — MlDsaParams.deterministic
//
// sign.Scheme.Sign is deterministic-only; honoring deterministic=false (the
// proto3 zero value, matching FIPS 204 -3.6's recommendation to prefer
// hedged/randomized signing) requires dropping to the scheme-specific
// package-level SignTo function. These tests prove the flag actually
// changes signing behavior rather than just being accepted and ignored.
// ============================================================================

func mlDSA65DetailsWithDeterminism(deterministic bool) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{
				ParameterSet:  types.MlDsaParameterSet_ML_DSA_65,
				Deterministic: deterministic,
			},
		},
	}
}

func TestSign_MLDSA65_deterministicTrue_producesIdenticalSignatures(t *testing.T) {
	alg := mlDSA65DetailsWithDeterminism(true)
	p, keyMaterial := genMLDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed twice under deterministic=true")

	sig1, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign (1st): %v", err)
	}
	sig2, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign (2nd): %v", err)
	}
	if !bytes.Equal(sig1.GetSignature(), sig2.GetSignature()) {
		t.Error("deterministic=true: two signatures over the same payload should be byte-identical")
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: payload, Signature: sig1.GetSignature(), Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSign_MLDSA65_deterministicFalse_producesDifferentSignatures proves the
// default (deterministic=false, hedged) actually randomizes — the concrete
// regression this commit guards against is deterministic=false silently
// behaving exactly like deterministic=true because scheme.Sign ignores the
// flag entirely.
func TestSign_MLDSA65_deterministicFalse_producesDifferentSignatures(t *testing.T) {
	alg := mlDSA65DetailsWithDeterminism(false)
	p, keyMaterial := genMLDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed twice under deterministic=false")

	sig1, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign (1st): %v", err)
	}
	sig2, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign (2nd): %v", err)
	}
	if bytes.Equal(sig1.GetSignature(), sig2.GetSignature()) {
		t.Error("deterministic=false: two signatures over the same payload should differ (hedged signing)")
	}

	for _, sig := range [][]byte{sig1.GetSignature(), sig2.GetSignature()} {
		verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
			KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: payload, Signature: sig, Algorithm: alg,
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !verifyResult.GetValid() {
			t.Error("expected valid=true for a hedged signature")
		}
	}
}

// TestSign_MLDSA65_unsetDeterministic_defaultsToHedged proves the proto3
// zero value (an omitted MlDsaParams.deterministic field) behaves as
// deterministic=false, matching FIPS 204's recommended default — not as
// deterministic=true, which would be the "safer-looking" but wrong default
// for a bool field where zero value already means something specific.
func TestSign_MLDSA65_unsetDeterministic_defaultsToHedged(t *testing.T) {
	alg := mlDSA65Details() // Deterministic field left unset
	p, keyMaterial := genMLDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload")

	sig1, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign (1st): %v", err)
	}
	sig2, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign (2nd): %v", err)
	}
	if bytes.Equal(sig1.GetSignature(), sig2.GetSignature()) {
		t.Error("unset deterministic field should default to hedged (false): signatures should differ")
	}
}

func genMLDSAKeyWithAlgorithm(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result
}
