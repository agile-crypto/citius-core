package loopback_test

import (
	"bytes"
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/loopback"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ecdsaP256Details returns an AlgorithmDetails for ECDSA-P256-SHA256.
func ecdsaP256Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		},
	}
}

// Compile-time assertions
var (
	_ provider.Backend                     = (*loopback.Provider)(nil)
	_ provider.AlgorithmCapabilityProvider = (*loopback.Provider)(nil)
)

func TestProvider_Name(t *testing.T) {
	p := loopback.New()
	if got := p.Name(); got != "loopback" {
		t.Errorf("Name: got %q want %q", got, "loopback")
	}
}

func TestProvider_Type(t *testing.T) {
	p := loopback.New()
	if got := p.Type(); got != "loopback" {
		t.Errorf("Type: got %q want %q", got, "loopback")
	}
}

func TestProvider_SupportedAlgorithms_returnsBothM1Algorithms(t *testing.T) {
	p := loopback.New()
	algs := p.SupportedAlgorithms()
	if len(algs) == 0 {
		t.Fatal("expected at least one supported algorithm")
	}
	ids := make(map[string]bool)
	for _, id := range algs {
		ids[id] = true
	}
	for _, want := range []string{"ecdsa-p256-sha256-der", "ml-dsa-65"} {
		if !ids[want] {
			t.Errorf("missing algorithm %q", want)
		}
	}
}

func TestProvider_GenerateKey_returnsSyntheticBytes(t *testing.T) {
	p := loopback.New()
	req := &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()}
	result, err := p.GenerateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(result.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(result.GetKeyMaterial()) == 0 {
		t.Error("expected non-empty key material")
	}
}

func TestProvider_Sign_echoesInput(t *testing.T) {
	p := loopback.New()
	payload := []byte("hello world")
	req := &providerpb.SignRequest{
		Input: payload,
	}
	result, err := p.Sign(context.Background(), req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(result.GetSignature(), payload) {
		t.Errorf("Sign: signature should equal payload for loopback provider")
	}
}

func TestProvider_Verify_matchingInputAndSignature_returnsTrue(t *testing.T) {
	p := loopback.New()
	payload := []byte("test message")
	req := &providerpb.VerifyRequest{
		Input:     payload,
		Signature: payload, // loopback: sig == input
	}
	result, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.GetValid() {
		t.Error("Verify: expected valid=true when signature == input")
	}
}

func TestProvider_Verify_mismatchedSignature_returnsFalse(t *testing.T) {
	p := loopback.New()
	req := &providerpb.VerifyRequest{
		Input:     []byte("original"),
		Signature: []byte("tampered"),
	}
	result, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.GetValid() {
		t.Error("Verify: expected valid=false for mismatched signature")
	}
}

func TestProvider_Verify_emptySignature_returnsFalse(t *testing.T) {
	p := loopback.New()
	req := &providerpb.VerifyRequest{
		Input:     []byte("data"),
		Signature: nil,
	}
	result, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.GetValid() {
		t.Error("Verify: expected valid=false for nil signature")
	}
}

func TestProvider_SignThenVerify_roundtrip(t *testing.T) {
	p := loopback.New()
	ctx := context.Background()
	payload := []byte("round-trip test")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		Input: payload,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Input:     payload,
		Signature: signResult.GetSignature(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("round-trip: Sign then Verify should return valid=true")
	}
}

func TestProvider_DestroyKey_succeeds(t *testing.T) {
	p := loopback.New()
	_, err := p.DestroyKey(context.Background(), &providerpb.DestroyKeyRequest{KeyMaterial: []byte("any")})
	if err != nil {
		t.Errorf("DestroyKey: unexpected error %v", err)
	}
}

func TestProvider_ExportPublicKey_returnsDeterministicBytes(t *testing.T) {
	p := loopback.New()
	req := &providerpb.ExportPublicKeyRequest{KeyMaterial: []byte("test-key-123")}
	resp, err := p.ExportPublicKey(context.Background(), req)
	if err != nil {
		t.Fatalf("ExportPublicKey: %v", err)
	}
	if len(resp.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	// Should be deterministic for the same request
	resp2, _ := p.ExportPublicKey(context.Background(), req)
	if !bytes.Equal(resp.GetPublicKeyBytes(), resp2.GetPublicKeyBytes()) {
		t.Error("ExportPublicKey should be deterministic for same request")
	}
}
