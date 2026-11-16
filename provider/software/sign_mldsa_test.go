package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// genMLDSAKey generates an ML-DSA-65 key and returns the provider and key material.
func genMLDSAKey(t *testing.T) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey ml-dsa-65: %v", err)
	}
	return p, result
}

// ============================================================================
// ML-DSA-65 Sign Tests
// ============================================================================

func TestSign_MLDSA65_happyPath(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	result, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("post-quantum message"),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Sign ml-dsa-65: %v", err)
	}
	if len(result.GetSignature()) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestSign_MLDSA65_signatureIsCorrectSize(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	result, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("message"),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Sign ml-dsa-65: %v", err)
	}
	if len(result.GetSignature()) != mldsa65.SignatureSize {
		t.Errorf("signature size: got %d want %d", len(result.GetSignature()), mldsa65.SignatureSize)
	}
}

func TestSign_MLDSA65_nilAlgorithm_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: []byte("fake-key"),
		Input:       []byte("data"),
		Algorithm:   nil,
	})
	if err == nil {
		t.Fatal("expected error for nil algorithm")
	}
}

// ============================================================================
// ML-DSA-65 Verify Tests
// ============================================================================

func TestVerify_MLDSA65_happyPath_validSignature(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	ctx := context.Background()
	payload := []byte("post-quantum test message")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("Verify: expected valid=true for correct signature")
	}
}

func TestVerify_MLDSA65_tamperedPayload_returnsFalse(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	ctx := context.Background()

	signResult, _ := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("original"),
		Algorithm:   mlDSA65Details(),
	})

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("tampered"),
		Signature:   signResult.GetSignature(),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("Verify: expected valid=false for tampered payload")
	}
}

func TestVerify_MLDSA65_invalidSignatureBytes_returnsFalse(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	verifyResult, err := p.Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("data"),
		Signature:   []byte("not-a-valid-signature"),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Verify with invalid sig should not return error: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("Verify: expected valid=false for garbage signature bytes")
	}
}

// ============================================================================
// Round-Trip Tests
// ============================================================================

func TestSignVerify_MLDSA65_roundTrip(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payloads := [][]byte{
		[]byte("short"),
		[]byte("a longer post-quantum message"),
		make([]byte, 4096),
	}
	for _, payload := range payloads {
		signResult, err := p.Sign(ctx, &providerpb.SignRequest{
			KeyMaterial: keyMaterial.GetKeyMaterial(),
			Input:       payload,
			Algorithm:   mlDSA65Details(),
		})
		if err != nil {
			t.Fatalf("Sign (len=%d): %v", len(payload), err)
		}
		verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
			KeyMaterial: keyMaterial.GetPublicKeyBytes(),
			Input:       payload,
			Signature:   signResult.GetSignature(),
			Algorithm:   mlDSA65Details(),
		})
		if err != nil {
			t.Fatalf("Verify (len=%d): %v", len(payload), err)
		}
		if !verifyResult.GetValid() {
			t.Errorf("round-trip failed for payload len=%d", len(payload))
		}
	}
}

// ============================================================================
// Smoke Test — both algorithms fully operational
// ============================================================================

func TestProvider_AllOperationsAvailable(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	algorithms := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"ecdsa-p256-sha256", ecdsaP256Details()},
		{"ml-dsa-65", mlDSA65Details()},
	}
	for _, tc := range algorithms {
		keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
			Algorithm: tc.alg,
		})
		if err != nil {
			t.Errorf("%s GenerateKey: %v", tc.name, err)
			continue
		}
		signResult, err := p.Sign(ctx, &providerpb.SignRequest{
			KeyMaterial: keyMaterial.GetKeyMaterial(),
			Input:       []byte("test"),
			Algorithm:   tc.alg,
		})
		if err != nil {
			t.Errorf("%s Sign: %v", tc.name, err)
			continue
		}
		verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
			KeyMaterial: keyMaterial.GetPublicKeyBytes(),
			Input:       []byte("test"),
			Signature:   signResult.GetSignature(),
			Algorithm:   tc.alg,
		})
		if err != nil {
			t.Errorf("%s Verify: %v", tc.name, err)
			continue
		}
		if !verifyResult.GetValid() {
			t.Errorf("%s round-trip failed", tc.name)
		}
	}
}
