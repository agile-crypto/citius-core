package software_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
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

// mlDSA65Details returns an AlgorithmDetails for ML-DSA-65.
func mlDSA65Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{
				ParameterSet: types.MlDsaParameterSet_ML_DSA_65,
			},
		},
	}
}

// ============================================================================
// ECDSA-P256 Key Generation Tests
// ============================================================================

func TestGenerateKey_ECDSA_P256_happyPath(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	resp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(resp.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(resp.GetKeyMaterial()) == 0 {
		t.Error("expected non-empty key material")
	}
}

func TestGenerateKey_ECDSA_P256_publicKeyIsDERParseable(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub, err := x509.ParsePKIXPublicKey(resp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve.Params().Name != "P-256" {
		t.Errorf("curve: got %q want %q", ecPub.Curve.Params().Name, "P-256")
	}
}

func TestGenerateKey_ECDSA_P256_privateKeyIsDERParseable(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	priv, err := x509.ParseECPrivateKey(resp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if priv.Curve.Params().Name != "P-256" {
		t.Errorf("curve: got %q want %q", priv.Curve.Params().Name, "P-256")
	}
}

func TestGenerateKey_ECDSA_P256_keysAreUnique(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	r1, _ := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	r2, _ := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated keys should not be identical")
	}
}

func TestGenerateKey_unknownAlgorithm_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_RsaPss{
				RsaPss: &types.RsaPssParams{},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func genECDSAKey(t *testing.T) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result
}

func TestSign_ECDSA_P256_happyPath(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	result, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("hello world"),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.GetSignature()) == 0 {
		t.Error("expected non-empty signature")
	}
}

// TestSign_unsupportedAlgorithm_returnsError uses Ed448 — a valid
// AlgorithmDetails arm this provider does not implement.  Ed25519 was the
// "unsupported algorithm" example here before Ed25519 was implemented; Ed448
// is not on the near-term roadmap and so is less likely to go stale the same
// way (see the analogous fix for ECDSA's unsupported-curve tests).
func TestSign_unsupportedAlgorithm_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: []byte("fake-key"),
		Input:       []byte("data"),
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_Ed448{
				Ed448: &types.Ed448Params{},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

func TestSign_emptyPayload_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte{},
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign(empty): %v", err)
	}
}

// TestSignVerify_emptyPayload_roundTrips proves Verify accepts an empty
// input just as Sign does — it must be able to verify whatever Sign
// produced, and Sign supports signing an empty message (see
// TestSign_emptyPayload_succeeds).
func TestSignVerify_emptyPayload_roundTrips(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	ctx := context.Background()

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte{},
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign(empty): %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte{},
		Signature:   signResult.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Verify(empty): %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("Verify(empty): expected valid=true for a signature over an empty message")
	}
}

func TestVerify_ECDSA_P256_happyPath_validSignature(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	ctx := context.Background()
	payload := []byte("test message")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("Verify: expected valid=true for correct signature")
	}
}

func TestVerify_ECDSA_P256_tamperedPayload_returnsFalse(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	ctx := context.Background()

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("original"),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("tampered"),
		Signature:   signResult.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("Verify: expected valid=false for tampered payload")
	}
}

func TestVerify_ECDSA_P256_tamperedSignature_returnsFalse(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	ctx := context.Background()
	payload := []byte("data")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := make([]byte, len(signResult.GetSignature()))
	copy(tampered, signResult.GetSignature())
	tampered[len(tampered)/2] ^= 0xFF

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   tampered,
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("Verify: expected valid=false for tampered signature")
	}
}

// TestVerify_unsupportedAlgorithm_returnsError uses Ed448 — see
// TestSign_unsupportedAlgorithm_returnsError for why.
func TestVerify_unsupportedAlgorithm_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: []byte("fake-key"),
		Input:       []byte("x"),
		Signature:   []byte("y"),
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_Ed448{
				Ed448: &types.Ed448Params{},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestSign_ECDSA_unsupportedCurve_returnsError uses secp256k1 — valid per
// EcdsaParams.curve's proto constraint but not implemented by this provider.
// P-384/P-521 were the "unsupported curve" example here before ECDSA was
// generalized to those curves; secp256k1 remains genuinely unsupported.
func TestSign_ECDSA_unsupportedCurve_returnsError(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("data"),
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_Ecdsa{
				Ecdsa: &types.EcdsaParams{
					Curve: types.EllipticCurve_ELLIPTIC_CURVE_SECP256K1,
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported curve secp256k1 on Sign")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

func TestVerify_ECDSA_unsupportedCurve_returnsError(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	// Sign with the correct P-256 algorithm first.
	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("data"),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Verify with secp256k1 — genuinely unsupported, should be rejected.
	_, err = p.Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("data"),
		Signature:   signResult.GetSignature(),
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_Ecdsa{
				Ecdsa: &types.EcdsaParams{
					Curve: types.EllipticCurve_ELLIPTIC_CURVE_SECP256K1,
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported curve secp256k1 on Verify")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

func TestSignVerify_ECDSA_P256_roundTrip(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	keyResult, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payloads := [][]byte{
		[]byte("short"),
		[]byte("a longer message with punctuation: !@#$%^&"),
		make([]byte, 4096),
	}

	for _, payload := range payloads {
		signResult, err := p.Sign(ctx, &providerpb.SignRequest{
			KeyMaterial: keyResult.GetKeyMaterial(),
			Input:       payload,
			Algorithm:   ecdsaP256Details(),
		})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
			KeyMaterial: keyResult.GetPublicKeyBytes(),
			Input:       payload,
			Signature:   signResult.GetSignature(),
			Algorithm:   ecdsaP256Details(),
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !verifyResult.GetValid() {
			t.Errorf("round-trip failed for payload of length %d", len(payload))
		}
	}
}
