package software_test

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// ECDSA — P-384 / P-521 curve generalization
// ============================================================================

// ecdsaDetails builds an AlgorithmDetails for the given curve/hash pair.
// hash may be HASH_ALGORITHM_UNSPECIFIED to exercise the curve-appropriate
// default (P-256->SHA-256, P-384->SHA-384, P-521->SHA-512).
func ecdsaDetails(curve types.EllipticCurve, hash types.HashAlgorithm) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: curve,
				Hash:  hash,
			},
		},
	}
}

func genECDSAKeyWithAlgorithm(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result
}

func TestGenerateKey_ECDSA_P384_happyPath(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	_, result := genECDSAKeyWithAlgorithm(t, alg)

	priv, err := x509.ParseECPrivateKey(result.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if priv.Curve.Params().Name != "P-384" {
		t.Errorf("curve = %s, want P-384", priv.Curve.Params().Name)
	}
}

func TestGenerateKey_ECDSA_P521_happyPath(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	_, result := genECDSAKeyWithAlgorithm(t, alg)

	priv, err := x509.ParseECPrivateKey(result.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if priv.Curve.Params().Name != "P-521" {
		t.Errorf("curve = %s, want P-521", priv.Curve.Params().Name)
	}
}

func TestGenerateKey_ECDSA_unsupportedCurve_returnsError(t *testing.T) {
	p := software.New()
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_SECP256K1, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err == nil {
		t.Fatal("expected error for unsupported curve secp256k1")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

func TestSignVerify_ECDSA_P384_defaultHash_roundTrip(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed with P-384, default hash")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true")
	}
}

func TestSignVerify_ECDSA_P521_defaultHash_roundTrip(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed with P-521, default hash")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSignVerify_ECDSA_P384_explicitSHA512_roundTrip proves a hash STRONGER
// than the curve's minimum (P-384's minimum is SHA-384) is accepted, not
// just the exact default.
func TestSignVerify_ECDSA_P384_explicitSHA512_roundTrip(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_SHA512)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSign_ECDSA_P521_hashBelowMinimum_returnsError proves the minimum-
// strength contract from EcdsaParams' ecdsa_curve_hash_match CEL rule is
// enforced here too: P-521 requires exactly SHA-512, so SHA-256 must be
// rejected rather than silently weakening the effective security.
func TestSign_ECDSA_P521_hashBelowMinimum_returnsError(t *testing.T) {
	genAlg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, genAlg)

	signAlg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   signAlg,
	})
	if err == nil {
		t.Fatal("expected error: SHA-256 is below P-521's minimum (SHA-512)")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_ECDSA_P384_hashBelowMinimum_returnsError(t *testing.T) {
	genAlg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, genAlg)

	signAlg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   signAlg,
	})
	if err == nil {
		t.Fatal("expected error: SHA-256 is below P-384's minimum (SHA-384)")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSignVerifyDigest_ECDSA_P384_roundTrip(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	digest := sha512.Sum384([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Digest:      digest[:],
		Signature:   signResp.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true")
	}
}

func TestSignVerifyDigest_ECDSA_P521_roundTrip(t *testing.T) {
	alg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	digest := sha512.Sum512([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Digest:      digest[:],
		Signature:   signResp.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSign_ECDSA_curveMismatch_returnsError proves the parsed-key-vs-declared
// -curve cross-check fires: a real P-256 key signed under a P-384 algorithm
// declaration must be rejected, not silently signed at the wrong (lower)
// effective security level.
func TestSign_ECDSA_curveMismatch_returnsError(t *testing.T) {
	_, keyMaterial := genECDSAKey(t) // P-256 key (see ecdsa_test.go)

	mismatchedAlg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	_, err := software.New().Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   mismatchedAlg,
	})
	if err == nil {
		t.Fatal("expected error: key is P-256 but algorithm declares P-384")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerify_ECDSA_curveMismatch_returnsError(t *testing.T) {
	_, keyMaterial := genECDSAKey(t) // P-256 key

	mismatchedAlg := ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	_, err := software.New().Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("payload"),
		Signature:   []byte("fake-sig"),
		Algorithm:   mismatchedAlg,
	})
	if err == nil {
		t.Fatal("expected error: key is P-256 but algorithm declares P-521")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
