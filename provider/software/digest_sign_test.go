package software_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// SignDigest / VerifyDigest — AlgorithmDetails Dispatch
// ============================================================================

func TestSignDigest_ECDSA_P256_happyPath(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	digest := sha256.Sum256([]byte("pre-hashed by the caller"))

	result, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(result.GetSignature()) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestSignDigest_VerifyDigest_roundtrip(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	ctx := context.Background()
	digest := sha256.Sum256([]byte("round-trip payload"))

	signResult, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	verifyResult, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Digest:      digest[:],
		Signature:   signResult.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true for a correctly round-tripped digest signature")
	}
}

func TestSignDigest_MLDSA_returnsInvalidArgument(t *testing.T) {
	// Pure ML-DSA is not prehashable — SignDigest must reject it with a
	// specific, explanatory error, not the generic "unsupported type" message
	// a truly unrecognized algorithm would get.
	_, err := software.New().SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
		Algorithm:   mlDSA65Details(),
	})
	if err == nil {
		t.Fatal("expected error for ML-DSA SignDigest")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerifyDigest_MLDSA_returnsInvalidArgument(t *testing.T) {
	_, err := software.New().VerifyDigest(context.Background(), &providerpb.VerifyDigestRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
		Signature:   []byte("fake-sig"),
		Algorithm:   mlDSA65Details(),
	})
	if err == nil {
		t.Fatal("expected error for ML-DSA VerifyDigest")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestSignDigest_unsetAlgorithm_returnsInvalidArgument proves an unset
// algorithm is rejected. protovalidate (wired into every software.Provider
// method) now catches this via AlgorithmDetails' required=true constraint
// before dispatch reaches the switch's default case, so the error is
// CodeInvalidArgument rather than the CodeNotImplemented the default case
// itself would return.
func TestSignDigest_unsetAlgorithm_returnsInvalidArgument(t *testing.T) {
	_, err := software.New().SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
	})
	if err == nil {
		t.Fatal("expected error for unset algorithm")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestVerifyDigest_unsetAlgorithm_returnsInvalidArgument is the VerifyDigest
// analogue of TestSignDigest_unsetAlgorithm_returnsInvalidArgument.
func TestVerifyDigest_unsetAlgorithm_returnsInvalidArgument(t *testing.T) {
	_, err := software.New().VerifyDigest(context.Background(), &providerpb.VerifyDigestRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
		Signature:   []byte("fake-sig"),
	})
	if err == nil {
		t.Fatal("expected error for unset algorithm")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
