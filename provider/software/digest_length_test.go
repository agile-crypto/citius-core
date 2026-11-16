package software_test

import (
	"context"
	"crypto/sha256"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// SignDigest / VerifyDigest — Digest Length Validation
// ============================================================================

func TestSignDigest_wrongDigestLength_returnsInvalidArgument(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	// A 20-byte digest cannot have come from SHA-256 (32 bytes).
	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        make([]byte, 20),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for digest length mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerifyDigest_wrongDigestLength_returnsInvalidArgument(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	_, err := p.VerifyDigest(context.Background(), &providerpb.VerifyDigestRequest{
		KeyMaterial:   keyMaterial.GetPublicKeyBytes(),
		Digest:        make([]byte, 20),
		Signature:     []byte("fake-sig"),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for digest length mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSignDigest_correctDigestLengthForDeclaredHash_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	digest := sha256.Sum256([]byte("payload"))

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
}

func TestSignDigest_sha384LengthMismatch_returnsInvalidArgument(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	digest := sha256.Sum256([]byte("payload")) // 32 bytes — wrong for SHA-384 (48 bytes)

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA384,
		Algorithm:     ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for digest length mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSignDigest_unspecifiedHashAlgorithm_skipsLengthCheck(t *testing.T) {
	// HASH_ALGORITHM_UNSPECIFIED (the zero value) has no fixed length, so any
	// digest length is accepted — this is what keeps the dispatch tests in
	// digest_sign_test.go (which don't declare a hash) passing.
	p, keyMaterial := genECDSAKey(t)

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      make([]byte, 20),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("SignDigest with unspecified hash_algorithm should not fail length validation: %v", err)
	}
}
