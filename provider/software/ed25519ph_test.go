package software_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// Ed25519ph — Prehashed Signing via SignDigest/VerifyDigest
// Matches the catalog's "ed25519ph" template. RFC 8032 defines Ed25519ph's
// PH function as exactly SHA-512 — unlike RSA's prehashed variants, there is
// no other hash choice, so SignDigestRequest.hash_algorithm here is
// validated against a single fixed expectation rather than used to select
// among several.
// ============================================================================

func ed25519PHDetails() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{Variant: types.Ed25519Variant_ED25519_VARIANT_PH},
		},
	}
}

func TestSignVerifyDigest_Ed25519PH_roundTrip(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	ctx := context.Background()
	digest := sha512.Sum512([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512,
		Algorithm:     ed25519PHDetails(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if got := len(signResp.GetSignature()); got != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", got, ed25519.SignatureSize)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial:   keyMaterial.GetPublicKeyBytes(),
		Digest:        digest[:],
		Signature:     signResp.GetSignature(),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512,
		Algorithm:     ed25519PHDetails(),
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSignDigest_Ed25519PH_variantUnspecified_defaultsToPH proves the
// UNSPECIFIED variant is treated as Ed25519ph for SignDigest — the opposite
// default from plain Sign, where UNSPECIFIED means pure Ed25519.
func TestSignDigest_Ed25519PH_variantUnspecified_defaultsToPH(t *testing.T) {
	unspecifiedAlg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{Ed25519: &types.Ed25519Params{}},
	}
	p, keyMaterial := genEd25519Key(t)
	digest := sha512.Sum512([]byte("payload"))

	signResp, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512, Algorithm: unspecifiedAlg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if got := len(signResp.GetSignature()); got != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", got, ed25519.SignatureSize)
	}
}

func TestVerifyDigest_Ed25519PH_tamperedSignature_returnsFalse(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	ctx := context.Background()
	digest := sha512.Sum512([]byte("payload"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512, Algorithm: ed25519PHDetails(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	tampered := make([]byte, len(signResp.GetSignature()))
	copy(tampered, signResp.GetSignature())
	tampered[len(tampered)/2] ^= 0xFF

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Digest: digest[:], Signature: tampered,
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512, Algorithm: ed25519PHDetails(),
	})
	if err != nil {
		t.Fatalf("VerifyDigest should not error on invalid signature, got: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("expected valid=false for tampered signature")
	}
}

func TestVerifyDigest_Ed25519PH_tamperedDigest_returnsFalse(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	ctx := context.Background()
	digest := sha512.Sum512([]byte("original"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512, Algorithm: ed25519PHDetails(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	tamperedDigest := sha512.Sum512([]byte("tampered"))
	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Digest: tamperedDigest[:], Signature: signResp.GetSignature(),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512, Algorithm: ed25519PHDetails(),
	})
	if err != nil {
		t.Fatalf("VerifyDigest should not error on invalid signature, got: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("expected valid=false for tampered digest")
	}
}

// TestSignDigest_Ed25519PH_wrongHashAlgorithm_returnsError proves a
// hash_algorithm other than SHA-512 is rejected outright — even one that
// coincidentally also produces a 64-byte digest (SHA3-512), since RFC 8032
// fixes Ed25519ph's PH function to SHA-512 specifically, not "any 64-byte
// hash". Digest-length validation alone cannot catch this.
func TestSignDigest_Ed25519PH_wrongHashAlgorithm_returnsError(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	digest := make([]byte, 64) // SHA3-512 output length, same as SHA-512's

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest,
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA3_512, Algorithm: ed25519PHDetails(),
	})
	if err == nil {
		t.Fatal("expected error for hash_algorithm=SHA3-512")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestSignDigest_Ed25519_pureVariant_returnsError proves the pure variant is
// rejected through SignDigest — pure Ed25519 is not prehashable at all.
func TestSignDigest_Ed25519_pureVariant_returnsError(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	digest := sha512.Sum512([]byte("payload"))

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA512, Algorithm: ed25519Details(),
	})
	if err == nil {
		t.Fatal("expected error for pure Ed25519 via SignDigest")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
