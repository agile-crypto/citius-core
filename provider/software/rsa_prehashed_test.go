package software_test

import (
	"context"
	"crypto/sha512"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// RSA — Prehashed Signing via SignDigest/VerifyDigest
//
// Matches the catalog's rsa-pss-{2048,3072,4096}-prehashed and
// rsa-pkcs1v15-2048-prehashed templates. These templates leave
// RsaPssParams.hash/RsaPkcs1V15Params.hash unset (HASH_ALGORITHM_UNSPECIFIED)
// since one prehashed template must accept digests produced under any hash
// the caller declares via SignDigestRequest.hash_algorithm — the digest bytes
// alone never say which hash produced them.
// ============================================================================

func TestSignVerifyDigest_RSAPSS_2048_SHA256_prehashed_roundTrip(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genRSAPSSKey(t, alg)
	ctx := context.Background()
	digest := sha512.Sum512_256([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if got := len(signResp.GetSignature()); got != 256 {
		t.Errorf("signature length = %d, want 256", got)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial:   keyMaterial.GetPublicKeyBytes(),
		Digest:        digest[:],
		Signature:     signResp.GetSignature(),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSignVerifyDigest_RSAPSS_hashAlgorithmSHA384_ignoresUnsetParamsHash
// proves the request's hash_algorithm (not the unset RsaPssParams.hash)
// determines the actual hash used — SHA-384 digests round-trip correctly
// even though the template declares no fixed hash.
func TestSignVerifyDigest_RSAPSS_hashAlgorithmSHA384_ignoresUnsetParamsHash(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genRSAPSSKey(t, alg)
	ctx := context.Background()
	digest := sha512.Sum384([]byte("hashed with SHA-384 by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA384,
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial:   keyMaterial.GetPublicKeyBytes(),
		Digest:        digest[:],
		Signature:     signResp.GetSignature(),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA384,
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true")
	}
}

func TestVerifyDigest_RSAPSS_prehashed_tamperedSignature_returnsFalse(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genRSAPSSKey(t, alg)
	ctx := context.Background()
	digest := sha512.Sum512_256([]byte("payload"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	tampered := make([]byte, len(signResp.GetSignature()))
	copy(tampered, signResp.GetSignature())
	tampered[len(tampered)/2] ^= 0xFF

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Digest: digest[:], Signature: tampered,
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest should not error on invalid signature, got: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("expected valid=false for tampered signature")
	}
}

func TestSignVerifyDigest_RSAPKCS1v15_2048_SHA256_prehashed_roundTrip(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genRSAPKCS1v15Key(t, alg)
	ctx := context.Background()
	digest := sha512.Sum512_256([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if got := len(signResp.GetSignature()); got != 256 {
		t.Errorf("signature length = %d, want 256", got)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial:   keyMaterial.GetPublicKeyBytes(),
		Digest:        digest[:],
		Signature:     signResp.GetSignature(),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true")
	}
}

func TestVerifyDigest_RSAPKCS1v15_prehashed_tamperedDigest_returnsFalse(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genRSAPKCS1v15Key(t, alg)
	ctx := context.Background()
	digest := sha512.Sum512_256([]byte("original"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	tamperedDigest := sha512.Sum512_256([]byte("tampered"))
	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Digest: tamperedDigest[:], Signature: signResp.GetSignature(),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest should not error on invalid signature, got: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("expected valid=false for tampered digest")
	}
}

// TestSignDigest_RSAPSS_keySizeMismatch_returnsError proves checkRSAKeySize
// still applies to the prehashed path — the same cross-check signRSAPSS uses.
func TestSignDigest_RSAPSS_keySizeMismatch_returnsError(t *testing.T) {
	genAlg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	p, keyMaterial := genRSAPSSKey(t, genAlg)
	mismatchedAlg := rsaPSSDetails(3072, types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	digest := sha512.Sum512_256([]byte("payload"))

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Digest: digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256, Algorithm: mismatchedAlg,
	})
	if err == nil {
		t.Fatal("expected error: key is 2048 bits but algorithm declares 3072")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
