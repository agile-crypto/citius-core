package software_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// RSA-PKCS1v15 — matches the catalog entries in proto/standard_algorithms/signatures.json
// ============================================================================

func rsaPKCS1v15Details(keySizeBits uint32, hash types.HashAlgorithm) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPkcs1V15{
			RsaPkcs1V15: &types.RsaPkcs1V15Params{
				KeySizeBits: keySizeBits,
				Hash:        hash,
			},
		},
	}
}

func genRSAPKCS1v15Key(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result
}

func TestGenerateKey_RSAPKCS1v15_2048_happyPath(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	_, result := genRSAPKCS1v15Key(t, alg)

	priv, err := x509.ParsePKCS8PrivateKey(result.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want *rsa.PrivateKey", priv)
	}
	if got := rsaKey.N.BitLen(); got != 2048 {
		t.Errorf("key size = %d bits, want 2048", got)
	}

	if _, err = x509.ParsePKIXPublicKey(result.GetPublicKeyBytes()); err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if got := result.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8 {
		t.Errorf("KeyMaterialEncoding = %s, want PKCS8", got)
	}
	if got := result.GetPublicKeyEncoding(); got != providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI {
		t.Errorf("PublicKeyEncoding = %s, want SPKI", got)
	}
}

// TestSignVerify_RSAPKCS1v15_2048_SHA256_roundTrip matches the catalog's
// rsa-pkcs1v15-sha256-2048.
func TestSignVerify_RSAPKCS1v15_2048_SHA256_roundTrip(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPKCS1v15Key(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed with RSA-PKCS1v15-2048-SHA256")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// PKCS1v15 signature length equals the modulus size: 2048 bits = 256 bytes.
	if got := len(signResult.GetSignature()); got != 256 {
		t.Errorf("signature length = %d, want 256", got)
	}
	if got := signResult.GetOutput().GetEncoding(); got != "raw" {
		t.Errorf("Output.encoding = %q, want %q", got, "raw")
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

// TestSignVerify_RSAPKCS1v15_3072_SHA384_roundTrip exercises a non-catalog
// key size/hash combination the underlying primitive still supports.
func TestSignVerify_RSAPKCS1v15_3072_SHA384_roundTrip(t *testing.T) {
	alg := rsaPKCS1v15Details(3072, types.HashAlgorithm_HASH_ALGORITHM_SHA384)
	p, keyMaterial := genRSAPKCS1v15Key(t, alg)
	ctx := context.Background()
	payload := []byte("payload")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: payload, Signature: signResult.GetSignature(), Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true")
	}
}

func TestVerify_RSAPKCS1v15_tamperedPayload_returnsFalse(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPKCS1v15Key(t, alg)
	ctx := context.Background()

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("original"), Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("tampered"),
		Signature:   signResult.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Verify should not error on invalid signature, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for tampered payload")
	}
}

func TestVerify_RSAPKCS1v15_tamperedSignature_returnsFalse(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPKCS1v15Key(t, alg)
	ctx := context.Background()
	payload := []byte("payload")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := make([]byte, len(signResult.GetSignature()))
	copy(tampered, signResult.GetSignature())
	tampered[len(tampered)/2] ^= 0xFF

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: payload, Signature: tampered, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Verify should not error on invalid signature, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for tampered signature")
	}
}

// TestSign_RSAPKCS1v15_keySizeMismatch_returnsError proves the declared
// key_size_bits is cross-checked against the actual parsed key, the same
// convention as RSA-PSS's checkRSAKeySize use.
func TestSign_RSAPKCS1v15_keySizeMismatch_returnsError(t *testing.T) {
	genAlg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPKCS1v15Key(t, genAlg)

	mismatchedAlg := rsaPKCS1v15Details(3072, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: mismatchedAlg,
	})
	if err == nil {
		t.Fatal("expected error: key is 2048 bits but algorithm declares 3072")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestSign_RSAPKCS1v15_unsupportedHash_returnsError proves a hash outside
// the {UNSPECIFIED, SHA-256, SHA-384, SHA-512} set is rejected defensively —
// buf.validate does not run at this in-process layer, and the proto's own
// constraint additionally excludes MD5/SHA-1 (collision attacks make
// PKCS#1 v1.5 forgery practical under those hashes).
func TestSign_RSAPKCS1v15_unsupportedHash_returnsError(t *testing.T) {
	alg := rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA3_256)
	p, keyMaterial := genRSAPKCS1v15Key(t, rsaPKCS1v15Details(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256))

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: alg,
	})
	if err == nil {
		t.Fatal("expected error for unsupported hash SHA3-256")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}
