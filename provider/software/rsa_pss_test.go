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
// RSA-PSS — matches the catalog entries in proto/standard_algorithms/signatures.json
// ============================================================================

func rsaPSSDetails(keySizeBits uint32, hash types.HashAlgorithm) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPss{
			RsaPss: &types.RsaPssParams{
				KeySizeBits: keySizeBits,
				Hash:        hash,
			},
		},
	}
}

func genRSAPSSKey(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result
}

func TestGenerateKey_RSAPSS_2048_happyPath(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	_, result := genRSAPSSKey(t, alg)

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

// TestSignVerify_RSAPSS_2048_SHA256_roundTrip matches the catalog's
// rsa-pss-sha256-mgf1-32-2048: 2048-bit key, SHA-256, salt = hash length.
func TestSignVerify_RSAPSS_2048_SHA256_roundTrip(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPSSKey(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed with RSA-PSS-2048-SHA256")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// PSS signature length equals the modulus size: 2048 bits = 256 bytes.
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

// TestSignVerify_RSAPSS_3072_SHA256_roundTrip matches the catalog's
// rsa-pss-sha256-mgf1-32-3072.
func TestSignVerify_RSAPSS_3072_SHA256_roundTrip(t *testing.T) {
	alg := rsaPSSDetails(3072, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPSSKey(t, alg)
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

// TestSignVerify_RSAPSS_4096_SHA384_roundTrip matches the catalog's
// rsa-pss-sha384-mgf1-48-4096.  The only 4096-bit key in this test file —
// RSA-4096 generation costs ~1.8s.
func TestSignVerify_RSAPSS_4096_SHA384_roundTrip(t *testing.T) {
	alg := rsaPSSDetails(4096, types.HashAlgorithm_HASH_ALGORITHM_SHA384)
	p, keyMaterial := genRSAPSSKey(t, alg)
	ctx := context.Background()
	payload := []byte("payload")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(signResult.GetSignature()); got != 512 { // 4096 bits = 512 bytes
		t.Errorf("signature length = %d, want 512", got)
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

func rsaPSSDetailsWithSalt(keySizeBits uint32, hash types.HashAlgorithm, mode types.RsaPssParams_SaltLengthMode, saltBytes uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPss{
			RsaPss: &types.RsaPssParams{
				KeySizeBits:     keySizeBits,
				Hash:            hash,
				SaltLengthMode:  mode,
				SaltLengthBytes: saltBytes,
			},
		},
	}
}

func TestSignVerify_RSAPSS_saltLengthMax_roundTrip(t *testing.T) {
	alg := rsaPSSDetailsWithSalt(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		types.RsaPssParams_SALT_LENGTH_MODE_MAX, 0)
	p, keyMaterial := genRSAPSSKey(t, alg)
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

func TestSignVerify_RSAPSS_saltLengthExplicit_roundTrip(t *testing.T) {
	alg := rsaPSSDetailsWithSalt(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		types.RsaPssParams_SALT_LENGTH_MODE_EXPLICIT, 20)
	p, keyMaterial := genRSAPSSKey(t, alg)
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

// TestSign_RSAPSS_explicitSaltZero_returnsError matches the proto's own CEL
// rule: "SALT_LENGTH_MODE_EXPLICIT requires salt_length_bytes > 0". The key
// is generated under a plain, CEL-valid algorithm — GenerateKey validates
// the whole request including this cross-field rule even though it never
// reads salt_length_bytes, so generating under the bad alg itself would fail
// before Sign ever ran.
func TestSign_RSAPSS_explicitSaltZero_returnsError(t *testing.T) {
	alg := rsaPSSDetailsWithSalt(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		types.RsaPssParams_SALT_LENGTH_MODE_EXPLICIT, 0)
	p, keyMaterial := genRSAPSSKey(t, rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256))

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: alg,
	})
	if err == nil {
		t.Fatal("expected error for SALT_LENGTH_MODE_EXPLICIT with salt_length_bytes=0")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerify_RSAPSS_tamperedPayload_returnsFalse(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPSSKey(t, alg)
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

func TestVerify_RSAPSS_tamperedSignature_returnsFalse(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPSSKey(t, alg)
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

// TestSign_RSAPSS_keySizeMismatch_returnsError proves the declared
// key_size_bits is cross-checked against the actual parsed key, the RSA
// analogue of ECDSA's checkCurveMatches.
func TestSign_RSAPSS_keySizeMismatch_returnsError(t *testing.T) {
	genAlg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	p, keyMaterial := genRSAPSSKey(t, genAlg)

	mismatchedAlg := rsaPSSDetails(3072, types.HashAlgorithm_HASH_ALGORITHM_SHA256)
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

// TestSign_RSAPSS_mgfHashDiffersFromHash_returnsError proves a template
// declaring mgf_hash different from hash is rejected — Go's crypto/rsa has
// no API to honor an independent MGF hash.
func TestSign_RSAPSS_mgfHashDiffersFromHash_returnsError(t *testing.T) {
	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPss{
			RsaPss: &types.RsaPssParams{
				KeySizeBits: 2048,
				Hash:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
				MgfHash:     types.HashAlgorithm_HASH_ALGORITHM_SHA512,
			},
		},
	}
	p, keyMaterial := genRSAPSSKey(t, alg)

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: alg,
	})
	if err == nil {
		t.Fatal("expected error for mgf_hash != hash")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestSign_RSAPSS_unsupportedHash_returnsError proves a hash outside the
// {UNSPECIFIED, SHA-256, SHA-384, SHA-512} set RsaPssParams.hash's proto
// constraint allows is rejected. protovalidate (wired into every
// software.Provider method) now catches this via that constraint before
// dispatch reaches rsaHash's own defensive check, so the error is
// CodeInvalidArgument rather than the CodeNotImplemented rsaHash itself
// would return.
func TestSign_RSAPSS_unsupportedHash_returnsError(t *testing.T) {
	alg := rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA3_256)
	p, keyMaterial := genRSAPSSKey(t, rsaPSSDetails(2048, types.HashAlgorithm_HASH_ALGORITHM_SHA256))

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: alg,
	})
	if err == nil {
		t.Fatal("expected error for unsupported hash SHA3-256")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
