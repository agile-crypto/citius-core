package software_test

import (
	"context"
	"crypto/sha512"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// ECDSA — IEEE P1363 Signature Format
// ============================================================================

func ecdsaDetailsWithFormat(curve types.EllipticCurve, hash types.HashAlgorithm, format types.SignatureFormat) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve:           curve,
				Hash:            hash,
				SignatureFormat: format,
			},
		},
	}
}

func TestSignVerify_ECDSA_P256_IEEEP1363_roundTrip(t *testing.T) {
	alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P256,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	payload := []byte("payload signed with IEEE P1363 format")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// P-256: 32-byte r || 32-byte s, fixed-width regardless of leading zeros.
	const wantLen = 64
	if got := len(signResult.GetSignature()); got != wantLen {
		t.Errorf("signature length = %d, want %d", got, wantLen)
	}
	if got := signResult.GetOutput().GetEncoding(); got != "p1363" {
		t.Errorf("Output.encoding = %q, want %q", got, "p1363")
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

func TestSignVerify_ECDSA_P384_IEEEP1363_signatureIsCorrectLength(t *testing.T) {
	alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P384,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)

	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	const wantLen = 96 // P-384: 48-byte r || 48-byte s
	if got := len(signResult.GetSignature()); got != wantLen {
		t.Errorf("signature length = %d, want %d", got, wantLen)
	}
}

func TestSignVerify_ECDSA_P521_IEEEP1363_signatureIsCorrectLength(t *testing.T) {
	alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P521,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)

	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	const wantLen = 132 // P-521: ceil(521/8)=66-byte r || 66-byte s
	if got := len(signResult.GetSignature()); got != wantLen {
		t.Errorf("signature length = %d, want %d", got, wantLen)
	}
}

func TestSignVerifyDigest_ECDSA_P256_IEEEP1363_roundTrip(t *testing.T) {
	alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P256,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)
	ctx := context.Background()
	digest := sha512.Sum512_256([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if got := len(signResp.GetSignature()); got != 64 {
		t.Errorf("signature length = %d, want 64", got)
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

// TestVerify_ECDSA_P1363WrongLength_returnsFalseNotError proves malformed
// P1363 signature bytes are treated as an invalid SIGNATURE (valid=false),
// not a hard error — matching this codebase's established convention that
// bad signature data is never conflated with bad key/config data (see the
// equivalent ML-DSA garbage-signature test).
func TestVerify_ECDSA_P1363WrongLength_returnsFalseNotError(t *testing.T) {
	alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P256,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363)
	_, keyMaterial := genECDSAKeyWithAlgorithm(t, alg)

	verifyResult, err := software.New().Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("payload"),
		Signature:   make([]byte, 10), // not 64 bytes
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Verify should not error on malformed signature bytes, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for wrong-length P1363 signature")
	}
}

// TestVerify_ECDSA_derSignatureDeclaredAsP1363_returnsFalseNotError proves a
// DER signature verified under a mismatched declared format fails cleanly —
// the two encodings are not interchangeable, and this must not be silently
// reinterpreted (see decodeECDSASignature's doc: DER and P1363 are not
// reliably distinguishable from the bytes alone, so the declared format is
// authoritative, not inferred).
func TestVerify_ECDSA_derSignatureDeclaredAsP1363_returnsFalseNotError(t *testing.T) {
	derAlg := ecdsaP256Details() // default format is DER
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, derAlg)
	payload := []byte("payload")

	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   derAlg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	p1363Alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P256,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363)
	verifyResult, err := p.Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(), // DER bytes, ~70-72 bytes long
		Algorithm:   p1363Alg,                  // declares P1363 (expects exactly 64 bytes)
	})
	if err != nil {
		t.Fatalf("Verify should not error, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false: DER signature is not valid P1363 for this key")
	}
}

// TestSign_ECDSA_unsupportedSignatureFormat_returnsError proves
// SIGNATURE_FORMAT_RAW — documented as the Ed25519/Ed448 native format — is
// rejected for ECDSA rather than silently aliased to P1363 or DER.
func TestSign_ECDSA_unsupportedSignatureFormat_returnsError(t *testing.T) {
	alg := ecdsaDetailsWithFormat(types.EllipticCurve_ELLIPTIC_CURVE_P256,
		types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_RAW)
	p, keyMaterial := genECDSAKeyWithAlgorithm(t, ecdsaP256Details())

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for unsupported SIGNATURE_FORMAT_RAW")
	}
}

func TestSign_ECDSA_derFormatDefault_outputEncodingIsDER(t *testing.T) {
	p, keyMaterial := genECDSAKey(t) // default AlgorithmDetails: format UNSPECIFIED

	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := signResult.GetOutput().GetEncoding(); got != "der" {
		t.Errorf("Output.encoding = %q, want %q", got, "der")
	}
}
