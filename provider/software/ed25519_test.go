package software_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// ============================================================================
// Ed25519 — matches the catalog's "ed25519" template (pure variant only)
// ============================================================================

func ed25519Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{
				Variant: types.Ed25519Variant_ED25519_VARIANT_PURE,
			},
		},
	}
}

func genEd25519Key(t *testing.T) (*software.Provider, *providerpb.GenerateKeyResponse) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result
}

func TestGenerateKey_Ed25519_happyPath(t *testing.T) {
	_, result := genEd25519Key(t)

	priv, err := x509.ParsePKCS8PrivateKey(result.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if _, ok := priv.(ed25519.PrivateKey); !ok {
		t.Fatalf("private key is %T, want ed25519.PrivateKey", priv)
	}

	pub, err := x509.ParsePKIXPublicKey(result.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("public key is %T, want ed25519.PublicKey", pub)
	}

	if got := result.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8 {
		t.Errorf("KeyMaterialEncoding = %s, want PKCS8", got)
	}
	if got := result.GetPublicKeyEncoding(); got != providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI {
		t.Errorf("PublicKeyEncoding = %s, want SPKI", got)
	}
}

func TestSignVerify_Ed25519_roundTrip(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	ctx := context.Background()
	payload := []byte("payload signed with pure Ed25519")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       payload,
		Algorithm:   ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(signResult.GetSignature()); got != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", got, ed25519.SignatureSize)
	}
	if got := signResult.GetOutput().GetEncoding(); got != "raw" {
		t.Errorf("Output.encoding = %q, want %q", got, "raw")
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true")
	}
}

// TestSign_Ed25519_variantUnspecified_defaultsToPure proves the
// UNSPECIFIED variant (the zero value, e.g. an omitted Ed25519Params.variant)
// behaves as pure Ed25519 rather than being rejected.
func TestSign_Ed25519_variantUnspecified_defaultsToPure(t *testing.T) {
	unspecifiedAlg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{Ed25519: &types.Ed25519Params{}},
	}
	p, keyMaterial := genEd25519Key(t)

	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: unspecifiedAlg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(signResult.GetSignature()); got != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", got, ed25519.SignatureSize)
	}
}

func TestVerify_Ed25519_tamperedPayload_returnsFalse(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	ctx := context.Background()

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("original"), Algorithm: ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("tampered"),
		Signature:   signResult.GetSignature(),
		Algorithm:   ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Verify should not error on invalid signature, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for tampered payload")
	}
}

func TestVerify_Ed25519_tamperedSignature_returnsFalse(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)
	ctx := context.Background()
	payload := []byte("payload")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := make([]byte, len(signResult.GetSignature()))
	copy(tampered, signResult.GetSignature())
	tampered[len(tampered)/2] ^= 0xFF

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: payload, Signature: tampered, Algorithm: ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Verify should not error on invalid signature, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for tampered signature")
	}
}

// TestVerify_Ed25519_wrongLengthSignature_returnsFalse proves malformed
// (wrong-length) signature bytes are treated as an invalid SIGNATURE
// (valid=false), never a hard error — matching this codebase's established
// convention for every other signature scheme.
func TestVerify_Ed25519_wrongLengthSignature_returnsFalse(t *testing.T) {
	p, keyMaterial := genEd25519Key(t)

	verifyResult, err := p.Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("payload"),
		Signature:   make([]byte, 10), // not 64 bytes
		Algorithm:   ed25519Details(),
	})
	if err != nil {
		t.Fatalf("Verify should not error on malformed signature bytes, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for wrong-length signature")
	}
}

// TestSign_Ed25519_ctxVariant_returnsError proves Ed25519ctx — a distinct,
// valid Ed25519Variant per the proto — is rejected rather than silently
// treated as pure Ed25519. It is not implemented by this provider.
func TestSign_Ed25519_ctxVariant_returnsError(t *testing.T) {
	ctxAlg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{Variant: types.Ed25519Variant_ED25519_VARIANT_CTX},
		},
	}
	p, keyMaterial := genEd25519Key(t)

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: ctxAlg,
	})
	if err == nil {
		t.Fatal("expected error for unsupported Ed25519ctx variant")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestSign_Ed25519_phVariant_returnsError proves Ed25519ph is rejected
// through the plain Sign path — it is only reachable via SignDigest, since
// the entire point of a prehashed variant is that the caller hashes first.
func TestSign_Ed25519_phVariant_returnsError(t *testing.T) {
	phAlg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{Variant: types.Ed25519Variant_ED25519_VARIANT_PH},
		},
	}
	p, keyMaterial := genEd25519Key(t)

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: phAlg,
	})
	if err == nil {
		t.Fatal("expected error for Ed25519ph via Sign")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}
