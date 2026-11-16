package software_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// GenerateKey still produces SEC1-encoded private keys (see provider.go's
// "sec1" encoding note), but the parser must also accept PKCS#8 — the format
// used by every other key type in this provider (RSA, Ed25519, ML-DSA) — so
// existing keys are never stranded if the writer switches formats later.
// These tests construct PKCS#8 key material independently of GenerateKey to
// prove that branch actually works, not just that it compiles.

func TestSign_ECDSA_acceptsPKCS8EncodedKeyMaterial(t *testing.T) {
	pkcs8DER, pkixDER := genECDSAPKCS8Key(t)

	p := software.New()
	ctx := context.Background()
	payload := []byte("payload signed with a PKCS#8 key")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: pkcs8DER,
		Input:       payload,
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Sign with PKCS#8 key: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: pkixDER,
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true for a signature produced from a PKCS#8-encoded key")
	}
}

func TestSignDigest_ECDSA_acceptsPKCS8EncodedKeyMaterial(t *testing.T) {
	pkcs8DER, pkixDER := genECDSAPKCS8Key(t)

	p := software.New()
	ctx := context.Background()
	digest := sha256.Sum256([]byte("pre-hashed by the caller"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: pkcs8DER,
		Digest:      digest[:],
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("SignDigest with PKCS#8 key: %v", err)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: pkixDER,
		Digest:      digest[:],
		Signature:   signResp.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("expected valid=true for a digest signature produced from a PKCS#8-encoded key")
	}
}

// TestSign_ECDSA_pkcs8NonECDSAKey_returnsError proves a PKCS#8 key of the
// wrong type is rejected with a clear error, not silently misinterpreted or
// mistakenly retried as SEC1 (which only encodes EC keys, so it would fail
// with a confusing "not EC" error instead of "not ECDSA").
func TestSign_ECDSA_pkcs8NonECDSAKey_returnsError(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	_, err = software.New().Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: pkcs8DER,
		Input:       []byte("payload"),
		Algorithm:   ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for a PKCS#8 key that is not ECDSA")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// genECDSAPKCS8Key generates a fresh ECDSA-P256 key and returns its PKCS#8
// private-key and PKIX public-key DER encodings.
func genECDSAPKCS8Key(t *testing.T) (pkcs8DER, pkixDER []byte) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	pkcs8DER, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkixDER, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return pkcs8DER, pkixDER
}
