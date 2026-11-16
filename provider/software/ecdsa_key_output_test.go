package software_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// These exercise the EXPLICIT branches directly (key_material_encoding set
// to SEC1 or PKCS8), as opposed to the UNSPECIFIED fallback branch — the
// other tests in this package (genECDSAKey, ecdsa_pkcs8_test.go) never set
// it, so they only ever exercise the fallback.

func TestSign_ECDSA_explicitSEC1Encoding_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t) // real key, SEC1-encoded (see provider.go)

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial:         keyMaterial.GetKeyMaterial(),
		Input:               []byte("payload"),
		Algorithm:           ecdsaP256Details(),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1,
	})
	if err != nil {
		t.Fatalf("Sign with explicit sec1 encoding: %v", err)
	}
}

func TestSign_ECDSA_explicitPKCS8Encoding_succeeds(t *testing.T) {
	pkcs8DER, _ := genECDSAPKCS8Key(t)

	_, err := software.New().Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial:         pkcs8DER,
		Input:               []byte("payload"),
		Algorithm:           ecdsaP256Details(),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
	})
	if err != nil {
		t.Fatalf("Sign with explicit pkcs8 encoding: %v", err)
	}
}

// TestSign_ECDSA_explicitEncodingMismatch_returnsError proves an explicit
// encoding is trusted fully: it must NOT silently retry the other format
// when the declared encoding disagrees with the actual bytes — that would
// mask a real bug (stored encoding disagreeing with the stored key).
func TestSign_ECDSA_explicitEncodingMismatch_returnsError(t *testing.T) {
	p, keyMaterial := genECDSAKey(t) // real key, actually SEC1-encoded

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial:         keyMaterial.GetKeyMaterial(),
		Input:               []byte("payload"),
		Algorithm:           ecdsaP256Details(),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8, // wrong — bytes are SEC1
	})
	if err == nil {
		t.Fatal("expected error: declared pkcs8 but key material is sec1")
	}
}

func TestSignDigest_ECDSA_explicitSEC1Encoding_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial:         keyMaterial.GetKeyMaterial(),
		Digest:              make([]byte, 32),
		Algorithm:           ecdsaP256Details(),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1,
	})
	if err != nil {
		t.Fatalf("SignDigest with explicit sec1 encoding: %v", err)
	}
}

func TestSignDigest_ECDSA_explicitEncodingMismatch_returnsError(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	_, err := p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		KeyMaterial:         keyMaterial.GetKeyMaterial(),
		Digest:              make([]byte, 32),
		Algorithm:           ecdsaP256Details(),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8, // wrong — bytes are sec1
	})
	if err == nil {
		t.Fatal("expected error: declared pkcs8 but key material is sec1")
	}
}
