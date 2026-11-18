package software_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestSignVerify_MLDSA65_legacyExpandedKeyFormat_stillWorks is the
// regression test the PKCS#8 storage switch requires: every ML-DSA key
// generated before this provider started storing PKCS#8-wrapped seeds is
// stored as the full expanded private key (CIRCL's native Pack() form).
// Those keys can never be upgraded to PKCS#8 — the expanded form does not
// carry the seed a PKCS#8 blob needs — so RAW must remain a permanent,
// fully-functional read path, not a transitional shim removed once "enough
// time has passed". This test builds a key exactly the way the pre-PKCS#8
// provider did (mldsa65.GenerateKey + Bytes()) and proves Sign/Verify still
// work against it when PRIVATE_KEY_ENCODING_RAW is declared explicitly.
func TestSignVerify_MLDSA65_legacyExpandedKeyFormat_stillWorks(t *testing.T) {
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("mldsa65.GenerateKey: %v", err)
	}
	legacyPrivBytes := priv.Bytes()
	legacyPubBytes := pub.Bytes()

	p := software.New()
	ctx := context.Background()
	payload := []byte("payload signed against a legacy expanded-key-format ML-DSA-65 key")

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial:         legacyPrivBytes,
		Input:               payload,
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW,
		Algorithm:           mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Sign against legacy expanded-key: %v", err)
	}
	if len(signResult.GetSignature()) != mldsa65.SignatureSize {
		t.Errorf("signature size: got %d want %d", len(signResult.GetSignature()), mldsa65.SignatureSize)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: legacyPubBytes,
		Input:       payload,
		Signature:   signResult.GetSignature(),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Verify against legacy expanded-key: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true for a signature produced with a legacy expanded-key-format private key")
	}
}

// TestSign_MLDSA65_legacyExpandedKeyFormat_unspecifiedEncoding_stillWorks
// proves the fallback also applies when the caller declares no encoding at
// all — the realistic case for a key that predates this provider tracking
// key_material_encoding in the first place.
func TestSign_MLDSA65_legacyExpandedKeyFormat_unspecifiedEncoding_stillWorks(t *testing.T) {
	_, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("mldsa65.GenerateKey: %v", err)
	}

	p := software.New()
	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: priv.Bytes(),
		Input:       []byte("payload"),
		Algorithm:   mlDSA65Details(), // KeyMaterialEncoding left unset
	})
	if err != nil {
		t.Fatalf("Sign against legacy expanded-key with unspecified encoding: %v", err)
	}
	if len(signResult.GetSignature()) != mldsa65.SignatureSize {
		t.Errorf("signature size: got %d want %d", len(signResult.GetSignature()), mldsa65.SignatureSize)
	}
}
