package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ============================================================================
// ML-DSA-44 / ML-DSA-87 — matches the catalog's "ml-dsa-44"/"ml-dsa-87"
// templates. ML-DSA-65 already had full coverage (mldsa_test.go,
// sign_mldsa_test.go) before this provider was generalized to the other two
// FIPS 204 parameter sets; these tests prove the generalization actually
// dispatches to the right CIRCL scheme rather than just compiling.
// ============================================================================

func mlDSA44Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{ParameterSet: types.MlDsaParameterSet_ML_DSA_44},
		},
	}
}

func mlDSA87Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{ParameterSet: types.MlDsaParameterSet_ML_DSA_87},
		},
	}
}

// TestGenerateKey_MLDSA44_correctKeySizes proves the public key stays in
// CIRCL's native packed (expanded) form while the private key is a much
// smaller PKCS#8-wrapped seed — see the ML-DSA-65 analogue for why.
func TestGenerateKey_MLDSA44_correctKeySizes(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: mlDSA44Details()})
	if err != nil {
		t.Fatalf("GenerateKey ml-dsa-44: %v", err)
	}
	if got := len(resp.GetPublicKeyBytes()); got != mldsa44.PublicKeySize {
		t.Errorf("public key size: got %d want %d", got, mldsa44.PublicKeySize)
	}
	if got := len(resp.GetKeyMaterial()); got >= mldsa44.PrivateKeySize {
		t.Errorf("private key material is %d bytes, want well under the expanded key size %d bytes", got, mldsa44.PrivateKeySize)
	}
}

func TestSignVerify_MLDSA44_roundTrip(t *testing.T) {
	p := software.New()
	ctx := context.Background()
	alg := mlDSA44Details()
	payload := []byte("ML-DSA-44 post-quantum message")

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(signResult.GetSignature()); got != mldsa44.SignatureSize {
		t.Errorf("signature size: got %d want %d", got, mldsa44.SignatureSize)
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

func TestVerify_MLDSA44_tamperedPayload_returnsFalse(t *testing.T) {
	p := software.New()
	ctx := context.Background()
	alg := mlDSA44Details()

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("original"), Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: []byte("tampered"), Signature: signResult.GetSignature(), Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Verify should not error on invalid signature, got: %v", err)
	}
	if verifyResult.GetValid() {
		t.Error("expected valid=false for tampered payload")
	}
}

// TestGenerateKey_MLDSA87_correctKeySizes proves the public key stays in
// CIRCL's native packed (expanded) form while the private key is a much
// smaller PKCS#8-wrapped seed — see the ML-DSA-65 analogue for why.
func TestGenerateKey_MLDSA87_correctKeySizes(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: mlDSA87Details()})
	if err != nil {
		t.Fatalf("GenerateKey ml-dsa-87: %v", err)
	}
	if got := len(resp.GetPublicKeyBytes()); got != mldsa87.PublicKeySize {
		t.Errorf("public key size: got %d want %d", got, mldsa87.PublicKeySize)
	}
	if got := len(resp.GetKeyMaterial()); got >= mldsa87.PrivateKeySize {
		t.Errorf("private key material is %d bytes, want well under the expanded key size %d bytes", got, mldsa87.PrivateKeySize)
	}
}

func TestSignVerify_MLDSA87_roundTrip(t *testing.T) {
	p := software.New()
	ctx := context.Background()
	alg := mlDSA87Details()
	payload := []byte("ML-DSA-87 post-quantum message")

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: payload, Algorithm: alg,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := len(signResult.GetSignature()); got != mldsa87.SignatureSize {
		t.Errorf("signature size: got %d want %d", got, mldsa87.SignatureSize)
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

func TestVerify_MLDSA87_tamperedSignature_returnsFalse(t *testing.T) {
	p := software.New()
	ctx := context.Background()
	alg := mlDSA87Details()
	payload := []byte("payload")

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
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

// TestVerify_MLDSA44_wrongParameterSetKey_returnsError proves a public key
// generated under one parameter set is rejected outright when Verify is
// asked to dispatch under a different one — ML-DSA-44 and ML-DSA-87 public
// keys are different, fixed sizes, so this is a malformed-KEY condition
// (scheme.UnmarshalBinaryPublicKey rejects the length mismatch), not a
// malformed-signature condition. Matches this codebase's established
// convention that a bad KEY is a real error while a bad SIGNATURE is not
// (see checkRSAKeySize's analogous key-size-mismatch test).
func TestVerify_MLDSA44_wrongParameterSetKey_returnsError(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: mlDSA44Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signResult, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(), Input: []byte("payload"), Algorithm: mlDSA44Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify against ML-DSA-87's dispatch using ML-DSA-44's public key bytes
	// and signature — a genuine size/scheme mismatch, not just a bad sig.
	_, err = p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(), Input: []byte("payload"), Signature: signResult.GetSignature(), Algorithm: mlDSA87Details(),
	})
	if err == nil {
		t.Fatal("expected error for ML-DSA-44 public key bytes verified under ML-DSA-87 dispatch")
	}
}

// TestSign_MLDSA44_PKCS8KeyWrongDeclaredParameterSet_returnsError proves the
// same cross-check on the PRIVATE key side: a PKCS#8 blob's embedded OID
// self-describes a scheme (circl/pki.UnmarshalPKIXPrivateKey looks it up
// directly), but that parsed scheme must still match what AlgorithmDetails
// declares — parseMLDSAPKCS8PrivateKey rejects a mismatch rather than
// trusting the OID as authoritative on its own.
func TestSign_MLDSA44_PKCS8KeyWrongDeclaredParameterSet_returnsError(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	keyMaterial, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: mlDSA44Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	_, err = p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial:         keyMaterial.GetKeyMaterial(),
		Input:               []byte("payload"),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
		Algorithm:           mlDSA87Details(),
	})
	if err == nil {
		t.Fatal("expected error for an ML-DSA-44 PKCS#8 key signed under ML-DSA-87 dispatch")
	}
}
