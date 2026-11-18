package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

func genChaCha20Key(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, []byte) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result.GetKeyMaterial()
}

func TestEncryptDecrypt_ChaCha20Poly1305_roundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"IETF", chacha20Poly1305Details()},
		{"XChaCha20", xChaCha20Poly1305Details()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, key := genChaCha20Key(t, tc.alg)
			ctx := context.Background()
			plaintext := []byte("payload encrypted under ChaCha20-Poly1305")
			aad := []byte("associated data")

			encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
				KeyMaterial: key, Plaintext: plaintext,
				ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}},
				Algorithm:   tc.alg,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if got := encResult.GetOutput().GetAeadOutput().GetTagLengthBytes(); got != 16 {
				t.Errorf("tag length = %d, want 16", got)
			}

			decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
				KeyMaterial: key, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
				ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}},
				Algorithm:   tc.alg,
			})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(decResult.GetPlaintext()) != string(plaintext) {
				t.Errorf("round-trip mismatch: got %q, want %q", decResult.GetPlaintext(), plaintext)
			}
		})
	}
}

func TestEncrypt_ChaCha20Poly1305_nonceLengthMatchesVariant(t *testing.T) {
	for _, tc := range []struct {
		name       string
		alg        *types.AlgorithmDetails
		wantLength int
	}{
		{"IETF", chacha20Poly1305Details(), 12},
		{"XChaCha20", xChaCha20Poly1305Details(), 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, key := genChaCha20Key(t, tc.alg)
			encResult, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
				KeyMaterial: key, Plaintext: []byte("payload"),
				ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
				Algorithm:   tc.alg,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if got := len(encResult.GetOutput().GetAeadOutput().GetNonce()); got != tc.wantLength {
				t.Errorf("nonce length = %d, want %d", got, tc.wantLength)
			}
		})
	}
}

func TestEncrypt_ChaCha20Poly1305_noncesAreUnique(t *testing.T) {
	alg := chacha20Poly1305Details()
	p, key := genChaCha20Key(t, alg)
	ctx := context.Background()

	r1, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt (1st): %v", err)
	}
	r2, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt (2nd): %v", err)
	}
	nonce1 := r1.GetOutput().GetAeadOutput().GetNonce()
	nonce2 := r2.GetOutput().GetAeadOutput().GetNonce()
	if string(nonce1) == string(nonce2) {
		t.Error("two Encrypt calls should not produce the same nonce")
	}
	if string(r1.GetCiphertext()) == string(r2.GetCiphertext()) {
		t.Error("two Encrypt calls over the same plaintext should not produce identical ciphertext (different nonces)")
	}
}

func TestDecrypt_ChaCha20Poly1305_tamperedCiphertext_returnsError(t *testing.T) {
	alg := chacha20Poly1305Details()
	p, key := genChaCha20Key(t, alg)
	ctx := context.Background()

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := make([]byte, len(encResult.GetCiphertext()))
	copy(tampered, encResult.GetCiphertext())
	tampered[0] ^= 0xFF

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: key, Ciphertext: tampered, Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDecrypt_ChaCha20Poly1305_wrongAAD_returnsError(t *testing.T) {
	alg := chacha20Poly1305Details()
	p, key := genChaCha20Key(t, alg)
	ctx := context.Background()

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: []byte("original aad")}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: key, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: []byte("wrong aad")}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for mismatched AAD")
	}
}

func TestDecrypt_ChaCha20Poly1305_wrongKey_returnsError(t *testing.T) {
	alg := chacha20Poly1305Details()
	p, key := genChaCha20Key(t, alg)
	_, otherKey := genChaCha20Key(t, alg)
	ctx := context.Background()

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: otherKey, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for decrypting with the wrong key")
	}
}

func TestEncrypt_ChaCha20Poly1305_keySizeMismatch_returnsError(t *testing.T) {
	alg := chacha20Poly1305Details()
	p, _ := genChaCha20Key(t, alg)

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: make([]byte, 16), Plaintext: []byte("payload"), // 128 bits, not the fixed 256-bit key
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error: ChaCha20-Poly1305 requires a 256-bit key")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestEncrypt_ChaCha20Poly1305_unsupportedVariant_returnsError proves the
// original DJB 64-bit-nonce variant — left unconstrained by the proto's CEL
// cross-field rules but not implemented by golang.org/x/crypto/chacha20poly1305
// — is rejected defensively.
func TestEncrypt_ChaCha20Poly1305_unsupportedVariant_returnsError(t *testing.T) {
	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{NonceSizeBits: 64, BlockCounterBits: 64},
		},
	}
	p, key := genChaCha20Key(t, chacha20Poly1305Details())

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for the unimplemented 64-bit-nonce DJB variant")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}
