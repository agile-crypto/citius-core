package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

func aesGCMDetailsFull(keySizeBits, ivSizeBits, tagSizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesGcm{
			AesGcm: &types.AesGcmParams{
				KeySizeBits: keySizeBits,
				IvSizeBits:  ivSizeBits,
				TagSizeBits: tagSizeBits,
			},
		},
	}
}

func genAESGCMKey(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, []byte) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result.GetKeyMaterial()
}

func TestEncryptDecrypt_AESGCM_128_192_256_roundTrip(t *testing.T) {
	for _, keySizeBits := range []uint32{128, 192, 256} {
		alg := aesGCMDetailsFull(keySizeBits, 96, 128)
		p, key := genAESGCMKey(t, alg)
		ctx := context.Background()
		plaintext := []byte("payload encrypted under AES-GCM")
		aad := []byte("associated data")

		encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
			KeyMaterial: key,
			Plaintext:   plaintext,
			ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}},
			Algorithm:   alg,
		})
		if err != nil {
			t.Fatalf("AES-%d-GCM Encrypt: %v", keySizeBits, err)
		}
		if got := len(encResult.GetOutput().GetAeadOutput().GetNonce()); got != 12 {
			t.Errorf("AES-%d-GCM: nonce length = %d, want 12", keySizeBits, got)
		}
		if got := encResult.GetOutput().GetAeadOutput().GetTagLengthBytes(); got != 16 {
			t.Errorf("AES-%d-GCM: tag length = %d, want 16", keySizeBits, got)
		}

		decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
			KeyMaterial: key,
			Ciphertext:  encResult.GetCiphertext(),
			Output:      encResult.GetOutput(),
			ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}},
			Algorithm:   alg,
		})
		if err != nil {
			t.Fatalf("AES-%d-GCM Decrypt: %v", keySizeBits, err)
		}
		if string(decResult.GetPlaintext()) != string(plaintext) {
			t.Errorf("AES-%d-GCM: round-trip mismatch: got %q, want %q", keySizeBits, decResult.GetPlaintext(), plaintext)
		}
	}
}

func TestEncrypt_AESGCM_noncesAreUnique(t *testing.T) {
	alg := aesGCMDetailsFull(256, 96, 128)
	p, key := genAESGCMKey(t, alg)
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

func TestDecrypt_AESGCM_tamperedCiphertext_returnsError(t *testing.T) {
	alg := aesGCMDetailsFull(256, 96, 128)
	p, key := genAESGCMKey(t, alg)
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

func TestDecrypt_AESGCM_wrongAAD_returnsError(t *testing.T) {
	alg := aesGCMDetailsFull(256, 96, 128)
	p, key := genAESGCMKey(t, alg)
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

func TestDecrypt_AESGCM_wrongKey_returnsError(t *testing.T) {
	alg := aesGCMDetailsFull(256, 96, 128)
	p, key := genAESGCMKey(t, alg)
	_, otherKey := genAESGCMKey(t, alg)
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

func TestEncrypt_AESGCM_keySizeMismatch_returnsError(t *testing.T) {
	genAlg := aesGCMDetailsFull(256, 96, 128)
	p, key := genAESGCMKey(t, genAlg)

	mismatchedAlg := aesGCMDetailsFull(128, 96, 128)
	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   mismatchedAlg,
	})
	if err == nil {
		t.Fatal("expected error: key is 256 bits but algorithm declares 128")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestEncryptDecrypt_AESGCM_nonStandardTagSize_roundTrip exercises
// NewGCMWithTagSize (standard 96-bit nonce, non-standard 96-bit tag).
func TestEncryptDecrypt_AESGCM_nonStandardTagSize_roundTrip(t *testing.T) {
	alg := aesGCMDetailsFull(256, 96, 96)
	p, key := genAESGCMKey(t, alg)
	ctx := context.Background()
	plaintext := []byte("payload")

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: plaintext,
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := encResult.GetOutput().GetAeadOutput().GetTagLengthBytes(); got != 12 {
		t.Errorf("tag length = %d, want 12", got)
	}

	decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: key, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResult.GetPlaintext()) != string(plaintext) {
		t.Error("round-trip mismatch with non-standard tag size")
	}
}

// TestEncryptDecrypt_AESGCM_nonStandardNonceSize_roundTrip exercises
// NewGCMWithNonceSize (non-standard 64-bit nonce, standard 128-bit tag).
func TestEncryptDecrypt_AESGCM_nonStandardNonceSize_roundTrip(t *testing.T) {
	alg := aesGCMDetailsFull(256, 64, 128)
	p, key := genAESGCMKey(t, alg)
	ctx := context.Background()
	plaintext := []byte("payload")

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: plaintext,
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := len(encResult.GetOutput().GetAeadOutput().GetNonce()); got != 8 {
		t.Errorf("nonce length = %d, want 8", got)
	}

	decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: key, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResult.GetPlaintext()) != string(plaintext) {
		t.Error("round-trip mismatch with non-standard nonce size")
	}
}

// TestEncrypt_AESGCM_bothNonStandardNonceAndTag_returnsError proves the
// combination Go's crypto/cipher has no public constructor for is rejected
// outright rather than silently falling back to a standard value.
func TestEncrypt_AESGCM_bothNonStandardNonceAndTag_returnsError(t *testing.T) {
	alg := aesGCMDetailsFull(256, 64, 96)
	p, key := genAESGCMKey(t, alg)

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for non-standard nonce AND tag size combined")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestEncrypt_AESGCM_tagSizeOutsideAllowedSet_returnsError proves a
// tag_size_bits value outside AesGcmParams' declared {96,104,112,120,128}
// set is rejected rather than silently truncated by integer division to a
// shorter, unintended tag length. protovalidate (wired into every
// software.Provider method) now catches this before dispatch reaches
// checkAESGCMSizesValid, so the error is CodeInvalidArgument rather than the
// CodeNotImplemented checkAESGCMSizesValid itself would return.
func TestEncrypt_AESGCM_tagSizeOutsideAllowedSet_returnsError(t *testing.T) {
	alg := aesGCMDetailsFull(256, 96, 127) // 127 is not in {96,104,112,120,128}
	p, key := genAESGCMKey(t, aesGCMDetailsFull(256, 96, 128))

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for tag_size_bits=127, not one of the proto's allowed values")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestEncrypt_AESGCM_ivSizeOutsideAllowedSet_returnsError is the
// iv_size_bits analogue of TestEncrypt_AESGCM_tagSizeOutsideAllowedSet_returnsError.
func TestEncrypt_AESGCM_ivSizeOutsideAllowedSet_returnsError(t *testing.T) {
	alg := aesGCMDetailsFull(256, 100, 128) // 100 is not in {64,96,128}
	p, key := genAESGCMKey(t, aesGCMDetailsFull(256, 96, 128))

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for iv_size_bits=100, not one of the proto's allowed values")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
