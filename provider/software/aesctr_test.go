package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

func genAESCTRKey(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, []byte) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result.GetKeyMaterial()
}

func TestEncryptDecrypt_AESCTR_128_192_256_roundTrip(t *testing.T) {
	for _, keySizeBits := range []uint32{128, 192, 256} {
		alg := aesCTRDetails(keySizeBits)
		p, key := genAESCTRKey(t, alg)
		ctx := context.Background()
		plaintext := []byte("payload encrypted under AES-CTR")

		encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
			KeyMaterial: key,
			Plaintext:   plaintext,
			ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
			Algorithm:   alg,
		})
		if err != nil {
			t.Fatalf("AES-%d-CTR Encrypt: %v", keySizeBits, err)
		}
		if got := len(encResult.GetOutput().GetBlockCipherOutput().GetIv()); got != 16 {
			t.Errorf("AES-%d-CTR: IV length = %d, want 16", keySizeBits, got)
		}
		if got := len(encResult.GetCiphertext()); got != len(plaintext) {
			t.Errorf("AES-%d-CTR: ciphertext length = %d, want %d (stream cipher, no padding)", keySizeBits, got, len(plaintext))
		}

		decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
			KeyMaterial: key,
			Ciphertext:  encResult.GetCiphertext(),
			Output:      encResult.GetOutput(),
			ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
			Algorithm:   alg,
		})
		if err != nil {
			t.Fatalf("AES-%d-CTR Decrypt: %v", keySizeBits, err)
		}
		if string(decResult.GetPlaintext()) != string(plaintext) {
			t.Errorf("AES-%d-CTR: round-trip mismatch: got %q, want %q", keySizeBits, decResult.GetPlaintext(), plaintext)
		}
	}
}

func TestEncrypt_AESCTR_noncesAreUnique(t *testing.T) {
	alg := aesCTRDetails(256)
	p, key := genAESCTRKey(t, alg)
	ctx := context.Background()

	r1, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt (1st): %v", err)
	}
	r2, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt (2nd): %v", err)
	}
	iv1 := r1.GetOutput().GetBlockCipherOutput().GetIv()
	iv2 := r2.GetOutput().GetBlockCipherOutput().GetIv()
	if string(iv1) == string(iv2) {
		t.Error("two Encrypt calls should not produce the same nonce")
	}
	if string(r1.GetCiphertext()) == string(r2.GetCiphertext()) {
		t.Error("two Encrypt calls over the same plaintext should not produce identical ciphertext (different nonces)")
	}
}

// TestDecrypt_AESCTR_wrongKey_producesDifferentPlaintext documents CTR's
// unauthenticated nature: unlike AES-CBC (padding check) or AES-GCM (auth
// tag), decrypting under the wrong key does not surface an error — it
// silently produces different (garbage) plaintext. See decryptAESCTR's doc
// comment.
func TestDecrypt_AESCTR_wrongKey_producesDifferentPlaintext(t *testing.T) {
	alg := aesCTRDetails(256)
	p, key := genAESCTRKey(t, alg)
	_, otherKey := genAESCTRKey(t, alg)
	ctx := context.Background()
	plaintext := []byte("payload")

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: plaintext,
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: otherKey, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Decrypt with wrong key: unexpected error (CTR has no authentication, decrypt never fails on its own): %v", err)
	}
	if string(decResult.GetPlaintext()) == string(plaintext) {
		t.Error("decrypting under the wrong key coincidentally reproduced the original plaintext")
	}
}

func TestEncrypt_AESCTR_keySizeMismatch_returnsError(t *testing.T) {
	genAlg := aesCTRDetails(256)
	p, key := genAESCTRKey(t, genAlg)

	mismatchedAlg := aesCTRDetails(128)
	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   mismatchedAlg,
	})
	if err == nil {
		t.Fatal("expected error: key is 256 bits but algorithm declares 128")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestEncrypt_AESCTR_unsupportedNonceCounterSplit_returnsError proves a
// nonce_size_bits/counter_bits combination other than the catalog's 96/32
// split is rejected — AesCtrParams' CEL rules constrain each field
// independently but declare no cross-field rule tying them together, so
// this provider must reject the combination itself.
func TestEncrypt_AESCTR_unsupportedNonceCounterSplit_returnsError(t *testing.T) {
	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCtr{
			AesCtr: &types.AesCtrParams{KeySizeBits: 256, NonceSizeBits: 64, CounterBits: 64},
		},
	}
	p, key := genAESCTRKey(t, aesCTRDetails(256))

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for nonce_size_bits=64/counter_bits=64, only the 96/32 split is implemented")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}
