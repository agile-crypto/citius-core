package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

func genAESCBCKey(t *testing.T, alg *types.AlgorithmDetails) (*software.Provider, []byte) {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return p, result.GetKeyMaterial()
}

func TestEncryptDecrypt_AESCBC_128_192_256_roundTrip(t *testing.T) {
	for _, keySizeBits := range []uint32{128, 192, 256} {
		alg := aesCBCDetails(keySizeBits)
		p, key := genAESCBCKey(t, alg)
		ctx := context.Background()
		plaintext := []byte("payload encrypted under AES-CBC")

		encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
			KeyMaterial: key,
			Plaintext:   plaintext,
			ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
			Algorithm:   alg,
		})
		if err != nil {
			t.Fatalf("AES-%d-CBC Encrypt: %v", keySizeBits, err)
		}
		if got := len(encResult.GetOutput().GetBlockCipherOutput().GetIv()); got != 16 {
			t.Errorf("AES-%d-CBC: IV length = %d, want 16", keySizeBits, got)
		}

		decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
			KeyMaterial: key,
			Ciphertext:  encResult.GetCiphertext(),
			Output:      encResult.GetOutput(),
			ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
			Algorithm:   alg,
		})
		if err != nil {
			t.Fatalf("AES-%d-CBC Decrypt: %v", keySizeBits, err)
		}
		if string(decResult.GetPlaintext()) != string(plaintext) {
			t.Errorf("AES-%d-CBC: round-trip mismatch: got %q, want %q", keySizeBits, decResult.GetPlaintext(), plaintext)
		}
	}
}

// TestEncryptDecrypt_AESCBC_blockAlignedPlaintext_roundTrip proves PKCS7
// padding always adds a full padding block, even when the plaintext is
// already an exact multiple of the AES block size, so unpadding stays
// unambiguous (RFC 5652).
func TestEncryptDecrypt_AESCBC_blockAlignedPlaintext_roundTrip(t *testing.T) {
	alg := aesCBCDetails(256)
	p, key := genAESCBCKey(t, alg)
	ctx := context.Background()
	plaintext := make([]byte, 32) // exactly two AES blocks

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: plaintext,
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got := len(encResult.GetCiphertext()); got != 48 {
		t.Errorf("ciphertext length = %d, want 48 (32 + one full padding block)", got)
	}

	decResult, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: key, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(decResult.GetPlaintext()) != len(plaintext) || string(decResult.GetPlaintext()) != string(plaintext) {
		t.Error("round-trip mismatch for block-aligned plaintext")
	}
}

func TestEncrypt_AESCBC_ivsAreUnique(t *testing.T) {
	alg := aesCBCDetails(256)
	p, key := genAESCBCKey(t, alg)
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
		t.Error("two Encrypt calls should not produce the same IV")
	}
	if string(r1.GetCiphertext()) == string(r2.GetCiphertext()) {
		t.Error("two Encrypt calls over the same plaintext should not produce identical ciphertext (different IVs)")
	}
}

func TestDecrypt_AESCBC_tamperedCiphertext_returnsError(t *testing.T) {
	alg := aesCBCDetails(256)
	p, key := genAESCBCKey(t, alg)
	ctx := context.Background()

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := make([]byte, len(encResult.GetCiphertext()))
	copy(tampered, encResult.GetCiphertext())
	tampered[len(tampered)-1] ^= 0xFF // corrupt the final padding byte

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: key, Ciphertext: tampered, Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for tampered ciphertext (invalid PKCS7 padding)")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDecrypt_AESCBC_wrongKey_returnsError(t *testing.T) {
	alg := aesCBCDetails(256)
	p, key := genAESCBCKey(t, alg)
	_, otherKey := genAESCBCKey(t, alg)
	ctx := context.Background()

	encResult, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: otherKey, Ciphertext: encResult.GetCiphertext(), Output: encResult.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for decrypting with the wrong key (garbage padding, near-certainly invalid)")
	}
}

func TestEncrypt_AESCBC_keySizeMismatch_returnsError(t *testing.T) {
	genAlg := aesCBCDetails(256)
	p, key := genAESCBCKey(t, genAlg)

	mismatchedAlg := aesCBCDetails(128)
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

// TestEncrypt_AESCBC_unsupportedPadding_returnsError proves a padding
// scheme other than PKCS7 is rejected rather than silently ignored — the
// catalog only ships PKCS7, so ISO7816/X923/ZERO/NONE are unimplemented.
func TestEncrypt_AESCBC_unsupportedPadding_returnsError(t *testing.T) {
	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCbc{
			AesCbc: &types.AesCbcParams{KeySizeBits: 256, IvSizeBits: 128, Padding: types.PaddingScheme_PADDING_SCHEME_ISO7816},
		},
	}
	p, key := genAESCBCKey(t, aesCBCDetails(256))

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for unsupported padding scheme")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestEncrypt_AESCBC_ivSizeOutsideAllowedValue_returnsError is the AES-CBC
// analogue of TestEncrypt_AESGCM_ivSizeOutsideAllowedSet_returnsError.
// protovalidate (wired into every software.Provider method) now catches this
// before dispatch reaches checkAESCBCParamsValid, so the error is
// CodeInvalidArgument rather than the CodeNotImplemented
// checkAESCBCParamsValid itself would return.
func TestEncrypt_AESCBC_ivSizeOutsideAllowedValue_returnsError(t *testing.T) {
	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCbc{
			AesCbc: &types.AesCbcParams{KeySizeBits: 256, IvSizeBits: 64, Padding: types.PaddingScheme_PADDING_SCHEME_PKCS7},
		},
	}
	p, key := genAESCBCKey(t, aesCBCDetails(256))

	_, err := p.Encrypt(context.Background(), &providerpb.EncryptRequest{
		KeyMaterial: key, Plaintext: []byte("payload"),
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
		Algorithm:   alg,
	})
	if err == nil {
		t.Fatal("expected error for iv_size_bits=64, the only valid value for AES-CBC is 128")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
