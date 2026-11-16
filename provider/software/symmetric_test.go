package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

func aesGCMDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesGcm{
			AesGcm: &types.AesGcmParams{KeySizeBits: keySizeBits, IvSizeBits: 96, TagSizeBits: 128},
		},
	}
}

func aesCBCDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCbc{
			AesCbc: &types.AesCbcParams{
				KeySizeBits: keySizeBits,
				IvSizeBits:  128,
				Padding:     types.PaddingScheme_PADDING_SCHEME_PKCS7,
			},
		},
	}
}

func aesCTRDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCtr{
			AesCtr: &types.AesCtrParams{KeySizeBits: keySizeBits, NonceSizeBits: 96, CounterBits: 32},
		},
	}
}

func chacha20Poly1305Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{
				NonceSizeBits:    96,
				BlockCounterBits: 32,
			},
		},
	}
}

func xChaCha20Poly1305Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{
				NonceSizeBits:    192,
				BlockCounterBits: 32,
				ExtendedNonce:    true,
			},
		},
	}
}

func genSymmetricKey(t *testing.T, alg *types.AlgorithmDetails) *providerpb.GenerateKeyResponse {
	t.Helper()
	p := software.New()
	result, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return result
}

func TestGenerateKey_AESGCM_128_192_256_correctKeySizes(t *testing.T) {
	for _, keySizeBits := range []uint32{128, 192, 256} {
		result := genSymmetricKey(t, aesGCMDetails(keySizeBits))
		if got := len(result.GetKeyMaterial()); got != int(keySizeBits/8) {
			t.Errorf("AES-%d-GCM: key material = %d bytes, want %d", keySizeBits, got, keySizeBits/8)
		}
	}
}

func TestGenerateKey_AESGCM_hasNoPublicKeyHalf(t *testing.T) {
	result := genSymmetricKey(t, aesGCMDetails(256))
	if got := len(result.GetPublicKeyBytes()); got != 0 {
		t.Errorf("expected no public key bytes for a symmetric key, got %d bytes", got)
	}
	if got := result.GetPublicKeyEncoding(); got != providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_UNSPECIFIED {
		t.Errorf("PublicKeyEncoding = %s, want UNSPECIFIED", got)
	}
}

func TestGenerateKey_AESGCM_keyMaterialEncodingIsRAW(t *testing.T) {
	result := genSymmetricKey(t, aesGCMDetails(256))
	if got := result.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW {
		t.Errorf("KeyMaterialEncoding = %s, want RAW", got)
	}
}

func TestGenerateKey_AESGCM_keysAreUnique(t *testing.T) {
	r1 := genSymmetricKey(t, aesGCMDetails(256))
	r2 := genSymmetricKey(t, aesGCMDetails(256))
	if string(r1.GetKeyMaterial()) == string(r2.GetKeyMaterial()) {
		t.Error("two generated AES keys should not be identical")
	}
}

// TestGenerateKey_AESGCM_unsupportedKeySize_returnsError proves an
// out-of-range key_size_bits is rejected. It's now caught by protovalidate's
// CEL constraint (key_size_bits: in [128,192,256]) before dispatch ever
// runs, so it surfaces as CodeInvalidArgument rather than the
// CodeNotImplemented generateSymmetricKey itself would have returned.
func TestGenerateKey_AESGCM_unsupportedKeySize_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: aesGCMDetails(100), // not one of 128/192/256
	})
	if err == nil {
		t.Fatal("expected error for unsupported AES key size")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestGenerateKey_AESCBC_correctKeySizes(t *testing.T) {
	for _, keySizeBits := range []uint32{128, 192, 256} {
		result := genSymmetricKey(t, aesCBCDetails(keySizeBits))
		if got := len(result.GetKeyMaterial()); got != int(keySizeBits/8) {
			t.Errorf("AES-%d-CBC: key material = %d bytes, want %d", keySizeBits, got, keySizeBits/8)
		}
	}
}

func TestGenerateKey_AESCTR_correctKeySizes(t *testing.T) {
	for _, keySizeBits := range []uint32{128, 192, 256} {
		result := genSymmetricKey(t, aesCTRDetails(keySizeBits))
		if got := len(result.GetKeyMaterial()); got != int(keySizeBits/8) {
			t.Errorf("AES-%d-CTR: key material = %d bytes, want %d", keySizeBits, got, keySizeBits/8)
		}
	}
}

func TestGenerateKey_ChaCha20Poly1305_correctKeySize(t *testing.T) {
	result := genSymmetricKey(t, chacha20Poly1305Details())
	const wantBytes = 32 // ChaCha20 key is fixed at 256 bits regardless of nonce variant
	if got := len(result.GetKeyMaterial()); got != wantBytes {
		t.Errorf("key material = %d bytes, want %d", got, wantBytes)
	}
	if got := result.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW {
		t.Errorf("KeyMaterialEncoding = %s, want RAW", got)
	}
}

func TestGenerateKey_ChaCha20Poly1305_keysAreUnique(t *testing.T) {
	r1 := genSymmetricKey(t, chacha20Poly1305Details())
	r2 := genSymmetricKey(t, chacha20Poly1305Details())
	if string(r1.GetKeyMaterial()) == string(r2.GetKeyMaterial()) {
		t.Error("two generated ChaCha20 keys should not be identical")
	}
}
