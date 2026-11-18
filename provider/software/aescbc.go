package software

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// checkAESCBCParamsValid rejects an ivSizeBits/padding combination this
// provider does not implement.
//
// iv_size_bits is a mathematical fact for CBC, not a caller choice — the IV
// must equal the block size (128 bits for AES) — but the proto's own const
// constraint on this field is not enforced anywhere at runtime either (see
// checkAESGCMSizesValid's doc comment for why), so it is still checked here
// defensively rather than assumed.
//
// Every catalog entry for AES-CBC uses PKCS7 padding (RFC 5652); the other
// four PaddingScheme values (NONE, ISO7816, X923, ZERO) have no shipped
// catalog entry and are rejected rather than guessed at — a template
// declaring one would be untested, unverified behavior.
func checkAESCBCParamsValid(ctx context.Context, op errors.Op, ivSizeBits uint32, padding types.PaddingScheme) error {
	const aesCBCIVSizeBits = 128
	if ivSizeBits != aesCBCIVSizeBits {
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES-CBC IV size: %d bits", ivSizeBits)
	}
	if padding != types.PaddingScheme_PADDING_SCHEME_PKCS7 {
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES-CBC padding scheme: %s", padding)
	}
	return nil
}

// pkcs7Pad appends RFC 5652 PKCS#7 padding to data so its length becomes a
// multiple of blockSize. Always adds at least one byte of padding — even
// when len(data) is already block-aligned — so unpadding is unambiguous.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padByte := byte(padLen & 0xff) // padLen is in [1, blockSize] (16 for AES), always fits in a byte
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	copy(padded[len(data):], bytes.Repeat([]byte{padByte}, padLen))
	return padded
}

// pkcs7Unpad removes and validates RFC 5652 PKCS#7 padding. A malformed
// padding byte, an out-of-range padding length, or padding bytes that don't
// all match the declared length are rejected — decrypting under the wrong
// key produces exactly this kind of garbage padding, so this check is the
// AES-CBC analogue of aead.Open's built-in authentication failure (CBC has
// no built-in integrity check of its own, hence "Note: CBC mode requires
// separate MAC for authentication" in the proto's own doc comment).
func pkcs7Unpad(ctx context.Context, op errors.Op, data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "ciphertext is not a multiple of the block size")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "invalid PKCS#7 padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// encryptAESCBC encrypts plaintext under a freshly generated random IV,
// PKCS7-padding plaintext to the AES block size first (CBC operates on
// whole blocks only; there is no built-in tag or padding the way AEAD
// modes have).
func encryptAESCBC(ctx context.Context, keyMaterial, plaintext []byte, params *types.AesCbcParams) (ciphertext, iv []byte, _ error) {
	const op errors.Op = "software.encryptAESCBC"

	if err := checkAESKeyMatchesDeclaredSize(ctx, op, keyMaterial, params.GetKeySizeBits()); err != nil {
		return nil, nil, err
	}
	if err := checkAESCBCParamsValid(ctx, op, params.GetIvSizeBits(), params.GetPadding()); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext, iv, nil
}

// decryptAESCBC decrypts ciphertext using the IV recorded at encryption
// time, then removes and validates the PKCS7 padding. Like Decrypt's other
// callers, a decrypt/padding failure surfaces as an error — DecryptResponse
// has no boolean channel the way Verify does.
func decryptAESCBC(ctx context.Context, keyMaterial, ciphertext, iv []byte, params *types.AesCbcParams) ([]byte, error) {
	const op errors.Op = "software.decryptAESCBC"

	if err := checkAESKeyMatchesDeclaredSize(ctx, op, keyMaterial, params.GetKeySizeBits()); err != nil {
		return nil, err
	}
	if err := checkAESCBCParamsValid(ctx, op, params.GetIvSizeBits(), params.GetPadding()); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyMaterial)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "IV is %d bytes, want %d bytes", len(iv), aes.BlockSize)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "ciphertext is not a multiple of the block size")
	}

	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
	return pkcs7Unpad(ctx, op, padded, aes.BlockSize)
}
