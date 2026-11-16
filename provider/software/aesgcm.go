package software

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

const (
	aesGCMStandardIVSizeBits  = 96
	aesGCMStandardTagSizeBits = 128
)

// checkAESKeyMatchesDeclaredSize cross-checks the actual key material length
// against AesGcmParams.key_size_bits — the AES analogue of checkRSAKeySize
// and checkCurveMatches: AlgorithmDetails is authoritative for dispatch, and
// aes.NewCipher alone cannot catch this, since a 24-byte key is a perfectly
// valid AES-192 key even when the caller declared AES-256.
func checkAESKeyMatchesDeclaredSize(ctx context.Context, op errors.Op, keyMaterial []byte, keySizeBits uint32) error {
	// Compare byte lengths rather than multiplying len(keyMaterial) by 8:
	// keySizeBits is protocol-bounded and safe to divide, but keyMaterial's
	// length is unbounded caller input, so multiplying it risks overflow.
	if wantBytes := int(keySizeBits / 8); len(keyMaterial) != wantBytes {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"key material is %d bytes, does not match declared key size %d bits (%d bytes)",
			len(keyMaterial), keySizeBits, wantBytes)
	}
	return nil
}

// checkAESGCMSizesValid rejects any ivSizeBits/tagSizeBits value outside
// AesGcmParams' declared proto ranges (iv_size_bits: {64, 96, 128},
// tag_size_bits: {96, 104, 112, 120, 128} — NIST SP 800-38D §5.2.1) — the
// same defensive-allowlist convention checkAESKeySize/rsaHash/
// curveForAlgorithm apply elsewhere in this provider.

func checkAESGCMSizesValid(ctx context.Context, op errors.Op, ivSizeBits, tagSizeBits uint32) error {
	switch ivSizeBits {
	case 64, 96, 128:
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES-GCM IV size: %d bits", ivSizeBits)
	}
	switch tagSizeBits {
	case 96, 104, 112, 120, 128:
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES-GCM tag size: %d bits", tagSizeBits)
	}
	return nil
}

// newAESGCM builds a cipher.AEAD honoring the declared nonce and tag sizes.
//
// Go's crypto/cipher only exposes NewGCMWithTagSize (standard 96-bit nonce,
// custom tag) and NewGCMWithNonceSize (custom nonce, standard 128-bit tag)
// as public constructors — there is no public API for overriding both
// simultaneously, even though the package's internal newGCM helper accepts
// both. A template declaring non-standard values for both is therefore
// rejected outright rather than approximated.
func newAESGCM(ctx context.Context, op errors.Op, key []byte, ivSizeBits, tagSizeBits uint32) (cipher.AEAD, error) {
	if err := checkAESGCMSizesValid(ctx, op, ivSizeBits, tagSizeBits); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	var aead cipher.AEAD
	switch {
	case ivSizeBits == aesGCMStandardIVSizeBits && tagSizeBits == aesGCMStandardTagSizeBits:
		aead, err = cipher.NewGCM(block)
	case ivSizeBits == aesGCMStandardIVSizeBits:
		aead, err = cipher.NewGCMWithTagSize(block, int(tagSizeBits/8))
	case tagSizeBits == aesGCMStandardTagSizeBits:
		aead, err = cipher.NewGCMWithNonceSize(block, int(ivSizeBits/8))
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"AES-GCM with both a non-standard nonce size (%d bits) and a non-standard tag size (%d bits) is not supported",
			ivSizeBits, tagSizeBits)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return aead, nil
}

// encryptAESGCM encrypts plaintext under a freshly generated random nonce,
// returning the ciphertext (with the authentication tag appended, per the
// standard AEAD convention cipher.AEAD.Seal already follows) and the nonce
// the caller must record for decryption.
func encryptAESGCM(ctx context.Context, keyMaterial, plaintext, aad []byte, params *types.AesGcmParams) (ciphertext, nonce []byte, _ error) {
	const op errors.Op = "software.encryptAESGCM"

	if err := checkAESKeyMatchesDeclaredSize(ctx, op, keyMaterial, params.GetKeySizeBits()); err != nil {
		return nil, nil, err
	}
	aead, err := newAESGCM(ctx, op, keyMaterial, params.GetIvSizeBits(), params.GetTagSizeBits())
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	return aead.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// decryptAESGCM decrypts ciphertext using the nonce recorded at encryption
// time. Unlike Verify's boolean result, DecryptResponse has no channel for
// "authentication failed, not an error" — decrypt failure MUST surface as an
// error here. aead.Open collapses every failure mode (tampered ciphertext,
// wrong tag, wrong AAD, wrong key) into one generic error by design — the
// same "deliberately vague to avoid oracle attacks" rationale rsa.VerifyPSS
// documents — so this reports a single generic authentication failure too.
func decryptAESGCM(ctx context.Context, keyMaterial, ciphertext, nonce, aad []byte, params *types.AesGcmParams) ([]byte, error) {
	const op errors.Op = "software.decryptAESGCM"

	if err := checkAESKeyMatchesDeclaredSize(ctx, op, keyMaterial, params.GetKeySizeBits()); err != nil {
		return nil, err
	}
	aead, err := newAESGCM(ctx, op, keyMaterial, params.GetIvSizeBits(), params.GetTagSizeBits())
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"nonce is %d bytes, want %d bytes", len(nonce), aead.NonceSize())
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "AES-GCM authentication failed")
	}
	return plaintext, nil
}
