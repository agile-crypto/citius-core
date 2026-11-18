package software

import (
	"context"
	"crypto/cipher"
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// ChaCha20Poly1305TagSizeBytes is the fixed Poly1305 authentication tag
// length (128 bits) — both variants below share it, and unlike AES-GCM's
// tag_size_bits, ChaCha20Poly1305Params has no field to negotiate it.
const ChaCha20Poly1305TagSizeBytes = chacha20poly1305.Overhead

// checkChaCha20KeySize rejects key material that isn't exactly 256 bits.
// ChaCha20Poly1305Params carries no key_size_bits field at all (see
// generateChaCha20Key's doc comment: RFC 8439 fixes the key size), so unlike
// AES there is no declared value to cross-check the key against — this
// checks the one fixed size the RFC allows.
func checkChaCha20KeySize(ctx context.Context, op errors.Op, keyMaterial []byte) error {
	if len(keyMaterial) != chacha20poly1305.KeySize {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"key material is %d bytes, ChaCha20-Poly1305 requires a %d-byte (256-bit) key",
			len(keyMaterial), chacha20poly1305.KeySize)
	}
	return nil
}

// newChaCha20Poly1305 builds a cipher.AEAD for the requested variant.
//
// The catalog ships exactly two combinations: RFC 8439 IETF ChaCha20-Poly1305
// (96-bit nonce, 32-bit counter, extended_nonce=false) and XChaCha20-Poly1305
// (192-bit nonce, 32-bit counter, extended_nonce=true) — both are cross-field
// combinations the proto's own CEL rules already enforce
// (chacha20_nonce_consistency, chacha20_ietf_counter). Left unconstrained by
// CEL is the original DJB 64-bit-nonce variant (nonce_size_bits=64, with
// either counter width) — golang.org/x/crypto/chacha20poly1305 implements
// neither that variant nor a 64-bit counter, so it is rejected here
// defensively rather than approximated.
func newChaCha20Poly1305(ctx context.Context, op errors.Op, key []byte, params *types.ChaCha20Poly1305Params) (cipher.AEAD, error) {
	switch {
	case params.GetNonceSizeBits() == 96 && params.GetBlockCounterBits() == 32 && !params.GetExtendedNonce():
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return aead, nil
	case params.GetNonceSizeBits() == 192 && params.GetBlockCounterBits() == 32 && params.GetExtendedNonce():
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return aead, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported ChaCha20-Poly1305 variant: nonce_size_bits=%d, block_counter_bits=%d, extended_nonce=%v",
			params.GetNonceSizeBits(), params.GetBlockCounterBits(), params.GetExtendedNonce())
	}
}

// encryptChaCha20Poly1305 mirrors encryptAESGCM. The tag is always 128 bits
// (ChaCha20Poly1305TagSizeBytes) for both variants, so unlike AES-GCM there
// is no tag-size parameter to read or report.
func encryptChaCha20Poly1305(ctx context.Context, keyMaterial, plaintext, aad []byte, params *types.ChaCha20Poly1305Params) (ciphertext, nonce []byte, _ error) {
	const op errors.Op = "software.encryptChaCha20Poly1305"

	if err := checkChaCha20KeySize(ctx, op, keyMaterial); err != nil {
		return nil, nil, err
	}
	aead, err := newChaCha20Poly1305(ctx, op, keyMaterial, params)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	return aead.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// decryptChaCha20Poly1305 mirrors decryptAESGCM, including collapsing every
// failure mode (tampered ciphertext, wrong tag, wrong AAD, wrong key) into
// one generic authentication error.
func decryptChaCha20Poly1305(ctx context.Context, keyMaterial, ciphertext, nonce, aad []byte, params *types.ChaCha20Poly1305Params) ([]byte, error) {
	const op errors.Op = "software.decryptChaCha20Poly1305"

	if err := checkChaCha20KeySize(ctx, op, keyMaterial); err != nil {
		return nil, err
	}
	aead, err := newChaCha20Poly1305(ctx, op, keyMaterial, params)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"nonce is %d bytes, want %d bytes", len(nonce), aead.NonceSize())
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "ChaCha20-Poly1305 authentication failed")
	}
	return plaintext, nil
}
