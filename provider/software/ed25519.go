package software

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// generateEd25519Key generates an Ed25519 key pair, encoded as PKCS#8
// (private) and PKIX SubjectPublicKeyInfo (public) — Go's x509 package
// supports ed25519.PrivateKey/PublicKey natively, so no raw-bytes fallback
// is needed the way ML-DSA currently requires one.
func generateEd25519Key(ctx context.Context) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "software.generateEd25519Key"

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	privDER, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	pubDER, err = x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	return pubDER, privDER, nil
}

// parseEd25519PrivateKey parses privDER as an Ed25519 private key. Only
// PKCS#8 is ever produced by this provider (see generateEd25519Key).
func parseEd25519PrivateKey(ctx context.Context, op errors.Op, privDER []byte, encoding providerpb.PrivateKeyEncoding) (ed25519.PrivateKey, error) {
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
		providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED:
		key, err := x509.ParsePKCS8PrivateKey(privDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				fmt.Sprintf("PKCS#8 key is not Ed25519: %T", key))
		}
		return edKey, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported Ed25519 private key encoding: %s", encoding))
	}
}

// parseEd25519PublicKey parses pubDER as an Ed25519 public key. SPKI is the
// only format this provider ever writes; see parseEd25519PrivateKey.
func parseEd25519PublicKey(ctx context.Context, op errors.Op, pubDER []byte, encoding providerpb.PublicKeyEncoding) (ed25519.PublicKey, error) {
	switch encoding {
	case providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI,
		providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_UNSPECIFIED:
		key, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "public key is not Ed25519")
		}
		return edKey, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported Ed25519 public key encoding: %s", encoding))
	}
}

// checkEd25519PureVariant rejects anything but the pure variant. Ed25519ctx
// is not implemented at all; Ed25519ph is prehashed by definition and so is
// never reachable through Sign/Verify — it has its own SignDigest/
// VerifyDigest path once implemented, exactly like every other prehashable
// signature scheme in this provider.
func checkEd25519PureVariant(ctx context.Context, op errors.Op, variant types.Ed25519Variant) error {
	switch variant {
	case types.Ed25519Variant_ED25519_VARIANT_UNSPECIFIED, types.Ed25519Variant_ED25519_VARIANT_PURE:
		return nil
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported Ed25519 variant for Sign/Verify: %s", variant))
	}
}

// signEd25519 signs payload with the pure Ed25519 variant (RFC 8032).
// Ed25519 hashes internally (SHA-512, two passes) and needs no caller-chosen
// hash algorithm — unlike ECDSA/RSA, there is no hash parameter here at all.
func signEd25519(ctx context.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, variant types.Ed25519Variant) ([]byte, error) {
	const op errors.Op = "software.signEd25519"

	if err := checkEd25519PureVariant(ctx, op, variant); err != nil {
		return nil, err
	}
	privKey, err := parseEd25519PrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privKey, payload), nil
}

// verifyEd25519 reports whether signature is a valid pure-Ed25519 signature
// over payload. ed25519.Verify already returns a plain bool rather than an
// error, so — unlike RSA/ECDSA verify — there is no separate error-collapsing
// step needed to honor this codebase's "bad signature is never an error"
// convention; the stdlib API enforces it structurally.
func verifyEd25519(ctx context.Context, pubDER, payload, signature []byte, keyEncoding providerpb.PublicKeyEncoding, variant types.Ed25519Variant) (bool, error) {
	const op errors.Op = "software.verifyEd25519"

	if err := checkEd25519PureVariant(ctx, op, variant); err != nil {
		return false, err
	}
	pubKey, err := parseEd25519PublicKey(ctx, op, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(pubKey, payload, signature), nil
}

// checkEd25519PHHash validates that a SignDigest/VerifyDigest call declares
// SHA-512 as the digest's origin hash. Unlike RSA's prehashed variants,
// Ed25519ph is not generic over hash algorithm — RFC 8032 §5.1 defines
// PH(x) = SHA-512(x), full stop, so there is no "Ed25519ph with SHA-384" or
// similar. Digest-length validation alone cannot catch a wrong hash here:
// SHA3-512, BLAKE2b-512, and others also produce 64-byte digests, so a
// caller declaring one of those would otherwise slip through unnoticed.
func checkEd25519PHHash(ctx context.Context, op errors.Op, hashAlg types.HashAlgorithm) error {
	switch hashAlg {
	case types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return nil
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("Ed25519ph requires a SHA-512 digest, got hash_algorithm=%s", hashAlg))
	}
}

// signEd25519PHDigest signs a pre-computed SHA-512 digest with Ed25519ph
// (RFC 8032). Used by SignDigest, where the caller has already hashed the
// message with SHA-512 — the mandatory hash for this variant.
func signEd25519PHDigest(ctx context.Context, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, hashAlg types.HashAlgorithm) ([]byte, error) {
	const op errors.Op = "software.signEd25519PHDigest"

	if err := checkEd25519PHHash(ctx, op, hashAlg); err != nil {
		return nil, err
	}
	privKey, err := parseEd25519PrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	sig, err := privKey.Sign(nil, digest, crypto.SHA512)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyEd25519PHDigest verifies a signature over a pre-computed SHA-512
// digest using Ed25519ph. Used by VerifyDigest; see signEd25519PHDigest.
func verifyEd25519PHDigest(ctx context.Context, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, hashAlg types.HashAlgorithm) (bool, error) {
	const op errors.Op = "software.verifyEd25519PHDigest"

	if err := checkEd25519PHHash(ctx, op, hashAlg); err != nil {
		return false, err
	}
	pubKey, err := parseEd25519PublicKey(ctx, op, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	if err = ed25519.VerifyWithOptions(pubKey, digest, signature, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		//nolint:nilerr // intentional: VerifyWithOptions returns a single
		// generic error for every failure mode, so any error here means
		// "invalid signature", never "provider malfunctioned" — the same
		// convention verifyEd25519 gets from ed25519.Verify's bool return.
		return false, nil
	}
	return true, nil
}
