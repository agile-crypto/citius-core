package software

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// generateRSAKey generates an RSA key pair of the given size, encoded as
// PKCS#8 (private) and PKIX SubjectPublicKeyInfo (public) — the same pair of
// standard, self-describing formats used elsewhere in this provider.
func generateRSAKey(ctx context.Context, keySizeBits uint32) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "software.generateRSAKey"

	privKey, err := rsa.GenerateKey(rand.Reader, int(keySizeBits))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	privDER, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	pubDER, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	return pubDER, privDER, nil
}

// parseRSAPrivateKey parses privDER as an RSA private key.  Only PKCS#8 is
// ever produced by this provider (see generateRSAKey), so — unlike ECDSA,
// which must reconcile the legacy SEC1 format — there is no fallback format
// to guess between; UNSPECIFIED simply means "PKCS#8, the only format this
// provider has ever written."
func parseRSAPrivateKey(ctx context.Context, op errors.Op, privDER []byte, encoding providerpb.PrivateKeyEncoding) (*rsa.PrivateKey, error) {
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
		providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED:
		key, err := x509.ParsePKCS8PrivateKey(privDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				fmt.Sprintf("PKCS#8 key is not RSA: %T", key))
		}
		return rsaKey, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported RSA private key encoding: %s", encoding))
	}
}

// parseRSAPublicKey parses pubDER as an RSA public key.  SPKI is the only
// format this provider ever writes; see parseRSAPrivateKey.
func parseRSAPublicKey(ctx context.Context, op errors.Op, pubDER []byte, encoding providerpb.PublicKeyEncoding) (*rsa.PublicKey, error) {
	switch encoding {
	case providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI,
		providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_UNSPECIFIED:
		key, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "public key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported RSA public key encoding: %s", encoding))
	}
}

// checkRSAKeySize cross-checks a parsed key's actual modulus size against
// the size AlgorithmDetails declares — the RSA analogue of checkCurveMatches
// for ECDSA: AlgorithmDetails is authoritative for dispatch, and the parsed
// key only validates that declaration rather than driving it.
func checkRSAKeySize(ctx context.Context, op errors.Op, key *rsa.PublicKey, declaredBits uint32) error {
	if actual := key.N.BitLen(); actual != int(declaredBits) {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("key size %d bits does not match declared algorithm key size %d bits", actual, declaredBits))
	}
	return nil
}

// rsaHash resolves the typed HashAlgorithm to crypto.Hash, restricted to
// exactly what RsaPssParams.hash's proto constraint allows: UNSPECIFIED
// (defaults to SHA-256 per the field's documented default), SHA-256,
// SHA-384, or SHA-512.
func rsaHash(ctx context.Context, op errors.Op, hash types.HashAlgorithm) (crypto.Hash, error) {
	switch hash {
	case types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.HashAlgorithm_HASH_ALGORITHM_SHA256:
		return crypto.SHA256, nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA384:
		return crypto.SHA384, nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return crypto.SHA512, nil
	default:
		return 0, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported RSA hash algorithm: %s", hash))
	}
}

// rsaDigestBytes hashes payload under hash.  Callers MUST validate hash via
// rsaHash first; SHA-256 is the default/fallthrough case since UNSPECIFIED
// and SHA-256 both map to it, and rsaHash has already rejected anything else.
func rsaDigestBytes(hash types.HashAlgorithm, payload []byte) []byte {
	switch hash {
	case types.HashAlgorithm_HASH_ALGORITHM_SHA384:
		d := sha512.Sum384(payload)
		return d[:]
	case types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		d := sha512.Sum512(payload)
		return d[:]
	default:
		d := sha256.Sum256(payload)
		return d[:]
	}
}

// checkRSAPSSMGF validates the declared mask generation function and MGF
// hash against what Go's crypto/rsa can actually do: SignPSS/VerifyPSS
// always use MGF1 with the SAME hash as the message hash — there is no API
// to specify an independent MGF hash.  A template declaring mgf_hash
// different from hash cannot be honored and is rejected rather than
// silently signed under the wrong MGF hash.
func checkRSAPSSMGF(ctx context.Context, op errors.Op, mgf types.MaskGenerationFunction, hash, mgfHash types.HashAlgorithm) error {
	if mgf != types.MaskGenerationFunction_MGF_UNSPECIFIED && mgf != types.MaskGenerationFunction_MGF_MGF1 {
		return errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported RSA-PSS mask generation function: %s", mgf))
	}
	if mgfHash != types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED && mgfHash != hash {
		return errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("RSA-PSS with mgf_hash (%s) different from hash (%s) is not supported", mgfHash, hash))
	}
	return nil
}

// rsaPSSSaltLength maps RsaPssParams.salt_length_mode/salt_length_bytes to
// Go's rsa.PSSOptions.SaltLength.
//
// Go's two named constants are numerically counter-intuitive relative to
// their names: PSSSaltLengthAuto = 0 (as large as possible when signing,
// auto-detected when verifying) and PSSSaltLengthEqualsHash = -1 (salt
// length equals the hash output length) — verified against crypto/rsa's
// docs directly rather than assumed, since guessing here would silently
// swap MAX and HASH_LENGTH.
func rsaPSSSaltLength(ctx context.Context, op errors.Op, mode types.RsaPssParams_SaltLengthMode, explicitBytes uint32) (int, error) {
	switch mode {
	case types.RsaPssParams_SALT_LENGTH_MODE_HASH_LENGTH:
		return rsa.PSSSaltLengthEqualsHash, nil
	case types.RsaPssParams_SALT_LENGTH_MODE_MAX:
		return rsa.PSSSaltLengthAuto, nil
	case types.RsaPssParams_SALT_LENGTH_MODE_EXPLICIT:
		if explicitBytes == 0 {
			return 0, errors.New(ctx, op, errors.CodeInvalidArgument,
				"SALT_LENGTH_MODE_EXPLICIT requires salt_length_bytes > 0")
		}
		return int(explicitBytes), nil
	default:
		return 0, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported RSA-PSS salt length mode: %s", mode))
	}
}

// signRSAPSSCore signs digest (already hashed under hashAlg) with RSA-PSS —
// the shared implementation signRSAPSS and signRSAPSSDigest both need. They
// differ only in how digest and hashAlg are obtained: signRSAPSS hashes
// payload under params.GetHash(); signRSAPSSDigest accepts an
// already-hashed digest and the caller-declared hashAlg directly (see
// signRSAPSSDigest for why the two sources differ for the prehashed case).
func signRSAPSSCore(ctx context.Context, op errors.Op, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPssParams) ([]byte, error) {
	privKey, err := parseRSAPrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	if err = checkRSAKeySize(ctx, op, &privKey.PublicKey, params.GetKeySizeBits()); err != nil {
		return nil, err
	}
	if err = checkRSAPSSMGF(ctx, op, params.GetMgf(), hashAlg, params.GetMgfHash()); err != nil {
		return nil, err
	}
	h, err := rsaHash(ctx, op, hashAlg)
	if err != nil {
		return nil, err
	}
	saltLen, err := rsaPSSSaltLength(ctx, op, params.GetSaltLengthMode(), params.GetSaltLengthBytes())
	if err != nil {
		return nil, err
	}

	sig, err := rsa.SignPSS(rand.Reader, privKey, h, digest, &rsa.PSSOptions{SaltLength: saltLen})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyRSAPSSCore is signRSAPSSCore's verify counterpart, shared by
// verifyRSAPSS and verifyRSAPSSDigest. A verification failure is never an
// error — Go's VerifyPSS deliberately collapses every failure mode (wrong
// signature, wrong salt length, malformed signature bytes) into the single
// ErrVerification, by design, to avoid adaptive attacks — so any non-nil
// error here means "invalid", not "the provider malfunctioned".
func verifyRSAPSSCore(ctx context.Context, op errors.Op, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPssParams) (bool, error) {
	pubKey, err := parseRSAPublicKey(ctx, op, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	if err = checkRSAKeySize(ctx, op, pubKey, params.GetKeySizeBits()); err != nil {
		return false, err
	}
	if err = checkRSAPSSMGF(ctx, op, params.GetMgf(), hashAlg, params.GetMgfHash()); err != nil {
		return false, err
	}
	h, err := rsaHash(ctx, op, hashAlg)
	if err != nil {
		return false, err
	}
	saltLen, err := rsaPSSSaltLength(ctx, op, params.GetSaltLengthMode(), params.GetSaltLengthBytes())
	if err != nil {
		return false, err
	}

	if err = rsa.VerifyPSS(pubKey, h, digest, signature, &rsa.PSSOptions{SaltLength: saltLen}); err != nil {
		//nolint:nilerr // intentional: rsa.VerifyPSS collapses every failure
		// mode (wrong signature, wrong salt length, malformed bytes) into
		// the single ErrVerification by design ("deliberately vague to
		// avoid adaptive attacks" — see the stdlib doc), so any error here
		// means "invalid signature", never "provider malfunctioned".
		return false, nil
	}
	return true, nil
}

func signRSAPSS(ctx context.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, params *types.RsaPssParams) ([]byte, error) {
	const op errors.Op = "software.signRSAPSS"
	return signRSAPSSCore(ctx, op, privDER, rsaDigestBytes(params.GetHash(), payload), keyEncoding, params.GetHash(), params)
}

// verifyRSAPSS reports whether signature is a valid RSA-PSS signature over
// payload. See verifyRSAPSSCore for the verification-failure-is-not-an-error
// rationale.
func verifyRSAPSS(ctx context.Context, pubDER, payload, signature []byte, keyEncoding providerpb.PublicKeyEncoding, params *types.RsaPssParams) (bool, error) {
	const op errors.Op = "software.verifyRSAPSS"
	return verifyRSAPSSCore(ctx, op, pubDER, rsaDigestBytes(params.GetHash(), payload), signature, keyEncoding, params.GetHash(), params)
}

// signRSAPSSDigest signs a pre-computed digest directly, without hashing.
// Used by SignDigest, where the caller has already hashed the message.
//
// Unlike signRSAPSS, the hash algorithm comes from hashAlg (the request's
// declared digest origin, SignDigestRequest.hash_algorithm) rather than
// params.GetHash(): the prehashed catalog templates (rsa-pss-*-prehashed)
// leave RsaPssParams.hash unset, since a single prehashed template accepts
// digests produced under any hash the caller declares — the digest bytes
// alone cannot say which hash produced them.
func signRSAPSSDigest(ctx context.Context, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPssParams) ([]byte, error) {
	const op errors.Op = "software.signRSAPSSDigest"
	return signRSAPSSCore(ctx, op, privDER, digest, keyEncoding, hashAlg, params)
}

// verifyRSAPSSDigest verifies a signature over a pre-computed digest
// directly, without hashing.  Used by VerifyDigest; see signRSAPSSDigest for
// why hashAlg (not params.GetHash()) selects the hash algorithm.
func verifyRSAPSSDigest(ctx context.Context, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPssParams) (bool, error) {
	const op errors.Op = "software.verifyRSAPSSDigest"
	return verifyRSAPSSCore(ctx, op, pubDER, digest, signature, keyEncoding, hashAlg, params)
}

// signRSAPKCS1v15Core signs digest (already hashed under hashAlg) with RSA
// PKCS#1 v1.5 — the shared implementation signRSAPKCS1v15 and
// signRSAPKCS1v15Digest both need; see signRSAPSSCore for why the two
// callers differ only in how digest/hashAlg are obtained.
func signRSAPKCS1v15Core(ctx context.Context, op errors.Op, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPkcs1V15Params) ([]byte, error) {
	privKey, err := parseRSAPrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	if err = checkRSAKeySize(ctx, op, &privKey.PublicKey, params.GetKeySizeBits()); err != nil {
		return nil, err
	}
	h, err := rsaHash(ctx, op, hashAlg)
	if err != nil {
		return nil, err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, h, digest)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyRSAPKCS1v15Core is signRSAPKCS1v15Core's verify counterpart, shared
// by verifyRSAPKCS1v15 and verifyRSAPKCS1v15Digest. Like verifyRSAPSSCore, a
// verification failure is never an error: rsa.VerifyPKCS1v15 returns a
// single generic error for every failure mode (wrong signature, malformed
// bytes), so any non-nil error here means "invalid signature", never
// "provider malfunctioned".
func verifyRSAPKCS1v15Core(ctx context.Context, op errors.Op, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPkcs1V15Params) (bool, error) {
	pubKey, err := parseRSAPublicKey(ctx, op, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	if err = checkRSAKeySize(ctx, op, pubKey, params.GetKeySizeBits()); err != nil {
		return false, err
	}
	h, err := rsaHash(ctx, op, hashAlg)
	if err != nil {
		return false, err
	}

	if err = rsa.VerifyPKCS1v15(pubKey, h, digest, signature); err != nil {
		//nolint:nilerr // intentional: rsa.VerifyPKCS1v15 returns a single
		// generic error for every failure mode, so any error here means
		// "invalid signature", never "provider malfunctioned".
		return false, nil
	}
	return true, nil
}

func signRSAPKCS1v15(ctx context.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, params *types.RsaPkcs1V15Params) ([]byte, error) {
	const op errors.Op = "software.signRSAPKCS1v15"
	return signRSAPKCS1v15Core(ctx, op, privDER, rsaDigestBytes(params.GetHash(), payload), keyEncoding, params.GetHash(), params)
}

// verifyRSAPKCS1v15 reports whether signature is a valid RSA PKCS#1 v1.5
// signature over payload. See verifyRSAPKCS1v15Core for the
// verification-failure-is-not-an-error rationale.
func verifyRSAPKCS1v15(ctx context.Context, pubDER, payload, signature []byte, keyEncoding providerpb.PublicKeyEncoding, params *types.RsaPkcs1V15Params) (bool, error) {
	const op errors.Op = "software.verifyRSAPKCS1v15"
	return verifyRSAPKCS1v15Core(ctx, op, pubDER, rsaDigestBytes(params.GetHash(), payload), signature, keyEncoding, params.GetHash(), params)
}

// signRSAPKCS1v15Digest signs a pre-computed digest directly, without
// hashing.  See signRSAPSSDigest for why hashAlg, not params.GetHash(),
// selects the hash algorithm for prehashed operations.
func signRSAPKCS1v15Digest(ctx context.Context, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPkcs1V15Params) ([]byte, error) {
	const op errors.Op = "software.signRSAPKCS1v15Digest"
	return signRSAPKCS1v15Core(ctx, op, privDER, digest, keyEncoding, hashAlg, params)
}

// verifyRSAPKCS1v15Digest verifies a signature over a pre-computed digest
// directly, without hashing.  See signRSAPSSDigest for why hashAlg, not
// params.GetHash(), selects the hash algorithm for prehashed operations.
func verifyRSAPKCS1v15Digest(ctx context.Context, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, hashAlg types.HashAlgorithm, params *types.RsaPkcs1V15Params) (bool, error) {
	const op errors.Op = "software.verifyRSAPKCS1v15Digest"
	return verifyRSAPKCS1v15Core(ctx, op, pubDER, digest, signature, keyEncoding, hashAlg, params)
}
