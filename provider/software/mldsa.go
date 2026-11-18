package software

import (
	"context"
	"fmt"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// mldsaScheme resolves the CIRCL generic sign.Scheme for a declared ML-DSA
// parameter set. AlgorithmDetails is authoritative for dispatch, the same
// convention checkCurveMatches/checkRSAKeySize apply elsewhere — a parameter
// set the caller declares but this provider does not implement is rejected
// outright rather than guessed at.
func mldsaScheme(ctx context.Context, op errors.Op, parameterSet types.MlDsaParameterSet) (sign.Scheme, error) {
	switch parameterSet {
	case types.MlDsaParameterSet_ML_DSA_44:
		return mldsa44.Scheme(), nil
	case types.MlDsaParameterSet_ML_DSA_65:
		return mldsa65.Scheme(), nil
	case types.MlDsaParameterSet_ML_DSA_87:
		return mldsa87.Scheme(), nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ML-DSA parameter set: %s", parameterSet))
	}
}

// generateMLDSAKey generates an ML-DSA key pair, storing the private half as
// PKCS#8 wrapping the seed (FIPS 204's xi) rather than the full expanded
// private key. circl/pki.MarshalPKIXPrivateKey special-cases ML-DSA to do
// exactly this — draft-ietf-lamps-dilithium-certificates recommends the seed
// form for storage efficiency, since scheme.DeriveKey can always reconstruct
// the expanded key and public key from it. The public half has no such
// seed-vs-expanded distinction, so it stays in CIRCL's native packed form.
func generateMLDSAKey(ctx context.Context, parameterSet types.MlDsaParameterSet) (pubBytes, privBytes []byte, _ error) {
	const op errors.Op = "software.generateMLDSAKey"

	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return nil, nil, err
	}

	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	pubBytes, err = pub.MarshalBinary()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	privBytes, err = pki.MarshalPKIXPrivateKey(priv)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return pubBytes, privBytes, nil
}

// parseMLDSAPrivateKey parses privBytes as an ML-DSA private key, dispatched
// on the declared encoding.
//
//   - PKCS8: the current storage format — a seed wrapped per
//     draft-ietf-lamps-dilithium-certificates, parsed and derived back into
//     a signing key by circl/pki.UnmarshalPKIXPrivateKey. The embedded OID
//     self-describes a scheme; that parsed scheme is cross-checked against
//     the one AlgorithmDetails declares rather than trusted on its own — the
//     same "declaration is authoritative, parsed data only validates it"
//     convention checkCurveMatches/checkRSAKeySize use elsewhere.
//   - RAW: the legacy expanded-key format every key generated before this
//     provider switched to PKCS#8 storage uses. Legacy keys can never be
//     upgraded to PKCS#8 — the expanded form does not carry the seed — so
//     this fallback is permanent, not a transitional shim.
//   - unspecified: legacy keys predate the encoding field entirely and so
//     carry no explicit value. Try PKCS#8 first; a successful parse (right
//     down to a matching scheme) is decisive on its own, a mismatched scheme
//     is a decisive config error, and only an outright parse failure falls
//     back to RAW — legacy expanded-key blobs are large, unstructured
//     lattice material with no realistic chance of also parsing as valid
//     PKCS#8 DER, so this fallback does not risk masking a real error the
//     way retrying a second *structured* encoding (as ECDSA's PKCS8-then-
//     SEC1 fallback must guard against) would.
func parseMLDSAPrivateKey(ctx context.Context, op errors.Op, privBytes []byte, encoding providerpb.PrivateKeyEncoding, scheme sign.Scheme, parameterSet types.MlDsaParameterSet) (sign.PrivateKey, error) {
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8:
		return parseMLDSAPKCS8PrivateKey(ctx, op, privBytes, scheme, parameterSet)
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW:
		privKey, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return privKey, nil
	default:
		if privKey, err := parseMLDSAPKCS8PrivateKey(ctx, op, privBytes, scheme, parameterSet); err == nil {
			return privKey, nil
		}
		privKey, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return privKey, nil
	}
}

func parseMLDSAPKCS8PrivateKey(ctx context.Context, op errors.Op, privBytes []byte, scheme sign.Scheme, parameterSet types.MlDsaParameterSet) (sign.PrivateKey, error) {
	privKey, err := pki.UnmarshalPKIXPrivateKey(privBytes)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if privKey.Scheme() != scheme {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"PKCS#8 key scheme %s does not match declared ML-DSA parameter set %s", privKey.Scheme().Name(), parameterSet)
	}
	return privKey, nil
}

// mldsaMaxContextLen is the longest domain separation context FIPS 204
// permits, and the same bound SignatureDomainContext.context declares.
const mldsaMaxContextLen = 255

// checkMLDSAContextLength rejects an over-long domain separation context,
// following the same defensive-check convention as checkAESKeyMatchesDeclaredSize
// and checkCurveMatches: AlgorithmDetails and the request are validated here
// rather than assumed well-formed.
//
// This is not redundant with the max_len constraint the request message
// declares. CIRCL's two signing paths disagree on how they report an
// over-long context — the package-level SignTo returns an error, while
// sign.Scheme.Sign panics on it — so without this check the deterministic
// path would crash the process rather than reject the request, on an input
// only a constraint declared in a different layer keeps out. Verify has no
// such cliff (CIRCL returns false), but is checked here too so an invalid
// request is reported as one instead of masquerading as a bad signature.
func checkMLDSAContextLength(ctx context.Context, op errors.Op, domainContext []byte) error {
	if len(domainContext) > mldsaMaxContextLen {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"domain separation context is %d bytes, exceeds the %d-byte maximum",
			len(domainContext), mldsaMaxContextLen)
	}
	return nil
}

// mldsaSignatureOpts wraps a domain separation context in the options type
// CIRCL's generic sign.Scheme takes.
//
// sign.SignatureOpts.Context is a string while FIPS 204 and this server's API
// both treat the context as arbitrary bytes; Go strings hold arbitrary bytes,
// so the conversion is lossless — CIRCL converts straight back with
// []byte(opts.Context) before hashing it in.
//
// A nil or empty domainContext yields Context: "", which produces the same
// signature as passing no context at all: FIPS 204 defines the empty context
// and the absent context to be the same value, so the two cannot be — and do
// not need to be — distinguished here.
func mldsaSignatureOpts(domainContext []byte) *sign.SignatureOpts {
	return &sign.SignatureOpts{Context: string(domainContext)}
}

// signMLDSA signs payload with the ML-DSA private key encoded in privBytes.
//
// domainContext is the FIPS 204 context string used for domain separation:
// a signature made under one context does not verify under another, which is
// what makes it safe to reuse one key across protocols. It arrives from
// SignRequest's domain_context scope arm and must be threaded into whichever
// of the two signing paths below runs — a dropped context yields a signature
// with no domain separation at all while the caller believes they asked for
// one, which verifies against anything and is strictly weaker than intended.
//
// sign.Scheme.Sign is deterministic-only — every CIRCL ML-DSA scheme wrapper
// hardcodes randomized=false internally — so honoring
// MlDsaParams.deterministic=false (proto3's zero value, matching FIPS 204
// -3.6's recommendation to prefer hedged/randomized signing) requires
// dropping to the package-level SignTo function instead, which does accept
// a randomized flag. That function is scheme-specific (mldsa44.SignTo vs
// mldsa65.SignTo vs mldsa87.SignTo), unlike everything else in this file
// that stays generic over sign.Scheme, so it needs its own per-parameter-set
// dispatch — see signMLDSARandomized.
func signMLDSA(ctx context.Context, privBytes, payload, domainContext []byte, keyEncoding providerpb.PrivateKeyEncoding, parameterSet types.MlDsaParameterSet, deterministic bool) ([]byte, error) {
	const op errors.Op = "software.signMLDSA"

	if err := checkMLDSAContextLength(ctx, op, domainContext); err != nil {
		return nil, err
	}
	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return nil, err
	}
	privKey, err := parseMLDSAPrivateKey(ctx, op, privBytes, keyEncoding, scheme, parameterSet)
	if err != nil {
		return nil, err
	}
	if deterministic {
		return scheme.Sign(privKey, payload, mldsaSignatureOpts(domainContext)), nil
	}
	return signMLDSARandomized(ctx, op, privKey, payload, domainContext, parameterSet)
}

// signMLDSARandomized performs hedged (randomized) ML-DSA signing via the
// scheme-specific package-level SignTo function — see signMLDSA for why
// sign.Scheme.Sign cannot do this. privKey must be the concrete private key
// type SignTo for parameterSet expects; parseMLDSAPrivateKey always returns
// exactly that type for a given parameterSet, since it derives from
// mldsaScheme(parameterSet) itself, so the type assertions inside
// signMLDSARandomizedWith cannot fail in practice.
func signMLDSARandomized(ctx context.Context, op errors.Op, privKey sign.PrivateKey, payload, domainContext []byte, parameterSet types.MlDsaParameterSet) ([]byte, error) {
	switch parameterSet {
	case types.MlDsaParameterSet_ML_DSA_44:
		return signMLDSARandomizedWith(ctx, op, privKey, payload, domainContext, mldsa44.SignatureSize, mldsa44.SignTo, "ML-DSA-44")
	case types.MlDsaParameterSet_ML_DSA_65:
		return signMLDSARandomizedWith(ctx, op, privKey, payload, domainContext, mldsa65.SignatureSize, mldsa65.SignTo, "ML-DSA-65")
	case types.MlDsaParameterSet_ML_DSA_87:
		return signMLDSARandomizedWith(ctx, op, privKey, payload, domainContext, mldsa87.SignatureSize, mldsa87.SignTo, "ML-DSA-87")
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported ML-DSA parameter set: %s", parameterSet)
	}
}

// signMLDSARandomizedWith is the single generic implementation
// signMLDSARandomized's three parameter-set cases each instantiate with
// their own concrete private key type and package-level SignTo function —
// mldsa44/mldsa65/mldsa87 have identical SignTo signatures but each takes
// its own concrete *PrivateKey type, so they cannot share one non-generic
// function value.
func signMLDSARandomizedWith[SK any](ctx context.Context, op errors.Op, privKey sign.PrivateKey, payload, domainContext []byte, sigSize int, signTo func(sk SK, msg, sigCtx []byte, randomized bool, sig []byte) error, paramSetName string) ([]byte, error) {
	sk, ok := privKey.(SK)
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeInternal, "%s private key has unexpected type %T", paramSetName, privKey)
	}
	sig := make([]byte, sigSize)
	if err := signTo(sk, payload, domainContext, true, sig); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyMLDSA reports whether signature is valid for payload under the given
// domainContext. The context must match the one used at signing byte for
// byte — that mismatch returning false, rather than being ignored, is the
// whole point of domain separation.
func verifyMLDSA(ctx context.Context, pubBytes, payload, signature, domainContext []byte, parameterSet types.MlDsaParameterSet) (bool, error) {
	const op errors.Op = "software.verifyMLDSA"

	if err := checkMLDSAContextLength(ctx, op, domainContext); err != nil {
		return false, err
	}
	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return false, err
	}
	pubKey, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		// Malformed stored public key — internal consistency error, not a sig failure.
		return false, errors.Wrap(ctx, op, err)
	}

	// scheme.Verify returns false for any invalid signature; it never errors.
	return scheme.Verify(pubKey, payload, signature, mldsaSignatureOpts(domainContext)), nil
}
