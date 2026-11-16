// Package software implements a provider.Backend backed by Go's standard crypto library
// plus the circl library for post-quantum algorithms (ML-DSA).
package software

import (
	"context"
	"fmt"
	"runtime"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"google.golang.org/protobuf/proto"
)

// Provider is a stateless software-backed provider.Backend implementation.
// Key material is NOT stored internally — the orchestrator manages persistence.
type Provider struct{}

// New creates a new software Provider.
func New() *Provider {
	return &Provider{}
}

func (p *Provider) Name() string { return "software" }
func (p *Provider) Type() string { return "software" }

// SupportedAlgorithms returns the algorithm IDs this provider handles.
// These IDs must exactly match the TemplateID values in the template catalog JSON.
//
// provider.Registry.MatchForTemplate gates CreateKey on this list: a
// template whose algorithm this provider's dispatch switches fully support
//
// Not supported at the moment: ecdsa-secp256k1-* (curve not implemented),
// ed25519ctx/ed448 (not implemented), and slh-dsa-*/hash-*-dsa-* (not
// implemented).
func (p *Provider) SupportedAlgorithms() []string {
	return []string{
		"ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ecdsa-p521-sha512-der",
		"ecdsa-p256-prehashed-der", "ecdsa-p384-prehashed-der", "ecdsa-p521-prehashed-der",
		"rsa-pss-sha256-mgf1-32-2048", "rsa-pss-sha256-mgf1-32-3072", "rsa-pss-sha384-mgf1-48-4096",
		"rsa-pss-2048-prehashed", "rsa-pss-3072-prehashed", "rsa-pss-4096-prehashed",
		"rsa-pkcs1v15-sha256-2048", "rsa-pkcs1v15-2048-prehashed",
		"ed25519", "ed25519ph",
		"ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
		"aes-128-gcm-128-96", "aes-192-gcm-128-96", "aes-256-gcm-128-96",
		"aes-128-cbc-pkcs7-128", "aes-192-cbc-pkcs7-128", "aes-256-cbc-pkcs7-128",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"chacha20-poly1305", "xchacha20-poly1305",
	}
}

// DestroyKey is a no-op for the stateless software provider.
// The orchestrator manages key lifecycle; the provider has no internal state.
func (p *Provider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}

// ExportPublicKey may/may-not supported by the stateless software provider.
// The orchestrator already has the public key bytes from GenerateKey.
func (p *Provider) ExportPublicKey(ctx context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	const op errors.Op = "software.Provider.ExportPublicKey"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented,
		"ExportPublicKey not supported: provider is stateless, orchestrator has the key bytes")
}

// GenerateKey generates a key pair for the given algorithm and returns the key material.
// The provider is stateless — key material is returned to the caller (orchestrator) for storage.
func (p *Provider) GenerateKey(ctx context.Context, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	const op errors.Op = "software.(Provider).GenerateKey"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	var (
		pubDER  []byte
		privDER []byte
		pubEnc  providerpb.PublicKeyEncoding
		err     error
	)

	// Dispatch on the typed AlgorithmDetails oneof.
	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		pubDER, privDER, err = generateECDSAKey(ctx, alg.Ecdsa.GetCurve())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// The two halves differ: x509.MarshalECPrivateKey writes SEC1
		// (RFC 5915) while x509.MarshalPKIXPublicKey writes SPKI (RFC 5280).
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_MlDsa:
		pubDER, privDER, err = generateMLDSAKey(ctx, alg.MlDsa.GetParameterSet())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// Private half: PKCS#8 wrapping the seed (see generateMLDSAKey).
		// Public half: no seed-vs-expanded distinction exists for it, so it
		// stays in CIRCL's native packed form — not yet SPKI.
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW
	case *types.AlgorithmDetails_RsaPss:
		pubDER, privDER, err = generateRSAKey(ctx, alg.RsaPss.GetKeySizeBits())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_RsaPkcs1V15:
		pubDER, privDER, err = generateRSAKey(ctx, alg.RsaPkcs1V15.GetKeySizeBits())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_Ed25519:
		pubDER, privDER, err = generateEd25519Key(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_AesGcm, *types.AlgorithmDetails_AesCbc, *types.AlgorithmDetails_AesCtr, *types.AlgorithmDetails_Chacha20Poly1305:
		privDER, err = generateSymmetricKey(ctx, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// Symmetric: no public half — pubDER/pubEnc stay at their zero values.
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm type: %T", req.GetAlgorithm().GetAlgorithm()))
	}

	return generatedKey(ctx, op, req.GetAlgorithm(), pubDER, privDER, pubEnc)
}

// Sign dispatches to the algorithm-specific sign implementation.
func (p *Provider) Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	const op errors.Op = "software.(Provider).Sign"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		sig, err := signECDSA(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(),
			alg.Ecdsa.GetCurve(), alg.Ecdsa.GetHash(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput(ecdsaSignatureEncodingLabel(alg.Ecdsa.GetSignatureFormat()))}, nil
	case *types.AlgorithmDetails_MlDsa:
		sig, err := signMLDSA(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetDomainContext().GetContext(),
			req.GetKeyMaterialEncoding(), alg.MlDsa.GetParameterSet(), alg.MlDsa.GetDeterministic())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_RsaPss:
		sig, err := signRSAPSS(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		sig, err := signRSAPKCS1v15(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_Ed25519:
		sig, err := signEd25519(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(), alg.Ed25519.GetVariant())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for sign: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Verify dispatches to the algorithm-specific verify implementation.
func (p *Provider) Verify(ctx context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	const op errors.Op = "software.(Provider).Verify"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		valid, err := verifyECDSA(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ecdsa.GetCurve(), alg.Ecdsa.GetHash(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_MlDsa:
		valid, err := verifyMLDSA(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetDomainContext().GetContext(), alg.MlDsa.GetParameterSet())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_RsaPss:
		valid, err := verifyRSAPSS(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		valid, err := verifyRSAPKCS1v15(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_Ed25519:
		valid, err := verifyEd25519(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ed25519.GetVariant())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for verify: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// validateDigestLength rejects a digest whose length contradicts the
// declared hash algorithm (e.g. a 20-byte digest claiming to be SHA-256,
// which must be 32 bytes).  Hash algorithms with no fixed length
// (UNSPECIFIED, OTHER, the SHAKE XOFs) are not checked — the caller declared
// no fixed-length hash, so there is nothing to validate the digest against.
func validateDigestLength(ctx context.Context, op errors.Op, hashAlg types.HashAlgorithm, digestLen int) error {
	wantLen, ok := provider.DigestLengthForHash(hashAlg)
	if !ok {
		return nil
	}
	if digestLen != wantLen {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("digest length %d bytes does not match expected length %d bytes for %s",
				digestLen, wantLen, hashAlg))
	}
	return nil
}

// SignDigest signs a pre-computed digest — the provider does NOT hash.
// Dispatches on the typed AlgorithmDetails oneof, exactly like Sign; the
// digest and key material alone cannot select the signature scheme (a single
// RSA key is valid under both PSS and PKCS1v15), so hash_algorithm describes
// only the digest's origin, never the algorithm to dispatch on.
func (p *Provider) SignDigest(ctx context.Context, req *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	const op errors.Op = "software.(Provider).SignDigest"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}
	if err := validateDigestLength(ctx, op, req.GetHashAlgorithm(), len(req.GetDigest())); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		sig, err := signECDSADigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			alg.Ecdsa.GetCurve(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput(ecdsaSignatureEncodingLabel(alg.Ecdsa.GetSignatureFormat()))}, nil
	case *types.AlgorithmDetails_MlDsa:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"SignDigest unsupported for ML-DSA: pure ML-DSA is not prehashable")
	case *types.AlgorithmDetails_RsaPss:
		sig, err := signRSAPSSDigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			req.GetHashAlgorithm(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		sig, err := signRSAPKCS1v15Digest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			req.GetHashAlgorithm(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_Ed25519:
		if alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_UNSPECIFIED &&
			alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_PH {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"SignDigest requires Ed25519ph: pure Ed25519 and Ed25519ctx are not prehashable")
		}
		sig, err := signEd25519PHDigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(), req.GetHashAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for digest sign: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// VerifyDigest verifies a signature over a pre-computed digest.
// Dispatches on the typed AlgorithmDetails oneof, exactly like Verify.
func (p *Provider) VerifyDigest(ctx context.Context, req *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	const op errors.Op = "software.(Provider).VerifyDigest"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}
	if err := validateDigestLength(ctx, op, req.GetHashAlgorithm(), len(req.GetDigest())); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		valid, err := verifyECDSADigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ecdsa.GetCurve(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_MlDsa:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"VerifyDigest unsupported for ML-DSA: pure ML-DSA is not prehashable")
	case *types.AlgorithmDetails_RsaPss:
		valid, err := verifyRSAPSSDigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), req.GetHashAlgorithm(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		valid, err := verifyRSAPKCS1v15Digest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), req.GetHashAlgorithm(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_Ed25519:
		if alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_UNSPECIFIED &&
			alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_PH {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"VerifyDigest requires Ed25519ph: pure Ed25519 and Ed25519ctx are not prehashable")
		}
		valid, err := verifyEd25519PHDigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), req.GetHashAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for digest verify: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Encrypt dispatches to the algorithm-specific encrypt implementation.
func (p *Provider) Encrypt(ctx context.Context, req *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	const op errors.Op = "software.(Provider).Encrypt"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_AesGcm:
		ciphertext, nonce, err := encryptAESGCM(ctx, req.GetKeyMaterial(), req.GetPlaintext(), req.GetAeadParams().GetAad(), alg.AesGcm)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.AeadOutput(nonce, alg.AesGcm.GetTagSizeBits()/8, "raw"),
		}, nil
	case *types.AlgorithmDetails_AesCbc:
		ciphertext, iv, err := encryptAESCBC(ctx, req.GetKeyMaterial(), req.GetPlaintext(), alg.AesCbc)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.BlockCipherOutput(iv, "raw"),
		}, nil
	case *types.AlgorithmDetails_AesCtr:
		ciphertext, iv, err := encryptAESCTR(ctx, req.GetKeyMaterial(), req.GetPlaintext(), alg.AesCtr)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.BlockCipherOutput(iv, "raw"),
		}, nil
	case *types.AlgorithmDetails_Chacha20Poly1305:
		ciphertext, nonce, err := encryptChaCha20Poly1305(ctx, req.GetKeyMaterial(), req.GetPlaintext(), req.GetAeadParams().GetAad(), alg.Chacha20Poly1305)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.AeadOutput(nonce, ChaCha20Poly1305TagSizeBytes, "raw"),
		}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for encrypt: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Decrypt dispatches to the algorithm-specific decrypt implementation.
// The nonce comes from req.GetOutput() — the ProviderOutput the core
// extracted from the stored OperationMetadata that Encrypt originally
// produced
func (p *Provider) Decrypt(ctx context.Context, req *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	const op errors.Op = "software.(Provider).Decrypt"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_AesGcm:
		plaintext, err := decryptAESGCM(ctx, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetAeadOutput().GetNonce(), req.GetAeadParams().GetAad(), alg.AesGcm)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_AesCbc:
		plaintext, err := decryptAESCBC(ctx, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetBlockCipherOutput().GetIv(), alg.AesCbc)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_AesCtr:
		plaintext, err := decryptAESCTR(ctx, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetBlockCipherOutput().GetIv(), alg.AesCtr)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_Chacha20Poly1305:
		plaintext, err := decryptChaCha20Poly1305(ctx, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetAeadOutput().GetNonce(), req.GetAeadParams().GetAad(), alg.Chacha20Poly1305)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for decrypt: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// ImplementationProperties reports this provider's implementation-security
// properties: a pure-Go implementation (Go's standard crypto library plus
// circl for ML-DSA), so memory-safe and no FIPS certification to report.
func (p *Provider) ImplementationProperties() *types.ImplementationProperties {
	return &types.ImplementationProperties{
		ImplementationLanguage: "go",
		MemorySafeLanguage:     proto.Bool(true),
	}
}

// ProviderInfo describes the software provider. It has one instance, so the
// provider-wide implementation is that instance's. The version is the Go
// toolchain the binary was built with, whose standard library is the
// implementation (circl's version is not reported).
func (p *Provider) ProviderInfo() *providerpb.ProviderInfo {
	return &providerpb.ProviderInfo{
		Name:                  "Go cryptography (standard library and circl)",
		Version:               runtime.Version(),
		Type:                  p.Type(),
		Description:           "In-process software provider: Go's crypto packages, with circl for ML-DSA.",
		ProviderType:          types.ProviderType_PROVIDER_TYPE_SOFTWARE,
		DefaultImplementation: p.ImplementationProperties(),
	}
}

// Compile-time assertion: Provider implements provider.Backend, Signer, and
// Cipher. The software provider does not (yet) implement Macer, Hasher,
// Randomizer, or KeyEstablisher.
var (
	_ provider.Backend   = (*Provider)(nil)
	_ provider.Signer    = (*Provider)(nil)
	_ provider.Cipher    = (*Provider)(nil)
	_ provider.Describer = (*Provider)(nil)
)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*Provider)(nil)

// Compile-time assertion: Provider implements ImplementationDescriber.
var _ provider.ImplementationDescriber = (*Provider)(nil)
