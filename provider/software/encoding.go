package software

import (
	"context"
	"fmt"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// privateKeyEncoding returns the encoding of the private key GenerateKey
// emits for alg's algorithm family, or UNSPECIFIED for a family it does not
// generate: SEC1 (RFC 5915) for ECDSA, PKCS#8 for RSA, Ed25519 and ML-DSA
// (wrapping the seed), and the raw key bytes for symmetric algorithms. Which
// parameters within a family are supported is SupportedAlgorithms' concern.
func privateKeyEncoding(alg *types.AlgorithmDetails) providerpb.PrivateKeyEncoding {
	switch alg.GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
	case *types.AlgorithmDetails_MlDsa, *types.AlgorithmDetails_RsaPss, *types.AlgorithmDetails_RsaPkcs1V15,
		*types.AlgorithmDetails_Ed25519:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
	case *types.AlgorithmDetails_AesGcm, *types.AlgorithmDetails_AesCbc, *types.AlgorithmDetails_AesCtr,
		*types.AlgorithmDetails_Chacha20Poly1305:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW
	default:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED
	}
}

// TransferCapabilities advertises the stored-payload channel for alg: the
// stored payload is the self-contained key bytes GenerateKey emits, which
// this provider can release to another provider, and it accepts another
// provider's payload in the same encoding. It exports, imports and wraps no
// key.
func (p *Provider) TransferCapabilities(alg *types.AlgorithmDetails) provider.Transfer {
	encoding := privateKeyEncoding(alg)
	if encoding == providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED {
		return provider.Transfer{}
	}
	stored := provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{encoding}}
	return provider.Transfer{Emit: stored, Accept: stored}
}

// Compile-time assertion: Provider implements TransferDescriber.
var _ provider.TransferDescriber = (*Provider)(nil)

// generatedKey is GenerateKey's response for the key it generated for alg.
// The provider is stateless: the orchestrator stores the key material.
// Output carries no encoding: key generation produces no operation artifact,
// and the key encodings are declared by the typed fields. Every family
// GenerateKey generates must have a private-key encoding: a payload that
// records none can be neither parsed reliably nor transferred.
func generatedKey(ctx context.Context, op errors.Op, alg *types.AlgorithmDetails,
	pubDER, privDER []byte, pubEnc providerpb.PublicKeyEncoding) (*providerpb.GenerateKeyResponse, error) {
	privEnc := privateKeyEncoding(alg)
	if privEnc == providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED {
		return nil, errors.New(ctx, op, errors.CodeInternal,
			fmt.Sprintf("no private-key encoding for algorithm type %T", alg.GetAlgorithm()))
	}
	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes:      pubDER,
		KeyMaterial:         privDER,
		Output:              provider.NoOutputUnencoded(),
		KeyMaterialEncoding: privEnc,
		PublicKeyEncoding:   pubEnc,
	}, nil
}
