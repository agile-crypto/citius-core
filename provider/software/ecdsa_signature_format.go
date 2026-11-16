package software

import (
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// ecdsaSignatureEncodingLabel maps the declared SignatureFormat to the
// artifact-encoding string recorded in ProviderOutput.encoding — the
// free-form string documenting how the SIGNATURE bytes are serialized, not
// to be confused with the typed key_material_encoding, which describes the
// KEY.  Mirrors EcdsaParams.signature_format's documented default: unset
// (or DER) means "der", anything else falls through to the format's own
// string.
func ecdsaSignatureEncodingLabel(format types.SignatureFormat) string {
	switch format {
	case types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363:
		return "p1363"
	default:
		return "der"
	}
}

// ecdsaASN1Signature mirrors the ASN.1 SEQUENCE { r INTEGER, s INTEGER }
// that crypto/ecdsa's SignASN1/VerifyASN1 use internally (RFC 3279 §2.2.3).
// Used here to produce/consume that same DER encoding directly from r, s,
// since encoding an ECDSA signature requires access to r and s regardless
// of which wire format (DER or IEEE P1363) is being produced.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// encodeECDSASignature serializes r, s per the declared SignatureFormat.
// UNSPECIFIED defaults to DER, matching EcdsaParams.signature_format's
// documented default ("Signature output format. Default: DER.").
func encodeECDSASignature(ctx context.Context, op errors.Op, r, s *big.Int, curve elliptic.Curve, format types.SignatureFormat) ([]byte, error) {
	switch format {
	case types.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_DER:
		return asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
	case types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363:
		// Fixed-size r || s, each zero-padded to the curve's coordinate byte
		// length (32 bytes for P-256, 48 for P-384, 66 for P-521).
		size := (curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	default:
		// SIGNATURE_FORMAT_RAW is documented as "Ed25519/Ed448 native
		// format" — ECDSA has no equivalent raw encoding distinct from
		// P1363, so it is rejected here rather than silently aliased to it.
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ECDSA signature format: %s", format))
	}
}

// decodeECDSASignature parses sig per the declared SignatureFormat — the
// inverse of encodeECDSASignature.  The format must be the one AlgorithmDetails
// declares, not guessed: unlike key ENCODING (PKCS#8 vs SEC1), DER and P1363
// are not reliably distinguishable from the bytes alone — a P1363 signature's
// leading byte can legitimately be 0x30, the DER SEQUENCE tag.
func decodeECDSASignature(ctx context.Context, op errors.Op, sig []byte, curve elliptic.Curve, format types.SignatureFormat) (r, s *big.Int, _ error) {
	switch format {
	case types.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_DER:
		var parsed ecdsaASN1Signature
		rest, err := asn1.Unmarshal(sig, &parsed)
		if err != nil {
			return nil, nil, errors.Wrap(ctx, op, err)
		}
		if len(rest) != 0 {
			return nil, nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"trailing data after ASN.1 ECDSA signature")
		}
		return parsed.R, parsed.S, nil
	case types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363:
		size := (curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return nil, nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				fmt.Sprintf("IEEE P1363 signature length %d does not match expected %d bytes for curve %s",
					len(sig), 2*size, curve.Params().Name))
		}
		r = new(big.Int).SetBytes(sig[:size])
		s = new(big.Int).SetBytes(sig[size:])
		return r, s, nil
	default:
		return nil, nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ECDSA signature format: %s", format))
	}
}
