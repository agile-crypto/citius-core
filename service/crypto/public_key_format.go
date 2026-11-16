package crypto

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// publicKeyFormats records, per provider type (Backend.Type()) and template
// ID, the single public key format the provider's Verify parses. Providers
// hardcode one format per template — the one their GenerateKey emits as
// public_key_encoding — so a caller-supplied public key must already be in
// that format. A provider type or template absent here supports none.
//
// TODO: replace with a capability the provider reports itself.
var publicKeyFormats = map[string]map[string]types.KeyFormat{
	"openssl": {
		"ecdsa-p256-sha256-der":       types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p384-sha384-der":       types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p521-sha512-der":       types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-sha256-mgf1-32-2048": types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-sha256-mgf1-32-3072": types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-sha384-mgf1-48-4096": types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pkcs1v15-sha256-2048":    types.KeyFormat_KEY_FORMAT_SPKI,
		"ed25519":                     types.KeyFormat_KEY_FORMAT_SPKI,
		"ed25519ph":                   types.KeyFormat_KEY_FORMAT_SPKI,
		"ml-dsa-44":                   types.KeyFormat_KEY_FORMAT_RAW,
		"ml-dsa-65":                   types.KeyFormat_KEY_FORMAT_RAW,
		"ml-dsa-87":                   types.KeyFormat_KEY_FORMAT_RAW,
	},
	"software": {
		"ecdsa-p256-sha256-der":       types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p384-sha384-der":       types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p521-sha512-der":       types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p256-prehashed-der":    types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p384-prehashed-der":    types.KeyFormat_KEY_FORMAT_SPKI,
		"ecdsa-p521-prehashed-der":    types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-sha256-mgf1-32-2048": types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-sha256-mgf1-32-3072": types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-sha384-mgf1-48-4096": types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-2048-prehashed":      types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-3072-prehashed":      types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pss-4096-prehashed":      types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pkcs1v15-sha256-2048":    types.KeyFormat_KEY_FORMAT_SPKI,
		"rsa-pkcs1v15-2048-prehashed": types.KeyFormat_KEY_FORMAT_SPKI,
		"ed25519":                     types.KeyFormat_KEY_FORMAT_SPKI,
		"ed25519ph":                   types.KeyFormat_KEY_FORMAT_SPKI,
		"ml-dsa-44":                   types.KeyFormat_KEY_FORMAT_RAW,
		"ml-dsa-65":                   types.KeyFormat_KEY_FORMAT_RAW,
		"ml-dsa-87":                   types.KeyFormat_KEY_FORMAT_RAW,
	},
}

// publicKeyEncodings maps the API key formats a provider may expect for a
// public key to the provider-level encoding passed in VerifyRequest.
var publicKeyEncodings = map[types.KeyFormat]providerpb.PublicKeyEncoding{
	types.KeyFormat_KEY_FORMAT_SPKI: providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI,
	types.KeyFormat_KEY_FORMAT_RAW:  providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW,
}

// publicKeyEncodingFor returns the provider-level encoding of a public key in
// format for prov and templateID, or "Unsupported public key format"
// (InvalidArgument) if format is not the one prov parses for that template.
func publicKeyEncodingFor(ctx context.Context, op errors.Op, prov provider.Backend, templateID string, format types.KeyFormat) (providerpb.PublicKeyEncoding, error) {
	expected, ok := publicKeyFormats[prov.Type()][templateID]
	if !ok || expected != format {
		return providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_UNSPECIFIED,
			errors.New(ctx, op, errors.CodeInvalidArgument, "Unsupported public key format")
	}
	encoding, ok := publicKeyEncodings[format]
	if !ok {
		return providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_UNSPECIFIED,
			errors.New(ctx, op, errors.CodeInvalidArgument, "Unsupported public key format")
	}
	return encoding, nil
}
