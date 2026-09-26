package template_test

import (
	"context"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
)

const (
	sha256 = api.HashAlgorithm_HASH_ALGORITHM_SHA256
	sha384 = api.HashAlgorithm_HASH_ALGORITHM_SHA384
	sha512 = api.HashAlgorithm_HASH_ALGORITHM_SHA512
)

// prehashedTemplate returns a template with one prehashed signature scope that
// accepts hashes.
func prehashedTemplate(id string, hashes ...api.HashAlgorithm) *template.Template {
	return template.NewTemplate(&api.TemplateInfo{
		TemplateId: id,
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Signature{
				Signature: &api.SignatureScopeSpec{
					Scope:                api.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
					AcceptedDigestHashes: hashes,
				},
			}},
			Operations: []api.CryptoOperation{
				api.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN,
				api.CryptoOperation_CRYPTO_OPERATION_DIGEST_VERIFY,
			},
		}},
	})
}

func prehashedRequest(hashes ...api.HashAlgorithm) *core.ScopeSpecification {
	spec := &core.ScopeSpecification{Scope: core.ScopeSignaturePrehashed}
	if len(hashes) == 0 {
		return spec
	}
	return spec.WithAcceptedDigestHashes(hashes)
}

func TestMatchesScope_acceptedDigestHashes(t *testing.T) {
	tmpl := prehashedTemplate("p256-prehashed", sha256, sha384, sha512)
	tests := []struct {
		name string
		want *core.ScopeSpecification
		ok   bool
	}{
		{"no requirement", prehashedRequest(), true},
		{"subset", prehashedRequest(sha256), true},
		{"whole list in another order", prehashedRequest(sha512, sha256, sha384), true},
		{"hash the template does not accept", prehashedRequest(api.HashAlgorithm_HASH_ALGORITHM_SHA3_256), false},
		{"partly accepted", prehashedRequest(sha256, api.HashAlgorithm_HASH_ALGORITHM_SHA3_256), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := template.MatchesScope(context.Background(), tmpl, tt.want)
			require.NoError(t, err)
			require.Equal(t, tt.ok, got)
		})
	}
}

func TestScopeSpecFor(t *testing.T) {
	ctx := context.Background()
	tmpl := prehashedTemplate("p384-prehashed", sha384, sha512)

	spec, err := template.ScopeSpecFor(ctx, tmpl, core.ScopeSignaturePrehashed)
	require.NoError(t, err)
	require.Equal(t, []api.HashAlgorithm{sha384, sha512}, spec.AcceptedDigestHashes())

	_, err = template.ScopeSpecFor(ctx, tmpl, core.ScopeSignatureStandard)
	require.Error(t, err)
}

func TestValidateAcceptedDigestHashes(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, template.ValidateAcceptedDigestHashes(ctx, prehashedTemplate("ok", sha256)))

	err := template.ValidateAcceptedDigestHashes(ctx, prehashedTemplate("empty"))
	require.ErrorContains(t, err, "accepted_digest_hashes")

	standard := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "standard",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Signature{
				Signature: &api.SignatureScopeSpec{Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD},
			}},
		}},
	})
	require.NoError(t, template.ValidateAcceptedDigestHashes(ctx, standard))
}
