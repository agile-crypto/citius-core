package template_test

import (
	"context"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func signatureCapability(scope api.SignatureScope, guarantees *api.SecurityGuarantees) *api.ScopedCapabilities {
	return &api.ScopedCapabilities{
		Scope: &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Signature{
			Signature: &api.SignatureScopeSpec{Scope: scope},
		}},
		Operations:         []api.CryptoOperation{api.CryptoOperation_CRYPTO_OPERATION_SIGN},
		SecurityGuarantees: guarantees,
	}
}

// A scope's own guarantees win; a scope without any falls back to the
// template's; a template with none gives none; an undeclared scope is
// reported as such.
func TestSecurityGuaranteesFor(t *testing.T) {
	ctx := context.Background()
	scoped := &api.SecurityGuarantees{Practical: &api.PracticalSecurityOutcomes{Integrity: true, NonRepudiation: true}}
	templateWide := &api.SecurityGuarantees{Practical: &api.PracticalSecurityOutcomes{Authenticity: true}}
	tmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "t",
		ScopedCapabilities: []*api.ScopedCapabilities{
			signatureCapability(api.SignatureScope_SIGNATURE_SCOPE_STANDARD, scoped),
			signatureCapability(api.SignatureScope_SIGNATURE_SCOPE_WITH_CONTEXT, nil),
		},
		SecurityGuarantees: templateWide,
	})

	got, declared, err := template.SecurityGuaranteesFor(ctx, tmpl, core.ScopeSignatureStandard)
	require.NoError(t, err)
	require.True(t, declared)
	require.True(t, proto.Equal(scoped, got))
	require.NotSame(t, scoped, got, "a copy, never the catalogue's message")

	got, declared, err = template.SecurityGuaranteesFor(ctx, tmpl, core.ScopeSignatureWithContext)
	require.NoError(t, err)
	require.True(t, declared)
	require.True(t, proto.Equal(templateWide, got))

	bare := template.NewTemplate(&api.TemplateInfo{
		TemplateId:         "bare",
		ScopedCapabilities: []*api.ScopedCapabilities{signatureCapability(api.SignatureScope_SIGNATURE_SCOPE_STANDARD, nil)},
	})
	got, declared, err = template.SecurityGuaranteesFor(ctx, bare, core.ScopeSignatureStandard)
	require.NoError(t, err)
	require.True(t, declared)
	require.Nil(t, got)

	got, declared, err = template.SecurityGuaranteesFor(ctx, tmpl, core.ScopeSignaturePrehashed)
	require.NoError(t, err)
	require.False(t, declared)
	require.Nil(t, got)
}
