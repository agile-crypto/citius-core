package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
)

func TestValidateSignatureScopeParams(t *testing.T) {
	noContext := crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
	domainContext := crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{}}
	vendor := crypto.SignatureScopeFields{VendorContext: &types.VendorSignatureContext{}}

	tests := []struct {
		name     string
		mode     signatureMode
		fields   crypto.SignatureScopeFields
		keyScope core.Scope
		wantErr  bool
	}{
		{"message/no context on standard key", signatureModeMessage, noContext, core.ScopeSignatureStandard, false},
		{"message/context on with-context key", signatureModeMessage, domainContext, core.ScopeSignatureWithContext, false},
		{"message/no context on prehashed key", signatureModeMessage, noContext, core.ScopeSignaturePrehashed, true},
		{"message/context on prehashed-with-context key", signatureModeMessage, domainContext, core.ScopeSignaturePrehashedWithContext, true},
		{"digest/no context on prehashed key", signatureModeDigest, noContext, core.ScopeSignaturePrehashed, false},
		{"digest/context on prehashed-with-context key", signatureModeDigest, domainContext, core.ScopeSignaturePrehashedWithContext, false},
		{"digest/no context on standard key", signatureModeDigest, noContext, core.ScopeSignatureStandard, true},
		{"digest/context on with-context key", signatureModeDigest, domainContext, core.ScopeSignatureWithContext, true},
		{"digest/no context on prehashed-with-context key", signatureModeDigest, noContext, core.ScopeSignaturePrehashedWithContext, true},
		{"vendor context bypasses scope matching", signatureModeDigest, vendor, core.ScopeSignatureStandard, false},
		{"missing scope field", signatureModeMessage, crypto.SignatureScopeFields{}, core.ScopeSignatureStandard, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			kv, err := key.NewVersion(ctx, "key:1", "key", "tmpl", "provider", 1, []byte("material"),
				&core.ScopeSpecification{Scope: tt.keyScope})
			require.NoError(t, err)

			err = validateSignatureScopeParams(ctx, "test", kv, tt.mode, tt.fields)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			requireCoreErrorCode(t, err, errors.CodeInvalidArgument)
		})
	}
}

func TestValidateSignatureRequest_requiresCatalogOperation(t *testing.T) {
	ctx := context.Background()
	noContext := crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
	capability := func(scope types.SignatureScope, ops ...types.CryptoOperation) *types.ScopedCapabilities {
		return &types.ScopedCapabilities{
			Scope: &types.ScopeSpecification{ScopeSpec: &types.ScopeSpecification_Signature{
				Signature: &types.SignatureScopeSpec{Scope: scope},
			}},
			Operations: ops,
		}
	}
	prehashed := template.NewTemplate(&types.TemplateInfo{
		TemplateId: "prehashed",
		ScopedCapabilities: []*types.ScopedCapabilities{capability(types.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
			types.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN, types.CryptoOperation_CRYPTO_OPERATION_DIGEST_VERIFY)},
	})
	signOnly := template.NewTemplate(&types.TemplateInfo{
		TemplateId: "sign-only",
		ScopedCapabilities: []*types.ScopedCapabilities{capability(types.SignatureScope_SIGNATURE_SCOPE_STANDARD,
			types.CryptoOperation_CRYPTO_OPERATION_SIGN)},
	})
	versionWithScope := func(scope core.Scope) *key.Version {
		kv, err := key.NewVersion(ctx, "key:1", "key", "tmpl", "provider", 1, []byte("material"),
			&core.ScopeSpecification{Scope: scope})
		require.NoError(t, err)
		return kv
	}

	require.NoError(t, validateSignatureRequest(ctx, "test", versionWithScope(core.ScopeSignaturePrehashed),
		prehashed, types.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN, noContext))
	require.NoError(t, validateSignatureRequest(ctx, "test", versionWithScope(core.ScopeSignatureStandard),
		signOnly, types.CryptoOperation_CRYPTO_OPERATION_SIGN, noContext))

	// Scope fields match the key scope, but the catalog does not list Verify.
	err := validateSignatureRequest(ctx, "test", versionWithScope(core.ScopeSignatureStandard),
		signOnly, types.CryptoOperation_CRYPTO_OPERATION_VERIFY, noContext)
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)

	// Digest operation on a standard-scoped key is rejected by the scope rule first.
	err = validateSignatureRequest(ctx, "test", versionWithScope(core.ScopeSignatureStandard),
		signOnly, types.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN, noContext)
	requireCoreErrorCode(t, err, errors.CodeInvalidArgument)
}
