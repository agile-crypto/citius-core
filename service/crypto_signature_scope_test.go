package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
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
