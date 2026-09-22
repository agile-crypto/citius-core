package service

import (
	"context"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/stretchr/testify/require"
)

func TestValidateTransformScope(t *testing.T) {
	tests := []struct {
		name         string
		keyPrimitive string
		scopeSpec    *core.ScopeSpecification
		wantCode     errors.Code
	}{
		{
			name:         "same primitive",
			keyPrimitive: core.PrimitiveSignature.String(),
			scopeSpec:    &core.ScopeSpecification{Scope: core.ScopeSignaturePrehashed},
		},
		{
			name:         "missing scope",
			keyPrimitive: core.PrimitiveSignature.String(),
			wantCode:     errors.CodeInvalidArgument,
		},
		{
			name:         "unknown scope",
			keyPrimitive: core.PrimitiveSignature.String(),
			scopeSpec:    &core.ScopeSpecification{Scope: core.ScopeUnknown},
			wantCode:     errors.CodeInvalidArgument,
		},
		{
			name:         "invalid scope",
			keyPrimitive: core.PrimitiveSignature.String(),
			scopeSpec:    &core.ScopeSpecification{Scope: core.Scope(1000)},
			wantCode:     errors.CodeInvalidArgument,
		},
		{
			name:         "different primitive",
			keyPrimitive: core.PrimitiveSignature.String(),
			scopeSpec:    &core.ScopeSpecification{Scope: core.ScopeAeadStandard},
			wantCode:     errors.CodeFailedPrecondition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTransformScope(context.Background(), tt.keyPrimitive, tt.scopeSpec)
			if tt.wantCode == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var coreErr *errors.Error
			require.True(t, errors.As(err, &coreErr))
			require.Equal(t, tt.wantCode, coreErr.Code)
		})
	}
}
