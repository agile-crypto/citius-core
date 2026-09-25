package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

func TestRetainedKeyMaterial(t *testing.T) {
	ctx := context.Background()
	source := retainedTemplate("source", "ECDSA", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
		Ecdsa: &types.EcdsaParams{Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256},
	}})
	target := retainedTemplate("target", "ECDSA", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
		Ecdsa: &types.EcdsaParams{
			Curve:         types.EllipticCurve_ELLIPTIC_CURVE_P256,
			Deterministic: true,
		},
	}})
	stored, err := proto.Marshal(&providerpb.GenerateKeyResponse{
		KeyMaterial:    []byte("private-material"),
		PublicKeyBytes: []byte("public-material"),
	})
	require.NoError(t, err)

	retained, err := retainedKeyMaterial(ctx, source, target, stored)
	require.NoError(t, err)
	require.Equal(t, stored, retained)
	require.NotSame(t, &stored[0], &retained[0])

	retained[0] ^= 0xff
	require.NotEqual(t, stored, retained)
}

func TestRetainedKeyMaterial_rejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	source := retainedTemplate("source", "ECDSA", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
		Ecdsa: &types.EcdsaParams{Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256},
	}})
	incompatible := retainedTemplate("target", "ECDSA", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
		Ecdsa: &types.EcdsaParams{Curve: types.EllipticCurve_ELLIPTIC_CURVE_P384},
	}})
	stored, err := proto.Marshal(&providerpb.GenerateKeyResponse{KeyMaterial: []byte("material")})
	require.NoError(t, err)

	_, err = retainedKeyMaterial(ctx, source, incompatible, stored)
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "incompatible template")

	_, err = retainedKeyMaterial(ctx, source, source, []byte{0xff})
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "stored key payload")

	missingFamily := source.Clone()
	missingFamily.Proto().KeyMaterialFamily = ""
	_, err = retainedKeyMaterial(ctx, missingFamily, source, stored)
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "key_material_family is required")
}

func retainedTemplate(id, family string, algorithm *types.AlgorithmDetails) *template.Template {
	return template.NewTemplate(&types.TemplateInfo{
		TemplateId:        id,
		KeyMaterialFamily: family,
		Algorithm:         algorithm,
	})
}

func requireCoreErrorCode(t *testing.T, err error, want errors.Code) {
	t.Helper()
	require.Error(t, err)
	var coreErr *errors.Error
	require.True(t, errors.As(err, &coreErr))
	require.Equal(t, want, coreErr.Code)
}
