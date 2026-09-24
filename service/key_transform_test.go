package service

import (
	"context"
	stderrors "errors"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
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

	checker := &retainedKeyChecker{}
	retained, err := retainedKeyMaterial(ctx, checker, source, target, stored)
	require.NoError(t, err)
	require.Equal(t, 1, checker.calls)
	require.Equal(t, []byte("private-material"), checker.material.GetKeyMaterial())
	require.Equal(t, []byte("public-material"), checker.material.GetPublicKeyBytes())
	require.Same(t, source.GetAlgorithm(), checker.source)
	require.Same(t, target.GetAlgorithm(), checker.target)
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

	checker := &retainedKeyChecker{}
	_, err = retainedKeyMaterial(ctx, checker, source, incompatible, stored)
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "incompatible template")
	require.Zero(t, checker.calls)

	_, err = retainedKeyMaterial(ctx, checker, source, source, []byte{0xff})
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "stored key payload")
	require.Zero(t, checker.calls)

	missingFamily := source.Clone()
	missingFamily.Proto().KeyMaterialFamily = ""
	_, err = retainedKeyMaterial(ctx, checker, missingFamily, source, stored)
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "key_material_family is required")
	require.Zero(t, checker.calls)

	_, err = retainedKeyMaterial(ctx, bareRetainedBackend{}, source, source, stored)
	requireCoreErrorCode(t, err, errors.CodeNotImplemented)
	require.ErrorContains(t, err, "cannot validate retained key material")

	checker.err = stderrors.New("key usage does not permit target algorithm")
	_, err = retainedKeyMaterial(ctx, checker, source, source, stored)
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "provider \"checker\" rejected retained material")
}

type bareRetainedBackend struct{}

func (bareRetainedBackend) Name() string { return "bare" }
func (bareRetainedBackend) Type() string { return "test" }
func (bareRetainedBackend) GenerateKey(context.Context, *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return nil, nil
}
func (bareRetainedBackend) DestroyKey(context.Context, *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return nil, nil
}
func (bareRetainedBackend) ExportPublicKey(context.Context, *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return nil, nil
}

type retainedKeyChecker struct {
	bareRetainedBackend
	calls    int
	material *providerpb.GenerateKeyResponse
	source   *types.AlgorithmDetails
	target   *types.AlgorithmDetails
	err      error
}

func (c *retainedKeyChecker) Name() string { return "checker" }
func (c *retainedKeyChecker) ValidateRetainedKey(_ context.Context, material *providerpb.GenerateKeyResponse, source, target *types.AlgorithmDetails) error {
	c.calls++
	c.material = material
	c.source = source
	c.target = target
	return c.err
}

var _ provider.KeyMaterialCompatibilityChecker = (*retainedKeyChecker)(nil)

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
