package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
)

const (
	hashSHA256 = types.HashAlgorithm_HASH_ALGORITHM_SHA256
	hashSHA384 = types.HashAlgorithm_HASH_ALGORITHM_SHA384
	hashSHA512 = types.HashAlgorithm_HASH_ALGORITHM_SHA512
)

// prehashedECDSATemplate is a P-256 ECDSA template with a prehashed signature
// scope that accepts hashes.
func prehashedECDSATemplate(id string, hashes ...types.HashAlgorithm) *template.Template {
	return template.NewTemplate(&types.TemplateInfo{
		TemplateId:        id,
		KeyMaterialFamily: "ECDSA",
		Algorithm: &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256},
		}},
		ScopedCapabilities: []*types.ScopedCapabilities{{
			Scope: &types.ScopeSpecification{ScopeSpec: &types.ScopeSpecification_Signature{
				Signature: &types.SignatureScopeSpec{
					Scope:                types.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
					AcceptedDigestHashes: hashes,
				},
			}},
			Operations: []types.CryptoOperation{
				types.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN,
				types.CryptoOperation_CRYPTO_OPERATION_DIGEST_VERIFY,
			},
		}},
	})
}

func prehashedSpec(hashes ...types.HashAlgorithm) *core.ScopeSpecification {
	spec := &core.ScopeSpecification{Scope: core.ScopeSignaturePrehashed}
	if len(hashes) == 0 {
		return spec
	}
	return spec.WithAcceptedDigestHashes(hashes)
}

func TestResolveDigestHashes(t *testing.T) {
	ctx := context.Background()
	tmpl := prehashedECDSATemplate("ecdsa-p256-prehashed", hashSHA256, hashSHA384, hashSHA512)

	tests := []struct {
		name     string
		tmpl     *template.Template
		spec     *core.ScopeSpecification
		want     []types.HashAlgorithm
		wantCode *errors.Code
	}{
		{name: "empty request takes the template's list", tmpl: tmpl, spec: prehashedSpec(),
			want: []types.HashAlgorithm{hashSHA256, hashSHA384, hashSHA512}},
		{name: "request narrows in its own order", tmpl: tmpl, spec: prehashedSpec(hashSHA512, hashSHA384),
			want: []types.HashAlgorithm{hashSHA512, hashSHA384}},
		{name: "hash outside the template's list", tmpl: tmpl,
			spec: prehashedSpec(types.HashAlgorithm_HASH_ALGORITHM_SHA3_256), wantCode: codePtr(errors.CodeInvalidArgument)},
		{name: "template without a list", tmpl: prehashedECDSATemplate("broken"), spec: prehashedSpec(),
			wantCode: codePtr(errors.CodeInternal)},
		{name: "non-prehashed scope unchanged", tmpl: tmpl,
			spec: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := append([]types.HashAlgorithm(nil), tt.spec.AcceptedDigestHashes()...)
			got, err := resolveDigestHashes(ctx, tt.tmpl, tt.spec)
			if tt.wantCode != nil {
				requireCoreErrorCode(t, err, *tt.wantCode)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.spec.Scope, got.Scope)
			if tt.want == nil {
				require.Empty(t, got.AcceptedDigestHashes())
			} else {
				require.Equal(t, tt.want, got.AcceptedDigestHashes())
			}
			require.Equal(t, before, append([]types.HashAlgorithm(nil), tt.spec.AcceptedDigestHashes()...),
				"the caller's spec must not change")
		})
	}
}

func TestValidateRequestedDigestHashes(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, validateRequestedDigestHashes(ctx, prehashedSpec(hashSHA256)))
	require.NoError(t, validateRequestedDigestHashes(ctx, &core.ScopeSpecification{Scope: core.ScopeSignatureStandard}))

	standard := (&core.ScopeSpecification{Scope: core.ScopeSignatureStandard}).WithAcceptedDigestHashes(
		[]types.HashAlgorithm{hashSHA256})
	requireCoreErrorCode(t, validateRequestedDigestHashes(ctx, standard), errors.CodeInvalidArgument)
}

func TestTransformKey_storesAcceptedDigestHashes(t *testing.T) {
	ctx := context.Background()
	source := prehashedECDSATemplate("ecdsa-p256-prehashed", hashSHA256, hashSHA384, hashSHA512)
	target := prehashedECDSATemplate("ecdsa-p256-prehashed-2", hashSHA256, hashSHA384)

	for _, tt := range []struct {
		name string
		spec *core.ScopeSpecification
		want []types.HashAlgorithm
	}{
		{"template list", prehashedSpec(), []types.HashAlgorithm{hashSHA256, hashSHA384}},
		{"narrowed list", prehashedSpec(hashSHA384), []types.HashAlgorithm{hashSHA384}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newTransformFixture(t, core.PrimitiveSignature, core.ScopeSignaturePrehashed, source, target)
			md, err := f.orchestrator.TransformKey(ctx, TransformKeySpec{
				KeyName:            transformKeyName,
				ScopeSpecification: tt.spec,
				TemplateID:         target.TemplateID(),
				RetainBytes:        true,
			})
			require.NoError(t, err)
			require.Equal(t, tt.want, md.ScopeSpec.AcceptedDigestHashes())

			stored := &core.ScopeSpecification{}
			require.NoError(t, stored.Deserialize(ctx, f.repo.versions[2].GetScopeSpecification()))
			require.Equal(t, tt.want, stored.AcceptedDigestHashes())
		})
	}

	// A hash the target template does not accept matches no template.
	f := newTransformFixture(t, core.PrimitiveSignature, core.ScopeSignaturePrehashed, source, target)
	_, err := f.orchestrator.TransformKey(ctx, TransformKeySpec{
		KeyName:            transformKeyName,
		ScopeSpecification: prehashedSpec(hashSHA512),
		TemplateID:         target.TemplateID(),
		RetainBytes:        true,
	})
	require.Error(t, err)
	require.Zero(t, f.repo.addVersionCalls)
}

func codePtr(c errors.Code) *errors.Code { return &c }
