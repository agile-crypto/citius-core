package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	transformKeyName    = "transform-key"
	transformKeyID      = "key-transform"
	transformProviderID = "software"
	transformPolicyID   = "policy"
)

func TestTransformKey_retainKeyBytes(t *testing.T) {
	tests := []struct {
		name      string
		primitive core.Primitive
		source    *template.Template
		target    *template.Template
		scope     core.Scope
	}{
		{
			name:      "ECDSA P-256 hash variant",
			primitive: core.PrimitiveSignature,
			source:    ecdsaTemplate("ecdsa-p256-sha256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false),
			target:    ecdsaTemplate("ecdsa-p256-deterministic", types.EllipticCurve_ELLIPTIC_CURVE_P256, true),
			scope:     core.ScopeSignatureStandard,
		},
		{
			name:      "AES-256 GCM to CBC across primitives",
			primitive: core.PrimitiveAead,
			source:    aesGcmTemplate("aes-256-gcm", 256),
			target:    aesCbcTemplate("aes-256-cbc", 256),
			scope:     core.ScopeSymmetricCipherBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			f := newTransformFixture(t, tt.primitive, tt.source, tt.target)
			storedBefore := append([]byte(nil), f.repo.versions[1].GetKeyMaterial()...)
			scopeSpec := &core.ScopeSpecification{Scope: tt.scope}

			md, err := f.orchestrator.TransformKey(ctx, TransformKeySpec{
				KeyName:            transformKeyName,
				ScopeSpecification: scopeSpec,
				TemplateID:         tt.target.TemplateID(),
				RetainBytes:        true,
			})
			require.NoError(t, err)

			require.Zero(t, f.backend.generateCalls, "retain mode must not generate key material")
			require.Equal(t, 1, f.repo.addVersionCalls)
			require.Equal(t, uint32(2), md.Version)
			require.Equal(t, tt.target.TemplateID(), md.TemplateID)
			require.Equal(t, transformProviderID, md.Provider)
			require.Equal(t, transformKeyID, md.KeyID)
			require.Equal(t, tt.primitive.String(), md.Primitive)
			require.Equal(t, tt.scope, md.ScopeSpec.Scope)

			newVersion := f.repo.versions[2]
			require.Equal(t, storedBefore, newVersion.GetKeyMaterial())
			require.Equal(t, tt.target.TemplateID(), newVersion.GetTemplateId())
			require.Equal(t, transformProviderID, newVersion.GetProviderId())

			oldVersion := f.repo.versions[1]
			require.Equal(t, storedBefore, oldVersion.GetKeyMaterial())
			require.Equal(t, tt.source.TemplateID(), oldVersion.GetTemplateId())
		})
	}
}

func TestTransformKey_retainKeyBytesRejectsBeforeSideEffects(t *testing.T) {
	p256 := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)
	tests := []struct {
		name       string
		primitive  core.Primitive
		source     *template.Template
		target     *template.Template
		templateID string
		scope      core.Scope
		mutate     func(*transformFixture)
		wantCode   errors.Code
		wantErr    string
	}{
		{
			name:      "missing template ID",
			primitive: core.PrimitiveSignature,
			source:    p256,
			target:    ecdsaTemplate("ecdsa-p256-deterministic", types.EllipticCurve_ELLIPTIC_CURVE_P256, true),
			scope:     core.ScopeSignatureStandard,
			wantCode:  errors.CodeInvalidArgument,
			wantErr:   "template ID is required",
		},
		{
			name:       "different ECDSA curve",
			primitive:  core.PrimitiveSignature,
			source:     p256,
			target:     ecdsaTemplate("ecdsa-p384", types.EllipticCurve_ELLIPTIC_CURVE_P384, false),
			templateID: "ecdsa-p384",
			scope:      core.ScopeSignatureStandard,
			wantCode:   errors.CodeFailedPrecondition,
			wantErr:    "incompatible template",
		},
		{
			name:       "different AES key size",
			primitive:  core.PrimitiveAead,
			source:     aesGcmTemplate("aes-128-gcm", 128),
			target:     aesGcmTemplate("aes-256-gcm", 256),
			templateID: "aes-256-gcm",
			scope:      core.ScopeAeadStandard,
			wantCode:   errors.CodeFailedPrecondition,
			wantErr:    "incompatible template",
		},
		{
			name:       "different material family",
			primitive:  core.PrimitiveSignature,
			source:     p256,
			target:     retainedTemplate("ed25519", "Ed25519", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ed25519{Ed25519: &types.Ed25519Params{}}}),
			templateID: "ed25519",
			scope:      core.ScopeSignatureStandard,
			wantCode:   errors.CodeFailedPrecondition,
			wantErr:    "incompatible template",
		},
		{
			name:       "current provider lacks target template",
			primitive:  core.PrimitiveSignature,
			source:     p256,
			target:     ecdsaTemplate("ecdsa-p256-deterministic", types.EllipticCurve_ELLIPTIC_CURVE_P256, true),
			templateID: "ecdsa-p256-deterministic",
			scope:      core.ScopeSignatureStandard,
			mutate: func(f *transformFixture) {
				delete(f.providers.supported, "ecdsa-p256-deterministic")
			},
			wantCode: errors.CodeProviderNotFound,
		},
		{
			name:       "corrupt stored payload",
			primitive:  core.PrimitiveSignature,
			source:     p256,
			target:     ecdsaTemplate("ecdsa-p256-deterministic", types.EllipticCurve_ELLIPTIC_CURVE_P256, true),
			templateID: "ecdsa-p256-deterministic",
			scope:      core.ScopeSignatureStandard,
			mutate: func(f *transformFixture) {
				f.repo.versions[1].KeyMaterial = []byte{0xff}
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  "stored key payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTransformFixture(t, tt.primitive, tt.source, tt.target)
			if tt.mutate != nil {
				tt.mutate(f)
			}

			_, err := f.orchestrator.TransformKey(context.Background(), TransformKeySpec{
				KeyName:            transformKeyName,
				ScopeSpecification: &core.ScopeSpecification{Scope: tt.scope},
				TemplateID:         tt.templateID,
				RetainBytes:        true,
			})
			requireCoreErrorCode(t, err, tt.wantCode)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			}
			require.Zero(t, f.backend.generateCalls)
			require.Zero(t, f.repo.addVersionCalls)
			require.Len(t, f.repo.versions, 1)
		})
	}
}

func TestTransformKey_regenerateKeyBytes(t *testing.T) {
	ctx := context.Background()
	source := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)
	target := ecdsaTemplate("ecdsa-p256-deterministic", types.EllipticCurve_ELLIPTIC_CURVE_P256, true)
	f := newTransformFixture(t, core.PrimitiveSignature, source, target)
	storedBefore := append([]byte(nil), f.repo.versions[1].GetKeyMaterial()...)

	md, err := f.orchestrator.TransformKey(ctx, TransformKeySpec{
		KeyName:            transformKeyName,
		ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		TemplateID:         target.TemplateID(),
	})
	require.NoError(t, err)
	require.Equal(t, 1, f.backend.generateCalls)
	require.Equal(t, uint32(2), md.Version)
	require.NotEqual(t, storedBefore, f.repo.versions[2].GetKeyMaterial())
	require.Equal(t, storedBefore, f.repo.versions[1].GetKeyMaterial())

	f = newTransformFixture(t, core.PrimitiveSignature, source, target)
	_, err = f.orchestrator.TransformKey(ctx, TransformKeySpec{
		KeyName:            transformKeyName,
		ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeAeadStandard},
		TemplateID:         target.TemplateID(),
	})
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.Zero(t, f.backend.generateCalls)
	require.Zero(t, f.repo.addVersionCalls)
}

// ── fixture ───────────────────────────────────────────────────────────────

type transformFixture struct {
	orchestrator KeyOrchestrator
	repo         *fakeKeyRepository
	providers    *fakeProviderRegistry
	backend      *countingBackend
}

func newTransformFixture(t *testing.T, primitive core.Primitive, source, target *template.Template) *transformFixture {
	t.Helper()
	ctx := context.Background()

	stored, err := proto.Marshal(&providerpb.GenerateKeyResponse{
		KeyMaterial:    []byte("source-private"),
		PublicKeyBytes: []byte("source-public"),
		Output:         provider.NoOutput("raw"),
	})
	require.NoError(t, err)

	k, err := key.NewKey(ctx, transformKeyID, transformPolicyID, primitive, 1,
		key.WithName(transformKeyName),
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err)
	v, err := key.NewVersion(ctx, computeVersionID(transformKeyID, 1), transformKeyID,
		source.TemplateID(), transformProviderID, 1, stored,
		&core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err)

	repo := &fakeKeyRepository{key: k, versions: map[uint32]*key.Version{1: v}}
	templates := &fakeTemplateRegistry{templates: map[string]*template.Template{
		source.TemplateID(): source,
		target.TemplateID(): target,
	}}
	backend := &countingBackend{}
	providers := &fakeProviderRegistry{
		backend:   backend,
		supported: map[string]bool{source.TemplateID(): true, target.TemplateID(): true},
	}

	o, err := NewKeyOrchestrator(repo, templates, providers, allowAllPolicy{})
	require.NoError(t, err)
	return &transformFixture{orchestrator: o, repo: repo, providers: providers, backend: backend}
}

func ecdsaTemplate(id string, curve types.EllipticCurve, deterministic bool) *template.Template {
	return retainedTemplate(id, "ECDSA", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
		Ecdsa: &types.EcdsaParams{Curve: curve, Deterministic: deterministic},
	}})
}

func aesGcmTemplate(id string, bits uint32) *template.Template {
	return retainedTemplate(id, "AES", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_AesGcm{
		AesGcm: &types.AesGcmParams{KeySizeBits: bits},
	}})
}

func aesCbcTemplate(id string, bits uint32) *template.Template {
	return retainedTemplate(id, "AES", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_AesCbc{
		AesCbc: &types.AesCbcParams{KeySizeBits: bits},
	}})
}

// fakeKeyRepository holds a single key and its versions in memory.
type fakeKeyRepository struct {
	key             *key.Key
	versions        map[uint32]*key.Version
	addVersionCalls int
}

func (r *fakeKeyRepository) GetKeyByID(ctx context.Context, id string) (*key.Key, error) {
	if id != r.key.GetPublicId() {
		return nil, errors.New(ctx, "fake.GetKeyByID", errors.CodeNotFound, "key %q not found", id)
	}
	return r.key.Clone(), nil
}

func (r *fakeKeyRepository) GetKeyByName(ctx context.Context, name string) (*key.Key, error) {
	if name != r.key.GetName() {
		return nil, errors.New(ctx, "fake.GetKeyByName", errors.CodeNotFound, "key %q not found", name)
	}
	return r.key.Clone(), nil
}

func (r *fakeKeyRepository) ListKeys(context.Context) ([]*key.Key, error) {
	return []*key.Key{r.key.Clone()}, nil
}

func (r *fakeKeyRepository) GetVersion(ctx context.Context, _ string, versionNum uint32) (*key.Version, error) {
	v, ok := r.versions[versionNum]
	if !ok {
		return nil, errors.New(ctx, "fake.GetVersion", errors.CodeNotFound, "version %d not found", versionNum)
	}
	return v.Clone(), nil
}

func (r *fakeKeyRepository) GetCurrentVersion(ctx context.Context, id string) (*key.Version, error) {
	return r.GetVersion(ctx, id, r.key.GetCurrentVersion())
}

func (r *fakeKeyRepository) CreateKey(context.Context, *key.Key, *key.Version, ...key.Option) error {
	return nil
}

func (r *fakeKeyRepository) UpdateKey(context.Context, *key.Key, ...key.Option) error { return nil }

func (r *fakeKeyRepository) AddVersion(_ context.Context, v *key.Version, _ ...key.Option) error {
	r.addVersionCalls++
	r.versions[v.GetVersion()] = v.Clone()
	r.key.CurrentVersion = v.GetVersion()
	return nil
}

func (r *fakeKeyRepository) DeleteKey(context.Context, string) error { return nil }

// fakeTemplateRegistry selects the single requested candidate by ID.
type fakeTemplateRegistry struct {
	templates map[string]*template.Template
}

func (r *fakeTemplateRegistry) Register(context.Context, *template.Template) error { return nil }

func (r *fakeTemplateRegistry) Get(ctx context.Context, id string) (*template.Template, error) {
	tmpl, ok := r.templates[id]
	if !ok {
		return nil, errors.New(ctx, "fake.Get", errors.CodeTemplateNotFound, "template %q not found", id)
	}
	return tmpl, nil
}

func (r *fakeTemplateRegistry) List(context.Context) []*template.Template { return nil }

func (r *fakeTemplateRegistry) Select(ctx context.Context, _ *core.ScopeSpecification, c template.CandidateSet) (*template.Template, error) {
	if len(c.IDs()) != 1 {
		return nil, errors.New(ctx, "fake.Select", errors.CodeTemplateNotFound, "explicit template required")
	}
	return r.Get(ctx, c.IDs()[0])
}

// fakeProviderRegistry matches one pinned backend for supported templates.
type fakeProviderRegistry struct {
	backend   *countingBackend
	supported map[string]bool
}

func (r *fakeProviderRegistry) Register(context.Context, provider.Backend) error { return nil }

func (r *fakeProviderRegistry) Get(context.Context, string) (provider.Backend, error) {
	return r.backend, nil
}

func (r *fakeProviderRegistry) GetDefault(context.Context) (provider.Backend, error) {
	return r.backend, nil
}

func (r *fakeProviderRegistry) List(context.Context) []provider.Backend {
	return []provider.Backend{r.backend}
}

func (r *fakeProviderRegistry) Remove(context.Context, string) error { return nil }

func (r *fakeProviderRegistry) Match(ctx context.Context, req provider.Requirements) (provider.Backend, error) {
	if req.ProviderName != transformProviderID || !r.supported[req.TemplateID] {
		return nil, errors.New(ctx, "fake.Match", errors.CodeProviderNotFound,
			"provider %q does not support template %q", req.ProviderName, req.TemplateID)
	}
	return r.backend, nil
}

// countingBackend records GenerateKey calls.
type countingBackend struct {
	generateCalls int
}

func (b *countingBackend) Name() string { return transformProviderID }
func (b *countingBackend) Type() string { return "fake" }

func (b *countingBackend) GenerateKey(context.Context, *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	b.generateCalls++
	return &providerpb.GenerateKeyResponse{
		KeyMaterial: []byte("generated-private"),
		Output:      provider.NoOutput("raw"),
	}, nil
}

func (b *countingBackend) DestroyKey(context.Context, *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}

func (b *countingBackend) ExportPublicKey(context.Context, *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{}, nil
}

// allowAllPolicy permits every operation.
type allowAllPolicy struct{ policy.Manager }

func (allowAllPolicy) ValidateOperation(context.Context, string, core.Operation, string, string) error {
	return nil
}

func (allowAllPolicy) ValidateKeyCreation(context.Context, string, *core.KeyCreationSpec) error {
	return nil
}

func (allowAllPolicy) AllowedTemplates(context.Context, string, *core.ScopeSpecification) ([]string, error) {
	return nil, nil
}
