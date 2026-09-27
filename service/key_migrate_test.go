package service

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

const (
	migrateSourceInstance = "software"
	migrateTargetInstance = "openssl"
	migrateFIPSInstance   = "openssl-fips"
)

var (
	strategySwitch  = messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH
	strategyArchive = messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE
)

func TestMigrateKey_providerSwitchPreservesBytes(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	storedBefore := append([]byte(nil), f.repo.versions[1].GetKeyMaterial()...)

	res, err := f.orchestrator.MigrateKey(ctx, MigrateKeySpec{
		KeyName:          transformKeyName,
		TargetInstanceID: migrateTargetInstance,
		Strategy:         strategySwitch,
	})
	require.NoError(t, err)

	for name, b := range f.backends {
		require.Zero(t, b.generateCalls, "provider switch must not generate material on %s", name)
	}
	require.Equal(t, 1, f.repo.addVersionCalls)
	newVersion := f.repo.versions[2]
	require.Equal(t, storedBefore, newVersion.GetKeyMaterial())
	require.Equal(t, migrateTargetInstance, newVersion.GetProviderId())
	require.Equal(t, f.template.TemplateID(), newVersion.GetTemplateId())
	require.Equal(t, f.repo.versions[1].GetScopeSpecification(), newVersion.GetScopeSpecification(),
		"a migration must keep the full scope specification")
	require.Equal(t, &storepb.KeyOrigin{
		Kind:             storepb.KeyOriginKind_KEY_ORIGIN_KIND_TRANSFERRED,
		SourceVersion:    1,
		SourceProviderId: migrateSourceInstance,
		Channel:          storepb.KeyTransferChannel_KEY_TRANSFER_CHANNEL_STORED_PAYLOAD,
	}, newVersion.GetOrigin())

	oldVersion := f.repo.versions[1]
	require.Equal(t, storedBefore, oldVersion.GetKeyMaterial())
	require.Equal(t, migrateSourceInstance, oldVersion.GetProviderId())

	require.Equal(t, &MigrationResult{
		Key:               res.Key,
		Strategy:          strategySwitch,
		KeyBytesPreserved: true,
		SourceProviderID:  "software",
		SourceInstanceID:  migrateSourceInstance,
		SourceVersion:     1,
		TargetProviderID:  "openssl",
		TargetInstanceID:  migrateTargetInstance,
	}, res)
	require.Equal(t, uint32(2), res.Key.Version)
	require.Equal(t, migrateTargetInstance, res.Key.Provider)
	require.Equal(t, newVersion.GetExtractable(), res.Key.Extractable, "metadata reports the version's extractability")

	resp, err := res.ToProto(ctx)
	require.NoError(t, err)
	require.True(t, resp.GetSuccess())
	require.Nil(t, resp.GetArchivedKeyInfo(), "only REKEY_AND_ARCHIVE archives a version")
	require.True(t, resp.GetResult().GetKeyBytesPreserved())
	require.Equal(t, migrateTargetInstance, resp.GetKeyMetadata().GetProvider())
}

func TestMigrateKey_rekeyAndArchiveGeneratesOnTarget(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	storedBefore := append([]byte(nil), f.repo.versions[1].GetKeyMaterial()...)

	res, err := f.orchestrator.MigrateKey(ctx, MigrateKeySpec{
		KeyName:          transformKeyName,
		TargetProviderID: "openssl",
		Strategy:         strategyArchive,
	})
	require.NoError(t, err)

	require.Equal(t, 1, f.backends[migrateTargetInstance].generateCalls)
	require.Zero(t, f.backends[migrateSourceInstance].generateCalls)
	require.NotEqual(t, storedBefore, f.repo.versions[2].GetKeyMaterial())
	require.Equal(t, migrateTargetInstance, f.repo.versions[2].GetProviderId())
	require.Equal(t, storepb.KeyOriginKind_KEY_ORIGIN_KIND_GENERATED, f.repo.versions[2].GetOrigin().GetKind())
	require.Equal(t, storedBefore, f.repo.versions[1].GetKeyMaterial(), "the archived version must be untouched")
	require.False(t, res.KeyBytesPreserved)
	require.Equal(t, uint32(1), res.SourceVersion)

	resp, err := res.ToProto(ctx)
	require.NoError(t, err)
	require.Equal(t, transformKeyName, resp.GetArchivedKeyInfo().GetArchivedKeyName())
	require.Equal(t, migrateSourceInstance, resp.GetArchivedKeyInfo().GetProviderId())
	require.Equal(t, strategyArchive, resp.GetResult().GetStrategyUsed())
}

func TestMigrateKey_providerTypeSkipsSourceInstance(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	// Move the key onto the openssl instance first, then ask for "any openssl
	// instance": the only other one is the FIPS instance.
	_, err := f.orchestrator.MigrateKey(ctx, MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch,
	})
	require.NoError(t, err)

	res, err := f.orchestrator.MigrateKey(ctx, MigrateKeySpec{
		KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategySwitch,
	})
	require.NoError(t, err)
	require.Equal(t, migrateFIPSInstance, res.TargetInstanceID)
	require.Equal(t, uint32(3), res.Key.Version)
	require.Equal(t, uint32(2), res.SourceVersion)
}

func TestMigrateKey_providerTypeSkipsInstancesThatCannotReceive(t *testing.T) {
	f := newMigrateFixture(t)
	f.backends[migrateTargetInstance].transfer = provider.Transfer{}

	res, err := f.orchestrator.MigrateKey(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategySwitch,
	})
	require.NoError(t, err)
	require.Equal(t, migrateFIPSInstance, res.TargetInstanceID)
}

func TestMigrateKey_rekeyFromAnUnregisteredSource(t *testing.T) {
	f := newMigrateFixture(t)
	delete(f.providers.backends, migrateSourceInstance)

	res, err := f.orchestrator.MigrateKey(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategyArchive,
	})
	require.NoError(t, err)
	require.Empty(t, res.SourceProviderID)
	require.Equal(t, migrateSourceInstance, res.SourceInstanceID)
}

func TestMigrateKey_rejectsBeforeSideEffects(t *testing.T) {
	tests := []struct {
		name     string
		spec     MigrateKeySpec
		mutate   func(*migrateFixture)
		wantCode errors.Code
		wantErr  string
	}{
		{
			name:     "missing key name",
			spec:     MigrateKeySpec{TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch},
			wantCode: errors.CodeInvalidArgument,
			wantErr:  "key name is required",
		},
		{
			name:     "no target",
			spec:     MigrateKeySpec{KeyName: transformKeyName, Strategy: strategySwitch},
			wantCode: errors.CodeInvalidArgument,
			wantErr:  "exactly one of",
		},
		{
			name: "both targets",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance,
				TargetProviderID: "openssl", Strategy: strategySwitch},
			wantCode: errors.CodeInvalidArgument,
			wantErr:  "exactly one of",
		},
		{
			name:     "unspecified strategy",
			spec:     MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance},
			wantCode: errors.CodeInvalidArgument,
			wantErr:  "strategy is required",
		},
		{
			name: "unimplemented strategy",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance,
				Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER},
			wantCode: errors.CodeNotImplemented,
		},
		{
			name:     "unknown key",
			spec:     MigrateKeySpec{KeyName: "nope", TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch},
			wantCode: errors.CodeNotFound,
		},
		{
			name:     "same instance",
			spec:     MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateSourceInstance, Strategy: strategySwitch},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  "already on provider instance",
		},
		{
			name: "target lacks the key's template",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategyArchive},
			mutate: func(f *migrateFixture) {
				delete(f.providers.supported[migrateTargetInstance], f.template.TemplateID())
			},
			wantCode: errors.CodeProviderNotFound,
		},
		{
			name:     "no instance of the provider type",
			spec:     MigrateKeySpec{KeyName: transformKeyName, TargetProviderID: "hsm", Strategy: strategyArchive},
			wantCode: errors.CodeProviderNotFound,
			wantErr:  `no instance of provider "hsm"`,
		},
		{
			name:     "provider type only offers the source instance",
			spec:     MigrateKeySpec{KeyName: transformKeyName, TargetProviderID: "software", Strategy: strategyArchive},
			wantCode: errors.CodeProviderNotFound,
		},
		{
			name: "corrupt stored payload",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				f.repo.versions[1].KeyMaterial = []byte{0xff}
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  "does not parse",
		},
		{
			name: "source instance no longer registered",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				delete(f.providers.backends, migrateSourceInstance)
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  "is not registered",
		},
		{
			name: "non-extractable version",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				f.repo.versions[1].Extractable = false
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  "is not extractable",
		},
		{
			name: "non-extractable version, whatever instance of the provider type",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				f.repo.versions[1].Extractable = false
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  "MIGRATION_STRATEGY_PROVIDER_SWITCH is not possible: version 1 of the key is not extractable",
		},
		{
			name: "target module at FIPS 140 level 3",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateFIPSInstance, Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				f.backends[migrateFIPSInstance].implementation.Fips_140.Level = types.Fips140Level_FIPS_140_LEVEL_3
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  `"openssl-fips" does not accept`,
		},
		{
			name: "target module reporting no FIPS 140 level",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateFIPSInstance, Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				f.backends[migrateFIPSInstance].implementation.Fips_140.Level = types.Fips140Level_FIPS_140_LEVEL_UNSPECIFIED
			},
			wantCode: errors.CodeFailedPrecondition,
			wantErr:  `"openssl-fips" does not accept`,
		},
		{
			name: "no instance of the provider type can receive the payload",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategySwitch},
			mutate: func(f *migrateFixture) {
				f.backends[migrateTargetInstance].transfer = provider.Transfer{}
				f.backends[migrateFIPSInstance].transfer = provider.Transfer{}
			},
			wantCode: errors.CodeProviderNotFound,
			wantErr:  `can receive the key with MIGRATION_STRATEGY_PROVIDER_SWITCH (openssl: MIGRATION_STRATEGY_PROVIDER_SWITCH to provider instance "openssl" is not possible: provider instance "openssl" does not accept`,
		},
		{
			name: "provider-type search stops on an unexpected error",
			spec: MigrateKeySpec{KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategyArchive},
			mutate: func(f *migrateFixture) {
				f.providers.matchErr = errors.New(context.Background(), "fake.Match", errors.CodeInternal, "registry unavailable")
			},
			wantCode: errors.CodeInternal,
			wantErr:  "registry unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMigrateFixture(t)
			if tt.mutate != nil {
				tt.mutate(f)
			}
			_, err := f.orchestrator.MigrateKey(context.Background(), tt.spec)
			requireCoreErrorCode(t, err, tt.wantCode)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			}
			for name, b := range f.backends {
				require.Zero(t, b.generateCalls, "no material may be generated on %s", name)
			}
			require.Zero(t, f.repo.addVersionCalls)
			require.Len(t, f.repo.versions, 1)
		})
	}
}

func TestMigrateKeySpec_FromProto(t *testing.T) {
	ctx := context.Background()

	var spec MigrateKeySpec
	require.NoError(t, spec.FromProto(ctx, &messagespb.MigrateKeyRequest{
		Name:     transformKeyName,
		Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: migrateTargetInstance},
		Strategy: strategySwitch,
	}))
	require.Equal(t, MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch}, spec)

	require.NoError(t, spec.FromProto(ctx, &messagespb.MigrateKeyRequest{
		Name:     transformKeyName,
		Target:   &messagespb.MigrateKeyRequest_ProviderTarget{ProviderTarget: &messagespb.ProviderTarget{ProviderId: "openssl"}},
		Strategy: strategyArchive,
	}))
	require.Equal(t, MigrateKeySpec{KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategyArchive}, spec)

	templateID := "ecdsa-p256"
	for name, req := range map[string]*messagespb.MigrateKeyRequest{
		"nil request": nil,
		"template id": {Name: transformKeyName, TemplateId: &templateID},
		"scope spec":  {Name: transformKeyName, ScopeSpec: &types.ScopeSpecification{}},
		"configuration": {Name: transformKeyName, Target: &messagespb.MigrateKeyRequest_ProviderTarget{
			ProviderTarget: &messagespb.ProviderTarget{ProviderId: "openssl", Configuration: map[string]string{"k": "v"}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			requireCoreErrorCode(t, new(MigrateKeySpec).FromProto(ctx, req), errors.CodeInvalidArgument)
		})
	}
}

// ── fixture ───────────────────────────────────────────────────────────────

type migrateFixture struct {
	orchestrator KeyOrchestrator
	repo         *fakeKeyRepository
	templates    *fakeTemplateRegistry
	providers    *multiProviderRegistry
	backends     map[string]*namedBackend
	template     *template.Template
}

// withPolicy rebuilds the fixture's orchestrator with pol.
func (f *migrateFixture) withPolicy(t *testing.T, pol policy.Engine) {
	t.Helper()
	o, err := NewKeyOrchestrator(f.repo, f.templates, f.providers, pol)
	require.NoError(t, err)
	f.orchestrator = o
}

// newMigrateFixture stores one ECDSA P-256 key on the software instance, with
// openssl and openssl-fips instances that both support its template.
func newMigrateFixture(t *testing.T) *migrateFixture {
	t.Helper()
	ctx := context.Background()
	tmpl := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)

	stored, err := proto.Marshal(&providerpb.GenerateKeyResponse{
		KeyMaterial:         []byte("source-private"),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1,
		PublicKeyBytes:      []byte("source-public"),
		Output:              provider.NoOutput("raw"),
	})
	require.NoError(t, err)

	k, err := key.NewKey(ctx, transformKeyID, transformPolicyID, core.PrimitiveSignature, 1,
		key.WithName(transformKeyName),
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err)
	v, err := key.NewVersion(ctx, computeVersionID(transformKeyID, 1), transformKeyID,
		tmpl.TemplateID(), migrateSourceInstance, 1, stored,
		&core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE),
		key.WithProvenance(key.Provenance{Extractable: true}))
	require.NoError(t, err)

	repo := &fakeKeyRepository{key: k, versions: map[uint32]*key.Version{1: v}}
	templates := &fakeTemplateRegistry{templates: map[string]*template.Template{tmpl.TemplateID(): tmpl}}
	backends := map[string]*namedBackend{
		migrateSourceInstance: {name: migrateSourceInstance, typ: "software", transfer: sec1StoredPayload},
		migrateTargetInstance: {name: migrateTargetInstance, typ: "openssl", transfer: sec1StoredPayload},
		migrateFIPSInstance:   {name: migrateFIPSInstance, typ: "openssl", transfer: sec1StoredPayload, implementation: fipsLevel1()},
	}
	providers := &multiProviderRegistry{
		order:    []string{migrateSourceInstance, migrateTargetInstance, migrateFIPSInstance},
		backends: backends,
		supported: map[string]map[string]bool{
			migrateSourceInstance: {tmpl.TemplateID(): true},
			migrateTargetInstance: {tmpl.TemplateID(): true},
			migrateFIPSInstance:   {tmpl.TemplateID(): true},
		},
		fips: map[string]bool{migrateFIPSInstance: true},
	}

	o, err := NewKeyOrchestrator(repo, templates, providers, allowAllPolicy{})
	require.NoError(t, err)
	return &migrateFixture{orchestrator: o, repo: repo, templates: templates, providers: providers, backends: backends, template: tmpl}
}

// multiProviderRegistry holds several named instances, listed in order. Its
// Match honours only a pin, template support and FIPS 140 certification, and
// records every request.
type multiProviderRegistry struct {
	order     []string
	backends  map[string]*namedBackend
	supported map[string]map[string]bool
	fips      map[string]bool
	matched   []provider.Requirements
	matchErr  error // when set, every Match fails with it
}

func (r *multiProviderRegistry) Register(context.Context, provider.Backend) error { return nil }

func (r *multiProviderRegistry) Get(ctx context.Context, name string) (provider.Backend, error) {
	b, ok := r.backends[name]
	if !ok {
		return nil, errors.New(ctx, "fake.Get", errors.CodeProviderNotFound, "provider %q not found", name)
	}
	return b, nil
}

func (r *multiProviderRegistry) GetDefault(ctx context.Context) (provider.Backend, error) {
	return r.Get(ctx, r.order[0])
}

func (r *multiProviderRegistry) List(context.Context) []provider.Backend {
	out := make([]provider.Backend, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.backends[name])
	}
	return out
}

func (r *multiProviderRegistry) Remove(context.Context, string) error { return nil }

func (r *multiProviderRegistry) Match(ctx context.Context, req provider.Requirements) (provider.Backend, error) {
	r.matched = append(r.matched, req)
	if r.matchErr != nil {
		return nil, r.matchErr
	}
	b, ok := r.backends[req.ProviderName]
	if !ok || !r.supported[req.ProviderName][req.TemplateID] {
		return nil, errors.New(ctx, "fake.Match", errors.CodeProviderNotFound,
			"provider %q does not support template %q", req.ProviderName, req.TemplateID)
	}
	if (req.Implementation.FIPS140Certified || req.Implementation.ApprovedGeneration) && !r.fips[req.ProviderName] {
		return nil, errors.New(ctx, "fake.Match", errors.CodeFailedPrecondition,
			"provider %q is not FIPS 140 certified", req.ProviderName)
	}
	return b, nil
}

// namedBackend is a countingBackend with its own instance name and type,
// implementation properties and transfer advertisement.
type namedBackend struct {
	countingBackend
	name, typ      string
	implementation *types.ImplementationProperties
	transfer       provider.Transfer
}

func (b *namedBackend) Name() string { return b.name }
func (b *namedBackend) Type() string { return b.typ }
func (b *namedBackend) ImplementationProperties() *types.ImplementationProperties {
	return b.implementation
}
func (b *namedBackend) TransferCapabilities(*types.AlgorithmDetails) provider.Transfer {
	return b.transfer
}

// A provider switch keeps the template, so it copies the payload without
// the retained-material compatibility check TransformKey applies, which
// ValidateMigration does not apply either.
func TestMigrateKey_providerSwitchDoesNotNeedRetainableTemplates(t *testing.T) {
	f := newMigrateFixture(t)
	f.template.Proto().KeyMaterialFamily = ""

	v, err := f.orchestrator.ValidateMigration(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch,
	})
	require.NoError(t, err)
	require.True(t, v.Options[0].Feasible, v.Options[0].Reason)

	_, err = f.orchestrator.MigrateKey(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch,
	})
	require.NoError(t, err)
}
