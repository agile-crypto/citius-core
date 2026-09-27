package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// templateListPolicy is allowAllPolicy with an allowed_templates list; nil
// means no policy restriction.
type templateListPolicy struct {
	allowAllPolicy
	allowed []string
}

func (p templateListPolicy) AllowedTemplates(context.Context, string, *core.ScopeSpecification) ([]string, error) {
	return p.allowed, nil
}

// softwareOnly is a template only the software instance implements; its ID
// sorts before the fixture's ecdsa-p256 so the template registry lists it
// first too.
const softwareOnly = "aaa-software-only"

// newSelectionFixture is the migrate fixture plus a template that only the
// software instance implements.
func newSelectionFixture(t *testing.T, allowed []string) *migrateFixture {
	t.Helper()
	f := newMigrateFixture(t)
	f.templates.templates[softwareOnly] = ecdsaTemplate(softwareOnly, types.EllipticCurve_ELLIPTIC_CURVE_P384, false)
	f.providers.supported[migrateSourceInstance][softwareOnly] = true
	f.withPolicy(t, templateListPolicy{allowed: allowed})
	return f
}

func createByScope(f *migrateFixture, pinned string) (*KeyMetadata, error) {
	return f.orchestrator.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:               "created",
		PolicyID:           transformPolicyID,
		ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		ProviderInstanceID: pinned,
	})
}

func TestCreateKey_scopeSelectionSkipsTemplatesNoProviderImplements(t *testing.T) {
	for name, allowed := range map[string][]string{
		"policy lists it first": {softwareOnly, "ecdsa-p256"},
		"no policy restriction": nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newSelectionFixture(t, allowed)
			md, err := createByScope(f, migrateTargetInstance)
			require.NoError(t, err)
			require.Equal(t, "ecdsa-p256", md.TemplateID, "openssl does not implement %s", softwareOnly)
			require.Equal(t, migrateTargetInstance, md.Provider)
		})
	}
}

func TestCreateKey_scopeSelectionKeepsPolicyOrderAmongServableTemplates(t *testing.T) {
	f := newSelectionFixture(t, []string{softwareOnly, "ecdsa-p256"})
	md, err := createByScope(f, migrateSourceInstance)
	require.NoError(t, err)
	require.Equal(t, softwareOnly, md.TemplateID)
}

func TestCreateKey_scopeSelectionNoServableTemplate(t *testing.T) {
	f := newSelectionFixture(t, []string{softwareOnly})
	_, err := createByScope(f, migrateTargetInstance)
	requireCoreErrorCode(t, err, errors.CodeTemplateNotFound)
	for name, b := range f.backends {
		require.Zero(t, b.generateCalls, "no material may be generated on %s", name)
	}
}

func TestTransformKey_scopeSelectionOnlyConsidersTheCurrentProvider(t *testing.T) {
	f := newSelectionFixture(t, []string{softwareOnly, "ecdsa-p256"})
	// Move the key to openssl, which does not implement softwareOnly.
	_, err := f.orchestrator.MigrateKey(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch,
	})
	require.NoError(t, err)

	md, err := f.orchestrator.TransformKey(context.Background(), TransformKeySpec{
		KeyName:            transformKeyName,
		ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
	})
	require.NoError(t, err)
	require.Equal(t, "ecdsa-p256", md.TemplateID)
	require.Equal(t, migrateTargetInstance, md.Provider)
}

func TestCreateKey_scopeSelectionReturnsUnexpectedRegistryErrors(t *testing.T) {
	f := newSelectionFixture(t, nil)
	f.providers.matchErr = errors.New(context.Background(), "fake.Match", errors.CodeInternal, "registry unavailable")

	_, err := createByScope(f, migrateTargetInstance)
	requireCoreErrorCode(t, err, errors.CodeInternal)
}

// describedBackend is a namedBackend that advertises templates and reports
// implementation properties, so the real provider registry can match it.
type describedBackend struct {
	namedBackend
	algorithms []string
	props      *types.ImplementationProperties
}

func (b *describedBackend) SupportedAlgorithms() []string { return b.algorithms }
func (b *describedBackend) ImplementationProperties() *types.ImplementationProperties {
	return b.props
}

// TestCreateKey_scopeSelectionAppliesProviderRequirementsWithoutAPin runs
// selection over the real provider registry with no pinned provider: a
// template the policy lists first is skipped when only a provider failing
// the request's requirements implements it.
func TestCreateKey_scopeSelectionAppliesProviderRequirementsWithoutAPin(t *testing.T) {
	const opensslOnly = "aaa-openssl-only"
	f := newMigrateFixture(t)
	f.templates.templates[opensslOnly] = ecdsaTemplate(opensslOnly, types.EllipticCurve_ELLIPTIC_CURVE_P384, false)
	registry := provider.NewRegistry()
	for _, b := range []*describedBackend{
		{
			namedBackend: namedBackend{name: "software", typ: "software"},
			algorithms:   []string{f.template.TemplateID()},
			props:        &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)},
		},
		{
			namedBackend: namedBackend{name: "openssl", typ: "openssl"},
			algorithms:   []string{opensslOnly, f.template.TemplateID()},
			props:        &types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)},
		},
	} {
		require.NoError(t, registry.Register(context.Background(), b))
	}
	o, err := NewKeyOrchestrator(f.repo, f.templates, registry, templateListPolicy{allowed: []string{opensslOnly, f.template.TemplateID()}})
	require.NoError(t, err)

	create := func(name string, reqs core.ProviderRequirements) *KeyMetadata {
		md, err := o.CreateKey(context.Background(), core.KeyCreationSpec{
			Name:                 name,
			PolicyID:             transformPolicyID,
			ScopeSpecification:   &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
			ProviderRequirements: reqs,
		})
		require.NoError(t, err)
		return md
	}
	md := create("unconstrained", core.ProviderRequirements{})
	require.Equal(t, opensslOnly, md.TemplateID, "with no requirement, policy order decides")
	require.Equal(t, "openssl", md.Provider)

	md = create("memory-safe", core.ProviderRequirements{MemorySafe: true})
	require.Equal(t, f.template.TemplateID(), md.TemplateID, "only openssl, which is not memory-safe, implements %s", opensslOnly)
	require.Equal(t, "software", md.Provider)
}
