package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/stretchr/testify/require"
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
// sorts before the fixture's ecdsa-p256 so catalog order puts it first too.
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
