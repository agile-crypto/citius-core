package service

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// providerRulePolicy is allowAllPolicy with a provider_requirements rule.
type providerRulePolicy struct {
	allowAllPolicy
	requirements core.ProviderRequirements
}

func (p providerRulePolicy) ProviderRequirements(context.Context, string) (core.ProviderRequirements, error) {
	return p.requirements, nil
}

var fipsRule = providerRulePolicy{requirements: core.ProviderRequirements{FIPS140Certified: true}}

func TestCreateKey_mergesRequestAndPolicyProviderRequirements(t *testing.T) {
	f := newMigrateFixture(t)
	f.withPolicy(t, fipsRule)
	f.backends[migrateFIPSInstance].implementation.MemorySafeLanguage = proto.Bool(true)

	md, err := f.orchestrator.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:                 "created",
		TemplateID:           f.template.TemplateID(),
		PolicyID:             transformPolicyID,
		ScopeSpecification:   &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		ProviderInstanceID:   migrateFIPSInstance,
		ProviderRequirements: core.ProviderRequirements{MemorySafe: true},
	})
	require.NoError(t, err)
	require.Equal(t, migrateFIPSInstance, md.Provider)
	require.Equal(t, core.ProviderRequirements{FIPS140Certified: true, MemorySafe: true},
		f.providers.matched[len(f.providers.matched)-1].Implementation,
		"the chosen provider must meet the request's and the policy's requirements")
}

func TestCreateKey_policyProviderRequirementsCannotBeRelaxed(t *testing.T) {
	f := newMigrateFixture(t)
	f.withPolicy(t, fipsRule)

	_, err := f.orchestrator.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:               "created",
		TemplateID:         f.template.TemplateID(),
		PolicyID:           transformPolicyID,
		ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		ProviderInstanceID: migrateTargetInstance,
	})
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	for name, b := range f.backends {
		require.Zero(t, b.generateCalls, "no material may be generated on %s", name)
	}
}

func TestTransformKey_enforcesPolicyProviderRequirements(t *testing.T) {
	f := newMigrateFixture(t)
	f.withPolicy(t, fipsRule)

	_, err := f.orchestrator.TransformKey(context.Background(), TransformKeySpec{
		KeyName:            transformKeyName,
		TemplateID:         f.template.TemplateID(),
		ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
	})
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.Zero(t, f.repo.addVersionCalls, "a key whose provider no longer meets its policy must be migrated, not transformed")
}

func TestMigrateKey_enforcesPolicyProviderRequirements(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	f.withPolicy(t, fipsRule)

	_, err := f.orchestrator.MigrateKey(ctx, MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch,
	})
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.Zero(t, f.repo.addVersionCalls)

	res, err := f.orchestrator.MigrateKey(ctx, MigrateKeySpec{
		KeyName: transformKeyName, TargetProviderID: "openssl", Strategy: strategySwitch,
	})
	require.NoError(t, err)
	require.Equal(t, migrateFIPSInstance, res.TargetInstanceID,
		"a provider-type target must skip instances that do not meet the policy")
}

// TestCreateKey_scopeFIPSApprovalDoesNotChooseTheProvider records decision
// DT-027: a scope's fips_approved selects FIPS-approved algorithms only;
// only a provider requirement forces a FIPS 140 certified provider.
func TestCreateKey_scopeFIPSApprovalDoesNotChooseTheProvider(t *testing.T) {
	f := newMigrateFixture(t)

	md, err := f.orchestrator.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:       "created",
		TemplateID: f.template.TemplateID(),
		PolicyID:   transformPolicyID,
		ScopeSpecification: &core.ScopeSpecification{
			Scope:         core.ScopeSignatureStandard,
			SecurityProps: &core.SecurityProperties{FipsApproved: true},
		},
		ProviderInstanceID: migrateTargetInstance,
	})
	require.NoError(t, err)
	require.Equal(t, migrateTargetInstance, md.Provider)
	require.True(t, f.providers.matched[len(f.providers.matched)-1].Implementation.IsZero())
}

var approvedGenerationRule = providerRulePolicy{requirements: core.ProviderRequirements{ApprovedGeneration: true}}

func TestMigrateKey_approvedGenerationNeedsAnApprovedLineageToKeepMaterial(t *testing.T) {
	ctx := context.Background()
	toFIPS := func(strategy messagespb.MigrationStrategy) MigrateKeySpec {
		return MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateFIPSInstance, Strategy: strategy}
	}

	f := newMigrateFixture(t)
	f.withPolicy(t, approvedGenerationRule)
	_, err := f.orchestrator.MigrateKey(ctx, toFIPS(strategySwitch))
	requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
	require.ErrorContains(t, err, "requires approved generation")
	require.Zero(t, f.repo.addVersionCalls)

	res, err := f.orchestrator.MigrateKey(ctx, toFIPS(strategyArchive))
	require.NoError(t, err, "rekeying onto an approved module is how such a key regains an approved lineage")
	require.True(t, f.repo.versions[res.Key.Version].GetApprovedLineage())

	f = newMigrateFixture(t)
	f.withPolicy(t, approvedGenerationRule)
	f.repo.versions[1].ApprovedLineage = true
	res, err = f.orchestrator.MigrateKey(ctx, toFIPS(strategySwitch))
	require.NoError(t, err)
	require.True(t, f.repo.versions[res.Key.Version].GetApprovedLineage())
}

func TestTransformKey_approvedGenerationNeedsAnApprovedLineageToRetainMaterial(t *testing.T) {
	for _, lineage := range []bool{false, true} {
		f := newMigrateFixture(t)
		f.withPolicy(t, approvedGenerationRule)
		f.repo.versions[1].ProviderId = migrateFIPSInstance
		f.repo.versions[1].ApprovedLineage = lineage

		_, err := f.orchestrator.TransformKey(context.Background(), TransformKeySpec{
			KeyName:            transformKeyName,
			TemplateID:         f.template.TemplateID(),
			ScopeSpecification: &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
			RetainBytes:        true,
		})
		if lineage {
			require.NoError(t, err)
			continue
		}
		requireCoreErrorCode(t, err, errors.CodeFailedPrecondition)
		require.ErrorContains(t, err, "requires approved generation")
		require.Zero(t, f.repo.addVersionCalls)
	}
}
