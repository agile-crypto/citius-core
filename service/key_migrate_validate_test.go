package service

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	"github.com/stretchr/testify/require"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
)

func assessments(v *MigrationValidation) map[messagespb.MigrationStrategy]StrategyAssessment {
	m := map[messagespb.MigrationStrategy]StrategyAssessment{}
	for _, o := range v.Options {
		m[o.Strategy] = o
	}
	return m
}

func TestValidateMigration_reportsEveryStrategyWithoutSideEffects(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	f.backends[migrateSourceInstance].implementation = fipsLevel1()

	v, err := f.orchestrator.ValidateMigration(ctx, MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance,
	})
	require.NoError(t, err)
	require.Zero(t, f.repo.addVersionCalls)
	for name, b := range f.backends {
		require.Zero(t, b.generateCalls, "validation must not generate material on %s", name)
	}

	require.Equal(t, f.template.TemplateID(), v.TemplateID)
	require.Equal(t, "software", v.SourceProviderID)
	require.Equal(t, migrateSourceInstance, v.SourceInstanceID)
	require.True(t, v.Extractable)
	require.True(t, v.SourceImplementation.GetFips_140().GetCertified())

	require.Len(t, v.Options, len(migrationStrategies))
	got := assessments(v)
	require.Equal(t, StrategyAssessment{Strategy: strategySwitch, Feasible: true, TargetInstanceID: migrateTargetInstance}, got[strategySwitch])
	require.Equal(t, StrategyAssessment{Strategy: strategyArchive, Feasible: true, TargetInstanceID: migrateTargetInstance}, got[strategyArchive])
	require.Contains(t, got[messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT].Reason, "share no plaintext key encoding")
	require.Contains(t, got[messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER].Reason, "share no key-wrapping mechanism")
	destroy := got[messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_DESTROY]
	require.False(t, destroy.Feasible)
	require.Equal(t, "MIGRATION_STRATEGY_REKEY_AND_DESTROY is not implemented", destroy.Reason)
	require.Empty(t, destroy.TargetInstanceID)

	require.Equal(t, strategySwitch, v.Recommended)
	require.NotEmpty(t, v.RecommendationReason)

	resp := v.ToProto()
	require.Equal(t, migrateSourceInstance, resp.GetCurrentState().GetInstanceId())
	require.True(t, resp.GetCurrentState().GetExtractable())
	require.Len(t, resp.GetOptions(), len(migrationStrategies))
	require.Equal(t, strategySwitch, resp.GetRecommendedStrategy())
}

func TestValidateMigration_recommendsRekeyWhenMaterialCannotMove(t *testing.T) {
	f := newMigrateFixture(t)
	f.repo.versions[1].Extractable = false

	v, err := f.orchestrator.ValidateMigration(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetProviderID: "openssl",
	})
	require.NoError(t, err)
	got := assessments(v)
	require.False(t, got[strategySwitch].Feasible)
	require.Contains(t, got[strategySwitch].Reason, "is not extractable")
	require.NotContains(t, got[strategySwitch].Reason, "service.", "reasons carry no operation names")
	require.True(t, got[strategyArchive].Feasible)
	require.Equal(t, strategyArchive, v.Recommended)
}

func TestValidateMigration_recommendsNothingWhenNoStrategyIsFeasible(t *testing.T) {
	f := newMigrateFixture(t)
	f.withPolicy(t, fipsRule)

	v, err := f.orchestrator.ValidateMigration(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance,
	})
	require.NoError(t, err)
	for _, o := range v.Options {
		require.False(t, o.Feasible, o.Strategy)
		require.NotEmpty(t, o.Reason, o.Strategy)
	}
	require.Equal(t, messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED, v.Recommended)
	require.NotEmpty(t, v.RecommendationReason)
}

func TestValidateMigration_limitsTheReportToAPreferredStrategy(t *testing.T) {
	f := newMigrateFixture(t)
	f.backends[migrateTargetInstance].transfer = provider.Transfer{}

	v, err := f.orchestrator.ValidateMigration(context.Background(), MigrateKeySpec{
		KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: strategySwitch,
	})
	require.NoError(t, err)
	require.Len(t, v.Options, 1)
	require.False(t, v.Options[0].Feasible)
	require.Contains(t, v.Options[0].Reason, `"openssl" does not accept`)
	require.Equal(t, messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED, v.Recommended)
}

func TestValidateMigration_errors(t *testing.T) {
	tests := []struct {
		name     string
		spec     MigrateKeySpec
		mutate   func(*migrateFixture)
		wantCode errors.Code
	}{
		{"missing key name", MigrateKeySpec{TargetInstanceID: migrateTargetInstance}, nil, errors.CodeInvalidArgument},
		{"no target", MigrateKeySpec{KeyName: transformKeyName}, nil, errors.CodeInvalidArgument},
		{"unknown strategy", MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance, Strategy: 99}, nil, errors.CodeInvalidArgument},
		{"unknown key", MigrateKeySpec{KeyName: "nope", TargetInstanceID: migrateTargetInstance}, nil, errors.CodeNotFound},
		{
			"unexpected error", MigrateKeySpec{KeyName: transformKeyName, TargetInstanceID: migrateTargetInstance},
			func(f *migrateFixture) {
				f.providers.matchErr = errors.New(context.Background(), "fake.Match", errors.CodeInternal, "registry unavailable")
			},
			errors.CodeInternal,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMigrateFixture(t)
			if tt.mutate != nil {
				tt.mutate(f)
			}
			_, err := f.orchestrator.ValidateMigration(context.Background(), tt.spec)
			requireCoreErrorCode(t, err, tt.wantCode)
		})
	}
}
