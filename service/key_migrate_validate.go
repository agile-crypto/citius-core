package service

import (
	"context"
	"slices"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
)

// migrationStrategies lists every migration strategy, in the order in which
// ValidateMigration reports them.
var migrationStrategies = []messagespb.MigrationStrategy{
	messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
	messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT,
	messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER,
	messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
	messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_DESTROY,
}

// StrategyAssessment says whether one strategy can migrate a key.
type StrategyAssessment struct {
	Strategy messagespb.MigrationStrategy
	Feasible bool
	// Reason says why the strategy is not feasible. Empty when it is.
	Reason string
	// TargetInstanceID is the instance the key would migrate to. Set only
	// when the strategy is feasible.
	TargetInstanceID string
}

// MigrationValidation reports which strategies can migrate a key to a
// target, as MigrateKey would decide, without side effects.
type MigrationValidation struct {
	// The key's current version.
	TemplateID       string
	SourceProviderID string // "" when SourceInstanceID is no longer registered
	SourceInstanceID string
	Extractable      bool
	// SourceImplementation describes SourceInstanceID; nil when it is no
	// longer registered or does not describe itself.
	SourceImplementation *types.ImplementationProperties

	Options []StrategyAssessment
	// Recommended is the feasible strategy to prefer, or UNSPECIFIED when
	// none is feasible; RecommendationReason says why.
	Recommended          messagespb.MigrationStrategy
	RecommendationReason string
}

// ToProto converts the validation to a ValidateKeyOperationResponse.
func (v *MigrationValidation) ToProto() *messagespb.ValidateKeyOperationResponse {
	if v == nil {
		return nil
	}
	resp := &messagespb.ValidateKeyOperationResponse{
		CurrentState: &messagespb.KeyState{
			TemplateId:     v.TemplateID,
			ProviderId:     v.SourceProviderID,
			InstanceId:     v.SourceInstanceID,
			Extractable:    v.Extractable,
			Implementation: v.SourceImplementation,
		},
		RecommendedStrategy:  v.Recommended,
		RecommendationReason: v.RecommendationReason,
	}
	for _, o := range v.Options {
		resp.Options = append(resp.Options, &messagespb.StrategyOption{
			Strategy:            o.Strategy,
			Feasible:            o.Feasible,
			InfeasibilityReason: o.Reason,
		})
	}
	return resp
}

// ValidateMigration reports whether each strategy can migrate a key to
// spec's target, applying every check MigrateKey applies before its first
// side effect. spec.Strategy, when set, limits the report to that strategy.
//
// A strategy's refusal is reported as its reason; only a failure to read
// the key, or an unexpected error, is returned as an error.
func (r *keyOrchestrator) ValidateMigration(ctx context.Context, spec MigrateKeySpec) (*MigrationValidation, error) {
	const op = "service.(keyOrchestrator).ValidateMigration"
	strategies := migrationStrategies
	if spec.Strategy != messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED {
		if !slices.Contains(migrationStrategies, spec.Strategy) {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "unknown migration strategy %s", spec.Strategy)
		}
		strategies = []messagespb.MigrationStrategy{spec.Strategy}
	}
	if err := validateMigrationTarget(ctx, spec); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	m, err := r.loadMigration(ctx, spec.KeyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	v := &MigrationValidation{
		TemplateID:           m.template.TemplateID(),
		SourceProviderID:     backendType(m.source),
		SourceInstanceID:     m.version.GetProviderId(),
		Extractable:          m.version.GetExtractable(),
		SourceImplementation: implementationOf(m.source),
	}
	for _, strategy := range strategies {
		spec.Strategy = strategy
		o := StrategyAssessment{Strategy: strategy}
		target, err := r.checkMigration(ctx, m, spec)
		switch {
		case err == nil && !migrationImplemented(strategy):
			o.Reason = strategy.String() + " is not implemented"
		case err == nil:
			o.Feasible, o.TargetInstanceID = true, target.Name()
		case errors.IsFailedPrecondition(err), errors.IsProviderNotFound(err), errors.IsPolicyViolation(err):
			o.Reason = refusalReason(err)
		default:
			return nil, errors.Wrap(ctx, op, err)
		}
		v.Options = append(v.Options, o)
	}
	v.Recommended, v.RecommendationReason = recommendMigration(v.Options)
	return v, nil
}

// recommendMigration picks the strategy to prefer among the feasible
// options, and says why.
func recommendMigration(options []StrategyAssessment) (messagespb.MigrationStrategy, string) {
	feasible := func(s messagespb.MigrationStrategy) bool {
		return slices.ContainsFunc(options, func(o StrategyAssessment) bool { return o.Strategy == s && o.Feasible })
	}
	switch {
	case feasible(messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH):
		return messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
			"the key's material moves unchanged, so data it protects needs no re-encryption or re-signing"
	case feasible(messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE):
		return messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
			"the key's material cannot move; new material is generated on the target and the current version stays on its provider for data it protects"
	default:
		return messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED, "no strategy can migrate the key to the target"
	}
}

// implementationOf returns b's implementation properties, or nil.
func implementationOf(b provider.Backend) *types.ImplementationProperties {
	if d, ok := b.(provider.ImplementationDescriber); ok {
		return d.ImplementationProperties()
	}
	return nil
}
