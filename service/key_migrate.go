package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	"github.com/agile-crypto/citius-api-go/gen/go/types"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/provider"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/agile-crypto/citius-core/template"
)

// MigrateKeySpec describes a MigrateKey request.
//
// Exactly one of TargetInstanceID (a registered provider instance name) or
// TargetProviderID (a provider type; the first instance of that type that
// supports the key's template, meets the policy's provider requirements and
// can carry out the strategy is used) must be set. A target instance must
// meet the same conditions.
//
// Supported strategies:
//   - MIGRATION_STRATEGY_PROVIDER_SWITCH copies the stored key payload
//     byte-for-byte to the target provider. The version must be extractable,
//     its source instance registered, and the payload's encoding one the
//     source releases and the target accepts as a stored payload. Under a
//     policy requiring approved generation, the version's lineage must be
//     approved.
//   - MIGRATION_STRATEGY_REKEY_AND_ARCHIVE generates new material on the
//     target provider. The previous version stays on the source provider, so
//     data it protects can still be decrypted or verified.
//
// The other strategies return CodeNotImplemented.
type MigrateKeySpec struct {
	KeyName          string
	TargetInstanceID string
	TargetProviderID string
	Strategy         messagespb.MigrationStrategy
}

// FromProto fills the spec from a MigrateKeyRequest. A migration keeps the
// key's template and scope, so a request naming either is rejected rather
// than ignored, as is provider configuration, which no provider consumes yet.
func (s *MigrateKeySpec) FromProto(ctx context.Context, req *messagespb.MigrateKeyRequest) error {
	const op = "service.(MigrateKeySpec).FromProto"
	if req == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "migrate key request proto is nil")
	}
	if req.ScopeSpec != nil || req.TemplateId != nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"a migration keeps the key's template and scope; use TransformKey to change them")
	}
	if len(req.GetProviderTarget().GetConfiguration()) > 0 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"provider target configuration is not supported")
	}
	*s = MigrateKeySpec{
		KeyName:          req.GetName(),
		TargetInstanceID: req.GetTargetInstanceId(),
		TargetProviderID: req.GetProviderTarget().GetProviderId(),
		Strategy:         req.GetStrategy(),
	}
	return nil
}

// MigrationResult reports the outcome of a MigrateKey call.
type MigrationResult struct {
	// Key is the key's metadata at the new current version.
	Key               *KeyMetadata
	Strategy          messagespb.MigrationStrategy
	KeyBytesPreserved bool
	SourceProviderID  string
	SourceInstanceID  string
	// SourceVersion is the previous current version, which stays on the
	// source provider instance.
	SourceVersion    uint32
	TargetProviderID string
	TargetInstanceID string
	// TargetImplementation is what the target instance reports about its
	// implementation (FIPS 140, memory safety, ...); nil when it reports
	// nothing.
	TargetImplementation *types.ImplementationProperties
}

// ToProto converts the result to a MigrateKeyResponse.
//
// For REKEY_AND_ARCHIVE the archived material is the previous version of the
// same key, still on the source instance, so ArchivedKeyInfo names the key
// itself; callers address the archived material with that name and
// SourceVersion. Sign and Encrypt always use the current version, so the
// archived version only serves Verify and Decrypt calls that name it.
// ArchivedKeyInfo.allowed_operations is left empty.
func (m *MigrationResult) ToProto(ctx context.Context) (*messagespb.MigrateKeyResponse, error) {
	const op = "service.(MigrationResult).ToProto"
	if m == nil {
		return nil, nil
	}
	md, err := m.Key.ToProto(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	resp := &messagespb.MigrateKeyResponse{
		Success:     true,
		Message:     fmt.Sprintf("migrated from %s version %d to %s version %d", m.SourceInstanceID, m.SourceVersion, m.TargetInstanceID, m.Key.Version),
		KeyMetadata: md,
		Result: &messagespb.MigrationResult{
			StrategyUsed:         m.Strategy,
			KeyBytesPreserved:    m.KeyBytesPreserved,
			SourceProviderId:     m.SourceProviderID,
			SourceInstanceId:     m.SourceInstanceID,
			TargetProviderId:     m.TargetProviderID,
			TargetInstanceId:     m.TargetInstanceID,
			TargetImplementation: m.TargetImplementation,
		},
	}
	if m.Strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE {
		resp.ArchivedKeyInfo = &messagespb.ArchivedKeyInfo{
			ArchivedKeyName: m.Key.Name,
			ProviderId:      m.SourceInstanceID,
		}
	}
	return resp, nil
}

// MigrateKey moves a key to another provider instance. See
// KeyOrchestrator.MigrateKey and MigrateKeySpec.
func (r *keyOrchestrator) MigrateKey(ctx context.Context, spec MigrateKeySpec) (*MigrationResult, error) {
	const op = "service.(keyOrchestrator).MigrateKey"
	if err := validateMigrateKeySpec(ctx, spec); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	m, err := r.loadMigration(ctx, spec.KeyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	target, err := r.checkMigration(ctx, m, spec)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	keyO, lastVersion, tmpl := m.key, m.version, m.template

	var (
		keyMaterial []byte
		provenance  key.Provenance
		preserve    bool
	)
	switch spec.Strategy {
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH:
		// The template is kept, and checkMigration has parsed the payload,
		// so it is copied as is.
		keyMaterial, preserve = append([]byte(nil), lastVersion.GetKeyMaterial()...), true
		provenance = keptProvenance(lastVersion, target, tmpl,
			storepb.KeyOriginKind_KEY_ORIGIN_KIND_TRANSFERRED, storepb.KeyTransferChannel_KEY_TRANSFER_CHANNEL_STORED_PAYLOAD)
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE:
		if keyMaterial, err = generateKeyMaterial(ctx, op, target, tmpl); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		provenance = generatedProvenance(target, tmpl)
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"migration strategy %s is not implemented", spec.Strategy)
	}
	md, err := r.appendVersion(ctx, keyO, lastVersion, tmpl.TemplateID(), target.Name(), keyMaterial, m.scope, provenance)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return &MigrationResult{
		Key:                  md,
		Strategy:             spec.Strategy,
		KeyBytesPreserved:    preserve,
		SourceProviderID:     backendType(m.source),
		SourceInstanceID:     lastVersion.GetProviderId(),
		SourceVersion:        lastVersion.GetVersion(),
		TargetProviderID:     target.Type(),
		TargetInstanceID:     target.Name(),
		TargetImplementation: provider.ImplementationOf(target),
	}, nil
}

// migration is what every strategy of a key's migration starts from.
type migration struct {
	key     *key.Key
	version *key.Version // the current version, whose material migrates
	// A migration keeps the key's template and its full scope specification:
	// only custody changes.
	scope    *core.ScopeSpecification
	template *template.Template
	source   provider.Backend // nil when version's instance is no longer registered
}

// loadMigration reads the key named keyName and its current version.
func (r *keyOrchestrator) loadMigration(ctx context.Context, keyName string) (*migration, error) {
	const op = "service.(keyOrchestrator).loadMigration"
	keyO, err := r.keys.GetKeyByName(ctx, keyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	version, err := r.keys.GetVersion(ctx, keyO.GetPublicId(), keyO.GetCurrentVersion())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	scope := &core.ScopeSpecification{}
	if err = scope.Deserialize(ctx, version.GetScopeSpecification()); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	tmpl, err := r.templates.Get(ctx, version.GetTemplateId())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	source, err := r.migrationSource(ctx, version.GetProviderId())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return &migration{key: keyO, version: version, scope: scope, template: tmpl, source: source}, nil
}

// checkMigration resolves the target of m with spec's target and strategy,
// and checks everything that can refuse the migration before any side
// effect. It does not check whether the strategy is implemented.
func (r *keyOrchestrator) checkMigration(ctx context.Context, m *migration, spec MigrateKeySpec) (provider.Backend, error) {
	const op = "service.(keyOrchestrator).checkMigration"
	target, err := r.migrationTarget(ctx, spec, m.key.GetPolicyId(), m.version, m.source, m.template)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	// A migration is authorized if creating the same key on the target
	// provider is.
	// TODO: this runs only on the target chosen, so a provider-type search
	// would stop at an instance the policy denies instead of trying the next.
	// No policy distinguishes instances yet.
	if err = r.validateTransformOp(ctx, m.key.GetName(), m.key.GetPolicyId(), m.scope, target, m.template, m.key.GetLabels()); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return target, nil
}

// validateMigrateKeySpec checks the request shape before any repository read.
func validateMigrateKeySpec(ctx context.Context, spec MigrateKeySpec) error {
	const op = "service.validateMigrateKeySpec"
	if err := validateMigrationTarget(ctx, spec); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	switch {
	case spec.Strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED:
		return errors.New(ctx, op, errors.CodeInvalidArgument, "migration strategy is required")
	case !slices.Contains(migrationStrategies, spec.Strategy):
		return errors.New(ctx, op, errors.CodeInvalidArgument, "unknown migration strategy %s", spec.Strategy)
	case !migrationImplemented(spec.Strategy):
		return errors.New(ctx, op, errors.CodeNotImplemented,
			"migration strategy %s is not implemented", spec.Strategy)
	default:
		return nil
	}
}

// migrationImplemented reports whether MigrateKey carries out strategy.
func migrationImplemented(strategy messagespb.MigrationStrategy) bool {
	return strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH ||
		strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE
}

// validateMigrationTarget checks that spec names a key and exactly one
// target.
func validateMigrationTarget(ctx context.Context, spec MigrateKeySpec) error {
	const op = "service.validateMigrationTarget"
	if spec.KeyName == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key name is required")
	}
	if (spec.TargetInstanceID == "") == (spec.TargetProviderID == "") {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"exactly one of target instance ID or target provider ID is required")
	}
	return nil
}

// migrationSource returns the provider instance a key's current version is
// on, or nil when that instance is no longer registered. A rekey needs
// nothing from the source; every transfer strategy needs it to vouch for
// the material.
func (r *keyOrchestrator) migrationSource(ctx context.Context, instance string) (provider.Backend, error) {
	const op = "service.(keyOrchestrator).migrationSource"
	b, err := r.providers.Get(ctx, instance)
	switch {
	case err == nil:
		return b, nil
	case errors.IsProviderNotFound(err):
		return nil, nil
	default:
		return nil, errors.Wrap(ctx, op, err)
	}
}

// transfersMaterial reports whether strategy moves the key's existing
// material to the target, rather than generating new material there.
func transfersMaterial(strategy messagespb.MigrationStrategy) bool {
	switch strategy {
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER:
		return true
	default:
		return false
	}
}

// backendType returns b's provider type, or "" for nil.
func backendType(b provider.Backend) string {
	if b == nil {
		return ""
	}
	return b.Type()
}

// migrationTarget resolves the provider instance version migrates to with
// spec.Strategy. The target must support the key's template, meet its
// policy's provider requirements, and, with source, carry out the strategy
// (see transferFeasibility). It is never version's own instance. A strategy
// that transfers the material also needs it to have an approved lineage
// when the policy requires approved generation.
//
// A provider-type target resolves to the first instance of that type that
// qualifies. An instance is passed over only when it does not; any other
// error stops the search.
func (r *keyOrchestrator) migrationTarget(ctx context.Context, spec MigrateKeySpec, policyID string,
	version *key.Version, source provider.Backend, tmpl *template.Template) (provider.Backend, error) {
	const op = "service.(keyOrchestrator).migrationTarget"
	sourceInstance := version.GetProviderId()
	if spec.TargetInstanceID == sourceInstance {
		return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
			"key is already on provider instance %q", sourceInstance)
	}
	custody, err := r.custody(ctx, policyID, "", core.ProviderRequirements{})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	custody.TemplateID = tmpl.TemplateID()
	if transfersMaterial(spec.Strategy) {
		if err = requireKeptLineage(ctx, custody, version); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}
	// What the version and its source decide refuses the migration whatever
	// the target, so it is checked once, before any target is considered.
	if ok, reason := sourceFeasibility(spec.Strategy, source, version, tmpl); !ok {
		return nil, errors.New(ctx, op, errors.CodeFailedPrecondition, "%s is not possible: %s", spec.Strategy, reason)
	}
	candidate := func(name string) (provider.Backend, error) {
		pinned := custody
		pinned.ProviderName = name
		target, matchErr := r.providers.Match(ctx, pinned)
		if matchErr != nil {
			return nil, matchErr
		}
		if ok, reason := targetFeasibility(spec.Strategy, source, target, version, tmpl); !ok {
			return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
				"%s to provider instance %q is not possible: %s", spec.Strategy, name, reason)
		}
		return target, nil
	}
	var target provider.Backend
	if spec.TargetInstanceID != "" {
		target, err = candidate(spec.TargetInstanceID)
	} else {
		target, err = r.firstMigrationTarget(ctx, spec, sourceInstance, tmpl, candidate)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return target, nil
}

// firstMigrationTarget returns the first instance of spec's provider type,
// other than sourceInstance, that candidate accepts. An instance candidate
// refuses is passed over, and the reason reported if none is accepted; any
// other error stops the search.
func (r *keyOrchestrator) firstMigrationTarget(ctx context.Context, spec MigrateKeySpec, sourceInstance string,
	tmpl *template.Template, candidate func(name string) (provider.Backend, error)) (provider.Backend, error) {
	const op = "service.(keyOrchestrator).firstMigrationTarget"
	var passedOver []string
	for _, b := range r.providers.List(ctx) {
		if b.Type() != spec.TargetProviderID || b.Name() == sourceInstance {
			continue
		}
		target, err := candidate(b.Name())
		switch {
		case err == nil:
			return target, nil
		case errors.IsProviderNotFound(err), errors.IsFailedPrecondition(err):
			passedOver = append(passedOver, fmt.Sprintf("%s: %s", b.Name(), refusalReason(err)))
		default:
			return nil, errors.Wrap(ctx, op, err)
		}
	}
	msg := fmt.Sprintf("no instance of provider %q other than %q supports template %q, meets the policy's provider requirements and can receive the key with %s",
		spec.TargetProviderID, sourceInstance, tmpl.TemplateID(), spec.Strategy)
	if len(passedOver) > 0 {
		msg += " (" + strings.Join(passedOver, "; ") + ")"
	}
	return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "%s", msg)
}

// refusalReason is err's messages, outermost first, without the operation
// names that locate them in the code. The first error that is not a core
// error is kept whole.
func refusalReason(err error) string {
	var messages []string
	for err != nil {
		e, ok := err.(*errors.Error) //nolint:errorlint // each layer is examined in turn
		if !ok {
			messages = append(messages, err.Error())
			break
		}
		if e.Message != "" {
			messages = append(messages, e.Message)
		}
		err = e.Wrapped
	}
	return strings.Join(messages, ": ")
}
