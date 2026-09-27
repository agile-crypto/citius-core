package service

import (
	"context"
	"fmt"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"

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
// supports the key's template and meets the policy's provider requirements
// is used) must be set. A target instance must meet those requirements too.
//
// Supported strategies:
//   - MIGRATION_STRATEGY_PROVIDER_SWITCH copies the stored key payload
//     byte-for-byte to the target provider. The version must be extractable,
//     its source instance registered, and the payload's encoding one the
//     source releases and the target accepts as a stored payload.
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
			StrategyUsed:      m.Strategy,
			KeyBytesPreserved: m.KeyBytesPreserved,
			SourceProviderId:  m.SourceProviderID,
			SourceInstanceId:  m.SourceInstanceID,
			TargetProviderId:  m.TargetProviderID,
			TargetInstanceId:  m.TargetInstanceID,
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

	keyO, err := r.keys.GetKeyByName(ctx, spec.KeyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	lastVersion, err := r.keys.GetVersion(ctx, keyO.GetPublicId(), keyO.GetCurrentVersion())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	// A migration keeps the key's template and its full scope specification:
	// only custody changes.
	versionSpec := &core.ScopeSpecification{}
	if err = versionSpec.Deserialize(ctx, lastVersion.GetScopeSpecification()); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	tmpl, err := r.templates.Get(ctx, lastVersion.GetTemplateId())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	sourceInstance := lastVersion.GetProviderId()
	source, err := r.migrationSource(ctx, sourceInstance)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	target, err := r.migrationTarget(ctx, spec, keyO.GetPolicyId(), lastVersion, source, tmpl)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// A migration is authorized if creating the same key on the target
	// provider is.
	if err = r.validateTransformOp(ctx, keyO.GetName(), keyO.GetPolicyId(), versionSpec, target, tmpl, keyO.GetLabels()); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	preserve := spec.Strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH
	var keyMaterial []byte
	if preserve {
		keyMaterial, err = retainedKeyMaterial(ctx, tmpl, tmpl, lastVersion.GetKeyMaterial())
	} else {
		keyMaterial, err = generateKeyMaterial(ctx, op, target, tmpl)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	provenance := generatedProvenance(target, tmpl)
	if preserve {
		provenance = keptProvenance(lastVersion, target, tmpl,
			storepb.KeyOriginKind_KEY_ORIGIN_KIND_TRANSFERRED, storepb.KeyTransferChannel_KEY_TRANSFER_CHANNEL_STORED_PAYLOAD)
	}
	md, err := r.appendVersion(ctx, keyO, lastVersion, tmpl.TemplateID(), target.Name(), keyMaterial, versionSpec, provenance)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return &MigrationResult{
		Key:               md,
		Strategy:          spec.Strategy,
		KeyBytesPreserved: preserve,
		SourceProviderID:  backendType(source),
		SourceInstanceID:  sourceInstance,
		SourceVersion:     lastVersion.GetVersion(),
		TargetProviderID:  target.Type(),
		TargetInstanceID:  target.Name(),
	}, nil
}

// validateMigrateKeySpec checks the request shape before any repository read.
func validateMigrateKeySpec(ctx context.Context, spec MigrateKeySpec) error {
	const op = "service.validateMigrateKeySpec"
	if spec.KeyName == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key name is required")
	}
	if (spec.TargetInstanceID == "") == (spec.TargetProviderID == "") {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"exactly one of target instance ID or target provider ID is required")
	}
	switch spec.Strategy {
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE:
		return nil
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED:
		return errors.New(ctx, op, errors.CodeInvalidArgument, "migration strategy is required")
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented,
			"migration strategy %s is not implemented", spec.Strategy)
	}
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
// (see transferFeasibility). It is never version's own instance.
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
	candidate := func(name string) (provider.Backend, error) {
		pinned := custody
		pinned.ProviderName = name
		target, err := r.providers.Match(ctx, pinned)
		if err != nil {
			return nil, err
		}
		if ok, reason := transferFeasibility(spec.Strategy, source, target, version, tmpl); !ok {
			return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
				"%s to provider instance %q is not possible: %s", spec.Strategy, name, reason)
		}
		return target, nil
	}
	if spec.TargetInstanceID != "" {
		target, err := candidate(spec.TargetInstanceID)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return target, nil
	}
	for _, b := range r.providers.List(ctx) {
		if b.Type() != spec.TargetProviderID || b.Name() == sourceInstance {
			continue
		}
		target, err := candidate(b.Name())
		switch {
		case err == nil:
			return target, nil
		case errors.IsProviderNotFound(err), errors.IsFailedPrecondition(err):
			continue
		default:
			return nil, errors.Wrap(ctx, op, err)
		}
	}
	return nil, errors.New(ctx, op, errors.CodeProviderNotFound,
		"no instance of provider %q other than %q supports template %q, meets the policy's provider requirements and can receive the key with %s",
		spec.TargetProviderID, sourceInstance, tmpl.TemplateID(), spec.Strategy)
}
