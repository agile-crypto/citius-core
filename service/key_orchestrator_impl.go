package service

import (
	"context"
	"fmt"
	"slices"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/agile-crypto/citius-core/template"
	"google.golang.org/protobuf/proto"
)

// keyOrchestrator implements the KeyOrchestrator interface.
// It requires key.Repository, template.Registry, provider.Registry, and policy.Engine to function.
type keyOrchestrator struct {
	keys      key.Repository
	templates template.Registry
	providers provider.Registry
	policy    policy.Engine
}

// NewKeyOrchestrator creates a new KeyOrchestrator.
// All four dependencies are required; returns an error if any is nil.
func NewKeyOrchestrator(
	keys key.Repository,
	templates template.Registry,
	providers provider.Registry,
	policyEngine policy.Engine,
) (KeyOrchestrator, error) {
	const op errors.Op = "service.NewKeyOrchestrator"
	ctx := context.Background()

	if keys == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"repository must not be nil")
	}
	if templates == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"template registry must not be nil")
	}
	if providers == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"provider registry must not be nil")
	}
	if policyEngine == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"policy engine must not be nil")
	}

	return &keyOrchestrator{
		keys:      keys,
		templates: templates,
		providers: providers,
		policy:    policyEngine,
	}, nil
}

// If templateID is non-empty, pickTemplate returns the template with that ID if it matches the scope spec;
// provider matching later reports whether a provider meeting custody implements it.
// If templateID is empty, pickTemplate returns the first template, in the policy's allowed_templates order
// (template registry List order when no policy applies), that matches the scope spec and that a provider meeting custody
// (its pinned instance, if any, and provider requirements) implements. A template no such provider can
// serve is never chosen, however early the policy lists it.
func (r *keyOrchestrator) pickTemplate(ctx context.Context, policyID string, templateID string, scopeSpec *core.ScopeSpecification, custody provider.Requirements) (*template.Template, error) {
	const op = "service.(keyOrchestrator).pickTemplate"
	if templateID != "" {
		candidates := template.OnlyTemplates(templateID)
		if len(candidates.IDs()) != 1 {
			return nil, errors.New(ctx, op, errors.CodeInternal,
				"expected exactly one template, got %d", len(candidates.IDs()))
		}
		tmpl, err := r.templates.Select(ctx, scopeSpec, candidates)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if tmpl == nil {
			return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
				"no template matching the given scope specification found (ID=%s)", templateID)
		}
		return tmpl, nil
	} else {
		// Scope-based path: parse the proto-encoded ScopeSpecification,
		// query policy for allowed templates, keep those a provider meeting
		// custody implements, then ask the registry to select.
		allowed, err := r.policy.AllowedTemplates(ctx, policyID, scopeSpec)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if allowed == nil {
			// nil means bypass (no policy in the system) - all templates eligible.
			for _, t := range r.templates.List(ctx) {
				allowed = append(allowed, t.TemplateID())
			}
		}

		servable, err := r.servable(ctx, allowed, custody)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		tmpl, err := r.templates.Select(ctx, scopeSpec, template.OnlyTemplates(servable...))
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return tmpl, nil
	}
}

// servable returns, in order, the template IDs in ids that a provider meeting
// custody implements. Only a "no such provider" or "provider does not meet
// the requirements" answer excludes a template; any other error from the
// registry is returned.
func (r *keyOrchestrator) servable(ctx context.Context, ids []string, custody provider.Requirements) ([]string, error) {
	const op = "service.(keyOrchestrator).servable"
	var out []string
	for _, id := range ids {
		custody.TemplateID = id
		_, err := r.providers.Match(ctx, custody)
		switch {
		case err == nil:
			out = append(out, id)
		case errors.IsProviderNotFound(err), errors.IsFailedPrecondition(err):
		default:
			return nil, errors.Wrap(ctx, op, err)
		}
	}
	return out, nil
}
func (r *keyOrchestrator) CreateKey(ctx context.Context, req core.KeyCreationSpec) (*KeyMetadata, error) {
	const op errors.Op = "service.(keyOrchestrator).CreateKey"

	// 1. Validate request
	if req.Name == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key name must not be empty")
	}
	if req.PolicyID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"policy ID must not be empty")
	}
	if req.ScopeSpecification == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"scope specification must not be nil and contain at least a scope")
	}

	// 2. Resolve template + derive scope.
	//    Two paths: explicit template_id OR scope-based selection.
	var tmpl *template.Template

	if req.ScopeSpecification.Scope == core.ScopeUnknown {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"scope is unknown or missing; scope is required for key creation")
	}
	custody, err := r.custody(ctx, req.PolicyID, req.ProviderInstanceID, req.ProviderRequirements)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	tmpl, versionSpec, err := r.pickVersionTemplate(ctx, req.PolicyID, req.TemplateID, req.ScopeSpecification, custody)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 2a. Policy: validate that create_key with this template is permitted.
	if err := r.policy.ValidateOperation(ctx, req.PolicyID,
		core.OperationCreateKey, tmpl.TemplateID(), ""); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 2b. Policy: validate key configuration constraints (extractable, rotation, etc.)
	if err := r.policy.ValidateKeyCreation(ctx, req.PolicyID, &req); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 3. Generate key material and persist key + initial version.
	return r.generateAndPersistKey(ctx, op, req, tmpl, versionSpec, custody)
}

// custody returns the provider requirements for a new version of a key under
// policyID: the pinned provider instance, if any, and the policy's provider
// requirements merged with requested. A request can add to the policy's
// requirements but never relax them.
func (r *keyOrchestrator) custody(ctx context.Context, policyID, pinned string, requested core.ProviderRequirements) (provider.Requirements, error) {
	const op = "service.(keyOrchestrator).custody"
	fromPolicy, err := r.policy.ProviderRequirements(ctx, policyID)
	if err != nil {
		return provider.Requirements{}, errors.Wrap(ctx, op, err)
	}
	return provider.Requirements{ProviderName: pinned, Implementation: requested.Merge(fromPolicy)}, nil
}

// pickVersionTemplate selects the template for a new key version, among
// those a provider meeting custody implements, and returns it with the scope
// specification to store on that version.
func (r *keyOrchestrator) pickVersionTemplate(ctx context.Context, policyID, templateID string, spec *core.ScopeSpecification, custody provider.Requirements) (*template.Template, *core.ScopeSpecification, error) {
	const op = "service.(keyOrchestrator).pickVersionTemplate"
	if err := validateRequestedDigestHashes(ctx, spec); err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	tmpl, err := r.pickTemplate(ctx, policyID, templateID, spec, custody)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	versionSpec, err := resolveDigestHashes(ctx, tmpl, spec)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return tmpl, versionSpec, nil
}

// validateRequestedDigestHashes rejects accepted digest hashes on a scope
// whose input is not a digest.
func validateRequestedDigestHashes(ctx context.Context, spec *core.ScopeSpecification) error {
	const op = "service.validateRequestedDigestHashes"
	if !spec.Scope.IsPrehashed() && len(spec.AcceptedDigestHashes()) > 0 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"accepted_digest_hashes applies only to prehashed signature scopes, not %s", spec.Scope)
	}
	return nil
}

// resolveDigestHashes returns the scope specification to store on a new key
// version. For a prehashed scope it records the digest hashes the version
// accepts: the requested list, which may narrow the template's, or the
// template's own list when the request names none. Other scopes are returned
// unchanged. The caller's spec is never modified.
func resolveDigestHashes(ctx context.Context, tmpl *template.Template, spec *core.ScopeSpecification) (*core.ScopeSpecification, error) {
	const op = "service.resolveDigestHashes"
	if !spec.Scope.IsPrehashed() {
		return spec, nil
	}
	tmplSpec, err := template.ScopeSpecFor(ctx, tmpl, spec.Scope)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	offered := tmplSpec.AcceptedDigestHashes()
	if len(offered) == 0 {
		return nil, errors.New(ctx, op, errors.CodeInternal,
			"template %s lists no accepted digest hash for prehashed scope %s", tmpl.TemplateID(), spec.Scope)
	}
	requested := spec.AcceptedDigestHashes()
	if len(requested) == 0 {
		return spec.WithAcceptedDigestHashes(offered), nil
	}
	for _, h := range requested {
		if !slices.Contains(offered, h) {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"template %s does not accept digest hash %s for scope %s", tmpl.TemplateID(), h, spec.Scope)
		}
	}
	return spec.WithAcceptedDigestHashes(requested), nil
}

// buildKeyMetadata projects a key.Key and its current key.Version into the
// API-facing KeyMetadata. v may be nil; version-scoped fields are
// then left at their zero values.
func buildKeyMetadata(ctx context.Context, k *key.Key, v *key.Version) (*KeyMetadata, error) {
	const op = "service.buildKeyMetadata"
	md := &KeyMetadata{
		Name:           k.GetName(),
		KeyID:          k.GetPublicId(),
		Primitive:      k.GetPrimitive(),
		Policy:         k.GetPolicyId(),
		LifecycleState: k.GetState(),
		Labels:         k.GetLabels(),
	}

	if v != nil {
		if data := v.GetScopeSpecification(); len(data) > 0 {
			scopeSpec := &core.ScopeSpecification{}
			if err := scopeSpec.Deserialize(ctx, data); err != nil {
				return nil, errors.Wrap(ctx, op, err)
			}
			md.ScopeSpec = scopeSpec
		}
	}

	if v != nil {
		md.Version = v.GetVersion()
		md.TemplateID = v.GetTemplateId()
		md.Provider = v.GetProviderId()
		md.Extractable = v.GetExtractable()
		//TODO: skip for now. TemplateInfo should be fetched by the application using the template id
		// if tmpl, err := r.templates.Get(ctx, v.GetTemplateId()); err == nil {
		// 	md.TemplateInfo = tmpl
		// }
	}

	return md, nil
}

func computeVersionID(keyID string, version uint32) string {
	return fmt.Sprintf("%s:%d", keyID, version)
}

// generateAndPersistKey handles provider key generation, proto marshaling, and
// repository persistence.  Extracted from CreateKey to keep cyclomatic
// complexity within linter limits.
func (r *keyOrchestrator) generateAndPersistKey(
	ctx context.Context,
	op errors.Op,
	req core.KeyCreationSpec,
	tmpl *template.Template,
	scopeSpec *core.ScopeSpecification,
	custody provider.Requirements,
) (*KeyMetadata, error) {
	// 1. Find a provider that supports this template — honouring an explicit
	// provider_id pin and the provider requirements of the request and
	// policy, rather than just the first provider that advertises the
	// template.
	custody.TemplateID = tmpl.TemplateID()
	prov, err := r.providers.Match(ctx, custody)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 2. Generate key material via the provider.
	genResp, err := prov.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: tmpl.GetAlgorithm(),
	})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, genResp.GetOutput()); err != nil {
		return nil, err
	}

	// 3. Build Key + initial Version, then persist.
	//
	// TODO: add saga compensation to prevent orphaned key
	// material if storage fails after provider key generation succeeds.
	keyID := core.NewID(core.KeyPrefix)
	initialVersion := uint32(1)

	versionID := computeVersionID(keyID, initialVersion)

	// Marshal the full GenerateKeyResponse so that both KeyMaterial (private)
	// and PublicKeyBytes are persisted.  The crypto orchestrator unmarshals to
	// pick the right bytes per operation (Sign => private, Verify => public).
	genRespBytes, err := proto.Marshal(genResp)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	k, err := key.NewKey(ctx, keyID, req.PolicyID, scopeSpec.Scope.GetPrimitive(), initialVersion,
		key.WithName(req.Name),
		key.WithLabels(req.Labels),
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE),
	)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	v, err := key.NewVersion(ctx, versionID, keyID, tmpl.TemplateID(), prov.Name(), initialVersion, genRespBytes, scopeSpec,
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE),
		key.WithProvenance(generatedProvenance(prov, tmpl)))
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	if err := r.keys.CreateKey(ctx, k, v); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	return buildKeyMetadata(ctx, k, v)
}

func (r *keyOrchestrator) ReadKey(ctx context.Context, keyName string, version uint32) (*KeyMetadata, error) {
	const op errors.Op = "service.(keyOrchestrator).ReadKey"
	k, err := r.keys.GetKeyByName(ctx, keyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	var v *key.Version
	if version == 0 {
		v, err = r.keys.GetCurrentVersion(ctx, k.GetPublicId())
	} else {
		v, err = r.keys.GetVersion(ctx, k.GetPublicId(), version)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return buildKeyMetadata(ctx, k, v)
}

func (r *keyOrchestrator) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	const op errors.Op = "service.(keyOrchestrator).ListKeys"
	keys, err := r.keys.ListKeys(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	out := make([]*KeyMetadata, 0, len(keys))
	for _, k := range keys {
		v, verr := r.keys.GetCurrentVersion(ctx, k.GetPublicId())
		if verr != nil {
			return nil, errors.Wrap(ctx, op, verr)
		}
		md, merr := buildKeyMetadata(ctx, k, v)
		if merr != nil {
			return nil, errors.Wrap(ctx, op, merr)
		}
		out = append(out, md)
	}
	return out, nil
}

func (r *keyOrchestrator) DeleteKey(ctx context.Context, keyName string) error {
	const op errors.Op = "service.(keyOrchestrator).DeleteKey"
	// 1. Fetch key metadata.
	k, err := r.keys.GetKeyByName(ctx, keyName)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	if err := r.keys.DeleteKey(ctx, k.GetPublicId()); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *keyOrchestrator) RotateKey(ctx context.Context, _ string) (*KeyMetadata, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).RotateKey", errors.CodeNotImplemented,
		"RotateKey not yet implemented")
}

func (r *keyOrchestrator) SuspendKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).SuspendKey", errors.CodeNotImplemented,
		"SuspendKey not yet implemented")
}

func (r *keyOrchestrator) RestoreKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).RestoreKey", errors.CodeNotImplemented,
		"RestoreKey not yet implemented")
}

func (r *keyOrchestrator) DestroyKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).DestroyKey", errors.CodeNotImplemented,
		"DestroyKey not yet implemented")
}

func (r *keyOrchestrator) ImportKey(ctx context.Context, _ core.ImportKeySpec) (*KeyMetadata, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).ImportKey", errors.CodeNotImplemented,
		"ImportKey not yet implemented")
}

func (r *keyOrchestrator) UpdateKeyPolicy(ctx context.Context, _ string, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).UpdateKeyPolicy", errors.CodeNotImplemented,
		"UpdateKeyPolicy not yet implemented")
}

// validateTransformScope requires a scope and enforces that it equals the
// scope of the key's current version. The scope is the key's contract with its
// callers: it fixes the input shape (message or digest, with or without a
// context, AEAD parameters or none) and the operations that accept it. A
// transform may change the algorithm behind that contract, never the contract
// itself, so callers keep working without code changes. Because every scope
// belongs to exactly one primitive, this also keeps the key's primitive, in
// both regenerate and retain mode.
func validateTransformScope(ctx context.Context, currentScope core.Scope, scopeSpec *core.ScopeSpecification) error {
	const op = "service.validateTransformScope"
	if scopeSpec == nil || !scopeSpec.Scope.IsValid() {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "scope specification is required")
	}
	if scopeSpec.Scope != currentScope {
		return errors.New(ctx, op, errors.CodeFailedPrecondition,
			"cannot transform key scope %q to %q: a transform must keep the key's scope",
			currentScope, scopeSpec.Scope)
	}
	return nil
}

// versionScope returns the scope recorded on a key version.
func versionScope(ctx context.Context, v *key.Version) (core.Scope, error) {
	const op = "service.versionScope"
	spec := &core.ScopeSpecification{}
	if err := spec.Deserialize(ctx, v.GetScopeSpecification()); err != nil {
		return core.ScopeUnknown, errors.Wrap(ctx, op, err)
	}
	return spec.Scope, nil
}

func retainedKeyMaterial(ctx context.Context, sourceTemplate, targetTemplate *template.Template, stored []byte) ([]byte, error) {
	const op = "service.retainedKeyMaterial"
	compatible, err := template.CompatibleKeyMaterial(sourceTemplate, targetTemplate)
	if err != nil {
		return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
			"cannot retain material from template %q for template %q: %v",
			sourceTemplate.TemplateID(), targetTemplate.TemplateID(), err)
	}
	if !compatible {
		return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
			"cannot retain material from template %q for incompatible template %q",
			sourceTemplate.TemplateID(), targetTemplate.TemplateID())
	}
	var storedResponse providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(stored, &storedResponse); err != nil {
		return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
			"stored key payload for template %q is invalid: %v", sourceTemplate.TemplateID(), err)
	}
	return append([]byte(nil), stored...), nil
}

func (r *keyOrchestrator) TransformKey(ctx context.Context, spec TransformKeySpec) (*KeyMetadata, error) {
	const op = "service.(keyOrchestrator).TransformKey"
	if spec.KeyName == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "key name is required")
	}
	if spec.RetainBytes && spec.TemplateID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"template ID is required when retaining key bytes")
	}

	// Retrieve the key and its current version, and enforce the scope contract
	// before any template selection, provider call, or persistence side effect.
	keyO, err := r.keys.GetKeyByName(ctx, spec.KeyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	lastVersion, err := r.keys.GetVersion(ctx, keyO.PublicId, keyO.CurrentVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	currentScope, err := versionScope(ctx, lastVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = validateTransformScope(ctx, currentScope, spec.ScopeSpecification); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// Select or validate a template using the same scope and property filtering
	// as CreateKey. TransformKey changes the algorithm while retaining custody;
	// MigrateKey is responsible for moving a key between providers. So only
	// templates the current provider implements, meeting the policy's provider
	// requirements, are candidates, and the current provider is pinned.
	custody, err := r.custody(ctx, keyO.GetPolicyId(), lastVersion.GetProviderId(), core.ProviderRequirements{})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	targetTemplate, versionSpec, err := r.pickVersionTemplate(ctx, keyO.PolicyId, spec.TemplateID, spec.ScopeSpecification, custody)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	custody.TemplateID = targetTemplate.TemplateID()
	provider, err := r.providers.Match(ctx, custody)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// Validation (same as for key creation)
	if err = r.validateTransformOp(ctx, keyO.GetName(), keyO.GetPolicyId(), spec.ScopeSpecification, provider, targetTemplate, keyO.GetLabels()); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	provenance, err := transformProvenance(ctx, custody, spec.RetainBytes, lastVersion, provider, targetTemplate)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	keyMaterial, err := r.transformKeyMaterial(ctx, spec.RetainBytes, lastVersion, targetTemplate, provider)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	metadata, err := r.appendVersion(ctx, keyO, lastVersion, targetTemplate.TemplateID(), provider.Name(), keyMaterial, versionSpec, provenance)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return metadata, nil
}

// transformProvenance is the provenance of the version a transform creates
// on prov for tmpl: that of lastVersion's material when retaining it, which
// custody (see requireKeptLineage) or prov (see retainFeasibility) may
// refuse, else that of new material.
func transformProvenance(ctx context.Context, custody provider.Requirements, retain bool,
	lastVersion *key.Version, prov provider.Backend, tmpl *template.Template) (key.Provenance, error) {
	const op = "service.transformProvenance"
	if !retain {
		return generatedProvenance(prov, tmpl), nil
	}
	if err := requireKeptLineage(ctx, custody, lastVersion); err != nil {
		return key.Provenance{}, errors.Wrap(ctx, op, err)
	}
	if ok, reason := retainFeasibility(prov, lastVersion, tmpl); !ok {
		return key.Provenance{}, errors.New(ctx, op, errors.CodeFailedPrecondition, "cannot retain the key's material: %s", reason)
	}
	return keptProvenance(lastVersion, prov, tmpl,
		storepb.KeyOriginKind_KEY_ORIGIN_KIND_RETAINED, storepb.KeyTransferChannel_KEY_TRANSFER_CHANNEL_STORED_PAYLOAD), nil
}

// appendVersion persists a new active version of keyO, numbered after
// lastVersion, with the given provenance, and returns the key's metadata at
// that version.
func (r *keyOrchestrator) appendVersion(ctx context.Context, keyO *key.Key, lastVersion *key.Version,
	templateID, providerID string, keyMaterial []byte, versionSpec *core.ScopeSpecification, provenance key.Provenance) (*KeyMetadata, error) {
	const op = "service.(keyOrchestrator).appendVersion"
	newVersionNumber := lastVersion.GetVersion() + 1
	newVersionID := computeVersionID(keyO.GetPublicId(), newVersionNumber)
	newVersion, err := key.NewVersion(ctx, newVersionID, keyO.GetPublicId(), templateID, providerID, newVersionNumber,
		keyMaterial, versionSpec, key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE), key.WithProvenance(provenance))
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = r.keys.AddVersion(ctx, newVersion); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	// Update the state of previous version
	// TODO: check how/when this hsould be done and the expected transition
	// TODO: provide method in repository to update state
	return buildKeyMetadata(ctx, keyO, newVersion)
}

// transformKeyMaterial returns the stored payload for the new key version:
// a byte-for-byte copy of the current payload when retaining key bytes, or
// freshly generated material otherwise. prov has already been matched for
// target, so retain mode never calls GenerateKey.
func (r *keyOrchestrator) transformKeyMaterial(ctx context.Context, retain bool, lastVersion *key.Version, target *template.Template, prov provider.Backend) ([]byte, error) {
	const op = "service.(keyOrchestrator).transformKeyMaterial"
	if !retain {
		return generateKeyMaterial(ctx, op, prov, target)
	}
	// TODO: Opaque or usage-restricted providers (for example HSMs with
	// immutable mechanism attributes) may need an optional provider-specific
	// retained-material validation capability. Provider matching already
	// proves that this provider advertises the target template; software and
	// OpenSSL material is additionally checked when the target operation parses it.
	return r.retainMaterial(ctx, lastVersion, target)
}

// retainMaterial loads the source template of lastVersion and returns a copy
// of its stored payload if the key material is compatible with target.
func (r *keyOrchestrator) retainMaterial(ctx context.Context, lastVersion *key.Version, target *template.Template) ([]byte, error) {
	const op = "service.(keyOrchestrator).retainMaterial"
	source, err := r.templates.Get(ctx, lastVersion.GetTemplateId())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return retainedKeyMaterial(ctx, source, target, lastVersion.GetKeyMaterial())
}

// generateKeyMaterial generates fresh material for tmpl and marshals the full
// GenerateKeyResponse so that both KeyMaterial (private) and PublicKeyBytes
// are persisted. The crypto orchestrator unmarshals to pick the right bytes
// per operation (Sign => private, Verify => public).
func generateKeyMaterial(ctx context.Context, op errors.Op, prov provider.Backend, tmpl *template.Template) ([]byte, error) {
	genResp, err := generateAndValidateKey(ctx, op, prov, &providerpb.GenerateKeyRequest{
		Algorithm: tmpl.GetAlgorithm(),
	})
	if err != nil {
		return nil, err
	}
	material, err := proto.Marshal(genResp)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return material, nil
}

// generateAndValidateKey calls the provider's GenerateKey and enforces the
// ProviderOutput contract (an unset algorithm_output is a provider bug, not
// a caller error).  Extracted from TransformKey to keep cyclomatic
// complexity within linter limits.
func generateAndValidateKey(ctx context.Context, op errors.Op, prov provider.Backend, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	genResp, err := prov.GenerateKey(ctx, req)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = requireProviderOutput(ctx, op, genResp.GetOutput()); err != nil {
		return nil, err
	}
	return genResp, nil
}

// Validates a transform operation against the policy with given policyID. Returns an error if the operation is not permitted.
// A transform operation is authorized if an equivalent create key operation is allowed.
func (r *keyOrchestrator) validateTransformOp(ctx context.Context, keyName string, policyID string, scopeSpec *core.ScopeSpecification, provider provider.Backend,
	template *template.Template, keyLabels map[string]string) error {
	const op = "service.(keyOrchestrator).validateTransformOp"
	// Policy: validate that create_key with this template is permitted.
	if err := r.policy.ValidateOperation(ctx, policyID,
		core.OperationCreateKey, template.TemplateID(), provider.Name()); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	// Policy: validate key configuration constraints (extractable, rotation, etc.)
	// Validation is equivalent to validating a key creation with the new template.
	keyCreationSpec := &core.KeyCreationSpec{
		Name:               keyName,
		PolicyID:           policyID,
		ScopeSpecification: scopeSpec,
		TemplateID:         template.TemplateID(),
		ProviderInstanceID: provider.Name(),
		Labels:             keyLabels,
	}
	if err := r.policy.ValidateKeyCreation(ctx, policyID, keyCreationSpec); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Compile-time assertion: keyOrchestrator implements KeyOrchestrator.
var _ KeyOrchestrator = (*keyOrchestrator)(nil)
