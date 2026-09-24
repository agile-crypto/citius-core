package service

import (
	"context"
	"fmt"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
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

// If templateID is non-empty, pickTemplate returns the template with that ID if it matches the scope spec.
// If templateID is empty, pickTemplate returns the single best template matching the scope spec and allowed by policy.
func (r *keyOrchestrator) pickTemplate(ctx context.Context, policyID string, templateID string, scopeSpec *core.ScopeSpecification) (*template.Template, error) {
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
		// query policy for allowed templates, then ask the registry to select.
		allowed, err := r.policy.AllowedTemplates(ctx, policyID, scopeSpec)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}

		var candidates template.CandidateSet
		if allowed == nil {
			// nil means bypass (no policy in the system) - all templates eligible.
			candidates = template.AllTemplates()
		} else {
			candidates = template.OnlyTemplates(allowed...)
		}

		tmpl, err := r.templates.Select(ctx, scopeSpec, candidates)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return tmpl, nil
	}
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
	tmpl, err := r.pickTemplate(ctx, req.PolicyID, req.TemplateID, req.ScopeSpecification)
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
	return r.generateAndPersistKey(ctx, op, req, tmpl, req.ScopeSpecification)
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
) (*KeyMetadata, error) {
	// 1. Find a provider that supports this template — honouring an explicit
	// provider_id pin (req.ProviderInstanceID) and the scope's security
	// requirements (e.g. FIPS), rather than just the first provider that
	// advertises the template.
	prov, err := r.providers.Match(ctx, provider.Requirements{
		TemplateID:   tmpl.TemplateID(),
		ProviderName: req.ProviderInstanceID,
		Security:     scopeSpec.SecurityProps,
	})
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
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
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

func validateTransformScope(ctx context.Context, keyPrimitive string, scopeSpec *core.ScopeSpecification) error {
	const op = "service.validateTransformScope"
	if scopeSpec == nil || !scopeSpec.Scope.IsValid() {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "scope specification is required")
	}
	requestedPrimitive := scopeSpec.Scope.GetPrimitive().String()
	if requestedPrimitive != keyPrimitive {
		return errors.New(ctx, op, errors.CodeFailedPrecondition,
			"cannot transform key primitive %q to %q", keyPrimitive, requestedPrimitive)
	}
	return nil
}

func validateTransformScopePresent(ctx context.Context, scopeSpec *core.ScopeSpecification) error {
	const op = "service.validateTransformScopePresent"
	if scopeSpec == nil || !scopeSpec.Scope.IsValid() {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "scope specification is required")
	}
	return nil
}

func retainedKeyMaterial(ctx context.Context, prov provider.Backend, sourceTemplate, targetTemplate *template.Template, stored []byte) ([]byte, error) {
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
	checker, ok := prov.(provider.KeyMaterialCompatibilityChecker)
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"provider %q cannot validate retained key material", prov.Name())
	}
	if err = checker.ValidateRetainedKey(ctx, &storedResponse, sourceTemplate.GetAlgorithm(), targetTemplate.GetAlgorithm()); err != nil {
		return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
			"provider %q rejected retained material from template %q for template %q: %v",
			prov.Name(), sourceTemplate.TemplateID(), targetTemplate.TemplateID(), err)
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

	// Retrieve the key and enforce its immutable primitive boundary before any
	// template selection, provider call, or persistence side effect.
	keyO, err := r.keys.GetKeyByName(ctx, spec.KeyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if err = validateTransformScopePresent(ctx, spec.ScopeSpecification); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if !spec.RetainBytes {
		if err = validateTransformScope(ctx, keyO.GetPrimitive(), spec.ScopeSpecification); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}

	lastVersion, err := r.keys.GetVersion(ctx, keyO.PublicId, keyO.CurrentVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// Select or validate a template using the same scope and property filtering
	// as CreateKey.
	targetTemplate, err := r.pickTemplate(ctx, keyO.PolicyId, spec.TemplateID, spec.ScopeSpecification)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	var sourceTemplate *template.Template
	if spec.RetainBytes {
		sourceTemplate, err = r.templates.Get(ctx, lastVersion.GetTemplateId())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		compatible, compatibilityErr := template.CompatibleKeyMaterial(sourceTemplate, targetTemplate)
		if compatibilityErr != nil {
			return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
				"cannot retain material from template %q for template %q: %v",
				sourceTemplate.TemplateID(), targetTemplate.TemplateID(), compatibilityErr)
		}
		if !compatible {
			return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
				"cannot retain material from template %q for incompatible template %q",
				sourceTemplate.TemplateID(), targetTemplate.TemplateID())
		}
	}

	// TransformKey changes the algorithm while retaining custody. MigrateKey is
	// responsible for moving a key between providers, so pin the current provider
	// while validating its template support and requested security properties.
	provider, err := r.providers.Match(ctx, provider.Requirements{
		TemplateID:   targetTemplate.TemplateID(),
		ProviderName: lastVersion.GetProviderId(),
		Security:     spec.ScopeSpecification.SecurityProps,
	})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	var retainedMaterial []byte
	if spec.RetainBytes {
		retainedMaterial, err = retainedKeyMaterial(ctx, provider, sourceTemplate, targetTemplate, lastVersion.GetKeyMaterial())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}

	// Validation (same as for key creation)
	if err = r.validateTransformOp(ctx, keyO.GetName(), keyO.GetPolicyId(), spec.ScopeSpecification, provider, targetTemplate, keyO.GetLabels()); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	keyMaterial := retainedMaterial
	if !spec.RetainBytes {
		genResp, generateErr := generateAndValidateKey(ctx, op, provider, &providerpb.GenerateKeyRequest{
			Algorithm: targetTemplate.GetAlgorithm(),
		})
		if generateErr != nil {
			return nil, generateErr
		}

		// Marshal the full GenerateKeyResponse so that both KeyMaterial (private)
		// and PublicKeyBytes are persisted. The crypto orchestrator unmarshals to
		// pick the right bytes per operation (Sign => private, Verify => public).
		keyMaterial, err = proto.Marshal(genResp)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}

	// Create new key version with the new material, same key ID, and incremented version number.
	newVersionNumber := lastVersion.GetVersion() + 1
	newVersionID := computeVersionID(keyO.GetPublicId(), newVersionNumber)
	newVersion, err := key.NewVersion(ctx, newVersionID, keyO.GetPublicId(), targetTemplate.TemplateID(), provider.Name(), newVersionNumber,
		keyMaterial, spec.ScopeSpecification, key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	err = r.keys.AddVersion(ctx, newVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	// Update the state of previous version
	// TODO: check how/when this hsould be done and the expected transition
	// TODO: provide method in repository to update state

	metadata, err := buildKeyMetadata(ctx, keyO, newVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return metadata, nil
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
		core.OperationCreateKey, template.TemplateID(), ""); err != nil {
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
