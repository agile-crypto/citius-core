package template

import (
	"context"
	"slices"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
)

// MatchesScope reports whether tmpl serves the given scope.
// If want is nil, then all templates match (equivalent to no filter).
// Inspects the template's ScopedCapabilities and checks if any ScopeSpecification
// matches the requested [core.ScopeSpecification] (Scope + SecurityProperties +
// Primitive-specific properties + additional properties).
// Matching rules:
//
//   - Scope: if want.Scope != Unknown, scopes must match exactly
//
//   - SecurityProperties: if want.SecurityProperties != nil, got field must be non-nil and satisfy boolean/integral matching rules
//
//   - Primitive-specific properties: if want.PrimitiveSpecificProps != nil, got must be non-nil, of the same type, and satisfy boolean matching rules
//
//   - Additional properties: every (key, value) pair in want.AdditionalProps must be present in got.AdditionalProps
//
//   - boolean matching rule: want true => got must be true; want false => ok
//
//   - integral matching rule: got value must be greater or equal to want value
func MatchesScope(ctx context.Context, tmpl *Template, want *core.ScopeSpecification) (bool, error) {
	const op = "template.MatchesScope"
	if want == nil {
		return true, nil
	}
	for _, sc := range tmpl.GetScopedCapabilities() {
		if sc.Scope == nil {
			return false, errors.New(ctx, op, errors.CodeInternal, "template %s has no scoped capabilities", tmpl.TemplateID())
		}
		templateSpec, err := core.ScopeSpecificationFromProto(ctx, sc.Scope)
		if err != nil {
			// TODO: may want to signal error without interrupting the process
			return false, errors.Wrap(ctx, op, err, errors.WithMessage("failed to read template's scope specification"))
		}
		if want.Scope != core.ScopeUnknown && templateSpec.Scope != want.Scope {
			continue
		}
		if !securityPropertiesMatch(want.SecurityProps, templateSpec.SecurityProps) {
			continue
		}
		matches, err := primitivePropertiesMatch(ctx, want.PrimitiveSpecificProps, templateSpec.PrimitiveSpecificProps)
		if err != nil {
			// TODO: may want to signal error without interrupting the process
			return false, errors.Wrap(ctx, op, err, errors.WithMessage("failed to compare primitive-specific properties for template %s", tmpl.TemplateID()))
		}
		if !matches {
			continue
		}
		if !additionalPropertiesMatch(want.AdditionalProps, templateSpec.AdditionalProps) {
			continue
		}
		return true, nil
	}
	return false, nil
}

// SupportsOperation reports whether tmpl declares operation for scope in its
// ScopedCapabilities. The catalog is the source of truth for which operations
// a (template, scope) pair permits: for example, the standard catalog lists
// DIGEST_SIGN/DIGEST_VERIFY only on prehashed signature scopes.
func SupportsOperation(ctx context.Context, tmpl *Template, scope core.Scope, operation types.CryptoOperation) (bool, error) {
	const op = "template.SupportsOperation"
	for _, sc := range tmpl.GetScopedCapabilities() {
		if sc.GetScope() == nil {
			continue
		}
		templateSpec, err := core.ScopeSpecificationFromProto(ctx, sc.GetScope())
		if err != nil {
			return false, errors.Wrap(ctx, op, err, errors.WithMessage("failed to read template's scope specification"))
		}
		if templateSpec.Scope != scope {
			continue
		}
		for _, declared := range sc.GetOperations() {
			if declared == operation {
				return true, nil
			}
		}
	}
	return false, nil
}

// securityPropertiesMatch checks whether template-side security properties (got)
// satisfy the caller-side security filter (want).
//
// Nil-semantics per field:
//   - want field nil  -> don't care -> always passes
//   - want field non-nil -> got field must be non-nil and equal
func securityPropertiesMatch(want, got *core.SecurityProperties) bool {
	if want == nil {
		return true
	}
	if got == nil {
		// caller specified security filters but template has no security properties -> no match
		return false
	}
	if want.FipsApproved && !got.FipsApproved {
		return false
	}
	if want.QuantumSafe && !got.QuantumSafe {
		return false
	}
	if want.SecurityLevel != types.NistSecurityLevel_NIST_SECURITY_LEVEL_UNSPECIFIED && got.SecurityLevel < want.SecurityLevel {
		return false
	}
	if got.SecurityStrength < want.SecurityStrength {
		return false
	}
	if want.NistStatus != types.NistStatus_NIST_STATUS_UNSPECIFIED && got.NistStatus != want.NistStatus {
		return false
	}
	return true
}

func matchesSignatureProperties(ctx context.Context, want *core.SignatureProperties, got core.PrimitiveSpecificProperties) (bool, error) {
	const op = "template.matchesSignatureProperties"
	g, ok := got.(*core.SignatureProperties)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInternal, "invalid PrimitiveSpecificProperties type: %T", got)
	}
	if want.Deterministic && !g.Deterministic {
		return false, nil
	}
	if want.NonMalleable && !g.NonMalleable {
		return false, nil
	}
	// A requested digest-hash list is a requirement: the template must accept
	// every hash in it.
	for _, h := range want.AcceptedDigestHashes {
		if !slices.Contains(g.AcceptedDigestHashes, h) {
			return false, nil
		}
	}
	return true, nil
}

func matchesAeadProperties(ctx context.Context, want *core.AEADProperties, got core.PrimitiveSpecificProperties) (bool, error) {
	const op = "template.matchesAeadProperties"
	g, ok := got.(*core.AEADProperties)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInternal, "invalid PrimitiveSpecificProperties type: %T", got)
	}
	if want.NonceMisuseResistant && !g.NonceMisuseResistant {
		return false, nil
	}
	return true, nil
}

func matchesKeyAgreementProperties(ctx context.Context, want *core.KeyAgreementProperties, got core.PrimitiveSpecificProperties) (bool, error) {
	const op = "template.matchesKeyAgreementProperties"
	g, ok := got.(*core.KeyAgreementProperties)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInternal, "invalid PrimitiveSpecificProperties type: %T", got)
	}
	if want.ForwardSecrecy && !g.ForwardSecrecy {
		return false, nil
	}
	return true, nil
}

func matchesKDFProperties(ctx context.Context, want *core.KDFProperties, got core.PrimitiveSpecificProperties) (bool, error) {
	const op = "template.matchesKDFProperties"
	g, ok := got.(*core.KDFProperties)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInternal, "invalid PrimitiveSpecificProperties type: %T", got)
	}
	if want.MemoryHard && !g.MemoryHard {
		return false, nil
	}
	return true, nil
}

// Check whether primitive-specific properties match.
// Matching semantics (caller filter vs. template properties):
//   - want == nil -> always matches (no requirements)
//   - boolean properties: want true => got must be true; want false => ok
//   - there is currently no non-boolean primitive-specific property
func primitivePropertiesMatch(ctx context.Context, want, got core.PrimitiveSpecificProperties) (bool, error) {
	const op = "template.primitivePropertiesMatch"
	if want == nil {
		return true, nil
	}
	if got == nil {
		return false, nil
	}
	switch w := want.(type) {
	case *core.SignatureProperties:
		return matchesSignatureProperties(ctx, w, got)
	case *core.AEADProperties:
		return matchesAeadProperties(ctx, w, got)
	case *core.KeyAgreementProperties:
		return matchesKeyAgreementProperties(ctx, w, got)
	case *core.KDFProperties:
		return matchesKDFProperties(ctx, w, got)
	default:
		// unknown PrimitiveSpecificProperties type -> no match
		return false, errors.New(ctx, op, errors.CodeInternal, "unsupported PrimitiveSpecificProperties type: %T", want)
	}
}

// Matching semantics for additional (non-primitive-specific) properties: want is a filter that must be fully satisfied by got.
// If a (key, value) pair is present in want.AdditionalProperties, the same pair must be present in got.AdditionalProperties.
func additionalPropertiesMatch(want, got map[string]string) bool {
	for k, v := range want {
		gotVal, ok := got[k]
		if !ok {
			return false
		}
		if gotVal != v {
			return false
		}
	}
	return true
}
