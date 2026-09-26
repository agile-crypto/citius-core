package template

import (
	"context"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
)

// ScopeSpecFor returns the template's scope specification for scope. It is an
// error for the template not to declare the scope.
func ScopeSpecFor(ctx context.Context, tmpl *Template, scope core.Scope) (*core.ScopeSpecification, error) {
	const op = "template.ScopeSpecFor"
	for _, sc := range tmpl.GetScopedCapabilities() {
		if sc.GetScope() == nil {
			continue
		}
		spec, err := core.ScopeSpecificationFromProto(ctx, sc.GetScope())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err, errors.WithMessage("failed to read scope specification of template %s", tmpl.TemplateID()))
		}
		if spec.Scope == scope {
			return spec, nil
		}
	}
	return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "template %s does not declare scope %s", tmpl.TemplateID(), scope)
}

// ValidateAcceptedDigestHashes requires every prehashed signature scope of
// tmpl to list at least one accepted digest hash. protovalidate only checks
// that a list is well formed and appears on prehashed scopes; requiring it on
// templates (and not on key-creation requests, where empty means "the
// template's list") is a catalog rule, enforced here.
func ValidateAcceptedDigestHashes(ctx context.Context, tmpl *Template) error {
	const op = "template.ValidateAcceptedDigestHashes"
	for _, sc := range tmpl.GetScopedCapabilities() {
		if sc.GetScope() == nil {
			continue
		}
		spec, err := core.ScopeSpecificationFromProto(ctx, sc.GetScope())
		if err != nil {
			return errors.Wrap(ctx, op, err, errors.WithMessage("failed to read scope specification of template %s", tmpl.TemplateID()))
		}
		if spec.Scope.IsPrehashed() && len(spec.AcceptedDigestHashes()) == 0 {
			return errors.New(ctx, op, errors.CodeInvalidArgument,
				"template %s: prehashed scope %s must list accepted_digest_hashes", tmpl.TemplateID(), spec.Scope)
		}
	}
	return nil
}
