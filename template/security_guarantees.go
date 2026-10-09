package template

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/protobuf/proto"
)

// SecurityGuaranteesFor returns the security guarantees tmpl gives for scope:
// those its scoped capability declares, or else the template's own (the
// fallback the proto defines). It returns a copy, and nil when neither
// declares any. declared is false, with no guarantees, when tmpl does not
// declare scope at all.
func SecurityGuaranteesFor(ctx context.Context, tmpl *Template, scope core.Scope) (guarantees *types.SecurityGuarantees, declared bool, err error) {
	const op = "template.SecurityGuaranteesFor"
	for _, sc := range tmpl.GetScopedCapabilities() {
		if sc.GetScope() == nil {
			continue
		}
		spec, err := core.ScopeSpecificationFromProto(ctx, sc.GetScope())
		if err != nil {
			return nil, false, errors.Wrap(ctx, op, err, errors.WithMessage("failed to read scope specification of template %s", tmpl.TemplateID()))
		}
		if spec.Scope != scope {
			continue
		}
		if g := sc.GetSecurityGuarantees(); g != nil {
			return proto.CloneOf(g), true, nil
		}
		if g := tmpl.Proto().GetSecurityGuarantees(); g != nil {
			return proto.CloneOf(g), true, nil
		}
		return nil, true, nil
	}
	return nil, false, nil
}
