package template

import (
	"context"

	core "github.com/agile-crypto/citius-core"
)

// CandidateSet specifies which template IDs are eligible for selection.
// Use the constructors [AllTemplates] and [OnlyTemplates] to create values;
// the zero value is NOT valid — callers must pick one of the two intents.
type CandidateSet struct {
	ids        []string
	restricted bool // true = only ids are eligible; false = every registered template is eligible
}

// AllTemplates returns a CandidateSet where every registered template is eligible.
// This is used when there is no policy restriction on which templates may be selected.
func AllTemplates() CandidateSet { return CandidateSet{restricted: false} }

// OnlyTemplates returns a CandidateSet restricted to the listed IDs.
// An empty list means "nothing is eligible" (NOT "everything is eligible").
func OnlyTemplates(ids ...string) CandidateSet {
	return CandidateSet{ids: ids, restricted: true}
}

// IsRestricted reports whether the set is limited to specific IDs.
func (c CandidateSet) IsRestricted() bool { return c.restricted }

// IDs returns the allowed template IDs. Only meaningful when IsRestricted is true.
func (c CandidateSet) IDs() []string { return c.ids }

// Registry manages algorithm template definitions and selection.
type Registry interface {
	Register(ctx context.Context, tmpl *Template) error
	Get(ctx context.Context, templateID string) (*Template, error)
	List(ctx context.Context) []*Template

	// Select picks the best template for a scope specification.
	// Core selection algorithm:
	//   1. Determine candidate IDs from candidates (restricted => only those IDs,
	//      unrestricted => every registered template is eligible).
	//   2. Filter by scope + security match (Scope, SecuriyProperties, PrimitiveSpecificProperties, additional properties).
	//   3. Return first matching active template, or CodeTemplateNotFound.
	Select(ctx context.Context, scopeSpec *core.ScopeSpecification,
		candidates CandidateSet) (*Template, error)

	// NOTE: LoadStandardCatalog is intentionally NOT part of this interface.
	// It is a startup/configuration concern implemented as a package-level function
	// in the template package: template.LoadStandardCatalog(path string, r Registry) error
}

// RegistryFactory builds the algorithm-template registry for one request.
type RegistryFactory func(ctx context.Context) (Registry, error)
