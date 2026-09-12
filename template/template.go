package template

import (
	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	"google.golang.org/protobuf/proto"
)

// Template is the domain representation of an algorithm template.
// Templates are loaded from JSON/YAML at startup and are never written to
// persistent storage. They define which algorithms are available, their
// security properties, and scope-based selection criteria.
type Template struct {
	stored *api.TemplateInfo
}

// NewTemplate wraps a TemplateInfo proto into a Template domain object.
func NewTemplate(stored *api.TemplateInfo) *Template {
	if stored == nil {
		stored = &api.TemplateInfo{}
	}
	return &Template{stored: stored}
}

// Proto returns the embedded TemplateInfo proto.
// NOTE: Template wraps an API-surface proto (caas.crypto.v1), not a storage proto.
// This is a pragmatic trade-off to avoid duplicating TemplateInfo's deeply nested
// algorithm types — see doc.go for rationale.
func (t *Template) Proto() *api.TemplateInfo { return t.stored }

// TemplateID returns the unique template identifier.
func (t *Template) TemplateID() string { return t.stored.GetTemplateId() }

// GetDisplayName returns the human-readable display name.
func (t *Template) GetDisplayName() string { return t.stored.GetDisplayName() }

// GetStatus returns the template lifecycle status.
func (t *Template) GetStatus() api.TemplateStatus { return t.stored.GetStatus() }

// GetAlgorithm returns the algorithm details.
func (t *Template) GetAlgorithm() *api.AlgorithmDetails { return t.stored.GetAlgorithm() }

// GetScopedCapabilities returns the scope-bundled capabilities.
func (t *Template) GetScopedCapabilities() []*api.ScopedCapabilities {
	return t.stored.GetScopedCapabilities()
}

// Clone returns a deep copy of the Template.
func (t *Template) Clone() *Template {
	return &Template{stored: proto.Clone(t.stored).(*api.TemplateInfo)}
}
