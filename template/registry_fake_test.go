package template_test

import (
	"context"
	"sync"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
)

// fakeRegistry is an in-memory template.Registry for tests in this package.
// core/template cannot depend on the Vault-backed implementation — that lives
// in internal/template, a separate module that itself depends on core/template.
type fakeRegistry struct {
	mu        sync.RWMutex
	templates map[string]*template.Template
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{templates: make(map[string]*template.Template)}
}

var _ template.Registry = (*fakeRegistry)(nil)

func (r *fakeRegistry) Register(ctx context.Context, t *template.Template) error {
	const op errors.Op = "fakeRegistry.Register"
	if t == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template must not be nil")
	}
	if t.TemplateID() == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template ID must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.templates[t.TemplateID()] = t
	return nil
}

func (r *fakeRegistry) Get(ctx context.Context, templateID string) (*template.Template, error) {
	const op errors.Op = "fakeRegistry.Get"
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.templates[templateID]
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound, "template not found: "+templateID)
	}
	return t, nil
}

func (r *fakeRegistry) List(ctx context.Context) []*template.Template {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*template.Template, 0, len(r.templates))
	for _, t := range r.templates {
		out = append(out, t)
	}
	return out
}

func (r *fakeRegistry) Select(ctx context.Context, scopeSpec *core.ScopeSpecification, cs template.CandidateSet) (*template.Template, error) {
	const op errors.Op = "fakeRegistry.Select"
	r.mu.RLock()
	defer r.mu.RUnlock()

	var ids []string
	if cs.IsRestricted() {
		ids = cs.IDs()
	} else {
		for id := range r.templates {
			ids = append(ids, id)
		}
	}

	for _, id := range ids {
		t, ok := r.templates[id]
		if !ok {
			continue
		}
		ok, err := template.MatchesScope(ctx, t, scopeSpec)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if ok {
			return t, nil
		}
	}
	return nil, errors.New(ctx, op, errors.CodeTemplateNotFound, "no template matches the selection criteria")
}
