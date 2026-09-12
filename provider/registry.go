package provider

import (
	"context"
	"sync"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
)

// Requirements narrows a Match call to a template, optionally a specific
// pinned provider, and optionally required security properties.
//
// There is deliberately no Capability field: app.ValidateProviderCapabilities
// (internal/app/validate.go) already makes "provider P advertises template T
// but cannot serve it" impossible to register, so re-filtering by capability
// per request would be dead code dressed as a safety net.
type Requirements struct {
	TemplateID   string
	ProviderName string
	Security     *core.SecurityProperties
}

// Registry manages the set of available Backend implementations.
type Registry interface {
	Register(ctx context.Context, p Backend) error
	Get(ctx context.Context, name string) (Backend, error)
	GetDefault(ctx context.Context) (Backend, error)
	List(ctx context.Context) []Backend
	Remove(ctx context.Context, name string) error
	Match(ctx context.Context, req Requirements) (Backend, error)
}

// RegistryFactory resolves the registry of crypto providers for one request.
//
// The registry is never remoted: it stays local and holds a mix of local and
// remote Backend values. So this factory normally returns a registry built once
// at startup; it is fallible and per-request only so that the read-only
// provider RPCs have the same shape as every other capability.
type RegistryFactory func(ctx context.Context) (Registry, error)

// registry is a thread-safe in-memory registry of provider backends.
type registry struct {
	mu        sync.RWMutex
	providers map[string]Backend
	order     []string // insertion-order for GetDefault fallback

	// byTemplate indexes provider names by the template IDs they advertise
	// via AlgorithmCapabilityProvider.SupportedAlgorithms(), built once at
	// Register time and kept in sync by Remove. Each slice is
	// insertion-ordered, same as order, so Match's template-only "first
	// match wins" behavior is unchanged from the pre-index scan it replaces.
	byTemplate map[string][]string
}

// NewRegistry creates an empty registry.
func NewRegistry() Registry {
	return &registry{
		providers:  make(map[string]Backend),
		byTemplate: make(map[string][]string),
	}
}

func (r *registry) Register(ctx context.Context, p Backend) error {
	const op errors.Op = "provider.(registry).Register"
	if p == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "provider must not be nil")
	}
	name := p.Name()
	if name == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "provider name must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[name]; exists {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "provider already registered: "+name)
	}
	r.providers[name] = p
	r.order = append(r.order, name)
	if sp, ok := p.(interface{ SupportedAlgorithms() []string }); ok {
		for _, alg := range sp.SupportedAlgorithms() {
			r.byTemplate[alg] = append(r.byTemplate[alg], name)
		}
	}
	return nil
}

func (r *registry) Get(ctx context.Context, name string) (Backend, error) {
	const op errors.Op = "provider.(registry).Get"
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "provider not found: "+name)
	}
	return p, nil
}

func (r *registry) GetDefault(ctx context.Context) (Backend, error) {
	const op errors.Op = "provider.(registry).GetDefault"
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.order) == 0 {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "no providers registered")
	}
	// For now, return the first registered provider.
	// TODO: add IsDefault support via provider metadata.
	// Fallback: first registered provider.
	return r.providers[r.order[0]], nil
}

func (r *registry) List(ctx context.Context) []Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Backend, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.providers[name])
	}
	return out
}

func (r *registry) Remove(ctx context.Context, name string) error {
	const op errors.Op = "provider.(registry).Remove"
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[name]
	if !ok {
		return errors.New(ctx, op, errors.CodeProviderNotFound, "provider not found: "+name)
	}
	delete(r.providers, name)
	// Remove from order slice
	for i, n := range r.order {
		if n == name {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	// Evict name from every template entry it was indexed under.
	if sp, ok := p.(interface{ SupportedAlgorithms() []string }); ok {
		for _, alg := range sp.SupportedAlgorithms() {
			names := r.byTemplate[alg]
			for i, n := range names {
				if n == name {
					names = append(names[:i], names[i+1:]...)
					break
				}
			}
			if len(names) == 0 {
				delete(r.byTemplate, alg)
			} else {
				r.byTemplate[alg] = names
			}
		}
	}
	return nil
}

// Match resolves the Backend that should serve req.
//
// If req.ProviderName is set, that exact provider is used: verified to
// advertise req.TemplateID and satisfy req.Security's hard filter, but never
// silently substituted for another provider if it does not. A caller that
// pinned a provider gets that provider or an error, not a surprise fallback.
//
// Otherwise, with req.Security nil (the template-only case —
// Requirements{TemplateID: id} with nothing else set), the first provider
// registered under req.TemplateID wins outright, matching the original
// first-match scan this replaced: no ranking happens on properties nobody
// asked about.
//
// With req.Security non-nil, every provider indexed under req.TemplateID is
// scored against it (see score in match.go) instead: a provider that fails
// the hard filter is excluded, and the highest-scoring survivor wins. Ties
// are broken by registration order — names is byTemplate's insertion-ordered
// slice, and only a strictly-greater score replaces the current best, so
// among equal scores the first-registered provider wins here too.
func (r *registry) Match(ctx context.Context, req Requirements) (Backend, error) {
	const op errors.Op = "provider.(Registry).Match"
	r.mu.RLock()
	defer r.mu.RUnlock()

	if req.ProviderName != "" {
		p, ok := r.providers[req.ProviderName]
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeProviderNotFound,
				"provider not found: "+req.ProviderName)
		}
		if !advertisesTemplate(p, req.TemplateID) {
			return nil, errors.New(ctx, op, errors.CodeProviderNotFound,
				"provider "+req.ProviderName+" does not support template: "+req.TemplateID)
		}
		if _, ok := scoreProvider(p, req.Security); !ok {
			return nil, errors.New(ctx, op, errors.CodeFailedPrecondition,
				"provider "+req.ProviderName+" does not satisfy required security properties")
		}
		return p, nil
	}

	if len(r.order) == 0 {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "no providers registered")
	}

	names := r.byTemplate[req.TemplateID]
	if len(names) == 0 {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound,
			"no provider supports template: "+req.TemplateID)
	}

	if req.Security == nil {
		return r.providers[names[0]], nil
	}

	best := ""
	bestScore := -1
	for _, name := range names {
		s, ok := scoreProvider(r.providers[name], req.Security)
		if !ok {
			continue
		}
		if s > bestScore {
			bestScore = s
			best = name
		}
	}
	if best == "" {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound,
			"no provider satisfies required security properties for template: "+req.TemplateID)
	}
	return r.providers[best], nil
}

// advertisesTemplate reports whether p declares templateID via
// AlgorithmCapabilityProvider.SupportedAlgorithms(). Same anonymous
// interface style as Register/Remove use to build byTemplate.
func advertisesTemplate(p Backend, templateID string) bool {
	sp, ok := p.(interface{ SupportedAlgorithms() []string })
	if !ok {
		return false
	}
	for _, alg := range sp.SupportedAlgorithms() {
		if alg == templateID {
			return true
		}
	}
	return false
}

// compile-time check
var _ Registry = (*registry)(nil)
