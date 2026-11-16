package template

import (
	"context"
	"sync"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/storage"
	"google.golang.org/protobuf/proto"
)

const templateStoragePrefix = "template/"

var _ Registry = (*VaultRegistry)(nil)

// VaultRegistry is a Vault-backed implementation of the Registry interface.
// Uses storage.Storage (typically storage.InmemStorage) with proto serialization,
// following the same pattern as StorageRepository in key, policy, and provider.
type VaultRegistry struct {
	mu        *sync.RWMutex
	templates storage.Storage
}

// NewVaultRegistry creates a VaultRegistry backed by the given storage.
// For in-memory usage, pass &storage.InmemStorage{}.
func NewVaultRegistry(ctx context.Context, store storage.Storage, opt ...Option) (*VaultRegistry, error) {
	const op errors.Op = "template.NewVaultRegistry"
	if store == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := GetVaultOptions(opt...)
	return &VaultRegistry{
		mu:        opts.Lock,
		templates: storage.NewView(store, templateStoragePrefix),
	}, nil
}

// Register stores a template. If a template with the same ID already exists,
// it is overwritten (permits startup re-loading).
func (r *VaultRegistry) Register(ctx context.Context, t *Template) error {
	const op errors.Op = "template.(VaultRegistry).Register"
	if t == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template must not be nil")
	}
	if t.TemplateID() == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template ID must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(t.Proto())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &storage.Entry{Key: t.TemplateID(), Value: b}
	if err := r.templates.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Get returns the template with the given ID, or a CodeTemplateNotFound error.
// Returns an independent copy via proto round-trip (marshal on Register, unmarshal on Get).
func (r *VaultRegistry) Get(ctx context.Context, templateID string) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Get"
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, err := r.templates.Get(ctx, templateID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
			"template not found: "+templateID)
	}
	stored := &api.TemplateInfo{}
	if err := proto.Unmarshal(entry.Value, stored); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewTemplate(stored), nil
}

// List returns all registered templates.
func (r *VaultRegistry) List(ctx context.Context) []*Template {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.templates.List(ctx, "")
	if err != nil {
		return []*Template{}
	}
	out := make([]*Template, 0, len(ids))
	for _, id := range ids {
		entry, err := r.templates.Get(ctx, id)
		if err != nil || entry == nil {
			continue
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			continue
		}
		out = append(out, NewTemplate(stored))
	}
	return out
}

// Get all the templates with the given IDs, applying the filter function to each.
// Returns a slice of matching templates, or an error if any filterFn call fails.
// If a template ID is not found, it is skipped (not an error).
func (r *VaultRegistry) selectTemplatesWithIDs(ctx context.Context, ids []string, filterFn func(t *Template) (bool, error)) ([]*Template, error) {
	const op = "template.(VaultRegistry).getAllTemplatesWithIDs"
	candidates := []*Template{}
	for _, id := range ids {
		entry, err := r.templates.Get(ctx, id)
		if err != nil || entry == nil {
			continue
		}
		stored := &api.TemplateInfo{}
		if err = proto.Unmarshal(entry.Value, stored); err != nil {
			continue
		}
		t := NewTemplate(stored)
		ok, err := filterFn(t)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if ok {
			candidates = append(candidates, t)
		}
	}
	return candidates, nil
}

// Select returns the best-matching template for the given request.
// The selection algorithm:
//  1. If candidates is restricted to one entry and scope is zero,
//     treat it as a direct lookup (fast path for template_id=explicit case).
//  2. Determine the candidate ID set: when candidates is restricted,
//     only those IDs are deserialized; when unrestricted, all stored IDs
//     are loaded (avoids deserializing templates the policy already excludes).
//  3. Deserialize each candidate and apply scope + security filters.
//  4. Return first matching candidate, or CodeTemplateNotFound.
//
// Security filtering (fips_approved, quantum_safe) is part of scope matching:
// the caller's ScopeSpecification carries typed security filter fields, matched against
// each template's ScopedCapabilities[].Scope.security (UniversalSecurityProperties).
//
// NOTE: Select accesses r.templates (storage.Storage) directly using readlock rather than
// calling r.Get()/r.List(), because those methods also acquire r.mu.RLock()
// and Go's sync.RWMutex is NOT reentrant.
// TODO: Optimize with caching instead of full storage scan with serialization and deserialization
func (r *VaultRegistry) Select(ctx context.Context, scopeSpec *core.ScopeSpecification, cs CandidateSet) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Select"
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Fast path: explicit template ID lookup (single restricted ID, no scope/security filters)
	if cs.IsRestricted() && len(cs.IDs()) == 1 && scopeSpec == nil {
		entry, err := r.templates.Get(ctx, cs.IDs()[0])
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if entry == nil {
			return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
				"template not found: "+cs.IDs()[0])
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return NewTemplate(stored), nil
	}

	// Step 1: determine the candidate ID set.
	// When the caller restricts to specific IDs, only those are eligible
	// (no point deserializing templates we already know the policy excludes).
	// When unrestricted, every stored template is a candidate.
	var ids []string
	if cs.IsRestricted() {
		ids = cs.IDs()
	} else {
		var err error
		ids, err = r.templates.List(ctx, "")
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}

	// Step 2: deserialize each candidate and apply scope + security filter.
	filterFn := func(t *Template) (bool, error) {
		ok, err := MatchesScope(ctx, t, scopeSpec)
		if err != nil {
			return false, errors.Wrap(ctx, op, err)
		}
		return ok, nil
	}
	candidates, err := r.selectTemplatesWithIDs(ctx, ids, filterFn)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	if len(candidates) == 0 {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
			"no template matches the selection criteria")
	}

	// Step 3: return first candidate (deterministic — storage/candidates iteration order)
	return candidates[0].Clone(), nil
}
