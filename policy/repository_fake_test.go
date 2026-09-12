package policy_test

import (
	"context"
	"sync"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
)

// fakeRepository is an in-memory policy.Repository for tests in this package.
// core/policy cannot depend on the Vault-backed implementation — that lives in
// internal/policy, a separate module that itself depends on core/policy.
type fakeRepository struct {
	mu       sync.RWMutex
	policies map[string]*policy.Policy
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{policies: make(map[string]*policy.Policy)}
}

var _ policy.Repository = (*fakeRepository)(nil)

func (r *fakeRepository) PutPolicy(ctx context.Context, p *policy.Policy) error {
	if p == nil {
		return errors.New(ctx, "fakeRepository.PutPolicy", errors.CodeInvalidArgument, "policy must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[p.Name()] = p.Clone()
	return nil
}

func (r *fakeRepository) GetPolicy(ctx context.Context, name string) (*policy.Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.policies[name]
	if !ok {
		return nil, errors.New(ctx, "fakeRepository.GetPolicy", errors.CodePolicyNotFound, "policy not found: "+name)
	}
	return p.Clone(), nil
}

func (r *fakeRepository) DeletePolicy(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.policies[name]; !ok {
		return errors.New(ctx, "fakeRepository.DeletePolicy", errors.CodePolicyNotFound, "policy not found: "+name)
	}
	delete(r.policies, name)
	return nil
}

func (r *fakeRepository) ListPolicies(ctx context.Context) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.policies))
	for name := range r.policies {
		names = append(names, name)
	}
	return names, nil
}
