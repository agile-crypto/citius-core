package policy

import "context"

// Repository defines the persistence contract for the Policy aggregate.
type Repository interface {
	PutPolicy(ctx context.Context, p *Policy) error
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	DeletePolicy(ctx context.Context, name string) error
	// ListPolicies returns the names of all stored policies, including those whose
	// name is a hierarchical path.
	ListPolicies(ctx context.Context) ([]string, error)
	// ListPoliciesWithPrefix returns the names of all stored policies located under the
	// folder named by prefix, at any depth. The prefix must be a complete folder path
	// ("test" or "test/namespace1"; a trailing separator is optional): partial folder names
	// such as "tes" match nothing. An empty prefix returns all policies, like ListPolicies.
	ListPoliciesWithPrefix(ctx context.Context, prefix string) ([]string, error)
}
