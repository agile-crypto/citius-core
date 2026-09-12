package policy

import "context"

// Repository defines the persistence contract for the Policy aggregate.
type Repository interface {
	PutPolicy(ctx context.Context, p *Policy) error
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]string, error)
}
