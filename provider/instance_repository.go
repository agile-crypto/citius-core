package provider

import "context"

// InstanceRepository persists and retrieves provider instance records.
// Parameter name is `publicID` - the external-facing identifier for the instance.
type InstanceRepository interface {
	PutProviderInstance(ctx context.Context, instance *Instance) error
	GetProviderInstance(ctx context.Context, publicID string) (*Instance, error)
	DeleteProviderInstance(ctx context.Context, publicID string) error
	ListProviderInstances(ctx context.Context) ([]string, error)
}

// InstanceManager manages the persisted provider instance records.
// Uses publicID consistently (same as InstanceRepository).
type InstanceManager interface {
	Create(ctx context.Context, pi *Instance) (*Instance, error)
	Read(ctx context.Context, publicID string) (*Instance, error)
	List(ctx context.Context) ([]*Instance, error)
	Delete(ctx context.Context, publicID string) error
}

// InstanceManagerFactory builds the manager for configured provider instances
// for one request.
//
// Unlike the registry, provider instances are persisted, so this factory is
// genuinely storage-backed: it closes over a Vault request's storage, a SQL
// pool, or a remote client. See policy.EngineFactory for the memoisation rule.
type InstanceManagerFactory func(ctx context.Context) (InstanceManager, error)
