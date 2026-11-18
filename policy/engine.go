package policy

import (
	"context"

	core "github.com/agile-crypto/citius-core"
)

// Evaluator validates operations and key creation against stored policies.
// This is the interface that service/key.Orchestrator and service/crypto.Orchestrator should depend on.
// Denial IS the error — methods return nil on allow, typed error on deny.
type Evaluator interface {
	// ValidateOperation checks whether a crypto operation is allowed under the named policy.
	// Use ValidateKeyCreation for pre-checking CreateKey operations with client-supplied specifications.
	// Returns nil if allowed; returns a typed error (with denial reason) if denied.
	ValidateOperation(ctx context.Context, policyName string,
		operation core.Operation, templateID string, providerID string) error

	// ValidateKeyCreation checks whether a key may be created with the given spec.
	ValidateKeyCreation(ctx context.Context, policyName string, spec *core.KeyCreationSpec) error

	// AllowedTemplates returns the template IDs permitted for the given scope by the named policy.
	// Deny-by-default: absent section returns an empty non-nil slice (nothing allowed).
	// Returns nil only when policyName is empty (bypass).
	AllowedTemplates(ctx context.Context, policyName string, scopeSpec *core.ScopeSpecification) ([]string, error)

	// ProviderRequirements returns the provider requirements the named policy
	// places on every key under it: the provider instance holding a key
	// version must meet them when the version is created, transformed or
	// migrated. A policy without the section, and an empty policyName
	// (bypass), require nothing.
	ProviderRequirements(ctx context.Context, policyName string) (core.ProviderRequirements, error)
}

// EvaluatorFactory builds only the evaluation half of the engine.
//
// A data-plane node needs "may I do this?" and must not receive the
// administrative half; keeping the narrower factory available means that
// separation can be expressed in the wiring rather than only in authorization.
type EvaluatorFactory func(ctx context.Context) (Evaluator, error)

// Manager handles policy CRUD lifecycle.
// This is the interface that the policy gRPC handler should depend on.
type Manager interface {
	CreatePolicy(ctx context.Context, p *Policy) (*Policy, error)
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	// UpdatePolicy replaces the stored policy named p.Name() and returns it
	// as stored. A positive expectedVersion makes the update conditional: it
	// fails with CodeFailedPrecondition unless the stored version equals it.
	// Zero means last-writer-wins.
	//
	// The condition is best effort, not atomic: Enforcer reads the stored
	// version and writes the new policy in two Repository calls, so two
	// concurrent updates with the same expectedVersion can both pass the
	// check, and the later write wins with the same new version number.
	// Closing the window needs a compare-and-put on Repository.
	UpdatePolicy(ctx context.Context, p *Policy, expectedVersion int64) (*Policy, error)
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]*Policy, error)
}

// Engine is the full policy interface. Enforcer implements this.
// Consumers should prefer the narrow interface they actually need:
//   - key.Orchestrator/crypto.Orchestrator => Evaluator
//   - Policy gRPC handler => Manager (and optionally Evaluator for EvaluatePolicy)
type Engine interface {
	Evaluator
	Manager
}

// EngineFactory builds the policy engine, and the repository behind it, for one
// request.
//
// The factory takes no backend handle: it is a closure that has already
// captured whatever it needs — a Vault request's storage, a SQL pool created at
// startup, or a gRPC connection to a remote policy service. That is what lets a
// transport accept a policy engine without knowing which deployment it is in.
//
// An implementation may return a freshly built engine per call or the same
// engine every time, provided what it returns is safe for concurrent use. Vault
// binds per request because the storage does; a SQL or embedded deployment
// wires once at setup and returns the memoised value, which keeps the local
// hot path allocation-free.
//
// Callers must not cache what a factory returns across requests.
type EngineFactory func(ctx context.Context) (Engine, error)
