package policy

import (
	"context"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
)

// Enforcer implements policy.Engine.
// It stores and retrieves policies from the provided Repository, and evaluates
// operations against those policies via a pluggable RulesEvaluator strategy.
type Enforcer struct {
	store     Repository
	evaluator RulesEvaluator
}

// NewEnforcer creates an Enforcer backed by the given Repository and
// RulesEvaluator strategy. Both parameters are required.
func NewEnforcer(s Repository, eval RulesEvaluator) (*Enforcer, error) {
	const op errors.Op = "policy.NewEnforcer"
	if s == nil {
		return nil, errors.New(context.Background(), op, errors.CodeInvalidArgument,
			"repository must not be nil")
	}
	if eval == nil {
		return nil, errors.New(context.Background(), op, errors.CodeInvalidArgument,
			"rules evaluator must not be nil")
	}
	return &Enforcer{store: s, evaluator: eval}, nil
}

// ---- Policy CRUD ----

func (r *Enforcer) CreatePolicy(ctx context.Context, p *Policy) (*Policy, error) {
	const op errors.Op = "policy.(Enforcer).CreatePolicy"
	if p == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	if err := p.VetForWrite(ctx, core.OpCreate); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	// Validate rules_json via evaluator
	if err := r.evaluator.Validate(p.RulesJSON()); err != nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"invalid rules_json: "+err.Error())
	}
	// Check for duplicate
	if _, err := r.store.GetPolicy(ctx, p.Name()); err == nil {
		return nil, errors.New(ctx, op, errors.CodeAlreadyExists,
			"policy already exists: "+p.Name())
	}
	if err := r.store.PutPolicy(ctx, p); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return r.store.GetPolicy(ctx, p.Name())
}

func (r *Enforcer) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	const op errors.Op = "policy.(Enforcer).GetPolicy"
	p, err := r.store.GetPolicy(ctx, name)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return p, nil
}

func (r *Enforcer) UpdatePolicy(ctx context.Context, p *Policy) error {
	const op errors.Op = "policy.(Enforcer).UpdatePolicy"
	if p == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	if err := p.VetForWrite(ctx, core.OpUpdate); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	// Validate rules_json via evaluator
	if err := r.evaluator.Validate(p.RulesJSON()); err != nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"invalid rules_json: "+err.Error())
	}
	// Verify policy exists before update
	if _, err := r.store.GetPolicy(ctx, p.Name()); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := r.store.PutPolicy(ctx, p); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *Enforcer) DeletePolicy(ctx context.Context, name string) error {
	const op errors.Op = "policy.(Enforcer).DeletePolicy"
	if err := r.store.DeletePolicy(ctx, name); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *Enforcer) ListPolicies(ctx context.Context) ([]*Policy, error) {
	const op errors.Op = "policy.(Enforcer).ListPolicies"
	ids, err := r.store.ListPolicies(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	out := make([]*Policy, 0, len(ids))
	for _, id := range ids {
		p, err := r.store.GetPolicy(ctx, id)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ---- Evaluation ----

// ValidateOperation checks whether a crypto operation is permitted by the named policy.
// Empty policyName = bypass (no policy assigned yet). When a policy IS assigned,
// deny-by-default applies: absent sections in rules_json mean deny, not allow.
// Evaluation order: template => operation. MeetsSecurityRequirements is deferred
// to the orchestrator layer which has access to TemplateSecurityInfo.
func (r *Enforcer) ValidateOperation(ctx context.Context, policyName string,
	operation core.Operation, templateID, providerID string) error {
	const op errors.Op = "policy.(Enforcer).ValidateOperation"

	// Empty policy name => bypass (no policy assigned yet)
	if policyName == "" {
		return nil
	}

	p, err := r.store.GetPolicy(ctx, policyName)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	rulesJSON := p.RulesJSON()

	// Check 1: Template allowed?
	if templateID != "" {
		var allowed bool
		allowed, err = r.evaluator.AllowsTemplate(rulesJSON, templateID)
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		if !allowed {
			return errors.New(ctx, op, errors.CodePolicyViolation,
				"template "+templateID+" not permitted by policy "+policyName)
		}
	}

	// Check 2: Operation allowed?
	allowed, err := r.evaluator.AllowsOperation(rulesJSON, operation)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if !allowed {
		return errors.New(ctx, op, errors.CodePolicyViolation,
			"operation "+string(operation)+" not permitted by policy "+policyName)
	}

	// Check 3: MeetsSecurityRequirements — deferred to orchestrator layer.
	// The orchestrator has the Template and can construct TemplateSecurityInfo.

	return nil
}

// ValidateKeyCreation is a stub for the moment — all key creation is allowed.
// TODO: Key creation restrictions (min key size, extractable, rotation) are to be implemented
// (key_configuration section in rules_json).
func (r *Enforcer) ValidateKeyCreation(_ context.Context, _ string, _ *core.KeyCreationSpec) error {
	return nil
}

// AllowedTemplates returns the template IDs the named policy explicitly permits.
// Empty policyName => bypass (nil, nil). Under deny-by-default, a policy with
// absent allowed_templates returns an empty non-nil slice (nothing allowed).
// TODO: The scopeSpec parameter is accepted but ignored for now. Implement later.
func (r *Enforcer) AllowedTemplates(ctx context.Context, policyName string,
	_ *core.ScopeSpecification) ([]string, error) {
	const op errors.Op = "policy.(Enforcer).AllowedTemplates"

	// Empty policy name => bypass (no policy assigned)
	if policyName == "" {
		return nil, nil
	}

	p, err := r.store.GetPolicy(ctx, policyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	ids, err := r.evaluator.AllowedTemplateIDs(p.RulesJSON())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	//TODO: need to filter by scope spec

	return ids, nil
}

// Compile-time assertion - TODO: uncomment when all policy.Engine methods are implemented.
var _ Engine = (*Enforcer)(nil)
