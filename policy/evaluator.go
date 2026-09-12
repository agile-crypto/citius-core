package policy

import core "github.com/agile-crypto/citius-core"

// RulesEvaluator is the strategy interface for interpreting rules_json.
// Different implementations handle different policy schemas or engines.
//
// All methods take the raw rules_json bytes (from StoredPolicy.rules_json)
// and evaluate against domain types. No proto imports allowed.
//
// Implementations:
//   - NoopRulesEvaluator — allows everything
//   - SimpleRulesEvaluator — JSON schema v1
//   - Future: OPA, Cedar, or v2 schema evaluators
type RulesEvaluator interface {
	// Validate checks that rulesJSON is well-formed and all values are known
	// domain constants. Called during CreatePolicy/UpdatePolicy to fail at write time.
	Validate(rulesJSON []byte) error

	// AllowsOperation checks if the given operation is permitted by the rules.
	// Deny-by-default: absent section returns (false, nil).
	// Returns (true, nil) if explicitly allowed, (false, nil) if denied, or (false, err) on parse error.
	AllowsOperation(rulesJSON []byte, op core.Operation) (bool, error)

	// AllowsTemplate checks if the given template ID is permitted by the rules.
	// Deny-by-default: absent section returns (false, nil).
	// Returns (true, nil) if explicitly allowed, (false, nil) if denied, or (false, err) on parse error.
	AllowsTemplate(rulesJSON []byte, templateID string) (bool, error)

	// MeetsSecurityRequirements checks template security properties against
	// the rules' security floor (fips_approved, block_deprecated, etc.).
	// Returns nil if requirements are met, or a descriptive error if not.
	MeetsSecurityRequirements(rulesJSON []byte, info TemplateSecurityInfo) error

	// AllowedTemplateIDs returns the template IDs explicitly permitted by the rules.
	// Deny-by-default: absent section returns an empty non-nil slice (nothing allowed).
	// Returns a non-empty slice if the rules explicitly list allowed templates.
	AllowedTemplateIDs(rulesJSON []byte) ([]string, error)
}

// TemplateSecurityInfo carries template metadata needed for policy security
// evaluation. This is the cross-aggregate data transfer type that avoids
// importing the template package (which would create an import cycle).
//
// The caller (Enforcer, or the orchestrator above it) constructs this from
// the template. The policy package is dependency-free from template internals.
type TemplateSecurityInfo struct {
	TemplateID           string
	SecurityStrengthBits uint32
	FIPSApproved         bool
	QuantumSafe          bool
	NistStatus           string // "approved", "recommended", "acceptable", "deprecated", "forbidden"
	TemplateStatus       string // "active", "acceptable", "deprecated", "forbidden", "experimental"
}

// ---------------------------------------------------------------------------
// NoopRulesEvaluator — allows everything. Used as default.
// ---------------------------------------------------------------------------

// NoopRulesEvaluator is a RulesEvaluator that imposes no restrictions.
// It validates that rulesJSON is valid JSON (or empty) but allows all operations.
type NoopRulesEvaluator struct{}

// NewNoopEvaluator returns a NoopRulesEvaluator.
func NewNoopEvaluator() *NoopRulesEvaluator { return &NoopRulesEvaluator{} }

func (*NoopRulesEvaluator) Validate([]byte) error                                        { return nil }
func (*NoopRulesEvaluator) AllowsOperation([]byte, core.Operation) (bool, error)         { return true, nil }
func (*NoopRulesEvaluator) AllowsTemplate([]byte, string) (bool, error)                  { return true, nil }
func (*NoopRulesEvaluator) MeetsSecurityRequirements([]byte, TemplateSecurityInfo) error { return nil }
func (*NoopRulesEvaluator) AllowedTemplateIDs([]byte) ([]string, error)                  { return nil, nil }

var _ RulesEvaluator = (*NoopRulesEvaluator)(nil)
