package policy

import (
	"encoding/json"
	"fmt"

	core "github.com/agile-crypto/citius-core"
)

// Rules is the parsed representation of StoredPolicy.rules_json.
// Zero proto imports — all fields use the same string vocabulary as core.*.
type Rules struct {
	Version                string                   `json:"version"`
	AllowedTemplates       []string                 `json:"allowed_templates,omitempty"`
	AllowedScopes          []ScopeRule              `json:"allowed_scopes,omitempty"`    // TODO parsed but not validated/evaluated
	AllowedProviders       *ProviderRule            `json:"allowed_providers,omitempty"` // TODO
	AllowedOperations      *OperationRule           `json:"allowed_operations,omitempty"`
	KeyConfiguration       *KeyConfigRule           `json:"key_configuration,omitempty"`       // TODO
	AllowedTransformations *TransformationRule      `json:"allowed_transformations,omitempty"` // TODO
	AllowedMigrations      *MigrationRule           `json:"allowed_migrations,omitempty"`      // TODO
	SecurityRequirements   *SecurityRequirementRule `json:"security_requirements,omitempty"`
}

// --- sub-types (validated + evaluated) ---

// OperationRule restricts which operations a policy permits.
type OperationRule struct {
	KeyOperations     []string `json:"key_operations,omitempty"`
	KeylessOperations []string `json:"keyless_operations,omitempty"` // TODO — parsed but not validated
}

// SecurityRequirementRule sets a security floor for templates.
type SecurityRequirementRule struct {
	MinSecurityStrengthBits *uint32 `json:"min_security_strength_bits,omitempty"` // TODO
	FIPSApproved            *bool   `json:"fips_approved,omitempty"`
	QuantumSafe             *bool   `json:"quantum_safe,omitempty"`    // TODO
	MinNistStatus           *string `json:"min_nist_status,omitempty"` // TODO
	BlockDeprecated         *bool   `json:"block_deprecated,omitempty"`
}

// --- TODO: sub-types (parsed for forward compat, not validated for now) ---

// ScopeRule restricts operations to specific primitives/scopes.
type ScopeRule struct {
	Primitive string   `json:"primitive"`
	Scopes    []string `json:"scopes,omitempty"`
}

// ProviderRule restricts which provider instances/types are permitted.
type ProviderRule struct {
	InstanceIDs []string `json:"instance_ids,omitempty"`
	Types       []string `json:"types,omitempty"`
}

// KeyConfigRule restricts key properties.
type KeyConfigRule struct {
	Extractable     *bool    `json:"extractable,omitempty"`
	RotationAllowed *bool    `json:"rotation_allowed,omitempty"`
	AllowedKeyOps   []string `json:"allowed_key_operations,omitempty"`
	MinKeySizeBits  *uint32  `json:"min_key_size_bits,omitempty"`
	MaxKeyLifetime  *string  `json:"max_key_lifetime,omitempty"`
}

// TransformationRule controls key transformation permissions.
type TransformationRule struct {
	Enabled                bool     `json:"enabled"`
	AllowRetainBytes       *bool    `json:"allow_retain_bytes,omitempty"`
	ScopeRule              string   `json:"scope_rule,omitempty"`
	AllowedTargetTemplates []string `json:"allowed_target_templates,omitempty"`
}

// MigrationRule controls key migration permissions.
type MigrationRule struct {
	Enabled                bool     `json:"enabled"`
	AllowedStrategies      []string `json:"allowed_strategies,omitempty"`
	AllowedTargetTypes     []string `json:"allowed_target_types,omitempty"`
	AllowedTargetInstances []string `json:"allowed_target_instances,omitempty"`
	AllowAlgorithmChange   *bool    `json:"allow_algorithm_change,omitempty"`
}

// ---------------------------------------------------------------------------
// ParseRules
// ---------------------------------------------------------------------------

// ParseRules deserializes raw JSON bytes into a Rules struct.
// nil or empty bytes return an empty Rules (all sections nil).
// Unknown JSON fields are silently ignored (forward compatibility).
func ParseRules(raw []byte) (*Rules, error) {
	if len(raw) == 0 {
		return &Rules{}, nil
	}
	rules := &Rules{}
	if err := json.Unmarshal(raw, rules); err != nil {
		return nil, fmt.Errorf("parse rules_json: %w", err)
	}
	return rules, nil
}

// ---------------------------------------------------------------------------
// Validate (subset)
// ---------------------------------------------------------------------------

// knownKeyOperations is the set of valid key-bound operation strings.
// These are the exact same string values as core.Operation constants.
var knownKeyOperations = map[string]bool{
	string(core.OperationCreateKey):    true,
	string(core.OperationReadKey):      true,
	string(core.OperationDeleteKey):    true,
	string(core.OperationSign):         true,
	string(core.OperationVerify):       true,
	string(core.OperationDigestSign):   true,
	string(core.OperationDigestVerify): true,
	string(core.OperationEncrypt):      true,
	string(core.OperationDecrypt):      true,
	string(core.OperationWrap):         true,
	string(core.OperationUnwrap):       true,
	string(core.OperationDeriveKey):    true,
	string(core.OperationRotateKey):    true,
}

// supportedVersions lists the schema versions this code understands.
var supportedVersions = map[string]bool{
	"1": true,
}

// Validate checks that field values are known domain constants.
// This is called at policy write time (VetForWrite path) to enforce
// "fail at creation time, not evaluation time".
//
// validates: version, allowed_templates (non-empty strings),
// allowed_operations.key_operations (known operations),
// security_requirements (bool fields — no string validation needed).
//
// TODO sections are silently skipped (no validation).
func (r *Rules) Validate() error {
	// --- Version ---
	if r.hasAnySections() && r.Version == "" {
		return fmt.Errorf("version is required when policy has rule sections")
	}
	if r.Version != "" && !supportedVersions[r.Version] {
		return fmt.Errorf("unsupported policy version %q (supported: 1)", r.Version)
	}

	// --- allowed_templates ---
	for i, tid := range r.AllowedTemplates {
		if tid == "" {
			return fmt.Errorf("allowed_templates[%d]: template ID must not be empty", i)
		}
		// Template IDs are free-form strings (e.g., "ecdsa-p256-sha256").
		// No registry lookup here — validation only checks non-empty.
	}

	// --- allowed_operations.key_operations ---
	if r.AllowedOperations != nil {
		for i, op := range r.AllowedOperations.KeyOperations {
			if !knownKeyOperations[op] {
				return fmt.Errorf("allowed_operations.key_operations[%d]: unknown operation %q", i, op)
			}
		}
	}

	// --- security_requirements ---
	// Bool fields (*bool) need no string validation. Presence implies the constraint.
	// MinNistStatus and MinSecurityStrengthBits are TODO — skip validation.

	return nil
}

// hasAnySections reports whether any rule section is non-nil/non-empty.
func (r *Rules) hasAnySections() bool {
	return len(r.AllowedTemplates) > 0 ||
		len(r.AllowedScopes) > 0 ||
		r.AllowedProviders != nil ||
		r.AllowedOperations != nil ||
		r.KeyConfiguration != nil ||
		r.AllowedTransformations != nil ||
		r.AllowedMigrations != nil ||
		r.SecurityRequirements != nil
}
