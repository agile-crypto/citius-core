package policy

import (
	"bytes"
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
	ProviderRequirements   *ProviderRequirementRule `json:"provider_requirements,omitempty"`
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

// ProviderRequirementRule sets the provider properties every key under the
// policy requires, whenever a key version is placed on a provider: at
// CreateKey, TransformKey and MigrateKey. It is a constraint, not an
// allowlist: absent means no requirement. A request may add requirements but
// cannot relax these. Field meanings follow core.ProviderRequirements;
// min_fips_level is a level from 1 to 4. The section holds requirements
// only: a preference such as prefer_hardware_accelerated belongs on the
// request. approved_generation requires every version's material to have
// been generated in, and only ever held by, FIPS 140 validated modules; it
// exists only here, because a lineage constraint must outlive creation.
type ProviderRequirementRule struct {
	FIPS140Certified        bool   `json:"fips_140_certified,omitempty"`
	MinFIPS140Level         uint32 `json:"min_fips_level,omitempty"`
	CommonCriteriaCertified bool   `json:"common_criteria_certified,omitempty"`
	FormallyVerified        bool   `json:"formally_verified,omitempty"`
	MemorySafe              bool   `json:"memory_safe,omitempty"`
	ConstantTime            bool   `json:"constant_time,omitempty"`
	SideChannelHardened     bool   `json:"side_channel_hardened,omitempty"`
	NoKnownCVE              bool   `json:"no_known_cve,omitempty"`
	ApprovedGeneration      bool   `json:"approved_generation,omitempty"`
}

// Requirements returns the rule as core.ProviderRequirements. A nil rule
// requires nothing.
func (r *ProviderRequirementRule) Requirements() core.ProviderRequirements {
	if r == nil {
		return core.ProviderRequirements{}
	}
	return core.ProviderRequirements{
		FIPS140Certified:        r.FIPS140Certified,
		MinFIPS140Level:         r.MinFIPS140Level,
		CommonCriteriaCertified: r.CommonCriteriaCertified,
		FormallyVerified:        r.FormallyVerified,
		MemorySafe:              r.MemorySafe,
		ConstantTime:            r.ConstantTime,
		SideChannelHardened:     r.SideChannelHardened,
		NoKnownCVE:              r.NoKnownCVE,
		ApprovedGeneration:      r.ApprovedGeneration,
	}
}

// --- TODO: sub-types (parsed, not validated or evaluated for now) ---

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
// Unknown fields, at any depth, are an error: a misspelt section or rule
// would otherwise be silently unenforced.
func ParseRules(raw []byte) (*Rules, error) {
	if len(raw) == 0 {
		return &Rules{}, nil
	}
	rules := &Rules{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(rules); err != nil {
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
// security_requirements (bool fields — no string validation needed),
// provider_requirements.min_fips_level (a level from 1 to 4).
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

	// --- provider_requirements ---
	if pr := r.ProviderRequirements; pr != nil && pr.MinFIPS140Level > core.MaxFIPS140Level {
		return fmt.Errorf("provider_requirements.min_fips_level: %d is not a level from 1 to %d",
			pr.MinFIPS140Level, core.MaxFIPS140Level)
	}

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
		r.SecurityRequirements != nil ||
		r.ProviderRequirements != nil
}
