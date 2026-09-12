package policy

import (
	"fmt"
	"slices"

	core "github.com/agile-crypto/citius-core"
)

// SimpleRulesEvaluator implements RulesEvaluator for JSON schema v1.
// It uses Rules (from rules.go) internally and has no state.
//
// Evaluation rules (deny-by-default):
//   - Absent section (nil) = deny all (nothing explicitly allowed)
//   - Present but empty array/object = deny all
//   - Non-empty array/object = must contain the value (explicit allow)
//   - Comparison is direct string equality (zero conversion)
//
// SecurityRequirements is the exception: absent = no security floor (no
// additional constraints). It is a constraint, not an allowlist.
type SimpleRulesEvaluator struct{}

// NewSimpleRulesEvaluator creates a SimpleRulesEvaluator.
func NewSimpleRulesEvaluator() *SimpleRulesEvaluator { return &SimpleRulesEvaluator{} }

var _ RulesEvaluator = (*SimpleRulesEvaluator)(nil)

// Validate parses rulesJSON and validates field values.
func (e *SimpleRulesEvaluator) Validate(rulesJSON []byte) error {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return err
	}
	return rules.Validate()
}

// AllowsOperation checks if op is in allowed_operations.key_operations.
// Deny-by-default: absent section => deny all. Empty [] => deny all.
func (e *SimpleRulesEvaluator) AllowsOperation(rulesJSON []byte, op core.Operation) (bool, error) {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return false, err
	}
	// No AllowedOperations section => deny (nothing explicitly allowed)
	if rules.AllowedOperations == nil {
		return false, nil
	}
	// KeyOperations is nil => deny (nothing explicitly allowed)
	if rules.AllowedOperations.KeyOperations == nil {
		return false, nil
	}
	// Empty [] => deny all. Non-empty => must contain op.
	return slices.Contains(rules.AllowedOperations.KeyOperations, string(op)), nil
}

// AllowsTemplate checks if templateID is in allowed_templates.
// Deny-by-default: absent (nil) => deny all. Empty [] => deny all.
func (e *SimpleRulesEvaluator) AllowsTemplate(rulesJSON []byte, templateID string) (bool, error) {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return false, err
	}
	// Absent section => deny (nothing explicitly allowed)
	if rules.AllowedTemplates == nil {
		return false, nil
	}
	// Empty [] => deny all. Non-empty => must contain templateID.
	return slices.Contains(rules.AllowedTemplates, templateID), nil
}

// MeetsSecurityRequirements checks the following security floor: fips_approved, block_deprecated.
// Returns nil if met, error if denied.
func (e *SimpleRulesEvaluator) MeetsSecurityRequirements(rulesJSON []byte, info TemplateSecurityInfo) error {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return err
	}
	if rules.SecurityRequirements == nil {
		return nil // no security floor
	}
	sec := rules.SecurityRequirements

	// fips_approved check
	if sec.FIPSApproved != nil && *sec.FIPSApproved && !info.FIPSApproved {
		return fmt.Errorf("policy requires FIPS-approved algorithms; template %q is not FIPS-approved", info.TemplateID)
	}

	// block_deprecated check
	if sec.BlockDeprecated != nil && *sec.BlockDeprecated {
		if info.TemplateStatus == "deprecated" || info.TemplateStatus == "forbidden" {
			return fmt.Errorf("policy blocks deprecated/forbidden algorithms; template %q has status %q", info.TemplateID, info.TemplateStatus)
		}
	}

	return nil
}

// AllowedTemplateIDs returns the allowed_templates slice.
// Deny-by-default: absent (nil) => empty non-nil slice (deny all).
// Non-empty => copy of the explicit allow list.
func (e *SimpleRulesEvaluator) AllowedTemplateIDs(rulesJSON []byte) ([]string, error) {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return nil, err
	}
	// Absent => empty (deny all, nothing explicitly allowed)
	if rules.AllowedTemplates == nil {
		return []string{}, nil
	}
	// Return a copy to prevent caller mutation
	out := make([]string, len(rules.AllowedTemplates))
	copy(out, rules.AllowedTemplates)
	return out, nil
}
