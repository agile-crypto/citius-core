package policy_test

import (
	"context"
	"encoding/json"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/stretchr/testify/require"
)

// setupWithRulesPolicy is defined in validate_test.go - shared across test files
// in the policy_test package.

// ============================================================================
// AllowedTemplates Tests
// ============================================================================

func TestAllowedTemplates_noPolicy_returnsNil(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	// No policy name => bypass (no restrictions)
	ids, err := enforcer.AllowedTemplates(ctx, "", &core.ScopeSpecification{})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil (bypass, no policy), got: %v", ids)
	}
}

func TestAllowedTemplates_emptyRules_returnsEmptySlice(t *testing.T) {
	// Empty rules_json - deny-by-default => no templates allowed
	enforcer := setupWithRulesPolicy(t, "open-policy", nil)

	ids, err := enforcer.AllowedTemplates(context.Background(), "open-policy", &core.ScopeSpecification{})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if ids == nil {
		t.Error("expected non-nil empty slice (deny-by-default), got nil")
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 allowed templates (deny-by-default), got %d: %v", len(ids), ids)
	}
}

func TestAllowedTemplates_withAllowList_returnsIDs(t *testing.T) {
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256", "ml-dsa-65"},
	}
	enforcer := setupWithRulesPolicy(t, "restricted", rules)

	ctx := context.Background()
	scopeSpec, err := core.NewScopeSpecification(
		ctx, core.ScopeSignatureStandard, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("NewScopeSpecification: %v", err)
	}
	ids, err := enforcer.AllowedTemplates(context.Background(), "restricted", scopeSpec)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 allowed templates, got %d: %v", len(ids), ids)
	}
	// Order preserved from rules_json
	if ids[0] != "ecdsa-p256-sha256" || ids[1] != "ml-dsa-65" {
		t.Errorf("unexpected IDs: %v", ids)
	}
}

func TestAllowedTemplates_policyNotFound_returnsError(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	_, err := enforcer.AllowedTemplates(ctx, "nonexistent", &core.ScopeSpecification{})
	if err == nil {
		t.Fatal("expected error when policy not found")
	}
}

func TestAllowedTemplates_scopeSpecIgnored_M1(t *testing.T) {
	// M1: scopeSpec is accepted but not used for filtering.
	// Same result regardless of scope.
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256"},
	}
	rulesJSON, _ := json.Marshal(rules)
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	p := policy.NewPolicy("pol_scope", "scope-test", rulesJSON)
	_, err := enforcer.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	scopeSpec, err := core.NewScopeSpecification(
		ctx, core.ScopeSignatureStandard, nil, nil, nil,
	)
	require.NoError(t, err, "NewScopeSpecification: %v", err)
	// With a specific scope
	ids1, _ := enforcer.AllowedTemplates(ctx, "scope-test", scopeSpec)
	// With empty scope
	ids2, _ := enforcer.AllowedTemplates(ctx, "scope-test", &core.ScopeSpecification{})
	if len(ids1) != len(ids2) || ids1[0] != ids2[0] {
		t.Errorf("M1: scopeSpec should not affect results; ids1=%v, ids2=%v", ids1, ids2)
	}
}
