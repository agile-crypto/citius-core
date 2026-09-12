package policy_test

import (
	"context"
	"encoding/json"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
)

// setupWithRulesPolicy creates an Enforcer with a SimpleRulesEvaluator and one policy
// whose rules_json is the given Rules (serialized to JSON).
func setupWithRulesPolicy(t *testing.T, policyName string, rules *policy.Rules) *policy.Enforcer {
	t.Helper()
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	var rulesJSON []byte
	if rules != nil {
		var err error
		rulesJSON, err = json.Marshal(rules)
		if err != nil {
			t.Fatalf("marshal rules: %v", err)
		}
	}

	p := policy.NewPolicy("pol_01HXYZ", policyName, rulesJSON)
	_, err := enforcer.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	return enforcer
}

// ============================================================================
// ValidateOperation Tests
// ============================================================================

func TestValidateOperation_noPolicy_defaultAllow(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	// Empty policy name = no restrictions (open default)
	err := enforcer.ValidateOperation(ctx, "", core.OperationSign, "ecdsa-p256-sha256", "")
	if err != nil {
		t.Errorf("expected nil with no policy, got: %v", err)
	}
}

func TestValidateOperation_emptyRules_deniesAll(t *testing.T) {
	// Policy with no rules (empty rules_json) => deny-by-default (nothing explicitly allowed)
	enforcer := setupWithRulesPolicy(t, "open-policy", nil)
	err := enforcer.ValidateOperation(context.Background(), "open-policy", core.OperationSign, "ecdsa-p256-sha256", "")
	if err == nil {
		t.Fatal("expected deny: empty rules_json should deny under deny-by-default")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestValidateOperation_templateAllowed(t *testing.T) {
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256", "ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{"sign", "verify"},
		},
	}
	enforcer := setupWithRulesPolicy(t, "restricted", rules)
	err := enforcer.ValidateOperation(context.Background(), "restricted", core.OperationSign, "ecdsa-p256-sha256", "")
	if err != nil {
		t.Errorf("expected allow, got: %v", err)
	}
}

func TestValidateOperation_templateDenied(t *testing.T) {
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{"sign"},
		},
	}
	enforcer := setupWithRulesPolicy(t, "ecdsa-only", rules)
	err := enforcer.ValidateOperation(context.Background(), "ecdsa-only", core.OperationSign, "ml-dsa-65", "")
	if err == nil {
		t.Fatal("expected deny: template not in allow list")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestValidateOperation_operationAllowed(t *testing.T) {
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{"sign", "verify"},
		},
	}
	enforcer := setupWithRulesPolicy(t, "sign-only", rules)
	err := enforcer.ValidateOperation(context.Background(), "sign-only", core.OperationSign, "ecdsa-p256-sha256", "")
	if err != nil {
		t.Errorf("expected allow, got: %v", err)
	}
}

func TestValidateOperation_operationDenied(t *testing.T) {
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"aes-256-gcm"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{"sign", "verify"},
		},
	}
	enforcer := setupWithRulesPolicy(t, "sign-only", rules)
	err := enforcer.ValidateOperation(context.Background(), "sign-only", core.OperationEncrypt, "aes-256-gcm", "")
	if err == nil {
		t.Fatal("expected deny: encrypt not in allowed operations")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestValidateOperation_templateAndOperationBothChecked(t *testing.T) {
	// Template allowed but operation denied → overall denied
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{"verify"}, // sign is NOT allowed
		},
	}
	enforcer := setupWithRulesPolicy(t, "verify-only", rules)
	err := enforcer.ValidateOperation(context.Background(), "verify-only", core.OperationSign, "ecdsa-p256-sha256", "")
	if err == nil {
		t.Fatal("expected deny: operation 'sign' not in allowed operations")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestValidateOperation_policyNotFound_returnsError(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	err := enforcer.ValidateOperation(ctx, "nonexistent", core.OperationSign, "ecdsa-p256-sha256", "")
	if err == nil {
		t.Fatal("expected error when policy not found")
	}
}

func TestValidateOperation_emptyTemplateID_skipsTemplateCheck(t *testing.T) {
	// When templateID is empty, template check is skipped — only operation check runs
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256"}, // would deny if checked
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{"sign"},
		},
	}
	enforcer := setupWithRulesPolicy(t, "skip-tpl", rules)
	err := enforcer.ValidateOperation(context.Background(), "skip-tpl", core.OperationSign, "", "")
	if err != nil {
		t.Errorf("expected allow (empty templateID skips template check), got: %v", err)
	}
}

// ============================================================================
// ValidateKeyCreation Tests
// ============================================================================

func TestValidateKeyCreation_M1_alwaysAllowed(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	spec := &core.KeyCreationSpec{
		TemplateID: "ecdsa-p256-sha256",
		Name:       "my-key",
	}
	err := enforcer.ValidateKeyCreation(ctx, "", spec)
	if err != nil {
		t.Errorf("M1: expected key creation always allowed; got: %v", err)
	}
}

// ============================================================================
// CreatePolicy rules_json Validation Tests
// ============================================================================

func TestCreatePolicy_invalidRulesJSON_rejected(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	p := policy.NewPolicy("pol_bad", "bad-rules", []byte(`{not valid json}`))
	_, err := enforcer.CreatePolicy(ctx, p)
	if err == nil {
		t.Fatal("expected error: invalid rules_json should be rejected at create time")
	}
}

func TestCreatePolicy_unknownOperation_rejected(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	rulesJSON := []byte(`{"version":"1","allowed_operations":{"key_operations":["teleport"]}}`)
	p := policy.NewPolicy("pol_bad", "bad-ops", rulesJSON)
	_, err := enforcer.CreatePolicy(ctx, p)
	if err == nil {
		t.Fatal("expected error: unknown operation 'teleport' in rules_json")
	}
}

func TestCreatePolicy_validRulesJSON_accepted(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	rulesJSON := []byte(`{"version":"1","allowed_templates":["ecdsa-p256-sha256"],"allowed_operations":{"key_operations":["sign","verify"]}}`)
	p := policy.NewPolicy("pol_good", "good-policy", rulesJSON)
	_, err := enforcer.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("CreatePolicy should accept valid rules_json: %v", err)
	}
}

func TestCreatePolicy_emptyRulesJSON_accepted(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	p := policy.NewPolicy("pol_empty", "empty-rules", nil) // no rules = deny-by-default (valid policy, denies everything)
	_, err := enforcer.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("CreatePolicy should accept empty rules_json: %v", err)
	}
}

// ============================================================================
// UpdatePolicy rules_json Validation Tests
// ============================================================================

func TestUpdatePolicy_invalidRulesJSON_rejected(t *testing.T) {
	ctx := context.Background()
	policyRepo := newFakeRepository()
	enforcer, _ := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())

	// Create valid policy first
	p := policy.NewPolicy("pol_01", "my-policy", nil)
	_, err := enforcer.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Update with invalid rules_json
	updated := policy.NewPolicy("pol_01_v2", "my-policy", []byte(`{broken json}`))
	err = enforcer.UpdatePolicy(ctx, updated)
	if err == nil {
		t.Fatal("expected error: invalid rules_json should be rejected at update time")
	}
}
