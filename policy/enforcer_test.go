package policy_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
)

// setupEnforcer creates an Enforcer backed by an in-memory fakeRepository.
func setupEnforcer(t *testing.T) *policy.Enforcer {
	t.Helper()
	policyRepo := newFakeRepository()
	enforcer, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return enforcer
}

func makePolicy(publicID, name string) *policy.Policy {
	return policy.NewPolicy(publicID, name, nil)
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewEnforcer_nilStorage_returnsError(t *testing.T) {
	_, err := policy.NewEnforcer(nil, policy.NewNoopEvaluator())
	if err == nil {
		t.Fatal("expected error for nil storage")
	}
}

func TestNewEnforcer_nilEvaluator_returnsError(t *testing.T) {
	policyRepo := newFakeRepository()
	_, err := policy.NewEnforcer(policyRepo, nil)
	if err == nil {
		t.Fatal("expected error for nil evaluator")
	}
}

// ============================================================================
// CreatePolicy Tests
// ============================================================================

func TestEnforcer_CreatePolicy_happyPath(t *testing.T) {
	e := setupEnforcer(t)
	ctx := context.Background()
	p := makePolicy("pol_01", "default-sig")

	created, err := e.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if created.Name() != "default-sig" {
		t.Errorf("Name: got %q want %q", created.Name(), "default-sig")
	}
}

func TestEnforcer_CreatePolicy_nilPolicy_returnsError(t *testing.T) {
	e := setupEnforcer(t)
	_, err := e.CreatePolicy(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func TestEnforcer_CreatePolicy_invalidPolicy_returnsError(t *testing.T) {
	// Missing Name fails VetForWrite
	e := setupEnforcer(t)
	p := policy.NewPolicy("pol_01", "", nil) // no name
	_, err := e.CreatePolicy(context.Background(), p)
	if err == nil {
		t.Fatal("expected error for invalid policy")
	}
}

func TestEnforcer_CreatePolicy_alreadyExists_returnsError(t *testing.T) {
	e := setupEnforcer(t)
	ctx := context.Background()
	_, _ = e.CreatePolicy(ctx, makePolicy("pol_01", "original"))
	_, err := e.CreatePolicy(ctx, makePolicy("pol_02", "original"))
	if err == nil {
		t.Fatal("expected error for duplicate policy name")
	}
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected AlreadyExists, got: %v", err)
	}
}

// ============================================================================
// GetPolicy Tests
// ============================================================================

func TestEnforcer_GetPolicy_happyPath(t *testing.T) {
	e := setupEnforcer(t)
	ctx := context.Background()
	_, _ = e.CreatePolicy(ctx, makePolicy("pol_01", "my-policy"))

	got, err := e.GetPolicy(ctx, "my-policy")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name() != "my-policy" {
		t.Errorf("Name: got %q want %q", got.Name(), "my-policy")
	}
}

func TestEnforcer_GetPolicy_notFound(t *testing.T) {
	e := setupEnforcer(t)
	_, err := e.GetPolicy(context.Background(), "pol_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound, got: %v", err)
	}
}

// ============================================================================
// UpdatePolicy Tests
// ============================================================================

func TestEnforcer_UpdatePolicy_happyPath(t *testing.T) {
	e := setupEnforcer(t)
	ctx := context.Background()
	_, _ = e.CreatePolicy(ctx, makePolicy("pol_01", "original"))

	err := e.UpdatePolicy(ctx, makePolicy("pol_01_v2", "original"))
	if err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	// Verify update took effect via GetPolicy
	got, err := e.GetPolicy(ctx, "original")
	if err != nil {
		t.Fatalf("GetPolicy after update: %v", err)
	}
	if got.PublicID() != "pol_01_v2" {
		t.Errorf("PublicID: got %q want %q", got.PublicID(), "pol_01_v2")
	}
}

func TestEnforcer_UpdatePolicy_notFound_returnsError(t *testing.T) {
	e := setupEnforcer(t)
	err := e.UpdatePolicy(context.Background(), makePolicy("pol_01", "nonexistent"))
	if err == nil {
		t.Fatal("expected error for updating non-existent policy")
	}
}

// ============================================================================
// DeletePolicy Tests
// ============================================================================

func TestEnforcer_DeletePolicy_happyPath(t *testing.T) {
	e := setupEnforcer(t)
	ctx := context.Background()
	_, _ = e.CreatePolicy(ctx, makePolicy("pol_01", "p"))
	if err := e.DeletePolicy(ctx, "p"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	_, err := e.GetPolicy(ctx, "p")
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound after delete, got: %v", err)
	}
}

func TestEnforcer_DeletePolicy_notFound_returnsError(t *testing.T) {
	e := setupEnforcer(t)
	err := e.DeletePolicy(context.Background(), "pol_notexist")
	if err == nil {
		t.Fatal("expected error for deleting non-existent policy")
	}
}

// ============================================================================
// ListPolicies Tests
// ============================================================================

func TestEnforcer_ListPolicies_all(t *testing.T) {
	e := setupEnforcer(t)
	ctx := context.Background()
	_, _ = e.CreatePolicy(ctx, makePolicy("pol_01", "p1"))
	_, _ = e.CreatePolicy(ctx, makePolicy("pol_02", "p2"))

	policies, err := e.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("ListPolicies: got %d want 2", len(policies))
	}
}

func TestEnforcer_ListPolicies_empty(t *testing.T) {
	e := setupEnforcer(t)
	policies, err := e.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if policies == nil {
		t.Error("ListPolicies should return empty slice not nil")
	}
}
