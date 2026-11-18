package key_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/software"
	keysvc "github.com/agile-crypto/citius-core/service/key"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
)

// ============================================================================
// Shared Test Setup
// ============================================================================

// testPolicyName is the name of the permissive policy seeded by setupOrchestrator.
const testPolicyName = "test-allow-all"

func defaultScopeSpec(t *testing.T) *core.ScopeSpecification {
	return scopeSpecWithScope(t, core.ScopeSignatureStandard)
}

func scopeSpecWithScope(t *testing.T, scope core.Scope) *core.ScopeSpecification {
	t.Helper()
	scopeSpec := &core.ScopeSpecification{
		Scope: scope,
	}
	return scopeSpec
}

// seedPermissivePolicy creates a policy that allows the ml-dsa-65 template and
// the create_key operation. Used by setupOrchestrator and inline test setups.
func seedPermissivePolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testperm", testPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
}

// catalogPath returns the absolute path to the standard_algorithms.json catalog.
func catalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "data", "standard_algorithms.json")
}

// setupOrchestratorFull creates a fully wired keysvc.Orchestrator backed by
// in-memory storage, the software provider, and the standard algorithm catalog.
// It returns the orchestrator, the underlying key.Repository (for lifecycle
// mutation in tests), and the policy.Engine (for seeding custom policies).
//
// The software provider advertises "ecdsa-p256-sha256" and "ml-dsa-65".
// The standard catalog contains "ml-dsa-65" (matching), so end-to-end tests
// use that template ID.
//
// A permissive policy (testPolicyName) is pre-seeded that allows ml-dsa-65 and
// the create_key operation.
func setupOrchestratorFull(t *testing.T) (keysvc.Orchestrator, key.Repository, provider.Registry, policy.Engine, template.Registry) {
	t.Helper()

	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, err := key.NewStorageRepository(ctx, store)
	if err != nil {
		t.Fatalf("NewStorageRepository: %v", err)
	}

	reg, err := template.NewStorageRegistry(ctx, store)
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}

	// Load the standard algorithm catalog — includes "ml-dsa-65".
	err = template.LoadStandardCatalog(ctx, catalogPath(), reg)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	provReg := provider.NewRegistry()
	sw := software.New()
	err = provReg.Register(ctx, sw)
	if err != nil {
		t.Fatalf("Register provider: %v", err)
	}

	policyRepo, err := policy.NewStorageRepository(ctx, store)
	if err != nil {
		t.Fatalf("policy.NewStorageRepository: %v", err)
	}
	eval := policy.NewSimpleRulesEvaluator()
	pol, err := policy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	seedPermissivePolicy(t, ctx, pol)

	orch, err := keysvc.NewOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("keysvc.NewOrchestrator: %v", err)
	}
	return orch, repo, provReg, pol, reg
}

// setupOrchestratorWithPolicy is a convenience wrapper that returns the
// orchestrator and policy engine (without the repo). Use setupOrchestratorFull
// when you also need the underlying key.Repository for lifecycle mutation.
func setupOrchestratorWithPolicy(t *testing.T) (keysvc.Orchestrator, policy.Engine) {
	t.Helper()
	orch, _, _, pol, _ := setupOrchestratorFull(t)
	return orch, pol
}

// setupOrchestrator is a convenience wrapper that returns only the orchestrator.
// Use setupOrchestratorWithPolicy when you need to seed additional policies.
func setupOrchestrator(t *testing.T) keysvc.Orchestrator {
	t.Helper()
	orch, _ := setupOrchestratorWithPolicy(t)
	return orch
}
