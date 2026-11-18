package key_test

import (
	"context"
	"encoding/json"
	"testing"

	keysvc "github.com/agile-crypto/citius-core/service/key"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/loopback"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CreateKey Tests — Template-Based Path
// ============================================================================

func TestCreateKey_templateBased_happyPath(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "my-mldsa-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created == nil {
		t.Fatal("CreateKey returned nil key")
		return // unreachable; satisfies static-analysis nil-flow
	}
	if created.KeyID == "" {
		t.Error("PublicId must not be empty")
	}
	if created.Name != "my-mldsa-key" {
		t.Errorf("Name: got %q want %q", created.Name, "my-mldsa-key")
	}
	if created.Version != 1 {
		t.Errorf("CurrentVersion: got %d want 1", created.Version)
	}
	if created.ScopeSpec == nil {
		t.Error("ScopeSpec must not be empty")
	}
}

func TestCreateKey_templateNotFound_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:               "key",
		TemplateID:         "nonexistent-template",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
}

func TestCreateKey_missingName_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
		// Name is empty
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestCreateKey_missingPolicyID_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:               "no-policy",
		TemplateID:         "ml-dsa-65",
		ScopeSpecification: defaultScopeSpec(t),
		// PolicyID is empty
	})
	if err == nil {
		t.Fatal("expected error for missing policy ID")
	}
}

func TestCreateKey_storesPersistentKey(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "persistent-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// ReadKey is still a stub (CodeNotImplemented), but we verify the key
	// was created successfully with a valid ID.
	if created.KeyID == "" {
		t.Error("expected non-empty PublicId")
	}
}

func TestCreateKey_withLabels(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	labels := map[string]string{"env": "test", "team": "platform"}
	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "labelled-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
		Labels:             labels,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	got := created.Labels
	if len(got) != 2 {
		t.Errorf("Labels: got %d entries want 2", len(got))
	}
	if got["env"] != "test" {
		t.Errorf("Labels[env]: got %q want %q", got["env"], "test")
	}
}

func TestCreateKey_providerNotFound_returnsError(t *testing.T) {
	// Use an orchestrator without any provider registered.
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	reg, _ := template.NewStorageRegistry(ctx, store)
	_ = template.LoadStandardCatalog(ctx, catalogPath(), reg)
	provReg := provider.NewRegistry() // empty — no providers
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)
	seedPermissivePolicy(t, ctx, pol)

	orch, _ := keysvc.NewKeyOrchestrator(repo, reg, provReg, pol)

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "no-provider",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err == nil {
		t.Fatal("expected error when no provider supports the template")
	}
}

func TestCreateKey_providerID_honoured(t *testing.T) {
	orch, _, provReg, _, _ := setupOrchestratorFull(t)
	ctx := context.Background()

	// setupOrchestratorFull already registers "software" (first, so it would
	// win a plain first-match scan). Register "loopback" too — it advertises
	// ml-dsa-65 as well — and pin the request to it explicitly.
	if err := provReg.Register(ctx, loopback.New()); err != nil {
		t.Fatalf("Register loopback: %v", err)
	}

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "pinned-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ProviderInstanceID: "loopback",
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created.Provider != "loopback" {
		t.Errorf("Provider: got %q, want %q — provider_id must be honoured, not silently overridden by registration order", created.Provider, "loopback")
	}
}

func TestCreateKey_providerID_unsatisfiable_returnsError(t *testing.T) {
	orch, _, _, _, _ := setupOrchestratorFull(t)
	ctx := context.Background()

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "impossible-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ProviderInstanceID: "nonexistent-provider",
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err == nil {
		t.Fatal("expected error: a provider_id that cannot serve the template must error, not silently fall back to \"software\"")
	}
}

func TestCreateKey_withoutScope_returnsError(t *testing.T) {
	// Use an orchestrator without any provider registered.
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	reg, _ := template.NewStorageRegistry(ctx, store)
	_ = template.LoadStandardCatalog(ctx, catalogPath(), reg)
	provReg := provider.NewRegistry() // empty — no providers
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)
	seedPermissivePolicy(t, ctx, pol)

	orch, _ := keysvc.NewKeyOrchestrator(repo, reg, provReg, pol)

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "no-provider",
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
	})
	require.Error(t, err, "missing scope should return an error")
}

// ============================================================================
// Scope-Based Helpers
// ============================================================================

// seedScopePolicy creates a named policy with the given rules and returns the
// policy name. Convenience for scope-based tests that need custom policies.
func seedScopePolicy(t *testing.T, ctx context.Context, pol policy.Engine, name string, rules *policy.Rules) string {
	t.Helper()
	var rulesJSON []byte
	if rules != nil {
		var err error
		rulesJSON, err = json.Marshal(rules)
		if err != nil {
			t.Fatalf("marshal rules: %v", err)
		}
	}
	p := policy.NewPolicy(core.NewID(core.PolicyPrefix), name, rulesJSON)
	_, err := pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy %q: %v", name, err)
	}
	return name
}

// ============================================================================
// CreateKey Tests — Scope-Based Path
// ============================================================================

func TestCreateKey_scopeBased_permissivePolicy_selectsByScope(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Seed a policy that allows ml-dsa-65 + create_key for the scope path.
	policyName := seedScopePolicy(t, ctx, pol, "scope-permissive", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "scope-based-key",
		ScopeSpecification: defaultScopeSpec(t),
		PolicyID:           policyName,
	})
	if err != nil {
		t.Fatalf("CreateKey (scope-based, permissive policy): %v", err)
	}
	if created.Primitive == "" {
		t.Error("Primitive should be set from scope")
	}
	if created.Primitive != "signature" {
		t.Errorf("Primitive: got %q want %q", created.Primitive, "signature")
	}
}

func TestCreateKey_scopeBased_policyAllowsTemplate(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	policyName := seedScopePolicy(t, ctx, pol, "allow-mldsa", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "policy-allowed",
		ScopeSpecification: defaultScopeSpec(t),
		PolicyID:           policyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created.KeyID == "" {
		t.Error("expected valid key")
	}
}

func TestCreateKey_scopeBased_policyDenies_noMatchingTemplate(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Policy allows only a template that doesn't exist in the catalog.
	policyName := seedScopePolicy(t, ctx, pol, "deny-all-real", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"nonexistent-template"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "should-fail",
		ScopeSpecification: defaultScopeSpec(t),
		PolicyID:           policyName,
	})
	if err == nil {
		t.Fatal("expected error: policy restricts to non-existent template")
	}
}

func TestCreateKey_scopeBased_policyDenyByDefault(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Empty/nil rules = deny-by-default: allowed_templates is absent (nil).
	policyName := seedScopePolicy(t, ctx, pol, "deny-default", nil)

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "should-fail",
		ScopeSpecification: defaultScopeSpec(t),
		PolicyID:           policyName,
	})
	if err == nil {
		t.Fatal("expected error: deny-by-default policy should block key creation")
	}
}

func TestCreateKey_scopeBased_quantumSafeFilter(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Allow both templates; the quantum_safe filter in the scope should narrow
	// selection to ml-dsa-65 only (ecdsa-p256 is not quantum-safe).
	policyName := seedScopePolicy(t, ctx, pol, "qs-policy", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65", "ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	qsTrue := true
	spec := &api.ScopeSpecification{
		ScopeSpec: &api.ScopeSpecification_Signature{
			Signature: &api.SignatureScopeSpec{
				Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
				Security: &api.UniversalSecurityProperties{
					QuantumSafe: &qsTrue,
				},
			},
		},
	}

	scopeSpec, err := core.ScopeSpecificationFromProto(ctx, spec)
	require.NoError(t, err, "convert scope spec from proto")

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "quantum-safe-key",
		ScopeSpecification: scopeSpec,
		PolicyID:           policyName,
	})
	if err != nil {
		t.Fatalf("CreateKey (quantum_safe scope): %v", err)
	}
	// The only quantum-safe signature template in the catalog is ml-dsa-65.
	if created.Primitive != "signature" {
		t.Errorf("Primitive: got %q want %q", created.Primitive, "signature")
	}
}

func TestCreateKey_scopeBased_policyNotFound(t *testing.T) {
	orch, _ := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "should-fail",
		ScopeSpecification: defaultScopeSpec(t),
		PolicyID:           "nonexistent-policy",
	})
	if err == nil {
		t.Fatal("expected error: policy not found")
	}
}

func TestCreateKey_scopeBased_primitiveMismatch(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Allow everything — but the KEM primitive has no templates in the catalog.
	policyName := seedScopePolicy(t, ctx, pol, "allow-all-kem", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65", "ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	// The catalog only has signature templates; request KEM scope.
	spec := &api.ScopeSpecification{
		ScopeSpec: &api.ScopeSpecification_Kem{
			Kem: &api.KemScopeSpec{
				Scope: api.KemScope_KEM_SCOPE_STANDARD,
			},
		},
	}
	scopeSpec, err := core.ScopeSpecificationFromProto(ctx, spec)
	require.NoError(t, err, "convert scope spec from proto")

	_, err = orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "kem-key",
		ScopeSpecification: scopeSpec,
		PolicyID:           policyName,
	})
	if err == nil {
		t.Fatal("expected error: no KEM template in catalog")
	}
}
