package crypto_test

import (
	"context"
	"testing"

	cryptosvc "github.com/agile-crypto/citius-core/service/crypto"
	keysvc "github.com/agile-crypto/citius-core/service/key"

	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/software"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
)

// ============================================================================
// Shared Crypto Orchestrator Setup
// ============================================================================

// setupCryptoOrchestratorFull creates a fully wired cryptosvc.Orchestrator backed
// by in-memory storage, the software provider, and the standard algorithm
// catalog. It returns the cryptosvc.Orchestrator, keysvc.Orchestrator (for creating
// keys in tests), and policy.Engine (for seeding custom policies).
func setupCryptoOrchestratorFull(t *testing.T) (cryptosvc.Orchestrator, keysvc.Orchestrator, policy.Engine) {
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

	keyOrch, err := keysvc.NewOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("keysvc.NewOrchestrator: %v", err)
	}

	ops, err := cryptosvc.NewOrchestrator(repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("cryptosvc.NewOrchestrator: %v", err)
	}
	return ops, keyOrch, pol
}

// setupCryptoOrchestrator is a convenience wrapper that returns only the
// cryptosvc.Orchestrator. Use setupCryptoOrchestratorFull when you also need
// the keysvc.Orchestrator or policy.Engine.
func setupCryptoOrchestrator(t *testing.T) cryptosvc.Orchestrator {
	t.Helper()
	ops, _, _ := setupCryptoOrchestratorFull(t)
	return ops
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewCryptoOrchestrator_allDependencies_succeeds(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	if ops == nil {
		t.Fatal("cryptosvc.NewOrchestrator returned nil")
	}
}

func TestNewCryptoOrchestrator_nilKeyReader_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	reg, _ := template.NewStorageRegistry(ctx, store)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := cryptosvc.NewOrchestrator(nil, pol, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil key reader")
	}
}

func TestNewCryptoOrchestrator_nilPolicyEngine_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	reg, _ := template.NewStorageRegistry(ctx, store)
	provReg := provider.NewRegistry()

	_, err := cryptosvc.NewOrchestrator(repo, nil, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
}

func TestNewCryptoOrchestrator_nilProviderRegistry_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	reg, _ := template.NewStorageRegistry(ctx, store)
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := cryptosvc.NewOrchestrator(repo, pol, nil, reg)
	if err == nil {
		t.Fatal("expected error for nil provider registry")
	}
}

func TestNewCryptoOrchestrator_nilTemplateRegistry_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := cryptosvc.NewOrchestrator(repo, pol, provReg, nil)
	if err == nil {
		t.Fatal("expected error for nil template registry")
	}
}

func TestNewCryptoOrchestrator_implementsInterface(t *testing.T) {
	// This test verifies the constructor return type satisfies cryptosvc.Orchestrator
	// by calling a method through the interface.
	ops := setupCryptoOrchestrator(t)
	// Exercise one method to prove ops satisfies cryptosvc.Orchestrator at runtime.
	_, err := ops.GenerateRandom(context.Background(), 16)
	if err == nil {
		t.Fatal("expected CodeNotImplemented from stub")
	}
}
