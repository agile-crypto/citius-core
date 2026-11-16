package integration_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/software"
	cryptosvc "github.com/agile-crypto/citius-core/service/crypto"
	keysvc "github.com/agile-crypto/citius-core/service/key"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
)

func scopeSpecWithScope(t *testing.T, scope core.Scope) *core.ScopeSpecification {
	t.Helper()
	scopeSpec := &core.ScopeSpecification{
		Scope: scope,
	}
	return scopeSpec
}

// catalogPath returns the absolute path to the standard_algorithms.json catalog.
func catalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "data", "standard_algorithms.json")
}

// ============================================================================
// Shared Crypto Orchestrator Setup
// ============================================================================

// setupCryptoOrchestratorFull creates a fully wired cryptosvc.CryptoOrchestrator backed
// by in-memory storage, the software provider, and the standard algorithm
// catalog. It returns the cryptosvc.CryptoOrchestrator, cryptosvc.KeyOrchestrator (for creating
// keys in tests), and policy.Engine (for seeding custom policies).
func setupCryptoOrchestratorFull(t *testing.T) (cryptosvc.CryptoOrchestrator, keysvc.KeyOrchestrator, policy.Engine) {
	t.Helper()
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, err := key.NewStorageRepository(ctx, store)
	if err != nil {
		t.Fatalf("NewStorageRepository: %v", err)
	}

	reg, err := template.NewVaultRegistry(ctx, store)
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

	keyOrch, err := keysvc.NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("keysvc.NewKeyOrchestrator: %v", err)
	}

	ops, err := cryptosvc.NewCryptoOrchestrator(repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("cryptosvc.NewCryptoOrchestrator: %v", err)
	}
	return ops, keyOrch, pol
}
