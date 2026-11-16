package key_test

import (
	"context"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/stretchr/testify/require"
)

// Uses setupOrchestrator from key_create_test.go

// ============================================================================
// ReadKey Tests
// ============================================================================

func TestReadKey_happyPath(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	scopeSpecBytes := defaultScopeSpec(t)
	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "read-me", TemplateID: "ml-dsa-65", PolicyID: testPolicyName, ScopeSpecification: scopeSpecBytes,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := orch.ReadKey(ctx, created.Name, 0)
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if got.KeyID != created.KeyID {
		t.Errorf("PublicId: got %q want %q", got.KeyID, created.KeyID)
	}
	if got.Name != "read-me" {
		t.Errorf("Name: got %q want %q", got.Name, "read-me")
	}
}

func TestReadKey_notFound(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.ReadKey(context.Background(), "key_nonexistent", 0)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound, got: %v", err)
	}
}

// ============================================================================
// ListKeys Tests
// ============================================================================

func TestListKeys_returnsAll(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	scopeSpecBytes := defaultScopeSpec(t)
	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{Name: "k1", TemplateID: "ml-dsa-65", PolicyID: testPolicyName, ScopeSpecification: scopeSpecBytes})
	require.NoError(t, err, "CreateKey k1")
	_, err = orch.CreateKey(ctx, core.KeyCreationSpec{Name: "k2", TemplateID: "ml-dsa-65", PolicyID: testPolicyName, ScopeSpecification: scopeSpecBytes})
	require.NoError(t, err, "CreateKey k2")

	keys, err := orch.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys: got %d want 2", len(keys))
	}
}

func TestListKeys_empty(t *testing.T) {
	orch := setupOrchestrator(t)
	keys, err := orch.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if keys == nil {
		t.Error("ListKeys should return empty slice, not nil")
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys: got %d want 0", len(keys))
	}
}

// ============================================================================
// DeleteKey Tests
// ============================================================================

func TestDeleteKey_happyPath(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "to-delete", TemplateID: "ml-dsa-65", PolicyID: testPolicyName, ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	err = orch.DeleteKey(ctx, created.Name)
	if err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// Key should no longer be readable.
	_, err = orch.ReadKey(ctx, created.Name, 0)
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound after delete, got: %v", err)
	}
}

func TestDeleteKey_removedFromList(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "list-then-delete", TemplateID: "ml-dsa-65", PolicyID: testPolicyName, ScopeSpecification: defaultScopeSpec(t),
	})
	require.NoError(t, err, "CreateKey")
	_, err = orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "keep-me", TemplateID: "ml-dsa-65", PolicyID: testPolicyName, ScopeSpecification: defaultScopeSpec(t),
	})
	require.NoError(t, err, "CreateKey")

	err = orch.DeleteKey(ctx, created.Name)
	require.NoError(t, err)

	keys, err := orch.ListKeys(ctx)
	require.NoError(t, err, "ListKeys")
	require.Len(t, keys, 1, "ListKeys after delete: got %d want 1", len(keys))
}

func TestDeleteKey_notFound(t *testing.T) {
	orch := setupOrchestrator(t)
	err := orch.DeleteKey(context.Background(), "key_nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting non-existent key")
	}
}

// ============================================================================
// Lifecycle Stub Tests
// ============================================================================

func TestRotateKey_notImplemented(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.RotateKey(context.Background(), "any")
	if err == nil || !errors.IsNotImplemented(err) {
		t.Errorf("RotateKey should be CodeNotImplemented, got: %v", err)
	}
}

func TestSuspendKey_notImplemented(t *testing.T) {
	orch := setupOrchestrator(t)
	err := orch.SuspendKey(context.Background(), "any")
	if err == nil || !errors.IsNotImplemented(err) {
		t.Errorf("SuspendKey should be CodeNotImplemented, got: %v", err)
	}
}

func TestRestoreKey_notImplemented(t *testing.T) {
	orch := setupOrchestrator(t)
	err := orch.RestoreKey(context.Background(), "any")
	if err == nil || !errors.IsNotImplemented(err) {
		t.Errorf("RestoreKey should be CodeNotImplemented, got: %v", err)
	}
}

func TestDestroyKey_notImplemented(t *testing.T) {
	orch := setupOrchestrator(t)
	err := orch.DestroyKey(context.Background(), "any")
	if err == nil || !errors.IsNotImplemented(err) {
		t.Errorf("DestroyKey should be CodeNotImplemented, got: %v", err)
	}
}

func TestImportKey_notImplemented(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.ImportKey(context.Background(), core.ImportKeySpec{})
	if err == nil || !errors.IsNotImplemented(err) {
		t.Errorf("ImportKey should be CodeNotImplemented, got: %v", err)
	}
}

func TestUpdateKeyPolicy_notImplemented(t *testing.T) {
	orch := setupOrchestrator(t)
	err := orch.UpdateKeyPolicy(context.Background(), "any", "any")
	if err == nil || !errors.IsNotImplemented(err) {
		t.Errorf("UpdateKeyPolicy should be CodeNotImplemented, got: %v", err)
	}
}
