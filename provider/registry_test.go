package provider_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// stubProvider is a minimal Backend for tests.
type stubProvider struct {
	name     string
	provType string
}

func (s *stubProvider) Name() string { return s.name }
func (s *stubProvider) Type() string {
	if s.provType != "" {
		return s.provType
	}
	return "stub"
}
func (s *stubProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return nil, errors.New(context.Background(), "stub.GenerateKey", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return nil, errors.New(context.Background(), "stub.DestroyKey", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return nil, errors.New(context.Background(), "stub.ExportPublicKey", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return nil, errors.New(context.Background(), "stub.Sign", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return nil, errors.New(context.Background(), "stub.Verify", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) SignDigest(_ context.Context, _ *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return nil, errors.New(context.Background(), "stub.SignDigest", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) VerifyDigest(_ context.Context, _ *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return nil, errors.New(context.Background(), "stub.VerifyDigest", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) Encrypt(_ context.Context, _ *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return nil, errors.New(context.Background(), "stub.Encrypt", errors.CodeNotImplemented, "stub")
}
func (s *stubProvider) Decrypt(_ context.Context, _ *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return nil, errors.New(context.Background(), "stub.Decrypt", errors.CodeNotImplemented, "stub")
}

// Compile-time assertion
var _ provider.Backend = (*stubProvider)(nil)

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewRegistry_notNil(t *testing.T) {
	r := provider.NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
}

// ============================================================================
// Register Tests
// ============================================================================

func TestRegistry_Register_happyPath(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	p := &stubProvider{name: "test"}

	if err := r.Register(ctx, p); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestRegistry_Register_nilProvider_returnsError(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	if err := r.Register(ctx, nil); err == nil {
		t.Fatal("expected error for nil provider")
	}
}

func TestRegistry_Register_emptyName_returnsError(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	if err := r.Register(ctx, &stubProvider{name: ""}); err == nil {
		t.Fatal("expected error for empty provider name")
	}
}

func TestRegistry_Register_duplicate_returnsError(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_ = r.Register(ctx, &stubProvider{name: "dup"})
	err := r.Register(ctx, &stubProvider{name: "dup"})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected AlreadyExists, got: %v", err)
	}
}

// ============================================================================
// Get Tests
// ============================================================================

func TestRegistry_Get_happyPath(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_ = r.Register(ctx, &stubProvider{name: "sw"})

	got, err := r.Get(ctx, "sw")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Error("Get returned nil provider")
	}
}

func TestRegistry_Get_notFound(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_, err := r.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected ProviderNotFound, got: %v", err)
	}
}

// ============================================================================
// GetDefault Tests
// ============================================================================

func TestRegistry_GetDefault_noProviders_returnsError(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_, err := r.GetDefault(ctx)
	if err == nil {
		t.Fatal("expected error when no providers registered")
	}
}

func TestRegistry_GetDefault_fallsBackToFirst(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_ = r.Register(ctx, &stubProvider{name: "first"})
	_ = r.Register(ctx, &stubProvider{name: "second"})

	got, err := r.GetDefault(ctx)
	if err != nil {
		t.Fatalf("GetDefault: %v", err)
	}
	if got.Name() != "first" {
		t.Errorf("GetDefault fallback: got %q want %q", got.Name(), "first")
	}
}

// ============================================================================
// List Tests
// ============================================================================

func TestRegistry_List_all(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_ = r.Register(ctx, &stubProvider{name: "p1"})
	_ = r.Register(ctx, &stubProvider{name: "p2"})

	list := r.List(ctx)
	if len(list) != 2 {
		t.Errorf("List: got %d want 2", len(list))
	}
}

func TestRegistry_List_empty(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	list := r.List(ctx)
	if list == nil {
		t.Error("List should return empty slice not nil")
	}
}

// ============================================================================
// Remove Tests
// ============================================================================

func TestRegistry_Remove_happyPath(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	_ = r.Register(ctx, &stubProvider{name: "to-remove"})

	if err := r.Remove(ctx, "to-remove"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	_, err := r.Get(ctx, "to-remove")
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected ProviderNotFound after remove, got: %v", err)
	}
}

func TestRegistry_Remove_notFound_returnsError(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()
	err := r.Remove(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for removing non-existent provider")
	}
}

// ============================================================================
// Concurrency Test
// ============================================================================

func TestRegistry_concurrent_register_get(t *testing.T) {
	ctx := context.Background()
	r := provider.NewRegistry()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			name := fmt.Sprintf("p%d", i)
			_ = r.Register(ctx, &stubProvider{name: name})
		}
		close(done)
	}()
	go func() {
		for i := 0; i < 100; i++ {
			_ = r.List(ctx)
		}
	}()
	<-done
}
