package crypto_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
)

// ============================================================================
// TODO: Stub Tests to be done after full implementation
// ============================================================================

func TestWrapKey_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.WrapKey(context.Background(), crypto.WrapKeyRequest{})
	if err == nil {
		t.Fatal("WrapKey should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for WrapKey, got: %v", err)
	}
}

func TestUnwrapKey_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.UnwrapKey(context.Background(), crypto.UnwrapKeyRequest{})
	if err == nil {
		t.Fatal("UnwrapKey should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for UnwrapKey, got: %v", err)
	}
}

func TestDeriveKey_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.DeriveKey(context.Background(), crypto.DeriveKeyRequest{})
	if err == nil {
		t.Fatal("DeriveKey should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for DeriveKey, got: %v", err)
	}
}

func TestGenerateMAC_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.GenerateMAC(context.Background(), crypto.MacRequest{})
	if err == nil {
		t.Fatal("GenerateMAC should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for GenerateMAC, got: %v", err)
	}
}

func TestVerifyMAC_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.VerifyMAC(context.Background(), crypto.VerifyMacRequest{})
	if err == nil {
		t.Fatal("VerifyMAC should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for VerifyMAC, got: %v", err)
	}
}

func TestDigest_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Digest(context.Background(), crypto.DigestRequest{})
	if err == nil {
		t.Fatal("Digest should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for Digest, got: %v", err)
	}
}

func TestGenerateRandom_notImplemented(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.GenerateRandom(context.Background(), 32)
	if err == nil {
		t.Fatal("GenerateRandom should return error")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for GenerateRandom, got: %v", err)
	}
}

// ============================================================================
// Interface Completeness
// ============================================================================

func TestCryptoOrchestrator_interfaceComplete(t *testing.T) {
	// Compile-time check: if this file compiles, cryptoOrchestrator satisfies service.CryptoOrchestrator.
	// The real assertion is in service/crypto_orchestrator_impl.go:
	//   var _ service.CryptoOrchestrator = (*cryptoOrchestrator)(nil)
	// From service_test, we verify via the constructor return type.
	ops := setupCryptoOrchestrator(t)
	if ops == nil {
		t.Fatal("expected non-nil service.CryptoOrchestrator from constructor")
	}
}
