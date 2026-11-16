package crypto_test

import (
	"context"
	"encoding/json"
	"testing"

	cryptosvc "github.com/agile-crypto/citius-core/service/crypto"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
)

// cryptoPolicyName is the name of the policy that allows create_key + sign.
const cryptoPolicyName = "test-crypto-allow"

// seedCryptoPolicy creates a policy that allows ml-dsa-65 with create_key
// and sign operations. Used by setupCryptoWithKey and sign tests.
func seedCryptoPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationSign),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testcrypto", cryptoPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed crypto policy: %v", err)
	}
}

// setupCryptoWithKey creates a wired cryptosvc.CryptoOrchestrator, seeds a policy that
// allows create_key + sign for ml-dsa-65, creates a key, and returns the
// cryptosvc.CryptoOrchestrator and the key's public ID.
func setupCryptoWithKey(t *testing.T) (cryptosvc.CryptoOrchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedCryptoPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "sign-test-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           cryptoPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.Name
}

// ============================================================================
// Sign Tests
// ============================================================================

func TestSign_MLDSA_happyPath(t *testing.T) {
	ops, keyName := setupCryptoWithKey(t)
	ctx := context.Background()

	result, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              []byte("post-quantum signing"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
	if result.KeyName != keyName {
		t.Errorf("KeyName: got %q want %q", result.KeyName, keyName)
	}
	if result.Algorithm == "" {
		t.Error("Algorithm must be populated in SignResult")
	}
	if result.ProviderName == "" {
		t.Error("ProviderName must be populated in SignResult")
	}
	if result.KeyVersion == 0 {
		t.Error("KeyVersionID must be populated in SignResult")
	}
}

func TestSign_keyNotFound_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyName: "key_nonexistent",
		Payload: []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound, got: %v", err)
	}
}

func TestSign_emptyKeyPublicID_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyName: "",
		Payload: []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for empty KeyPublicID")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_emptyPayload_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyName: "key_doesntmatter",
		Payload: nil,
	})
	if err == nil {
		t.Fatal("expected error for empty Payload")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_policyDeniesSign_returnsError(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	// Seed a policy that allows create_key but NOT sign.
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	}
	rulesJSON, _ := json.Marshal(rules)
	p := policy.NewPolicy("pol_nosign", "no-sign-policy", rulesJSON)
	_, err := pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// Create key under the restrictive policy.
	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "no-sign-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           "no-sign-policy",
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Sign should fail with policy violation.
	_, err = ops.Sign(ctx, crypto.SignRequest{
		KeyName:              created.Name,
		Payload:              []byte("should fail"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for policy-denied sign")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestSign_noScopeParams_returnsError(t *testing.T) {
	ops, keyName := setupCryptoWithKey(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyName: keyName,
		Payload: []byte("data"),
		// no scope_params set
	})
	if err == nil {
		t.Fatal("expected error when no scope_params are set")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_MLDSA_noContext_succeeds(t *testing.T) {
	// The key was created via template ml-dsa-65 whose primary scope is
	// "standard", so NoContext (standard) matches the key's declared scope.
	ops, keyName := setupCryptoWithKey(t)
	result, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyName:              keyName,
		Payload:              []byte("standard scope signing"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign with NoContext on ML-DSA: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestSign_scopeMismatch_returnsError(t *testing.T) {
	// Key created via template ml-dsa-65 has primary scope "standard".
	// DomainContext maps to "with_context" — scope mismatch.
	ops, keyName := setupCryptoWithKey(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyName:              keyName,
		Payload:              []byte("data"),
		SignatureScopeFields: crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{}},
	})
	if err == nil {
		t.Fatal("expected error for scope mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
