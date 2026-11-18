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

// verifyPolicyName is the name of the policy that allows create_key + sign + verify.
const verifyPolicyName = "test-verify-allow"

// seedVerifyPolicy creates a policy that allows ml-dsa-65 with create_key,
// sign, and verify operations. Used by Verify tests that need to sign first.
func seedVerifyPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationSign),
				string(core.OperationVerify),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testverify", verifyPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed verify policy: %v", err)
	}
}

// setupCryptoWithKeyForVerify creates a wired cryptosvc.Orchestrator, seeds a
// policy that allows create_key + sign + verify for ml-dsa-65, creates a key,
// and returns the cryptosvc.Orchestrator and the key's public ID.
func setupCryptoWithKeyForVerify(t *testing.T) (cryptosvc.Orchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedVerifyPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "verify-test-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           verifyPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.Name
}

// ============================================================================
// Verify Tests
// ============================================================================

func TestVerify_MLDSA_validSignature_returnsTrue(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("post-quantum verification")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("expected valid=true for correct ML-DSA signature")
	}
	if verifyResult.KeyName != keyName {
		t.Errorf("KeyName: got %q want %q", verifyResult.KeyName, keyName)
	}
	if verifyResult.Algorithm == "" {
		t.Error("Algorithm must be populated in VerifyResult")
	}
	if verifyResult.ProviderName == "" {
		t.Error("ProviderName must be populated in VerifyResult")
	}
	if verifyResult.KeyVersion != signResult.KeyVersion {
		t.Errorf("KeyVersion: got %d want the version requested (%d)", verifyResult.KeyVersion, signResult.KeyVersion)
	}
}

func TestVerify_MLDSA_validSignature_noKeyVersion_returnsTrue(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("post-quantum verification")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("expected valid=true for correct ML-DSA signature")
	}
	if verifyResult.KeyName != keyName {
		t.Errorf("KeyName: got %q want %q", verifyResult.KeyName, keyName)
	}
	if verifyResult.Algorithm == "" {
		t.Error("Algorithm must be populated in VerifyResult")
	}
	if verifyResult.ProviderName == "" {
		t.Error("ProviderName must be populated in VerifyResult")
	}
	// No version requested: the current one is used, and reported.
	if verifyResult.KeyVersion != signResult.KeyVersion || verifyResult.KeyVersion == 0 {
		t.Errorf("KeyVersion: got %d want the current version (%d)", verifyResult.KeyVersion, signResult.KeyVersion)
	}
}

func TestVerify_tamperedPayload_returnsFalse_notError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              []byte("original"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              []byte("tampered"), // different payload
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("tampered payload should NOT return error, got: %v", err)
	}
	if verifyResult.Valid {
		t.Error("expected valid=false for tampered payload")
	}
}

func TestVerify_tamperedSignature_returnsFalse_notError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("data")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	sig := signResult.Signature
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)/2] ^= 0xFF

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            tampered,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("tampered signature should NOT return error, got: %v", err)
	}
	if verifyResult.Valid {
		t.Error("expected valid=false for tampered signature")
	}
}

func TestVerify_keyNotFound_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyName:   "key_nonexistent",
		Payload:   []byte("data"),
		Signature: []byte("sig"),
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound, got: %v", err)
	}
}

func TestVerify_emptyKeyPublicID_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyName:   "",
		Payload:   []byte("data"),
		Signature: []byte("sig"),
	})
	if err == nil {
		t.Fatal("expected error for empty KeyPublicID")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerify_policyDeniesVerify_returnsError(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	// Seed a policy that allows create_key + sign but NOT verify.
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
	rulesJSON, _ := json.Marshal(rules)
	p := policy.NewPolicy("pol_noverify", "no-verify-policy", rulesJSON)
	_, err := pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// Create key under the restrictive policy.
	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "no-verify-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           "no-verify-policy",
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Sign first (allowed).
	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              created.Name,
		Payload:              []byte("data"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify should fail with policy violation.
	_, err = ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              created.Name,
		KeyVersion:           signResult.KeyVersion,
		Payload:              []byte("data"),
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for policy-denied verify")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestVerify_noScopeParams_returnsError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForVerify(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyName:   keyName,
		Payload:   []byte("data"),
		Signature: []byte("sig"),
		// no scope_params set
	})
	if err == nil {
		t.Fatal("expected error when no scope_params are set")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSignVerify_roundTrip_MLDSA65(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("canonical round-trip test: ML-DSA-65")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("round-trip failed: valid=false")
	}
	if verifyResult.KeyName != keyName {
		t.Errorf("KeyName: got %q want %q", verifyResult.KeyName, keyName)
	}
	if verifyResult.Algorithm == "" {
		t.Error("Algorithm must be populated")
	}
	if verifyResult.ProviderName == "" {
		t.Error("ProviderName must be populated")
	}
}

func TestVerify_scopeMismatch_returnsError(t *testing.T) {
	// Key created via template ml-dsa-65 has primary scope "standard".
	// DomainContext maps to "with_context" — scope mismatch.
	ops, keyName := setupCryptoWithKeyForVerify(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyName:              keyName,
		Payload:              []byte("data"),
		Signature:            []byte("sig"),
		SignatureScopeFields: crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{}},
	})
	if err == nil {
		t.Fatal("expected error for scope mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
