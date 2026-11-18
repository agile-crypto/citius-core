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

// setupCryptoWithScopedKey creates a wired cryptosvc.Orchestrator holding one
// ml-dsa-65 key bound to the given scope.
//
// ml-dsa-65 is the right template for this: its catalog entry declares both a
// SIGNATURE_SCOPE_STANDARD and a SIGNATURE_SCOPE_WITH_CONTEXT capability, so
// the same template can back a key under either scope, and the key's own
// ScopeSpecification — fixed here at creation — is what pins down which
// contract that key actually offers its callers.
func setupCryptoWithScopedKey(t *testing.T, scope core.Scope) (cryptosvc.Orchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

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
	const policyName = "test-sigscope-allow"
	if _, err = pol.CreatePolicy(ctx, policy.NewPolicy("pol_testsigscope", policyName, rulesJSON)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "sigscope-test-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           policyName,
		ScopeSpecification: scopeSpecWithScope(t, scope),
	})
	if err != nil {
		t.Fatalf("CreateKey(%s): %v", scope, err)
	}
	return ops, created.Name
}

// TestSign_signatureScopeAndContext_mustAgree covers the full matrix of key
// scope against caller-supplied scope_params.
//
// A key's Scope is a contract with its callers about which parameters they
// must supply, so a request that does not match it is rejected rather than
// quietly reinterpreted: a standard-scope key must not accept a domain
// context (it would be silently unused, giving no domain separation despite
// the caller asking for it), and a with-context key must not accept a request
// that omits the context (it would produce a signature outside the domain the
// caller intended). Only the two agreeing combinations are allowed through.
func TestSign_signatureScopeAndContext_mustAgree(t *testing.T) {
	tests := []struct {
		name      string
		keyScope  core.Scope
		fields    crypto.SignatureScopeFields
		wantError bool
	}{
		{
			name:     "standard key, no_context: agree",
			keyScope: core.ScopeSignatureStandard,
			fields:   crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
		},
		{
			name:      "standard key, domain_context supplied: rejected",
			keyScope:  core.ScopeSignatureStandard,
			fields:    crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{Context: []byte("ctx")}},
			wantError: true,
		},
		{
			name:      "standard key, empty domain_context still counts as asking for one: rejected",
			keyScope:  core.ScopeSignatureStandard,
			fields:    crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{}},
			wantError: true,
		},
		{
			name:      "standard key, no scope_params arm set: rejected",
			keyScope:  core.ScopeSignatureStandard,
			fields:    crypto.SignatureScopeFields{},
			wantError: true,
		},
		{
			name:     "with_context key, domain_context supplied: agree",
			keyScope: core.ScopeSignatureWithContext,
			fields:   crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{Context: []byte("ctx")}},
		},
		{
			name:      "with_context key, no_context: rejected",
			keyScope:  core.ScopeSignatureWithContext,
			fields:    crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
			wantError: true,
		},
		{
			name:      "with_context key, no scope_params arm set: rejected",
			keyScope:  core.ScopeSignatureWithContext,
			fields:    crypto.SignatureScopeFields{},
			wantError: true,
		},
		{
			// FIPS 204 makes the empty context a legal value equal to the
			// absent one; what the scope requires is that the caller declare
			// the domain_context arm, not that its value be non-empty.
			name:     "with_context key, empty domain_context: agree",
			keyScope: core.ScopeSignatureWithContext,
			fields:   crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops, keyName := setupCryptoWithScopedKey(t, tc.keyScope)
			_, err := ops.Sign(context.Background(), crypto.SignRequest{
				KeyName:              keyName,
				Payload:              []byte("payload"),
				SignatureScopeFields: tc.fields,
			})
			if tc.wantError {
				if err == nil {
					t.Fatal("expected the request to be rejected")
				}
				if !errors.IsInvalidArgument(err) {
					t.Errorf("expected CodeInvalidArgument, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected the request to succeed: %v", err)
			}
		})
	}
}

// TestSignVerify_withContext_bindsContextEndToEnd is the orchestrator-level
// proof that a with-context key actually delivers the domain separation its
// scope promises. The provider-level tests cover the primitive; this covers
// the path a real caller takes, which is where the context was previously
// accepted and then dropped.
func TestSignVerify_withContext_bindsContextEndToEnd(t *testing.T) {
	ops, keyName := setupCryptoWithScopedKey(t, core.ScopeSignatureWithContext)
	ctx := context.Background()
	payload := []byte("payload")
	signingContext := []byte("billing-service-v1")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName: keyName,
		Payload: payload,
		SignatureScopeFields: crypto.SignatureScopeFields{
			DomainContext: &types.SignatureDomainContext{Context: signingContext},
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifySameContext, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:    keyName,
		KeyVersion: signResult.KeyVersion,
		Payload:    payload,
		Signature:  signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{
			DomainContext: &types.SignatureDomainContext{Context: signingContext},
		},
	})
	if err != nil {
		t.Fatalf("Verify (same context): %v", err)
	}
	if !verifySameContext.Valid {
		t.Error("same context: expected valid=true")
	}

	verifyOtherContext, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyName:    keyName,
		KeyVersion: signResult.KeyVersion,
		Payload:    payload,
		Signature:  signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{
			DomainContext: &types.SignatureDomainContext{Context: []byte("reporting-service-v1")},
		},
	})
	if err != nil {
		t.Fatalf("Verify (different context) must not error, only report invalid: %v", err)
	}
	if verifyOtherContext.Valid {
		t.Error("different context: expected valid=false — a signature is being accepted outside the domain it was made for")
	}
}
