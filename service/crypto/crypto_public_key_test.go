package crypto_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	cryptosvc "github.com/agile-crypto/citius-core/service/crypto"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/software"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

const (
	// publicKeyVerifyPolicyName allows verify for ml-dsa-65 and ecdsa-p256-sha256-der.
	publicKeyVerifyPolicyName = "test-public-key-verify"
	// publicKeyECDSAOnlyPolicyName allows verify for ecdsa-p256-sha256-der only.
	publicKeyECDSAOnlyPolicyName = "test-public-key-verify-ecdsa-only"

	mldsaTemplate = "ml-dsa-65"             // RAW public key in software
	ecdsaTemplate = "ecdsa-p256-sha256-der" // SPKI public key in software
)

// publicKeyFixture is a cryptosvc.Orchestrator wired with a single
// software provider, plus what tests need to produce key pairs and
// signatures outside the orchestrator: VerifyWithPublicKey involves no
// stored key.
type publicKeyFixture struct {
	ops       cryptosvc.Orchestrator
	sw        *software.Provider
	templates template.Registry
}

// setupPublicKeyVerify creates a cryptosvc.Orchestrator backed by
// in-memory storage, the standard algorithm catalog and only the software
// provider, and seeds publicKeyVerifyPolicyName and
// publicKeyECDSAOnlyPolicyName.
func setupPublicKeyVerify(t *testing.T) publicKeyFixture {
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
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	seedVerifyOnlyPolicy(t, ctx, pol, "pol_pkverify", publicKeyVerifyPolicyName, mldsaTemplate, ecdsaTemplate)
	seedVerifyOnlyPolicy(t, ctx, pol, "pol_pkverifyecdsa", publicKeyECDSAOnlyPolicyName, ecdsaTemplate)

	ops, err := cryptosvc.NewOrchestrator(repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("cryptosvc.NewOrchestrator: %v", err)
	}
	return publicKeyFixture{ops: ops, sw: sw, templates: reg}
}

// seedVerifyOnlyPolicy creates a policy that allows the verify operation for
// templateIDs.
func seedVerifyOnlyPolicy(t *testing.T, ctx context.Context, pol policy.Engine, id, name string, templateIDs ...string) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: templateIDs,
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationVerify)},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	_, err = pol.CreatePolicy(ctx, policy.NewPolicy(id, name, rulesJSON))
	if err != nil {
		t.Fatalf("seed policy %q: %v", name, err)
	}
}

// signedPayload is a payload signed by the software provider with a fresh key
// pair for a template.
type signedPayload struct {
	publicKey []byte
	payload   []byte
	signature []byte
}

// signWithSoftware generates a key pair for templateID with the software
// provider and signs payload with it under scope.
func (f publicKeyFixture) signWithSoftware(t *testing.T, templateID string, payload []byte, scope crypto.SignatureScopeFields) signedPayload {
	t.Helper()
	ctx := context.Background()

	tmpl, err := f.templates.Get(ctx, templateID)
	if err != nil {
		t.Fatalf("Get template %q: %v", templateID, err)
	}
	genResp, err := f.sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tmpl.GetAlgorithm()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signReq := &providerpb.SignRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Input:               payload,
		Algorithm:           tmpl.GetAlgorithm(),
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	}
	switch {
	case scope.NoContext != nil:
		signReq.ScopeParams = &providerpb.SignRequest_NoContext{NoContext: scope.NoContext}
	case scope.DomainContext != nil:
		signReq.ScopeParams = &providerpb.SignRequest_DomainContext{DomainContext: scope.DomainContext}
	}
	signResp, err := f.sw.Sign(ctx, signReq)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signedPayload{
		publicKey: genResp.GetPublicKeyBytes(),
		payload:   payload,
		signature: signResp.GetSignature(),
	}
}

func noContextScope() crypto.SignatureScopeFields {
	return crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
}

// verifyRequest builds a request verifying s under publicKeyVerifyPolicyName.
func (s signedPayload) verifyRequest(templateID string, format types.KeyFormat, scope crypto.SignatureScopeFields) crypto.VerifyWithPublicKeyRequest {
	return crypto.VerifyWithPublicKeyRequest{
		PublicKey:            s.publicKey,
		PublicKeyFormat:      format,
		Payload:              s.payload,
		Signature:            s.signature,
		SignatureScopeFields: scope,
		TemplateID:           templateID,
		PolicyName:           publicKeyVerifyPolicyName,
	}
}

// ============================================================================
// VerifyWithPublicKey — valid signatures
// ============================================================================

func TestVerifyWithPublicKey_validSignature_returnsTrue(t *testing.T) {
	f := setupPublicKeyVerify(t)
	tests := []struct {
		name       string
		templateID string
		format     types.KeyFormat
		scope      crypto.SignatureScopeFields
	}{
		{"ML-DSA RAW", mldsaTemplate, types.KeyFormat_KEY_FORMAT_RAW, noContextScope()},
		{"ML-DSA RAW with context", mldsaTemplate, types.KeyFormat_KEY_FORMAT_RAW,
			crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{Context: []byte("ctx")}}},
		{"ECDSA SPKI", ecdsaTemplate, types.KeyFormat_KEY_FORMAT_SPKI, noContextScope()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := f.signWithSoftware(t, tt.templateID, []byte("stateless verification"), tt.scope)

			result, err := f.ops.VerifyWithPublicKey(context.Background(), signed.verifyRequest(tt.templateID, tt.format, tt.scope))
			if err != nil {
				t.Fatalf("VerifyWithPublicKey: %v", err)
			}
			if !result.Valid {
				t.Error("expected valid=true for correct signature")
			}
			if result.TemplateID != tt.templateID {
				t.Errorf("TemplateID: got %q want %q", result.TemplateID, tt.templateID)
			}
			if result.ProviderID != f.sw.Name() {
				t.Errorf("ProviderID: got %q want %q", result.ProviderID, f.sw.Name())
			}
		})
	}
}

func TestVerifyWithPublicKey_pinnedProvider_returnsTrue(t *testing.T) {
	f := setupPublicKeyVerify(t)
	signed := f.signWithSoftware(t, ecdsaTemplate, []byte("pinned"), noContextScope())

	req := signed.verifyRequest(ecdsaTemplate, types.KeyFormat_KEY_FORMAT_SPKI, noContextScope())
	req.ProviderID = f.sw.Name()
	result, err := f.ops.VerifyWithPublicKey(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyWithPublicKey: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid=true for correct signature")
	}
	if result.ProviderID != f.sw.Name() {
		t.Errorf("ProviderID: got %q want %q", result.ProviderID, f.sw.Name())
	}
}

// ============================================================================
// VerifyWithPublicKey — invalid signatures
// ============================================================================

// Invalid signatures are NOT an error — they return Valid=false.
func TestVerifyWithPublicKey_invalidSignature_returnsFalse_notError(t *testing.T) {
	f := setupPublicKeyVerify(t)
	tests := []struct {
		name       string
		templateID string
		format     types.KeyFormat
	}{
		{"ML-DSA", mldsaTemplate, types.KeyFormat_KEY_FORMAT_RAW},
		{"ECDSA", ecdsaTemplate, types.KeyFormat_KEY_FORMAT_SPKI},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := f.signWithSoftware(t, tt.templateID, []byte("original"), noContextScope())
			other := f.signWithSoftware(t, tt.templateID, []byte("original"), noContextScope())

			tamperedSig := append([]byte(nil), signed.signature...)
			tamperedSig[len(tamperedSig)/2] ^= 0xFF

			cases := map[string]func(r *crypto.VerifyWithPublicKeyRequest){
				"tampered payload":   func(r *crypto.VerifyWithPublicKeyRequest) { r.Payload = []byte("tampered") },
				"tampered signature": func(r *crypto.VerifyWithPublicKeyRequest) { r.Signature = tamperedSig },
				"other public key":   func(r *crypto.VerifyWithPublicKeyRequest) { r.PublicKey = other.publicKey },
			}
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					req := signed.verifyRequest(tt.templateID, tt.format, noContextScope())
					mutate(&req)
					result, err := f.ops.VerifyWithPublicKey(context.Background(), req)
					if err != nil {
						t.Fatalf("invalid signature should NOT return error, got: %v", err)
					}
					if result.Valid {
						t.Error("expected valid=false")
					}
				})
			}
		})
	}
}

// ============================================================================
// VerifyWithPublicKey — policy
// ============================================================================

func TestVerifyWithPublicKey_templateNotAllowedByPolicy_returnsError(t *testing.T) {
	f := setupPublicKeyVerify(t)
	signed := f.signWithSoftware(t, mldsaTemplate, []byte("data"), noContextScope())

	req := signed.verifyRequest(mldsaTemplate, types.KeyFormat_KEY_FORMAT_RAW, noContextScope())
	req.PolicyName = publicKeyECDSAOnlyPolicyName
	_, err := f.ops.VerifyWithPublicKey(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for template not allowed by policy")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestVerifyWithPublicKey_unknownPolicy_returnsError(t *testing.T) {
	f := setupPublicKeyVerify(t)
	signed := f.signWithSoftware(t, ecdsaTemplate, []byte("data"), noContextScope())

	req := signed.verifyRequest(ecdsaTemplate, types.KeyFormat_KEY_FORMAT_SPKI, noContextScope())
	req.PolicyName = "no-such-policy"
	_, err := f.ops.VerifyWithPublicKey(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown policy")
	}
}

// ============================================================================
// VerifyWithPublicKey — public key format
// ============================================================================

// TO UPDATE: the formats the software provider accepts are hardcoded in the
// orchestrator (cryptosvc.publicKeyFormats). Update this test when providers
// can express their supported public key format as a capability.
func TestVerifyWithPublicKey_softwareProvider_wrongFormat_returnsError(t *testing.T) {
	f := setupPublicKeyVerify(t)
	tests := []struct {
		name       string
		templateID string
		format     types.KeyFormat
	}{
		{"ML-DSA SPKI", mldsaTemplate, types.KeyFormat_KEY_FORMAT_SPKI},
		{"ML-DSA PEM", mldsaTemplate, types.KeyFormat_KEY_FORMAT_PEM},
		{"ECDSA RAW", ecdsaTemplate, types.KeyFormat_KEY_FORMAT_RAW},
		{"ECDSA JWK", ecdsaTemplate, types.KeyFormat_KEY_FORMAT_JWK},
		{"ECDSA unspecified", ecdsaTemplate, types.KeyFormat_KEY_FORMAT_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed := f.signWithSoftware(t, tt.templateID, []byte("data"), noContextScope())

			_, err := f.ops.VerifyWithPublicKey(context.Background(), signed.verifyRequest(tt.templateID, tt.format, noContextScope()))
			if err == nil {
				t.Fatal("expected error for unsupported public key format")
			}
			if !errors.IsInvalidArgument(err) {
				t.Errorf("expected CodeInvalidArgument, got: %v", err)
			}
			if !strings.Contains(err.Error(), "Unsupported public key format") {
				t.Errorf("expected \"Unsupported public key format\", got: %v", err)
			}
		})
	}
}

// ============================================================================
// VerifyWithPublicKey — invalid inputs
// ============================================================================

func TestVerifyWithPublicKey_invalidInput_returnsError(t *testing.T) {
	f := setupPublicKeyVerify(t)
	signed := f.signWithSoftware(t, ecdsaTemplate, []byte("data"), noContextScope())

	tests := []struct {
		name   string
		mutate func(r *crypto.VerifyWithPublicKeyRequest)
		is     func(error) bool
	}{
		{"empty public key", func(r *crypto.VerifyWithPublicKeyRequest) { r.PublicKey = nil }, errors.IsInvalidArgument},
		{"empty template", func(r *crypto.VerifyWithPublicKeyRequest) { r.TemplateID = "" }, errors.IsInvalidArgument},
		{"empty policy", func(r *crypto.VerifyWithPublicKeyRequest) { r.PolicyName = "" }, errors.IsInvalidArgument},
		{"no scope params", func(r *crypto.VerifyWithPublicKeyRequest) {
			r.SignatureScopeFields = crypto.SignatureScopeFields{}
		}, errors.IsInvalidArgument},
		{"scope not declared by template", func(r *crypto.VerifyWithPublicKeyRequest) {
			r.SignatureScopeFields = crypto.SignatureScopeFields{DomainContext: &types.SignatureDomainContext{Context: []byte("ctx")}}
		}, errors.IsFailedPrecondition},
		{"unknown pinned provider", func(r *crypto.VerifyWithPublicKeyRequest) { r.ProviderID = "no-such-provider" }, errors.IsProviderNotFound},
		{"unmet provider requirements", func(r *crypto.VerifyWithPublicKeyRequest) {
			r.ProviderRequirements = core.ProviderRequirements{FIPS140Certified: true}
		}, nil},
		{"malformed public key", func(r *crypto.VerifyWithPublicKeyRequest) { r.PublicKey = []byte("not a key") }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := signed.verifyRequest(ecdsaTemplate, types.KeyFormat_KEY_FORMAT_SPKI, noContextScope())
			tt.mutate(&req)
			result, err := f.ops.VerifyWithPublicKey(context.Background(), req)
			if err == nil {
				t.Fatalf("expected error, got result %+v", result)
			}
			if tt.is != nil && !tt.is(err) {
				t.Errorf("unexpected error code: %v", err)
			}
		})
	}
}

func TestVerifyWithPublicKey_unknownTemplate_returnsError(t *testing.T) {
	f := setupPublicKeyVerify(t)
	signed := f.signWithSoftware(t, ecdsaTemplate, []byte("data"), noContextScope())

	// The policy is checked first: an unknown template is never allowed.
	_, err := f.ops.VerifyWithPublicKey(context.Background(),
		signed.verifyRequest("no-such-template", types.KeyFormat_KEY_FORMAT_SPKI, noContextScope()))
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
}
