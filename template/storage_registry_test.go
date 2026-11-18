package template_test

import (
	"context"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
)

func ecdsaTemplate() *template.Template {
	return template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ecdsa-p256-sha256",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_Ecdsa{
				Ecdsa: &api.EcdsaParams{
					Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  api.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
						Security: &api.UniversalSecurityProperties{
							FipsApproved: boolPtr(true),
							QuantumSafe:  boolPtr(false),
						},
					},
				},
			},
			Operations: []api.CryptoOperation{
				api.CryptoOperation_CRYPTO_OPERATION_SIGN,
				api.CryptoOperation_CRYPTO_OPERATION_VERIFY,
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
	})
}

func mldsaTemplate() *template.Template {
	return template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ml-dsa-65",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_MlDsa{
				MlDsa: &api.MlDsaParams{
					ParameterSet: api.MlDsaParameterSet_ML_DSA_65,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
						Security: &api.UniversalSecurityProperties{
							QuantumSafe:  boolPtr(true),
							FipsApproved: boolPtr(false),
						},
					},
				},
			},
			Operations: []api.CryptoOperation{
				api.CryptoOperation_CRYPTO_OPERATION_SIGN,
				api.CryptoOperation_CRYPTO_OPERATION_VERIFY,
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
	})
}

var registryFn = func() template.Registry {
	store := &storage.InmemStorage{}
	r, err := template.NewStorageRegistry(context.Background(), store)
	if err != nil {
		panic("failed to create template InmemStorageRegistry: " + err.Error())
	}
	return r
}

// ============================================================================
// Register Tests
// ============================================================================

func TestInmemStorageRegistry_Register_success(t *testing.T) {
	r := registryFn()
	if err := r.Register(context.Background(), ecdsaTemplate()); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestInmemStorageRegistry_Register_nil_returnsError(t *testing.T) {
	r := registryFn()
	if err := r.Register(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil template")
	}
}

func TestInmemStorageRegistry_Register_emptyID_returnsError(t *testing.T) {
	r := registryFn()
	tmpl := template.NewTemplate(&api.TemplateInfo{TemplateId: ""})
	if err := r.Register(context.Background(), tmpl); err == nil {
		t.Fatal("expected error for empty template ID")
	}
}

func TestInmemStorageRegistry_Register_duplicate_overwrite(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	updated := template.NewTemplate(&api.TemplateInfo{
		TemplateId:  "ecdsa-p256-sha256",
		DisplayName: "Updated ECDSA",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_Ecdsa{
				Ecdsa: &api.EcdsaParams{
					Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  api.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
	})
	if err := r.Register(context.Background(), updated); err != nil {
		t.Fatalf("second Register: %v", err)
	}
	got, _ := r.Get(context.Background(), "ecdsa-p256-sha256")
	if got.GetDisplayName() != "Updated ECDSA" {
		t.Errorf("DisplayName: got %q want %q", got.GetDisplayName(), "Updated ECDSA")
	}
}

// ============================================================================
// Get Tests
// ============================================================================

func TestInmemStorageRegistry_Get_success(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	got, err := r.Get(context.Background(), "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TemplateID() != "ecdsa-p256-sha256" {
		t.Errorf("TemplateID: got %q want %q", got.TemplateID(), "ecdsa-p256-sha256")
	}
	if got.GetStatus() != api.TemplateStatus_TEMPLATE_STATUS_ACTIVE {
		t.Error("expected Status=TEMPLATE_STATUS_ACTIVE")
	}
}

func TestInmemStorageRegistry_Get_notFound(t *testing.T) {
	r := registryFn()
	_, err := r.Get(context.Background(), "no-such-template")
	if err == nil {
		t.Fatal("expected error for missing template")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func TestInmemStorageRegistry_Get_returnsClone(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	got, _ := r.Get(context.Background(), "ecdsa-p256-sha256")
	got.Proto().TemplateId = "mutated"
	// Re-fetch should still have original value (proto round-trip gives independent copy)
	got2, _ := r.Get(context.Background(), "ecdsa-p256-sha256")
	if got2.TemplateID() != "ecdsa-p256-sha256" {
		t.Error("Get should return an independent copy (proto round-trip)")
	}
}

// ============================================================================
// List Tests
// ============================================================================

func TestInmemStorageRegistry_List_all(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	_ = r.Register(context.Background(), mldsaTemplate())
	list := r.List(context.Background())
	if len(list) != 2 {
		t.Errorf("List: got %d want 2", len(list))
	}
}

func TestInmemStorageRegistry_List_empty(t *testing.T) {
	r := registryFn()
	list := r.List(context.Background())
	if list == nil {
		t.Error("List should return empty slice, not nil")
	}
}

// ============================================================================
// Select Tests
// ============================================================================

// registryWithBothTemplates is a helper that registers both templates.
func registryWithBothTemplates(t *testing.T) template.Registry {
	t.Helper()
	ctx := context.Background()
	r := registryFn()
	if err := r.Register(ctx, ecdsaTemplate()); err != nil {
		t.Fatalf("Register ecdsa: %v", err)
	}
	if err := r.Register(ctx, mldsaTemplate()); err != nil {
		t.Fatalf("Register mldsa: %v", err)
	}
	return r
}

// signatureScope matches any signature template regardless of scope variant.
var signatureScope = &core.ScopeSpecification{Scope: core.ScopeSignatureStandard}

func TestInmemStorageRegistry_Select_byScope_noSecurityFilter(t *testing.T) {
	r := registryWithBothTemplates(t)
	// No security filter and all templates eligible — both match scope.
	// Should return one of the two (deterministic).
	ctx := context.Background()
	got, err := r.Select(ctx, signatureScope, template.AllTemplates())
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got == nil {
		t.Fatal("Select returned nil template")
	}
}

func TestInmemStorageRegistry_Select_requireQuantumSafe(t *testing.T) {
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	got, err := r.Select(ctx, &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
		SecurityProps: &core.SecurityProperties{
			QuantumSafe: boolPtr(true),
		},
	}, template.AllTemplates())
	if err != nil {
		t.Fatalf("Select with quantum_safe: %v", err)
	}
	if got.TemplateID() != "ml-dsa-65" {
		t.Errorf("expected ml-dsa-65, got %q", got.TemplateID())
	}
}

func TestInmemStorageRegistry_Select_requireFIPSApproved(t *testing.T) {
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	got, err := r.Select(ctx, &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
		SecurityProps: &core.SecurityProperties{
			FipsApproved: boolPtr(true),
		},
	}, template.AllTemplates())
	if err != nil {
		t.Fatalf("Select with fips_approved: %v", err)
	}
	if got.TemplateID() != "ecdsa-p256-sha256" {
		t.Errorf("expected ecdsa-p256-sha256, got %q", got.TemplateID())
	}
}

func TestInmemStorageRegistry_Select_allowedTemplates_restrictsCandidates(t *testing.T) {
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	// Only ecdsa is allowed by policy
	got, err := r.Select(ctx, signatureScope, template.OnlyTemplates("ecdsa-p256-sha256"))
	if err != nil {
		t.Fatalf("Select with OnlyTemplates: %v", err)
	}
	if got.TemplateID() != "ecdsa-p256-sha256" {
		t.Errorf("expected ecdsa-p256-sha256, got %q", got.TemplateID())
	}
}

func TestInmemStorageRegistry_Select_allowedTemplates_emptyCandidates(t *testing.T) {
	r := registryWithBothTemplates(t)
	// Policy only allows a template that isn't registered
	ctx := context.Background()
	_, err := r.Select(ctx, signatureScope, template.OnlyTemplates("nonexistent-template"))
	if err == nil {
		t.Fatal("expected error when no candidates match AllowedTemplates")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}

func TestInmemStorageRegistry_Select_securityFilter_noMatch(t *testing.T) {
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	_, err := r.Select(ctx, &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
		SecurityProps: &core.SecurityProperties{
			QuantumSafe:  boolPtr(true),
			FipsApproved: boolPtr(true),
		},
	}, template.AllTemplates())
	if err == nil {
		t.Fatal("expected error — no template is both quantum_safe and fips_approved")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}

func TestInmemStorageRegistry_Select_emptyRegistry(t *testing.T) {
	r := registryFn()
	ctx := context.Background()
	_, err := r.Select(ctx, signatureScope, template.AllTemplates())
	if err == nil {
		t.Fatal("expected error for empty registry")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}

func TestInmemStorageRegistry_Select_explicitTemplateID_bypasses(t *testing.T) {
	// When AllowedTemplates has exactly one entry and scope is nil, return it directly.
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	got, err := r.Select(ctx, nil, template.OnlyTemplates("ecdsa-p256-sha256"))
	if err != nil {
		t.Fatalf("Select explicit: %v", err)
	}
	if got.TemplateID() != "ecdsa-p256-sha256" {
		t.Errorf("expected ecdsa-p256-sha256, got %q", got.TemplateID())
	}
}

func TestInmemStorageRegistry_Select_scopeVariantMismatch(t *testing.T) {
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	// Templates have signature/standard; ask for prehashed — should find no match.
	_, err := r.Select(ctx, &core.ScopeSpecification{
		Scope: core.ScopeSignaturePrehashed,
	}, template.AllTemplates())
	if err == nil {
		t.Fatal("expected error for scope variant mismatch")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}

func TestInmemStorageRegistry_Select_primitiveMismatch(t *testing.T) {
	r := registryWithBothTemplates(t)
	ctx := context.Background()
	// Templates are signature-scoped; ask for AEAD.
	_, err := r.Select(ctx, &core.ScopeSpecification{
		Scope: core.ScopeAeadStandard,
	}, template.AllTemplates())
	if err == nil {
		t.Fatal("expected error for primitive mismatch")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}
