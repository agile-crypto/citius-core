package template_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/template"
)

// catalogPath returns the absolute path to the standard_algorithms.json
// catalog. These tests live here (rather than in citius-core, where
// LoadStandardCatalog/ParseStandardCatalog are actually defined) because they
// need filesystem access to citius-server's real production catalog --
// citius-core is a standalone module now and has no copy of it.
func catalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "proto", "standard_algorithms.json")
}

// readCatalog reads the standard_algorithms.json file for test helpers.
func readCatalog(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(catalogPath())
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	return data
}

func verifyEcdsaP256Template(t *testing.T, r template.Registry, ctx context.Context) {
	t.Helper()
	ecdsa, err := r.Get(ctx, "ecdsa-p256-sha256-der")
	if err != nil {
		t.Fatalf("Get ecdsa: %v", err)
	}
	if ecdsa.GetStatus() != api.TemplateStatus_TEMPLATE_STATUS_ACTIVE {
		t.Errorf("ecdsa: expected TEMPLATE_STATUS_ACTIVE, got %v", ecdsa.GetStatus())
	}
	ecdsaAlg := ecdsa.GetAlgorithm().GetEcdsa()
	if ecdsaAlg == nil {
		t.Fatal("ecdsa-p256-sha256-der: expected ECDSA AlgorithmDetails")
	}
	if ecdsaAlg.GetCurve() != api.EllipticCurve_ELLIPTIC_CURVE_P256 {
		t.Errorf("ecdsa curve: got %v want ELLIPTIC_CURVE_P256", ecdsaAlg.GetCurve())
	}
	if ecdsaAlg.GetHash() != api.HashAlgorithm_HASH_ALGORITHM_SHA256 {
		t.Errorf("ecdsa hash: got %v want HASH_ALGORITHM_SHA256", ecdsaAlg.GetHash())
	}
	ecdsaScopes := ecdsa.GetScopedCapabilities()
	if len(ecdsaScopes) == 0 {
		t.Fatal("ecdsa: expected at least one scoped capability")
	}
	sigScope := ecdsaScopes[0].GetScope().GetSignature()
	if sigScope == nil {
		t.Fatal("ecdsa: expected signature scope specification")
	}
	if sigScope.GetScope() != api.SignatureScope_SIGNATURE_SCOPE_STANDARD {
		t.Errorf("ecdsa scope: got %v want SIGNATURE_SCOPE_STANDARD", sigScope.GetScope())
	}
	ecdsaSec := sigScope.GetSecurity()
	if ecdsaSec == nil {
		t.Fatal("ecdsa: expected UniversalSecurityProperties in scope")
		return // unreachable; satisfies static-analysis nil-flow
	}
	if ecdsaSec.FipsApproved == nil || !*ecdsaSec.FipsApproved {
		t.Error("ecdsa: expected fips_approved=true in scope security")
	}
}

func verifyMlDsa65Template(t *testing.T, r template.Registry, ctx context.Context) {
	t.Helper()
	mldsa, err := r.Get(ctx, "ml-dsa-65")
	if err != nil {
		t.Fatalf("Get mldsa: %v", err)
	}
	mldsaAlg := mldsa.GetAlgorithm().GetMlDsa()
	if mldsaAlg == nil {
		t.Fatal("ml-dsa-65: expected ML-DSA AlgorithmDetails")
	}
	if mldsaAlg.GetParameterSet() != api.MlDsaParameterSet_ML_DSA_65 {
		t.Errorf("mldsa parameter_set: got %v want ML_DSA_65", mldsaAlg.GetParameterSet())
	}
	mldsaScopes := mldsa.GetScopedCapabilities()
	if len(mldsaScopes) == 0 {
		t.Fatal("ml-dsa-65: expected at least one scoped capability")
	}
	mldsaSigScope := mldsaScopes[0].GetScope().GetSignature()
	if mldsaSigScope == nil {
		t.Fatal("ml-dsa-65: expected signature scope specification")
	}
	if mldsaSigScope.GetScope() != api.SignatureScope_SIGNATURE_SCOPE_STANDARD {
		t.Errorf("ml-dsa-65 scope: got %v want SIGNATURE_SCOPE_STANDARD", mldsaSigScope.GetScope())
	}
	mldsaSec := mldsaSigScope.GetSecurity()
	if mldsaSec == nil {
		t.Fatal("ml-dsa-65: expected UniversalSecurityProperties in scope")
		return // unreachable; satisfies static-analysis nil-flow
	}
	if mldsaSec.QuantumSafe == nil || !*mldsaSec.QuantumSafe {
		t.Error("ml-dsa-65: expected quantum_safe=true in scope security")
	}
	if mldsaSec.FipsApproved == nil || !*mldsaSec.FipsApproved {
		t.Error("ml-dsa-65: expected fips_approved=true in scope security")
	}
}

func TestLoadStandardCatalog_loadsM1Templates(t *testing.T) {
	r := registryFn()
	err := template.LoadStandardCatalog(context.Background(), catalogPath(), r)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}
	ctx := context.Background()
	verifyEcdsaP256Template(t, r, ctx)
	verifyMlDsa65Template(t, r, ctx)
}

func TestLoadStandardCatalog_loadsAllTemplates(t *testing.T) {
	r := registryFn()
	err := template.LoadStandardCatalog(context.Background(), catalogPath(), r)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	templates := r.List(context.Background())
	if len(templates) == 0 {
		t.Fatal("expected at least 1 template from standard catalog")
	}
	t.Logf("loaded %d templates from standard catalog", len(templates))
}

func TestParseStandardCatalog_hasVersion(t *testing.T) {
	catalog, err := template.ParseStandardCatalog(context.Background(), readCatalog(t))
	if err != nil {
		t.Fatalf("ParseStandardCatalog: %v", err)
	}
	if catalog.GetVersion() == "" {
		t.Error("expected non-empty catalog version")
	}
	t.Logf("catalog version: %s", catalog.GetVersion())
}

// TestLoadStandardCatalog_allEntriesPassConstraintValidation is a regression
// guard on the real production catalog: every one of its entries must pass
// CEL/buf.validate constraint validation.
// If a future catalog edit introduces a constraint violation, this test
// fails with the same error server startup would produce, rather than that
// surfacing only much later as a defensive rejection deep in provider code.
func TestLoadStandardCatalog_allEntriesPassConstraintValidation(t *testing.T) {
	r := registryFn()
	if err := template.LoadStandardCatalog(context.Background(), catalogPath(), r); err != nil {
		t.Fatalf("LoadStandardCatalog: real production catalog failed constraint validation: %v", err)
	}
}
