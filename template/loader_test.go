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

// catalogPath returns the absolute path to the standard_algorithms.json catalog.
func catalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "proto", "standard_algorithms.json")
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

// newTestRegistry creates an in-memory fakeRegistry for tests.
func newTestRegistry(t *testing.T) template.Registry {
	t.Helper()
	return newFakeRegistry()
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
	r := newTestRegistry(t)
	err := template.LoadStandardCatalog(context.Background(), catalogPath(), r)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}
	ctx := context.Background()
	verifyEcdsaP256Template(t, r, ctx)
	verifyMlDsa65Template(t, r, ctx)
}

func TestLoadStandardCatalog_loadsAllTemplates(t *testing.T) {
	r := newTestRegistry(t)
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

func TestLoadStandardCatalog_fileNotFound(t *testing.T) {
	r := newTestRegistry(t)
	err := template.LoadStandardCatalog(context.Background(), "/nonexistent/path/catalog.json", r)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseStandardCatalog_invalidJSON(t *testing.T) {
	_, err := template.ParseStandardCatalog(context.Background(), []byte(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseStandardCatalog_emptyCatalog(t *testing.T) {
	catalog, err := template.ParseStandardCatalog(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("ParseStandardCatalog empty: %v", err)
	}
	if len(catalog.GetTemplates()) != 0 {
		t.Errorf("expected 0 templates from empty catalog, got %d", len(catalog.GetTemplates()))
	}
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
	r := newTestRegistry(t)
	if err := template.LoadStandardCatalog(context.Background(), catalogPath(), r); err != nil {
		t.Fatalf("LoadStandardCatalog: real production catalog failed constraint validation: %v", err)
	}
}

// TestLoadStandardCatalog_constraintViolation_returnsError proves a catalog
// entry violating a declared CEL/buf.validate constraint — here,
// AesGcmParams.tag_size_bits outside its declared {96,104,112,120,128} set —
// fails LoadStandardCatalog with a clear error instead of loading
// successfully and only being caught later (if at all) deep inside provider
// code.
func TestLoadStandardCatalog_constraintViolation_returnsError(t *testing.T) {
	badCatalog := `{
		"version": "0.1.0",
		"templates": {
			"bad-aes-gcm": {
				"templateId": "bad-aes-gcm",
				"algorithm": {
					"primitive": "CRYPTO_PRIMITIVE_AE",
					"aesGcm": {
						"keySizeBits": 256,
						"ivSizeBits": 96,
						"tagSizeBits": 127
					}
				},
				"scopedCapabilities": [
					{
						"scope": {"aead": {"scope": "AEAD_SCOPE_STANDARD"}},
						"operations": ["CRYPTO_OPERATION_ENCRYPT", "CRYPTO_OPERATION_DECRYPT"]
					}
				],
				"status": "TEMPLATE_STATUS_ACTIVE"
			}
		}
	}`
	catalogFile := filepath.Join(t.TempDir(), "bad_catalog.json")
	if err := os.WriteFile(catalogFile, []byte(badCatalog), 0o600); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	r := newTestRegistry(t)
	err := template.LoadStandardCatalog(context.Background(), catalogFile, r)
	if err == nil {
		t.Fatal("expected error for tag_size_bits=127, not one of the proto's allowed values")
	}
	t.Logf("correctly rejected: %v", err)

	if _, getErr := r.Get(context.Background(), "bad-aes-gcm"); getErr == nil {
		t.Error("invalid template should not have been registered")
	}
}

// TestLoadStandardCatalog_validEntry_stillLoads is the negative control for
// TestLoadStandardCatalog_constraintViolation_returnsError — proves the same
// catalog shape with a valid tag_size_bits loads successfully, so the error
// above is genuinely caused by the constraint violation, not some other
// defect in the minimal catalog JSON used for that test.
func TestLoadStandardCatalog_validEntry_stillLoads(t *testing.T) {
	goodCatalog := `{
		"version": "0.1.0",
		"templates": {
			"good-aes-gcm": {
				"templateId": "good-aes-gcm",
				"algorithm": {
					"primitive": "CRYPTO_PRIMITIVE_AE",
					"aesGcm": {
						"keySizeBits": 256,
						"ivSizeBits": 96,
						"tagSizeBits": 128
					}
				},
				"scopedCapabilities": [
					{
						"scope": {"aead": {"scope": "AEAD_SCOPE_STANDARD"}},
						"operations": ["CRYPTO_OPERATION_ENCRYPT", "CRYPTO_OPERATION_DECRYPT"]
					}
				],
				"status": "TEMPLATE_STATUS_ACTIVE"
			}
		}
	}`
	catalogFile := filepath.Join(t.TempDir(), "good_catalog.json")
	if err := os.WriteFile(catalogFile, []byte(goodCatalog), 0o600); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	r := newTestRegistry(t)
	if err := template.LoadStandardCatalog(context.Background(), catalogFile, r); err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}
	if _, getErr := r.Get(context.Background(), "good-aes-gcm"); getErr != nil {
		t.Errorf("valid template should have been registered: %v", getErr)
	}
}
