package template_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agile-crypto/citius-core/template"
)

// newTestRegistry creates an in-memory fakeRegistry for tests.
func newTestRegistry(t *testing.T) template.Registry {
	t.Helper()
	return newFakeRegistry()
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
