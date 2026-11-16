package software_test

import (
	"context"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Compile-time assertion: Provider implements provider.Backend.
var _ provider.Backend = (*software.Provider)(nil)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*software.Provider)(nil)

// Compile-time assertion: Provider implements ImplementationDescriber.
var _ provider.ImplementationDescriber = (*software.Provider)(nil)

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNew_notNil(t *testing.T) {
	p := software.New()
	if p == nil {
		t.Fatal("software.New() returned nil")
	}
}

// ============================================================================
// Identity Tests
// ============================================================================

func TestProvider_Name(t *testing.T) {
	p := software.New()
	if got := p.Name(); got != "software" {
		t.Errorf("Name: got %q want %q", got, "software")
	}
}

func TestProvider_Type(t *testing.T) {
	p := software.New()
	if got := p.Type(); got != "software" {
		t.Errorf("Type: got %q want %q", got, "software")
	}
}

// ============================================================================
// ImplementationProperties Tests
// ============================================================================

func TestProvider_ImplementationProperties(t *testing.T) {
	p := software.New()
	props := p.ImplementationProperties()

	if got := props.GetImplementationLanguage(); got != "go" {
		t.Errorf("ImplementationLanguage: got %q want %q", got, "go")
	}
	if !props.GetMemorySafeLanguage() {
		t.Error("MemorySafeLanguage: got false, want true (Go's standard crypto library + circl)")
	}
	if props.GetFips_140() != nil {
		t.Errorf("Fips_140: got %v, want nil — software provider has no FIPS certification to report", props.GetFips_140())
	}
}

func TestProvider_ProviderInfo(t *testing.T) {
	p := software.New()
	info := provider.InfoOf(p)

	if info.GetType() != p.Type() || info.GetName() == "" || info.GetDescription() == "" {
		t.Errorf("identity: type %q name %q description %q", info.GetType(), info.GetName(), info.GetDescription())
	}
	if info.GetVersion() != runtime.Version() {
		t.Errorf("Version: got %q want %q", info.GetVersion(), runtime.Version())
	}
	if info.GetProviderType() != api.ProviderType_PROVIDER_TYPE_SOFTWARE {
		t.Errorf("ProviderType: got %v want SOFTWARE", info.GetProviderType())
	}
	if !proto.Equal(info.GetDefaultImplementation(), p.ImplementationProperties()) {
		t.Errorf("DefaultImplementation %v differs from the only instance's %v",
			info.GetDefaultImplementation(), p.ImplementationProperties())
	}
}

// ============================================================================
// SupportedAlgorithms Tests
// ============================================================================

func TestProvider_SupportedAlgorithms_hasKeyAlgorithms(t *testing.T) {
	p := software.New()
	algs := p.SupportedAlgorithms()

	ids := make(map[string]bool)
	for _, id := range algs {
		ids[id] = true
	}

	// A representative sample across every family SupportedAlgorithms
	// advertises — not exhaustive (see
	// TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches
	// for exhaustive, dispatch-verified coverage).
	for _, want := range []string{
		"ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ecdsa-p521-sha512-der",
		"rsa-pss-sha256-mgf1-32-2048", "rsa-pkcs1v15-sha256-2048",
		"ed25519", "ed25519ph",
		"ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
		"aes-128-gcm-128-96", "aes-256-gcm-128-96",
	} {
		if !ids[want] {
			t.Errorf("missing %s from SupportedAlgorithms", want)
		}
	}
}

// standardCatalogPath returns the absolute path to the standard_algorithms.json
// catalog, mirroring the identically-named helper in internal/template's own
// tests (that package's helper is unexported and this one lives in a
// different package, so it cannot be reused directly).
func standardCatalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "data", "standard_algorithms.json")
}

// assertAdvertisesGeneratedEncoding checks that the stored-payload encoding
// p advertises for alg is the one GenerateKey emitted in genResp, and that
// the key material really is in it: a core switching a key onto or off p
// acts on the advertisement.
func assertAdvertisesGeneratedEncoding(t *testing.T, p *software.Provider, alg *api.AlgorithmDetails, genResp *providerpb.GenerateKeyResponse) {
	t.Helper()
	requireEncodedAs(t, genResp.GetKeyMaterialEncoding(), genResp.GetKeyMaterial())
	stored := provider.TransferOf(p, alg)
	want := []providerpb.PrivateKeyEncoding{genResp.GetKeyMaterialEncoding()}
	if !slices.Equal(stored.Emit.StoredPayload, want) || !slices.Equal(stored.Accept.StoredPayload, want) {
		t.Errorf("stored payload: emits %v, accepts %v; GenerateKey emitted %v",
			stored.Emit.StoredPayload, stored.Accept.StoredPayload, want)
	}
}

// TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches is
// the regression guard for the SupportedAlgorithms/dispatch-switch
// consistency bug: every template ID this provider advertises must (a)
// exist in the real production catalog, (b) succeed at GenerateKey via the
// real provider, and (c) complete a real Sign+Verify or Encrypt+Decrypt
// round trip through that same key — not just compile, and not just
// generate a key that then has no working operation. Before GenerateKey
// coverage existed, provider.Registry.Match could route CreateKey
// to this provider for a template whose algorithm the dispatch switches
// didn't actually implement — or the reverse, silently blocking CreateKey
// for an algorithm that fully works once a key exists. The round-trip
// assertions close the next gap in that same class: a template whose
// GenerateKey arm exists but whose Sign/Verify or Encrypt/Decrypt arm was
// never wired up (or was wired up but broken) would still pass a
// GenerateKey-only check.
func TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches(t *testing.T) {
	data, err := os.ReadFile(standardCatalogPath())
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	ctx := context.Background()
	// Parse the catalog proto-JSON directly rather than via
	// internal/template.ParseStandardCatalog: this test package
	// (internal/provider/software) is not allowed to import internal/template
	// (sibling bounded contexts, enforced by depguard), and this is the same
	// protojson.Unmarshal call that function itself makes.
	catalog := &api.StandardAlgorithmCatalog{}
	if err = protojson.Unmarshal(data, catalog); err != nil {
		t.Fatalf("protojson.Unmarshal catalog: %v", err)
	}
	templates := catalog.GetTemplates()

	p := software.New()
	for _, id := range p.SupportedAlgorithms() {
		t.Run(id, func(t *testing.T) {
			tmpl, ok := templates[id]
			if !ok {
				t.Fatalf("%s: advertised in SupportedAlgorithms but not found in the standard catalog", id)
			}
			alg := tmpl.GetAlgorithm()
			genResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			assertAdvertisesGeneratedEncoding(t, p, alg, genResp)

			switch a := alg.GetAlgorithm().(type) {
			case *api.AlgorithmDetails_Ed25519:
				// Ed25519ph is the one signature variant Sign/Verify
				// rejects outright (signEd25519 requires the pure/ctx
				// variants) — it is only reachable via SignDigest/
				// VerifyDigest with a real SHA-512 digest, see
				// checkEd25519PHHash.
				if a.Ed25519.GetVariant() == api.Ed25519Variant_ED25519_VARIANT_PH {
					assertSignVerifyDigestRoundTrip(t, p, genResp, alg)
				} else {
					assertSignVerifyRoundTrip(t, p, genResp, alg)
				}
			case *api.AlgorithmDetails_Ecdsa, *api.AlgorithmDetails_RsaPss, *api.AlgorithmDetails_RsaPkcs1V15,
				*api.AlgorithmDetails_MlDsa:
				assertSignVerifyRoundTrip(t, p, genResp, alg)
			case *api.AlgorithmDetails_AesGcm, *api.AlgorithmDetails_Chacha20Poly1305:
				assertAEADEncryptDecryptRoundTrip(t, p, genResp, alg)
			case *api.AlgorithmDetails_AesCbc, *api.AlgorithmDetails_AesCtr:
				assertBlockCipherEncryptDecryptRoundTrip(t, p, genResp, alg)
			default:
				t.Fatalf("unhandled AlgorithmDetails oneof type %T for %s — add a dispatch-arm assertion for it", alg.GetAlgorithm(), id)
			}
		})
	}
}

// assertSignVerifyRoundTrip signs a fixed payload and verifies it under the
// same key, for the asymmetric families TestProvider_SupportedAlgorithms_
// everyEntryMatchesCatalogAndDispatches routes here. ScopeParams is left
// unset (matches every other Sign/Verify test in this package) — the proto
// has no CEL rule requiring one of its oneof options to be set.
func assertSignVerifyRoundTrip(t *testing.T, p *software.Provider, genResp *providerpb.GenerateKeyResponse, alg *api.AlgorithmDetails) {
	t.Helper()
	ctx := context.Background()
	payload := []byte("dispatch-arm coverage payload")

	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Input:               payload,
		Algorithm:           alg,
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: genResp.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signResp.GetSignature(),
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("Verify: expected valid=true for a signature just produced by Sign")
	}
}

// assertSignVerifyDigestRoundTrip is assertSignVerifyRoundTrip's SignDigest/
// VerifyDigest analogue, for the one signature variant (Ed25519ph) that
// Sign/Verify rejects outright — see checkEd25519PHHash, which requires a
// real SHA-512 digest, not an arbitrary byte string.
func assertSignVerifyDigestRoundTrip(t *testing.T, p *software.Provider, genResp *providerpb.GenerateKeyResponse, alg *api.AlgorithmDetails) {
	t.Helper()
	ctx := context.Background()
	digest := sha512.Sum512([]byte("dispatch-arm coverage payload"))

	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial:         genResp.GetKeyMaterial(),
		Digest:              digest[:],
		HashAlgorithm:       api.HashAlgorithm_HASH_ALGORITHM_SHA512,
		Algorithm:           alg,
		KeyMaterialEncoding: genResp.GetKeyMaterialEncoding(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial:   genResp.GetPublicKeyBytes(),
		Digest:        digest[:],
		HashAlgorithm: api.HashAlgorithm_HASH_ALGORITHM_SHA512,
		Signature:     signResp.GetSignature(),
		Algorithm:     alg,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("VerifyDigest: expected valid=true for a signature just produced by SignDigest")
	}
}

// assertAEADEncryptDecryptRoundTrip covers the AEAD cipher families
// (AES-GCM, ChaCha20-Poly1305/XChaCha20-Poly1305), which read AeadParams.
func assertAEADEncryptDecryptRoundTrip(t *testing.T, p *software.Provider, genResp *providerpb.GenerateKeyResponse, alg *api.AlgorithmDetails) {
	t.Helper()
	ctx := context.Background()
	plaintext := []byte("dispatch-arm coverage payload")

	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: &providerpb.EncryptRequest_AeadParams{AeadParams: &api.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decResp, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Output:      encResp.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &api.AeadEncryptParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.GetPlaintext()) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decResp.GetPlaintext(), plaintext)
	}
}

// assertBlockCipherEncryptDecryptRoundTrip covers the non-AEAD block cipher
// families (AES-CBC, AES-CTR), which read NoParams instead of AeadParams.
func assertBlockCipherEncryptDecryptRoundTrip(t *testing.T, p *software.Provider, genResp *providerpb.GenerateKeyResponse, alg *api.AlgorithmDetails) {
	t.Helper()
	ctx := context.Background()
	plaintext := []byte("dispatch-arm coverage payload")

	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &api.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decResp, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Output:      encResp.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &api.NoParams{}},
		Algorithm:   alg,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.GetPlaintext()) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decResp.GetPlaintext(), plaintext)
	}
}

// ============================================================================
// DestroyKey Tests (no-op for stateless provider)
// ============================================================================

func TestProvider_DestroyKey_noopReturnsNil(t *testing.T) {
	p := software.New()
	// DestroyKey is a no-op for stateless provider - always succeeds
	resp, err := p.DestroyKey(context.Background(), &providerpb.DestroyKeyRequest{KeyMaterial: []byte("any")})
	if err != nil {
		t.Errorf("DestroyKey: unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("DestroyKey: expected non-nil response")
	}
}

// ============================================================================
// ExportPublicKey Tests
// ============================================================================

func TestProvider_ExportPublicKey_returnsNotImplemented(t *testing.T) {
	p := software.New()
	_, err := p.ExportPublicKey(context.Background(), &providerpb.ExportPublicKeyRequest{KeyMaterial: []byte("any")})
	if err == nil {
		t.Fatal("expected error from ExportPublicKey (stateless provider)")
	}
	// TODO: Stateless provider doesn't return keys for now - ExportPublicKey is not supported
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// pkcs8 is the outer structure of a PKCS#8 PrivateKeyInfo (RFC 5208), enough
// to tell PKCS#8 from other encodings for any key type.
type pkcs8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// requireEncodedAs fails unless key parses in encoding.
func requireEncodedAs(t *testing.T, encoding providerpb.PrivateKeyEncoding, key []byte) {
	t.Helper()
	var err error
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1:
		_, err = x509.ParseECPrivateKey(key)
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8:
		var info pkcs8
		var rest []byte
		if rest, err = asn1.Unmarshal(key, &info); err == nil && len(rest) > 0 {
			err = fmt.Errorf("%d trailing bytes", len(rest))
		}
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW:
		if n := len(key); n != 16 && n != 24 && n != 32 {
			err = fmt.Errorf("%d bytes is no symmetric key size", n)
		}
	default:
		err = fmt.Errorf("unexpected encoding %s", encoding)
	}
	if err != nil {
		t.Errorf("key material is not %s: %v", encoding, err)
	}
}
