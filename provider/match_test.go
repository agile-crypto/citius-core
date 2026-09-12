package provider_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"google.golang.org/protobuf/proto"
)

// capableProvider is a stub ProviderInstance that supports a set of algorithm IDs.
type capableProvider struct {
	name       string
	algorithms []string // algorithm IDs this provider supports
}

func (c *capableProvider) Name() string { return c.name }
func (c *capableProvider) Type() string { return "stub" }
func (c *capableProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (c *capableProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (c *capableProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (c *capableProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Output: provider.NoOutput("raw")}, nil
}
func (c *capableProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (c *capableProvider) SignDigest(_ context.Context, _ *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return &providerpb.SignDigestResponse{Output: provider.NoOutput("raw")}, nil
}
func (c *capableProvider) VerifyDigest(_ context.Context, _ *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return &providerpb.VerifyDigestResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (c *capableProvider) Encrypt(_ context.Context, _ *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return &providerpb.EncryptResponse{Output: provider.NoOutput("raw")}, nil
}
func (c *capableProvider) Decrypt(_ context.Context, _ *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return &providerpb.DecryptResponse{Output: provider.NoOutputUnencoded()}, nil
}

// SupportedAlgorithms returns the algorithm IDs this provider handles.
// Used by MatchForTemplate for matching.
func (c *capableProvider) SupportedAlgorithms() []string { return c.algorithms }

var _ provider.Backend = (*capableProvider)(nil)

// describingProvider adds ImplementationDescriber to capableProvider, so
// Match tests can exercise the hard filter and soft score against a
// Backend, not just score's own unit tests in match_internal_test.go.
type describingProvider struct {
	capableProvider
	props *types.ImplementationProperties
}

func (d *describingProvider) ImplementationProperties() *types.ImplementationProperties {
	return d.props
}

var _ provider.ImplementationDescriber = (*describingProvider)(nil)

// ============================================================================
// Match (template-only) Tests
// ============================================================================
//
// Requirements{TemplateID: id} with nothing else set — the shape the deleted
// MatchForTemplate wrapper used to build internally.

func TestRegistry_Match_templateOnly_found(t *testing.T) {
	r := provider.NewRegistry()

	p := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256", "ml-dsa-65"},
	}
	_ = r.Register(t.Context(), p)

	got, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ecdsa-p256-sha256"})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if got == nil {
		t.Fatal("Match returned nil provider")
	}
	if got.Name() != "software" {
		t.Errorf("Match: got provider %q want %q", got.Name(), "software")
	}
}

func TestRegistry_Match_templateOnly_notFound(t *testing.T) {
	r := provider.NewRegistry()

	p := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	_ = r.Register(t.Context(), p)

	_, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ml-dsa-65"}) // not in capabilities
	if err == nil {
		t.Fatal("expected error for unmatched template")
	}
}

func TestRegistry_Match_templateOnly_noProviders_returnsError(t *testing.T) {
	r := provider.NewRegistry()
	_, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ecdsa-p256-sha256"})
	if err == nil {
		t.Fatal("expected error when no providers registered")
	}
}

func TestRegistry_Match_templateOnly_multipleProviders_firstMatchReturned(t *testing.T) {
	r := provider.NewRegistry()

	p1 := &capableProvider{
		name:       "loopback",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	p2 := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	_ = r.Register(t.Context(), p1)
	_ = r.Register(t.Context(), p2)

	// Both match; loopback was registered first
	got, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ecdsa-p256-sha256"})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if got.Name() != "loopback" {
		t.Errorf("expected first-registered provider, got %q", got.Name())
	}
}

func TestRegistry_Match_templateOnly_providerWithoutSupportedAlgorithms_skipped(t *testing.T) {
	// A provider that doesn't implement SupportedAlgorithms() should be skipped,
	// not cause Match to fail.
	r := provider.NewRegistry()

	// minimalProvider doesn't have SupportedAlgorithms() — should be skipped
	minimal := &minimalProvider{provName: "no-caps"}
	good := &capableProvider{
		name:       "good",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	_ = r.Register(t.Context(), minimal)
	_ = r.Register(t.Context(), good)

	got, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ecdsa-p256-sha256"})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if got.Name() != "good" {
		t.Errorf("expected to skip provider without SupportedAlgorithms, got %q", got.Name())
	}
}

func TestRegistry_Match_templateOnly_afterRemove_evictsIndex(t *testing.T) {
	r := provider.NewRegistry()

	// A second, unrelated provider stays registered throughout, so r.order
	// never empties out — this forces Match through the byTemplate lookup
	// instead of short-circuiting on the "no providers registered"
	// empty-registry case, which would mask a broken eviction.
	other := &capableProvider{
		name:       "openssl",
		algorithms: []string{"aes-256-gcm-128-96"},
	}
	if err := r.Register(t.Context(), other); err != nil {
		t.Fatalf("Register other: %v", err)
	}

	p := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256", "ml-dsa-65"},
	}
	if err := r.Register(t.Context(), p); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ecdsa-p256-sha256"}); err != nil {
		t.Fatalf("Match before Remove: %v", err)
	}

	if err := r.Remove(t.Context(), "software"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	_, err := r.Match(t.Context(), provider.Requirements{TemplateID: "ecdsa-p256-sha256"})
	if err == nil {
		t.Fatal("expected error: provider was removed, template should no longer match")
	}
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected CodeProviderNotFound, got: %v", err)
	}

	// The unrelated provider's own template must still match — proves Remove
	// evicted exactly "software"'s entries, not the whole index.
	got, err := r.Match(t.Context(), provider.Requirements{TemplateID: "aes-256-gcm-128-96"})
	if err != nil {
		t.Fatalf("Match for surviving provider: %v", err)
	}
	if got.Name() != "openssl" {
		t.Errorf("expected surviving provider %q, got %q", "openssl", got.Name())
	}
}

// minimalProvider is a ProviderInstance without SupportedAlgorithms().
// Used to test that Match gracefully skips such providers.
type minimalProvider struct{ provName string }

func (m *minimalProvider) Name() string { return m.provName }
func (m *minimalProvider) Type() string { return "minimal" }
func (m *minimalProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *minimalProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (m *minimalProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *minimalProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *minimalProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (m *minimalProvider) SignDigest(_ context.Context, _ *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return &providerpb.SignDigestResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *minimalProvider) VerifyDigest(_ context.Context, _ *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return &providerpb.VerifyDigestResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (m *minimalProvider) Encrypt(_ context.Context, _ *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return &providerpb.EncryptResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *minimalProvider) Decrypt(_ context.Context, _ *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return &providerpb.DecryptResponse{Output: provider.NoOutputUnencoded()}, nil
}

var _ provider.Backend = (*minimalProvider)(nil)

// ============================================================================
// Match Tests
// ============================================================================

func TestRegistry_Match_pinnedProvider_honoured(t *testing.T) {
	r := provider.NewRegistry()
	loopback := &capableProvider{name: "loopback", algorithms: []string{"ecdsa-p256-sha256"}}
	software := &capableProvider{name: "software", algorithms: []string{"ecdsa-p256-sha256"}}
	_ = r.Register(t.Context(), loopback)
	_ = r.Register(t.Context(), software)

	got, err := r.Match(t.Context(), provider.Requirements{
		TemplateID:   "ecdsa-p256-sha256",
		ProviderName: "software",
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if got.Name() != "software" {
		t.Errorf("expected pinned provider %q, got %q — a pin must not silently fall back", "software", got.Name())
	}
}

func TestRegistry_Match_pinnedProvider_notRegistered_errors(t *testing.T) {
	r := provider.NewRegistry()

	_, err := r.Match(t.Context(), provider.Requirements{
		TemplateID:   "ecdsa-p256-sha256",
		ProviderName: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for a pinned provider that was never registered")
	}
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected CodeProviderNotFound, got: %v", err)
	}
}

func TestRegistry_Match_pinnedProvider_doesNotSupportTemplate_errors(t *testing.T) {
	r := provider.NewRegistry()
	_ = r.Register(t.Context(), &capableProvider{name: "software", algorithms: []string{"ml-dsa-65"}})

	_, err := r.Match(t.Context(), provider.Requirements{
		TemplateID:   "ecdsa-p256-sha256", // not in "software"'s algorithms
		ProviderName: "software",
	})
	if err == nil {
		t.Fatal("expected error: pinned provider does not advertise the requested template, must not fall back to another provider")
	}
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected CodeProviderNotFound, got: %v", err)
	}
}

func TestRegistry_Match_pinnedProvider_failsHardFilter_errors(t *testing.T) {
	r := provider.NewRegistry()
	nonFIPS := &describingProvider{
		capableProvider: capableProvider{name: "software", algorithms: []string{"aes-256-gcm-128-96"}},
		props:           &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)},
	}
	_ = r.Register(t.Context(), nonFIPS)

	_, err := r.Match(t.Context(), provider.Requirements{
		TemplateID:   "aes-256-gcm-128-96",
		ProviderName: "software",
		Security:     &core.SecurityProperties{FipsApproved: true},
	})
	if err == nil {
		t.Fatal("expected error: pinned provider cannot substantiate FIPS, must not silently succeed anyway")
	}
	if !errors.IsFailedPrecondition(err) {
		t.Errorf("expected CodeFailedPrecondition, got: %v", err)
	}
}

// TestRegistry_Match_fipsRequired_flipsSelectionToFIPSInstance is the
// scenario this whole matching mechanism exists for: software is registered
// first (as wire.go does) and would win a plain first-match scan, but when
// the caller requires FIPS, only the FIPS-mode instance can serve — and it
// must win even though it registered second.
func TestRegistry_Match_fipsRequired_flipsSelectionToFIPSInstance(t *testing.T) {
	r := provider.NewRegistry()

	software := &describingProvider{
		capableProvider: capableProvider{name: "software", algorithms: []string{"aes-256-gcm-128-96"}},
		props:           &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)},
	}
	opensslFIPS := &describingProvider{
		capableProvider: capableProvider{name: "openssl-fips", algorithms: []string{"aes-256-gcm-128-96"}},
		props: &types.ImplementationProperties{
			Fips_140:            &types.Fips140Certification{Certified: true},
			HardwareAccelerated: proto.Bool(true),
		},
	}

	if err := r.Register(t.Context(), software); err != nil {
		t.Fatalf("Register software: %v", err)
	}
	if err := r.Register(t.Context(), opensslFIPS); err != nil {
		t.Fatalf("Register openssl-fips: %v", err)
	}

	// No security requirement: registration order wins, same as before.
	got, err := r.Match(t.Context(), provider.Requirements{TemplateID: "aes-256-gcm-128-96"})
	if err != nil {
		t.Fatalf("Match (no requirement): %v", err)
	}
	if got.Name() != "software" {
		t.Fatalf("Match (no requirement): expected first-registered %q, got %q", "software", got.Name())
	}

	// FIPS required: selection flips to the second-registered FIPS instance.
	got, err = r.Match(t.Context(), provider.Requirements{
		TemplateID: "aes-256-gcm-128-96",
		Security:   &core.SecurityProperties{FipsApproved: true},
	})
	if err != nil {
		t.Fatalf("Match (FIPS required): %v", err)
	}
	if got.Name() != "openssl-fips" {
		t.Errorf("Match (FIPS required): expected %q, got %q", "openssl-fips", got.Name())
	}
}
