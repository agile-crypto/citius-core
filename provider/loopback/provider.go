// Package loopback provides a deterministic provider.Backend implementation for testing.
// It does not perform real cryptography. Never use in production.
//
// The loopback provider is designed to make integration tests hermetic and deterministic:
//   - GenerateKey returns synthetic fixed bytes ("LOOPBACK_PUB", "LOOPBACK_PRIV")
//   - Sign echoes the input bytes as the signature
//   - Verify returns true iff signature == input (the loopback invariant)
//
// This allows verifying the full CreateKey=>Sign=>Verify flow without any real crypto.
package loopback

import (
	"bytes"
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// Provider is a loopback provider.Backend implementation.
// Sign echoes the input as the signature; Verify checks input == signature.
type Provider struct{}

// New returns a new loopback Provider.
func New() *Provider { return &Provider{} }

// Name returns the provider's unique name.
func (p *Provider) Name() string { return "loopback" }

// Type returns the provider type identifier.
func (p *Provider) Type() string { return "loopback" }

// SupportedAlgorithms returns the algorithm IDs this provider handles.
// IDs must exactly match TemplateID values in the standard algorithm catalog JSON.
func (p *Provider) SupportedAlgorithms() []string {
	return []string{"ecdsa-p256-sha256-der", "ml-dsa-65"}
}

// GenerateKey returns synthetic deterministic bytes — no real key material.
func (p *Provider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes: []byte("LOOPBACK_PUB"),
		KeyMaterial:    []byte("LOOPBACK_PRIV"),
		Output:         provider.NoOutput("raw"),
	}, nil
}

// DestroyKey is a no-op for the loopback provider.
func (p *Provider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}

// ExportPublicKey returns deterministic public key bytes.
func (p *Provider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{
		PublicKeyBytes: []byte("LOOPBACK_PUB"),
		Output:         provider.NoOutput("raw"),
	}, nil
}

// Sign echoes the input as the "signature".
// This makes round-trip testing trivial: Verify succeeds when signature == input.
func (p *Provider) Sign(_ context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Signature: req.GetInput(), Output: provider.NoOutput("raw")}, nil
}

// Verify returns valid=true when signature == input (the loopback invariant from Sign).
func (p *Provider) Verify(_ context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{
		Valid:  bytes.Equal(req.GetSignature(), req.GetInput()),
		Output: provider.NoOutputUnencoded(),
	}, nil
}

// SignDigest echoes the digest as the "signature" (loopback invariant).
func (p *Provider) SignDigest(_ context.Context, req *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return &providerpb.SignDigestResponse{Signature: req.GetDigest(), Output: provider.NoOutput("raw")}, nil
}

// VerifyDigest returns valid=true when signature == digest (loopback invariant).
func (p *Provider) VerifyDigest(_ context.Context, req *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return &providerpb.VerifyDigestResponse{
		Valid:  bytes.Equal(req.GetSignature(), req.GetDigest()),
		Output: provider.NoOutputUnencoded(),
	}, nil
}

// Encrypt echoes the plaintext as ciphertext (loopback — not real encryption).
func (p *Provider) Encrypt(_ context.Context, req *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return &providerpb.EncryptResponse{
		Ciphertext: req.GetPlaintext(),
		Output:     provider.NoOutput("raw"),
	}, nil
}

// Decrypt echoes the ciphertext as plaintext (loopback — not real decryption).
func (p *Provider) Decrypt(_ context.Context, req *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return &providerpb.DecryptResponse{
		Plaintext: req.GetCiphertext(),
		Output:    provider.NoOutputUnencoded(),
	}, nil
}

// ProviderInfo describes the loopback provider. It has no version of its own
// and no default implementation: it performs no cryptography, so it can
// substantiate no implementation property.
func (p *Provider) ProviderInfo() *providerpb.ProviderInfo {
	return &providerpb.ProviderInfo{
		Name:         "Loopback (testing only)",
		Type:         p.Type(),
		Description:  "Deterministic in-process test provider. It performs no real cryptography; never use it in production.",
		ProviderType: types.ProviderType_PROVIDER_TYPE_SOFTWARE,
	}
}

// Compile-time assertions.
var (
	_ provider.Backend                     = (*Provider)(nil)
	_ provider.Signer                      = (*Provider)(nil)
	_ provider.Cipher                      = (*Provider)(nil)
	_ provider.AlgorithmCapabilityProvider = (*Provider)(nil)
	_ provider.Describer                   = (*Provider)(nil)
)
