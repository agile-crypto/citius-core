package provider_test

import (
	"context"
	"reflect"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
)

// bareBackend implements provider.Backend and nothing else — the baseline
// for proving HasCapability returns false when no optional interface is met.
type bareBackend struct{}

func (bareBackend) Name() string { return "bare" }
func (bareBackend) Type() string { return "bare" }
func (bareBackend) GenerateKey(context.Context, *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return nil, nil
}
func (bareBackend) DestroyKey(context.Context, *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return nil, nil
}
func (bareBackend) ExportPublicKey(context.Context, *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return nil, nil
}

type signerBackend struct{ bareBackend }

func (signerBackend) Sign(context.Context, *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return nil, nil
}
func (signerBackend) Verify(context.Context, *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return nil, nil
}
func (signerBackend) SignDigest(context.Context, *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return nil, nil
}
func (signerBackend) VerifyDigest(context.Context, *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return nil, nil
}

type cipherBackend struct{ bareBackend }

func (cipherBackend) Encrypt(context.Context, *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return nil, nil
}
func (cipherBackend) Decrypt(context.Context, *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return nil, nil
}

type macerBackend struct{ bareBackend }

func (macerBackend) GenerateMac(context.Context, *providerpb.GenerateMacRequest) (*providerpb.GenerateMacResponse, error) {
	return nil, nil
}
func (macerBackend) VerifyMac(context.Context, *providerpb.VerifyMacRequest) (*providerpb.VerifyMacResponse, error) {
	return nil, nil
}

type hasherBackend struct{ bareBackend }

func (hasherBackend) Digest(context.Context, *providerpb.DigestRequest) (*providerpb.DigestResponse, error) {
	return nil, nil
}
func (hasherBackend) Xof(context.Context, *providerpb.XofRequest) (*providerpb.XofResponse, error) {
	return nil, nil
}

type randomizerBackend struct{ bareBackend }

func (randomizerBackend) GenerateRandom(context.Context, *providerpb.GenerateRandomRequest) (*providerpb.GenerateRandomResponse, error) {
	return nil, nil
}
func (randomizerBackend) SeedRandom(context.Context, *providerpb.SeedRandomRequest) (*providerpb.SeedRandomResponse, error) {
	return nil, nil
}

type keyEstablisherBackend struct{ bareBackend }

func (keyEstablisherBackend) WrapKey(context.Context, *providerpb.WrapKeyRequest) (*providerpb.WrapKeyResponse, error) {
	return nil, nil
}
func (keyEstablisherBackend) UnwrapKey(context.Context, *providerpb.UnwrapKeyRequest) (*providerpb.UnwrapKeyResponse, error) {
	return nil, nil
}
func (keyEstablisherBackend) DeriveKey(context.Context, *providerpb.DeriveKeyRequest) (*providerpb.DeriveKeyResponse, error) {
	return nil, nil
}
func (keyEstablisherBackend) KeyAgreement(context.Context, *providerpb.KeyAgreementRequest) (*providerpb.KeyAgreementResponse, error) {
	return nil, nil
}
func (keyEstablisherBackend) EncapsulateKey(context.Context, *providerpb.EncapsulateKeyRequest) (*providerpb.EncapsulateKeyResponse, error) {
	return nil, nil
}
func (keyEstablisherBackend) DecapsulateKey(context.Context, *providerpb.DecapsulateKeyRequest) (*providerpb.DecapsulateKeyResponse, error) {
	return nil, nil
}

// compile-time checks: each stub implements exactly the interface it claims.
var (
	_ provider.Backend        = bareBackend{}
	_ provider.Signer         = signerBackend{}
	_ provider.Cipher         = cipherBackend{}
	_ provider.Macer          = macerBackend{}
	_ provider.Hasher         = hasherBackend{}
	_ provider.Randomizer     = randomizerBackend{}
	_ provider.KeyEstablisher = keyEstablisherBackend{}
)

func TestHasCapability(t *testing.T) {
	allCaps := []provider.Capability{
		provider.CapabilitySign, provider.CapabilityCipher, provider.CapabilityMac,
		provider.CapabilityHash, provider.CapabilityRandom, provider.CapabilityKeyEstablish,
	}

	tests := []struct {
		name string
		b    provider.Backend
		want provider.Capability // "" means the backend satisfies none of allCaps
	}{
		{"bare", bareBackend{}, ""},
		{"signer", signerBackend{}, provider.CapabilitySign},
		{"cipher", cipherBackend{}, provider.CapabilityCipher},
		{"macer", macerBackend{}, provider.CapabilityMac},
		{"hasher", hasherBackend{}, provider.CapabilityHash},
		{"randomizer", randomizerBackend{}, provider.CapabilityRandom},
		{"keyEstablisher", keyEstablisherBackend{}, provider.CapabilityKeyEstablish},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range allCaps {
				got := provider.HasCapability(tt.b, c)
				want := c == tt.want
				if got != want {
					t.Errorf("HasCapability(%s, %s) = %v, want %v", tt.name, c, got, want)
				}
			}
		})
	}
}

func TestCapabilityForOperation(t *testing.T) {
	tests := []struct {
		op     types.CryptoOperation
		want   provider.Capability
		wantOK bool
	}{
		{types.CryptoOperation_CRYPTO_OPERATION_SIGN, provider.CapabilitySign, true},
		{types.CryptoOperation_CRYPTO_OPERATION_VERIFY, provider.CapabilitySign, true},
		{types.CryptoOperation_CRYPTO_OPERATION_DIGEST_SIGN, provider.CapabilitySign, true},
		{types.CryptoOperation_CRYPTO_OPERATION_DIGEST_VERIFY, provider.CapabilitySign, true},
		{types.CryptoOperation_CRYPTO_OPERATION_ENCRYPT, provider.CapabilityCipher, true},
		{types.CryptoOperation_CRYPTO_OPERATION_DECRYPT, provider.CapabilityCipher, true},
		{types.CryptoOperation_CRYPTO_OPERATION_GENERATE_MAC, provider.CapabilityMac, true},
		{types.CryptoOperation_CRYPTO_OPERATION_VERIFY_MAC, provider.CapabilityMac, true},
		{types.CryptoOperation_CRYPTO_OPERATION_DIGEST, provider.CapabilityHash, true},
		{types.CryptoOperation_CRYPTO_OPERATION_GENERATE_RANDOM, provider.CapabilityRandom, true},
		{types.CryptoOperation_CRYPTO_OPERATION_SEED_RANDOM, provider.CapabilityRandom, true},
		{types.CryptoOperation_CRYPTO_OPERATION_WRAP_KEY, provider.CapabilityKeyEstablish, true},
		{types.CryptoOperation_CRYPTO_OPERATION_UNWRAP_KEY, provider.CapabilityKeyEstablish, true},
		{types.CryptoOperation_CRYPTO_OPERATION_DERIVE_KEY, provider.CapabilityKeyEstablish, true},
		{types.CryptoOperation_CRYPTO_OPERATION_KEY_AGREEMENT, provider.CapabilityKeyEstablish, true},
		{types.CryptoOperation_CRYPTO_OPERATION_ENCAPSULATE, provider.CapabilityKeyEstablish, true},
		{types.CryptoOperation_CRYPTO_OPERATION_DECAPSULATE, provider.CapabilityKeyEstablish, true},
		// Key-lifecycle and dual-function operations: not served by a capability interface.
		{types.CryptoOperation_CRYPTO_OPERATION_UNSPECIFIED, "", false},
		{types.CryptoOperation_CRYPTO_OPERATION_CREATE_KEY, "", false},
		{types.CryptoOperation_CRYPTO_OPERATION_ROTATE_KEY, "", false},
		{types.CryptoOperation_CRYPTO_OPERATION_DIGEST_ENCRYPT, "", false},
		{types.CryptoOperation_CRYPTO_OPERATION_SIGN_ENCRYPT, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.op.String(), func(t *testing.T) {
			got, ok := provider.CapabilityForOperation(tt.op)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("CapabilityForOperation(%s) = (%q, %v), want (%q, %v)",
					tt.op, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func scopedCaps(ops ...types.CryptoOperation) *types.ScopedCapabilities {
	return &types.ScopedCapabilities{Operations: ops}
}

func TestRequiredCapabilities(t *testing.T) {
	tests := []struct {
		name string
		caps []*types.ScopedCapabilities
		want []provider.Capability
	}{
		{
			name: "empty",
			caps: nil,
			want: []provider.Capability{},
		},
		{
			name: "single scope, single capability",
			caps: []*types.ScopedCapabilities{
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_ENCRYPT, types.CryptoOperation_CRYPTO_OPERATION_DECRYPT),
			},
			want: []provider.Capability{provider.CapabilityCipher},
		},
		{
			// Real shape: ml-dsa-65's two signature scopes (STANDARD, WITH_CONTEXT)
			// both need SIGN/VERIFY — must dedupe to one entry, not two.
			name: "ML-DSA-shaped: two signature scopes collapse to one capability",
			caps: []*types.ScopedCapabilities{
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_SIGN, types.CryptoOperation_CRYPTO_OPERATION_VERIFY),
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_SIGN, types.CryptoOperation_CRYPTO_OPERATION_VERIFY),
			},
			want: []provider.Capability{provider.CapabilitySign},
		},
		{
			// Real shape: a hybrid KEM+key-agreement template. ENCAPSULATE/
			// DECAPSULATE and KEY_AGREEMENT both map to KeyEstablish, so this
			// also collapses to one entry — every template in the current
			// catalog does, per docs/CAPABILITY_DISPATCH_PLAN.md.
			name: "hybrid-shaped: KEM + key-agreement scopes collapse to one capability",
			caps: []*types.ScopedCapabilities{
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_ENCAPSULATE, types.CryptoOperation_CRYPTO_OPERATION_DECAPSULATE),
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_KEY_AGREEMENT),
			},
			want: []provider.Capability{provider.CapabilityKeyEstablish},
		},
		{
			// Synthetic shape: no template in the current catalog needs two
			// distinct capabilities, but nothing in the proto forbids one —
			// this proves the union (not just the dedupe) is real, and that
			// the result is sorted rather than insertion-ordered.
			name: "synthetic multi-capability template: sorted union",
			caps: []*types.ScopedCapabilities{
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_SIGN, types.CryptoOperation_CRYPTO_OPERATION_VERIFY),
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_ENCRYPT, types.CryptoOperation_CRYPTO_OPERATION_DECRYPT),
			},
			want: []provider.Capability{provider.CapabilityCipher, provider.CapabilitySign},
		},
		{
			// Key-lifecycle-only operations contribute nothing.
			name: "unmapped operations contribute no capability",
			caps: []*types.ScopedCapabilities{
				scopedCaps(types.CryptoOperation_CRYPTO_OPERATION_CREATE_KEY, types.CryptoOperation_CRYPTO_OPERATION_ROTATE_KEY),
			},
			want: []provider.Capability{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := provider.RequiredCapabilities(tt.caps)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RequiredCapabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
