package software_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// TestProviderMethods_rejectRequestsViolatingCELConstraints proves every
// software.Provider RPC method enforces the buf.validate CEL constraints
// declared on its request message (e.g. key_material's bytes.min_len = 1)
// before running any dispatch logic — this is the provider's own trust
// boundary, distinct from and in addition to the orchestrator's caller-facing
// validation (see service/crypto_orchestrator_impl.go).
func TestProviderMethods_rejectRequestsViolatingCELConstraints(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	// key_material carries bytes.min_len = 1 on every request below; leaving
	// it empty is the one violation every method's request shape shares.
	tests := []struct {
		name string
		call func() error
	}{
		{"GenerateKey", func() error {
			_, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{})
			return err
		}},
		{"Sign", func() error {
			_, err := p.Sign(ctx, &providerpb.SignRequest{Input: []byte("payload")})
			return err
		}},
		{"Verify", func() error {
			_, err := p.Verify(ctx, &providerpb.VerifyRequest{Input: []byte("payload"), Signature: []byte("sig")})
			return err
		}},
		{"SignDigest", func() error {
			_, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{Digest: []byte("digest")})
			return err
		}},
		{"VerifyDigest", func() error {
			_, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{Digest: []byte("digest"), Signature: []byte("sig")})
			return err
		}},
		{"Encrypt", func() error {
			_, err := p.Encrypt(ctx, &providerpb.EncryptRequest{Plaintext: []byte("payload")})
			return err
		}},
		{"Decrypt", func() error {
			_, err := p.Decrypt(ctx, &providerpb.DecryptRequest{Ciphertext: []byte("ciphertext")})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("expected error for empty key_material")
			}
			if !errors.IsInvalidArgument(err) {
				t.Errorf("expected CodeInvalidArgument, got: %v", err)
			}
		})
	}
}
