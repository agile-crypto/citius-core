package service

import (
	"context"

	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/key"
)

// CryptoOrchestrator performs cryptographic operations using stored keys.
// Implementations coordinate key retrieval, policy validation, and provider dispatch
// crossing aggregate boundaries.
type CryptoOrchestrator interface {
	Sign(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error)
	Verify(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error)
	DigestSign(ctx context.Context, req crypto.DigestSignRequest) (crypto.SignResult, error)
	DigestVerify(ctx context.Context, req crypto.DigestVerifyRequest) (crypto.VerifyResult, error)
	Encrypt(ctx context.Context, req crypto.EncryptRequest) (crypto.EncryptResult, error)
	Decrypt(ctx context.Context, req crypto.DecryptRequest) (crypto.DecryptResult, error)
	WrapKey(ctx context.Context, req crypto.WrapKeyRequest) (crypto.WrapKeyResult, error)
	UnwrapKey(ctx context.Context, req crypto.UnwrapKeyRequest) (crypto.UnwrapKeyResult, error)
	DeriveKey(ctx context.Context, req crypto.DeriveKeyRequest) (*key.Key, error)
	GenerateMAC(ctx context.Context, req crypto.MacRequest) (crypto.MacResult, error)
	VerifyMAC(ctx context.Context, req crypto.VerifyMacRequest) (crypto.VerifyMacResult, error)
	Digest(ctx context.Context, req crypto.DigestRequest) (crypto.DigestResult, error)
	GenerateRandom(ctx context.Context, length int) ([]byte, error)
}

// CryptoOrchestratorFactory builds the cryptographic-operation orchestrator for
// one request, under the same rules as KeyOrchestratorFactory.
type CryptoOrchestratorFactory func(ctx context.Context) (CryptoOrchestrator, error)
