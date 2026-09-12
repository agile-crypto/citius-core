// Package provider defines the Backend interface — the Go-side contract
// that every crypto provider must implement.
//
// Request and response types are the proto-generated messages from
// gen/go/provider (proto/provider/*.proto).  This ensures 1:1 type identity
// with the gRPC wire format — no translation layer, no drift.
//
// Proto mapping:
//
//	Backend.GenerateKey     => KeyOrchestrationService.GenerateKey
//	Backend.DestroyKey      => KeyOrchestrationService.DestroyKey
//	Backend.ExportPublicKey => KeyOrchestrationService.ExportPublicKey
//
// Every cryptographic primitive is expressed as an optional capability
// interface.  A provider implements only the capabilities it supports; the
// orchestrator type-asserts the capability it needs and returns
// CodeNotImplemented when the provider lacks it:
//
//	Signer          => CryptoService.Sign / Verify / SignDigest / VerifyDigest
//	Cipher          => CryptoService.Encrypt / Decrypt
//	Macer           => CryptoService.GenerateMac / VerifyMac
//	Hasher          => CryptoService.Digest / Xof
//	Randomizer      => RandomService.GenerateRandom / SeedRandom
//	KeyEstablisher  => KeyEstablishmentService.*
package provider

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
)

// Backend is the Go interface that every crypto provider must implement.
//
// It covers only provider identity and key lifecycle — the operations every
// provider must support.  Method signatures use proto-generated request/response
// types from gen/go/provider, ensuring 1:1 correspondence with the gRPC service
// contracts (KeyOrchestrationService).
//
// For in-process Go providers (software, loopback): implement directly.
// For out-of-process gRPC providers: a thin adapter wraps the gRPC client
// stubs into this interface (forwarding proto messages 1:1).
//
// Key material sovereignty: GenerateKeyResponse.key_material is opaque to
// the core.  The orchestrator stores it as-is and passes it back in every
// subsequent request.  Only the provider that generated the material knows
// how to interpret it.
//
// Name() and Type() are Go-level identity methods that correspond to
// ProviderIdentityService.GetInfo() in the full gRPC flow.  They exist
// as convenience methods for the in-process registry.
//
// Cryptographic primitives (sign, encrypt, MAC, digest, random, key
// establishment) are NOT part of Backend.  They are expressed as optional
// capability interfaces below so that a provider implements only what it
// supports, and support is discoverable via a Go type assertion.
type Backend interface {
	Name() string
	Type() string
	GenerateKey(ctx context.Context, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error)
	DestroyKey(ctx context.Context, req *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error)
	ExportPublicKey(ctx context.Context, req *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error)
}

// Signer is an optional interface for providers that support signature
// operations (CryptoService.Sign / Verify / SignDigest / VerifyDigest).
//
// Sign takes a message and hashes it; SignDigest takes a digest the caller
// already computed and signs it as-is. The qualifier names the input, not an
// action performed on it — see SignDigestRequest in the provider proto for why
// that convention is worth holding to against OpenSSL's opposite one.
type Signer interface {
	Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error)
	Verify(ctx context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error)
	SignDigest(ctx context.Context, req *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error)
	VerifyDigest(ctx context.Context, req *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error)
}

// Cipher is an optional interface for providers that support encryption
// operations (CryptoService.Encrypt / Decrypt).
type Cipher interface {
	Encrypt(ctx context.Context, req *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error)
}

// Macer is an optional interface for providers that support MAC operations
// (CryptoService.GenerateMac / VerifyMac).
type Macer interface {
	GenerateMac(ctx context.Context, req *providerpb.GenerateMacRequest) (*providerpb.GenerateMacResponse, error)
	VerifyMac(ctx context.Context, req *providerpb.VerifyMacRequest) (*providerpb.VerifyMacResponse, error)
}

// Hasher is an optional interface for providers that support digest and XOF
// operations (CryptoService.Digest / Xof).
type Hasher interface {
	Digest(ctx context.Context, req *providerpb.DigestRequest) (*providerpb.DigestResponse, error)
	Xof(ctx context.Context, req *providerpb.XofRequest) (*providerpb.XofResponse, error)
}

// Randomizer is an optional interface for providers that support random-byte
// generation (RandomService.GenerateRandom / SeedRandom).
type Randomizer interface {
	GenerateRandom(ctx context.Context, req *providerpb.GenerateRandomRequest) (*providerpb.GenerateRandomResponse, error)
	SeedRandom(ctx context.Context, req *providerpb.SeedRandomRequest) (*providerpb.SeedRandomResponse, error)
}

// KeyEstablisher is an optional interface for providers that support key-to-key
// operations (KeyEstablishmentService.*).
type KeyEstablisher interface {
	WrapKey(ctx context.Context, req *providerpb.WrapKeyRequest) (*providerpb.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, req *providerpb.UnwrapKeyRequest) (*providerpb.UnwrapKeyResponse, error)
	DeriveKey(ctx context.Context, req *providerpb.DeriveKeyRequest) (*providerpb.DeriveKeyResponse, error)
	KeyAgreement(ctx context.Context, req *providerpb.KeyAgreementRequest) (*providerpb.KeyAgreementResponse, error)
	EncapsulateKey(ctx context.Context, req *providerpb.EncapsulateKeyRequest) (*providerpb.EncapsulateKeyResponse, error)
	DecapsulateKey(ctx context.Context, req *providerpb.DecapsulateKeyRequest) (*providerpb.DecapsulateKeyResponse, error)
}

// AlgorithmCapabilityProvider is an optional interface that provider
// implementations can implement to expose their supported algorithm IDs.
//
// This is currently a simplification of ProviderIdentityService.GetCapabilities().
// TODO: replace with a typed GetCapabilities(ctx) ([]*providerpb.AlgorithmCapability, error)
// once the registry/matcher consume the full AlgorithmCapability list.
//
// Providers that do NOT implement AlgorithmCapabilityProvider are gracefully
// skipped during template-based matching.
type AlgorithmCapabilityProvider interface {
	SupportedAlgorithms() []string
}

// ImplementationDescriber is an optional interface that provider
// implementations can implement to report the security-relevant properties
// of their concrete implementation (FIPS certification, constant-time,
// hardware acceleration, memory-safe language, ...).
//
// Optional, same as AlgorithmCapabilityProvider: a provider that does not
// implement it is not excluded from matching — it simply cannot substantiate
// any of these properties, so it scores neutral rather than being penalised.
// A provider must only report what it can actually substantiate; do not
// fabricate certificate numbers or validation dates a real audit would
// contradict.
type ImplementationDescriber interface {
	ImplementationProperties() *types.ImplementationProperties
}
