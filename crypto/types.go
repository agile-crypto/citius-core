package crypto

import (
	messages "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// SignatureScopeFields groups the scope_params for signature operations.
// Embedded in SignRequest and VerifyRequest so callers can pass them as a
// single value (e.g., req.SignatureScopeFields) to validation helpers.
//
// Exactly one field should be non-nil, mirroring the scope_params oneof
// in caas.crypto.v1.SignRequest / VerifyRequest.
type SignatureScopeFields struct {
	NoContext     *types.NoParams               // ECDSA, RSA-PSS, DSA (no context needed)
	DomainContext *types.SignatureDomainContext // EdDSA, ML-DSA, SLH-DSA (0-255 byte context)
	VendorContext *types.VendorSignatureContext // vendor/custom scope
}

// SignRequest carries the inputs for a Sign operation at the orchestrator level.
// The orchestrator resolves key material and passes scope_params through to the provider.
type SignRequest struct {
	KeyName string // identifies which key to use (proto: key_name)
	Payload []byte // data to sign (proto: input)

	// Scope-based context for domain separation — exactly one must be non-nil.
	// Maps to the scope_params oneof in caas.crypto.v1.SignRequest.
	// The gRPC handler copies the user's scope choice as-is.
	SignatureScopeFields
}

// SignResult carries the outputs of a Sign operation.
// Output carries NoAlgorithmOutput + encoding (signing has no system-generated params).
type SignResult struct {
	Signature    []byte
	KeyName      string                   // echo back for caller context
	KeyVersion   uint32                   // version that was used
	Algorithm    string                   // template ID (e.g., "ecdsa-p256-sha256")
	ProviderName string                   // which provider performed the operation
	Output       *messages.ProviderOutput // from provider (NoAlgorithmOutput + encoding)
}

type VerifyRequest struct {
	KeyName    string
	KeyVersion uint32 // version that was used
	Payload    []byte // original data that was signed
	Signature  []byte
	Output     *messages.ProviderOutput // from provider (NoAlgorithmOutput + encoding)
	// Scope must match the scope used during signing.
	SignatureScopeFields
}

// VerifyResult carries the outputs of a Verify operation.
// Invalid signature is NOT an error — it returns Valid=false.
type VerifyResult struct {
	Valid        bool
	KeyName      string
	Algorithm    string
	ProviderName string
	Output       *messages.ProviderOutput // from provider
}

// DigestSignRequest carries the inputs for a DigestSign operation — signing a
// pre-computed digest rather than the full message (proto: DigestSignRequest).
//
// The provider does NOT hash; HashAlgorithm describes the hash that produced
// Digest, used for digest-size validation and (for RSA) the DigestInfo/PSS
// hash — it does NOT select the signature scheme.  Neither the digest nor the
// key material determines PSS vs PKCS1v15, curve, or output encoding; the
// orchestrator resolves AlgorithmDetails from the template and passes it to
// the provider, exactly as Sign does.
type DigestSignRequest struct {
	KeyName          string              // identifies which key to use
	Digest           []byte              // pre-computed digest — the provider signs this raw
	HashAlgorithm    types.HashAlgorithm // hash that produced Digest
	HashAlgorithmOID string              // optional OID when HashAlgorithm is HASH_ALGORITHM_OTHER

	// Scope-based context for domain separation — exactly one must be non-nil.
	// Maps to the scope_params oneof in caas.crypto.v1.DigestSignRequest.
	SignatureScopeFields
}

// DigestVerifyRequest carries the inputs for a DigestVerify operation —
// verifying a signature over a pre-computed digest (proto: DigestVerifyRequest).
type DigestVerifyRequest struct {
	KeyName          string
	KeyVersion       uint32 // version that was used
	Digest           []byte // pre-computed digest that was signed
	Signature        []byte
	HashAlgorithm    types.HashAlgorithm // must match the hash used for the corresponding DigestSign
	HashAlgorithmOID string
	Output           *messages.ProviderOutput // from DigestSign (carries signature encoding)

	// Scope must match the scope used during DigestSign.
	SignatureScopeFields
}

// EncryptionScopeFields groups the scope_params for encryption operations.
// Embedded in EncryptRequest and DecryptRequest so callers and validation
// helpers can pass them as a single value, mirroring SignatureScopeFields.
//
// Exactly one field should be non-nil, mirroring the scope_params oneof in
// caas.crypto.v1.EncryptRequest / DecryptRequest.
type EncryptionScopeFields struct {
	NoParams         *types.NoParams                // AES-CBC, AES-CTR, ChaCha20, 3DES
	AeadParams       *types.AeadEncryptParams       // AES-GCM, AES-CCM, ChaCha20-Poly1305 (carries AAD)
	XtsParams        *types.XtsEncryptParams        // AES-XTS (carries tweak)
	AsymmetricParams *types.AsymmetricEncryptParams // RSA-OAEP (carries label)
	VendorParams     *types.VendorEncryptionParams  // vendor/custom scope
}

type EncryptRequest struct {
	KeyName   string
	Plaintext []byte

	// Scope-based operation parameters — exactly one must be non-nil.
	// Maps to the scope_params oneof in caas.crypto.v1.EncryptRequest.
	EncryptionScopeFields
}

type EncryptResult struct {
	Ciphertext   []byte
	KeyVersion   uint32                   // version that was used
	Output       *messages.ProviderOutput // IV/nonce, tag, encoding — from provider
	Algorithm    string
	ProviderName string
}

type DecryptRequest struct {
	KeyName    string
	KeyVersion uint32 // version that was used
	Ciphertext []byte
	Output     *messages.ProviderOutput // stored ProviderOutput from EncryptResult (carries IV/nonce)

	// Scope-based operation parameters — must match encryption.
	EncryptionScopeFields
}

type DecryptResult struct {
	Plaintext    []byte
	Algorithm    string
	ProviderName string
	Output       *messages.ProviderOutput // from provider (encoding)
}

// WrapKeyRequest carries the inputs for a WrapKey operation.
// TODO: add wrapping scope_params (NoParams, AeadParams, VendorWrapParams)
// matching caas.crypto.v1.WrapKeyRequest.
type WrapKeyRequest struct {
	WrappingKeyID string
	KeyToWrapID   string
}

// WrapKeyResult carries the outputs of a WrapKey operation.
// TODO: add Output *messages.ProviderOutput (carries IV/nonce for wrapping modes).
type WrapKeyResult struct {
	WrappedKeyBytes []byte
	Algorithm       string
	KeyVersion      uint32 // version that was used
}

// UnwrapKeyRequest carries the inputs for an UnwrapKey operation.
// TODO: add wrapping scope_params matching caas.crypto.v1.UnwrapKeyRequest.
type UnwrapKeyRequest struct {
	WrappingKeyID   string
	WrappedKeyBytes []byte
}

// UnwrapKeyResult carries the outputs of an UnwrapKey operation.
// The orchestrator is responsible for creating a key.Key aggregate from the
// unwrapped material and persisting it via key.Repository.
type UnwrapKeyResult struct {
	UnwrappedKeyMaterial []byte                   // raw key bytes returned by the provider
	KeyVersion           uint32                   // version that was used
	Algorithm            string                   // algorithm of the unwrapped key
	Output               *messages.ProviderOutput // provider-generated output

}

// DeriveKeyRequest carries the inputs for a DeriveKey operation.
// TODO: add KDF scope_params (HkdfParams, Pbkdf2Params, Argon2Params, EcdhParams, etc.)
// matching caas.crypto.v1.DeriveKeyRequest.
type DeriveKeyRequest struct {
	BaseKeyID string
	Info      []byte
}

// MacRequest carries the inputs for a GenerateMAC operation.
// TODO: add MAC scope_params (NoParams, VendorMacParams)
// matching caas.crypto.v1.GenerateMacRequest.
type MacRequest struct {
	KeyID string
	Data  []byte
}

// MacResult carries the outputs of a GenerateMAC operation.
// TODO: add Output *messages.ProviderOutput (NoAlgorithmOutput + encoding).
type MacResult struct {
	MAC       []byte
	Algorithm string
}

// VerifyMacRequest carries the inputs for a VerifyMAC operation.
// TODO: add MAC scope_params matching caas.crypto.v1.VerifyMacRequest.
type VerifyMacRequest struct {
	KeyID string
	Data  []byte
	MAC   []byte
}

// VerifyMacResult carries the outputs of a VerifyMAC operation.
type VerifyMacResult struct {
	Valid     bool
	Algorithm string
}

// DigestRequest carries the inputs for a Digest (hash) operation.
// TODO: add digest scope_params matching caas.crypto.v1.DigestRequest.
type DigestRequest struct {
	Data      []byte
	Algorithm string // e.g., "SHA-256"; empty = provider default
}

// DigestResult carries the outputs of a Digest operation.
type DigestResult struct {
	Digest    []byte
	Algorithm string
}
