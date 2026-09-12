package core

import (
	"context"
)

// Operation string constants for cryptographic operations.
// Used in PolicyEngine.ValidateOperation(ctx, policyName, operation, templateID, providerID)
// where `operation` is a string and these values are typed as Operation (a string alias).

type Operation string

const (
	OperationCreateKey = Operation("create_key")
	OperationReadKey   = Operation("read_key")
	OperationDeleteKey = Operation("delete_key")
	OperationSign      = Operation("sign")
	OperationVerify    = Operation("verify")
	// OperationDigestSign and OperationDigestVerify are distinct from
	// OperationSign/OperationVerify — prehashed signing (CKM_ECDSA) is a
	// different PKCS#11 mechanism family from hash-then-sign
	// (CKM_ECDSA_SHA256), and a policy permitting one should not silently
	// permit the other.
	OperationDigestSign   = Operation("digest_sign")
	OperationDigestVerify = Operation("digest_verify")
	OperationEncrypt      = Operation("encrypt")
	OperationDecrypt      = Operation("decrypt")
	OperationWrap         = Operation("wrap")
	OperationUnwrap       = Operation("unwrap")
	OperationDeriveKey    = Operation("derive_key")
	OperationRotateKey    = Operation("rotate_key")
)

// WriteOp describes the storage operation for VetForWrite.
// This is distinct from Operation (which represents crypto operations like sign/verify/encrypt).
// WriteOp represents database write operations (create/update/delete) used by VetForWrite
// to apply operation-specific validation rules.
type WriteOp int

const (
	OpCreate WriteOp = iota
	OpUpdate
	OpDelete
)

// KeyCreationSpec carries the inputs for a CreateKey call across package boundaries.
// It is NOT a proto type — it holds Go-native values resolved from the gRPC request.
// Also referenced by UnwrapKeyRequest.TargetKeySpec and DeriveKeyRequest.Spec
type KeyCreationSpec struct {
	Name               string
	TemplateID         string // set when key_specification=template_id
	ScopeSpecification *ScopeSpecification
	PolicyID           string
	ProviderInstanceID string // optional: if empty, use default provider
	Labels             map[string]string
}

// KeyMaterial holds the raw bytes of a key as returned by GetKeyWithMaterial.
// PrivateKeyBytes may be empty for public-key-only operations.
type KeyMaterial struct {
	PublicKeyBytes  []byte
	PrivateKeyBytes []byte // nil for public-key-only operations
	Algorithm       string
}

// VetForWriter is implemented by domain types that can be validated before a storage write.
type VetForWriter interface {
	VetForWrite(ctx context.Context, op WriteOp) error
}

// ImportKeySpec carries the inputs for an ImportKey call across package boundaries.
// Like KeyCreationSpec, it holds Go-native values resolved from the gRPC ImportKeyRequest.
type ImportKeySpec struct {
	Name                string
	PolicyName          string
	KeyMaterial         []byte              // raw or wrapped key bytes
	Format              string              // plain string (e.g., "raw", "pkcs8"); TODO: typed KeyFormat enum
	UnwrappingKeyName   string              // required if Format is "wrapped"
	ProviderID          string              // optional: target provider
	TemplateID          string              // set when key_specification=template_id
	Scope               *ScopeSpecification // set when key_specification=scope
	PreferredProperties map[string]string   // soft preference hints for scope-based selection
	Labels              map[string]string
}
