package core

// Primitive identifies a cryptographic primitive family.
// Each primitive groups Scopes that share the same key type and operational purpose.
type Primitive int

const (
	// Lower bound for enum. Serves as zero-value, used when primitive is not applicable or not specified
	PrimitiveUnknown Primitive = iota

	// ── Primitives ─────────────────────────────────────────────────────────────
	PrimitiveSignature
	PrimitiveAead
	PrimitiveMac
	PrimitiveKem
	PrimitiveKeyAgreement
	PrimitiveKdf
	PrimitiveHash
	PrimitiveKeyWrapping
	PrimitiveSymmetricCipher
	PrimitiveDiskEncryption
	PrimitiveGenericSecret

	// Upper bound for enum
	primitiveMax
)

func (p Primitive) IsValid() bool {
	return PrimitiveUnknown < p && p < primitiveMax
}

// String returns the snake_case name of the primitive.
func (p Primitive) String() string {
	switch p {
	case PrimitiveSignature:
		return "signature"
	case PrimitiveAead:
		return "aead"
	case PrimitiveMac:
		return "mac"
	case PrimitiveKem:
		return "kem"
	case PrimitiveKeyAgreement:
		return "key_agreement"
	case PrimitiveKdf:
		return "kdf"
	case PrimitiveHash:
		return "hash"
	case PrimitiveKeyWrapping:
		return "key_wrapping"
	case PrimitiveSymmetricCipher:
		return "symmetric_cipher"
	case PrimitiveDiskEncryption:
		return "disk_encryption"
	case PrimitiveGenericSecret:
		return "generic_secret"
	default:
		return "unknown"
	}
}

// ListScopes returns the list of scopes that belong to this primitive.
func (p Primitive) ListScopes() []Scope {
	switch p {
	case PrimitiveSignature:
		return []Scope{ScopeSignatureStandard, ScopeSignatureWithContext, ScopeSignaturePrehashed, ScopeSignaturePrehashedWithContext}
	case PrimitiveAead:
		return []Scope{ScopeAeadStandard, ScopeAeadDeterministic, ScopeAeadStreaming}
	case PrimitiveMac:
		return []Scope{ScopeMacStandard, ScopeMacStreaming}
	case PrimitiveKem:
		return []Scope{ScopeKemStandard, ScopeKemHybrid}
	case PrimitiveKeyAgreement:
		return []Scope{ScopeKeyAgreementStandard, ScopeKeyAgreementHybrid}
	case PrimitiveKdf:
		return []Scope{ScopeKdfExtractExpand, ScopeKdfPassword, ScopeKdfAgreement, ScopeKdfCounter, ScopeKdfTLS, ScopeKdfGost, ScopeKdfVendor}
	case PrimitiveHash:
		return []Scope{ScopeHashStandard, ScopeHashXof}
	case PrimitiveKeyWrapping:
		return []Scope{ScopeKeyWrappingStandard, ScopeKeyWrappingWithPadding}
	case PrimitiveSymmetricCipher:
		return []Scope{ScopeSymmetricCipherBlock, ScopeSymmetricCipherStream}
	case PrimitiveDiskEncryption:
		return []Scope{ScopeDiskEncryptionStandard}
	case PrimitiveGenericSecret:
		return []Scope{ScopeGenericSecretStandard}
	default:
		return nil
	}
}

// ListPrimitives returns a slice of all defined Primitives, in ascending order.
func ListPrimitives() []Primitive {
	res := make([]Primitive, 0, primitiveMax-1)
	for p := PrimitiveUnknown + 1; p < primitiveMax; p++ {
		res = append(res, p)
	}
	return res
}
