package core

import types "github.com/agile-crypto/citius-api-go/gen/go/types"

// Scope is the SDK-level type for the operational variant of a cryptographic primitive.
// Each constant identifies a distinct caller interface: the set of parameters the caller
// must supply, independent of the concrete algorithm chosen by policy.
type Scope int

const unknownScopeStr = "unknown"

const (
	ScopeUnknown Scope = iota // zero-value scope, used when scope is not applicable or not specified
	// ── Signature ──────────────────────────────────────────────────────────────
	ScopeSignatureStandard             // Sign message directly
	ScopeSignatureWithContext          // Sign with domain separation context
	ScopeSignaturePrehashed            // Sign pre-computed digest
	ScopeSignaturePrehashedWithContext // Sign digest with context

	// ── AEAD ───────────────────────────────────────────────────────────────────
	ScopeAeadStandard      // Standard AEAD (nonce, optional AAD)
	ScopeAeadDeterministic // Deterministic AEAD (no nonce, AAD required)
	ScopeAeadStreaming     // Streaming AEAD (segment size param)

	// ── MAC ────────────────────────────────────────────────────────────────────
	ScopeMacStandard  // Standard MAC
	ScopeMacStreaming // Streaming MAC (incremental update)

	// ── KEM ────────────────────────────────────────────────────────────────────
	ScopeKemStandard // Standard KEM
	ScopeKemHybrid   // Hybrid classical + PQ KEM

	// ── Key Agreement ──────────────────────────────────────────────────────────
	ScopeKeyAgreementStandard // Standard ECDH/X25519
	ScopeKeyAgreementHybrid   // Hybrid classical + PQ key agreement

	// ── KDF ────────────────────────────────────────────────────────────────────
	ScopeKdfExtractExpand // IKM + salt + info → key (HKDF)
	ScopeKdfPassword      // password + salt + cost → key (PBKDF2, Argon2)
	ScopeKdfAgreement     // peer public key → shared secret (ECDH, X25519/X448)
	ScopeKdfCounter       // label + context + counter format → key (SP800-108)
	ScopeKdfTLS           // cipher suite + seed → key material (TLS PRF, TLS 1.2)
	ScopeKdfGost          // ukm → key (GOST R 34.11)
	ScopeKdfVendor        // custom parameters → key (vendor-specific)

	// ── Hash ───────────────────────────────────────────────────────────────────
	ScopeHashStandard // Standard hash function
	ScopeHashXof      // Extendable output function

	// ── Key Wrapping ───────────────────────────────────────────────────────────
	ScopeKeyWrappingStandard    // Standard key wrap
	ScopeKeyWrappingWithPadding // Key wrap with padding

	// ── Symmetric Cipher ───────────────────────────────────────────────────────
	ScopeSymmetricCipherBlock  // Block cipher (CBC, ECB) — provider generates IV
	ScopeSymmetricCipherStream // Stream cipher (CTR, OFB) — provider generates IV

	// ── Disk Encryption ────────────────────────────────────────────────────────
	ScopeDiskEncryptionStandard // AES-XTS (IEEE 1619) — caller provides tweak

	// ── Generic Secret ─────────────────────────────────────────────────────────
	ScopeGenericSecretStandard // Standard generic secret management

	// Upper bound for enum
	scopeMax
)

var scopeStrings = map[Scope]string{
	ScopeSignatureStandard:             "signature_standard",
	ScopeSignatureWithContext:          "signature_with_context",
	ScopeSignaturePrehashed:            "signature_prehashed",
	ScopeSignaturePrehashedWithContext: "signature_prehashed_with_context",
	ScopeAeadStandard:                  "aead_standard",
	ScopeAeadDeterministic:             "aead_deterministic",
	ScopeAeadStreaming:                 "aead_streaming",
	ScopeMacStandard:                   "mac_standard",
	ScopeMacStreaming:                  "mac_streaming",
	ScopeKemStandard:                   "kem_standard",
	ScopeKemHybrid:                     "kem_hybrid",
	ScopeKeyAgreementStandard:          "key_agreement_standard",
	ScopeKeyAgreementHybrid:            "key_agreement_hybrid",
	ScopeKdfExtractExpand:              "kdf_extract_expand",
	ScopeKdfPassword:                   "kdf_password",
	ScopeKdfAgreement:                  "kdf_agreement",
	ScopeKdfCounter:                    "kdf_counter",
	ScopeKdfTLS:                        "kdf_tls",
	ScopeKdfGost:                       "kdf_gost",
	ScopeKdfVendor:                     "kdf_vendor",
	ScopeHashStandard:                  "hash_standard",
	ScopeHashXof:                       "hash_xof",
	ScopeKeyWrappingStandard:           "key_wrapping_standard",
	ScopeKeyWrappingWithPadding:        "key_wrapping_with_padding",
	ScopeSymmetricCipherBlock:          "symmetric_cipher_block",
	ScopeSymmetricCipherStream:         "symmetric_cipher_stream",
	ScopeDiskEncryptionStandard:        "disk_encryption_standard",
	ScopeGenericSecretStandard:         "generic_secret_standard",
}

// var scopeValues map[string]Scope = func() map[string]Scope {
// 	m := make(map[string]Scope, len(scopeStrings))
// 	for k, v := range scopeStrings {
// 		m[v] = k
// 	}
// 	return m
// }()

func (s Scope) IsValid() bool {
	return ScopeUnknown < s && s < scopeMax
}

// String returns the unique string identifier for this Scope in the format
// "<primitive>_<_name>" using snake_case.
func (s Scope) String() string {
	if str, ok := scopeStrings[s]; ok {
		return str
	}
	return unknownScopeStr
}

// ListScopes returns a slice of all defined Scopes, in ascending order.
func ListScopes() []Scope {
	res := make([]Scope, 0, scopeMax-1)
	for s := ScopeUnknown + 1; s < scopeMax; s++ {
		res = append(res, s)
	}
	return res
}

// Returns the Primitive that the given scope belongs to.
// Returns 0 for an unknown or zero-value Scope
func (s Scope) GetPrimitive() Primitive {
	switch s {
	case ScopeSignatureStandard, ScopeSignatureWithContext,
		ScopeSignaturePrehashed, ScopeSignaturePrehashedWithContext:
		return PrimitiveSignature
	case ScopeAeadStandard, ScopeAeadDeterministic, ScopeAeadStreaming:
		return PrimitiveAead
	case ScopeMacStandard, ScopeMacStreaming:
		return PrimitiveMac
	case ScopeKemStandard, ScopeKemHybrid:
		return PrimitiveKem
	case ScopeKeyAgreementStandard, ScopeKeyAgreementHybrid:
		return PrimitiveKeyAgreement
	case ScopeKdfExtractExpand, ScopeKdfPassword, ScopeKdfAgreement,
		ScopeKdfCounter, ScopeKdfTLS, ScopeKdfGost, ScopeKdfVendor:
		return PrimitiveKdf
	case ScopeHashStandard, ScopeHashXof:
		return PrimitiveHash
	case ScopeKeyWrappingStandard, ScopeKeyWrappingWithPadding:
		return PrimitiveKeyWrapping
	case ScopeSymmetricCipherBlock, ScopeSymmetricCipherStream:
		return PrimitiveSymmetricCipher
	case ScopeDiskEncryptionStandard:
		return PrimitiveDiskEncryption
	case ScopeGenericSecretStandard:
		return PrimitiveGenericSecret
	default:
		return PrimitiveUnknown
	}
}

var scopeToProto map[Scope]any = map[Scope]any{
	ScopeSignatureStandard:             types.SignatureScope_SIGNATURE_SCOPE_STANDARD,
	ScopeSignatureWithContext:          types.SignatureScope_SIGNATURE_SCOPE_WITH_CONTEXT,
	ScopeSignaturePrehashed:            types.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
	ScopeSignaturePrehashedWithContext: types.SignatureScope_SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT,
	ScopeAeadStandard:                  types.AeadScope_AEAD_SCOPE_STANDARD,
	ScopeAeadDeterministic:             types.AeadScope_AEAD_SCOPE_DETERMINISTIC,
	ScopeAeadStreaming:                 types.AeadScope_AEAD_SCOPE_STREAMING,
	ScopeMacStandard:                   types.MacScope_MAC_SCOPE_STANDARD,
	ScopeMacStreaming:                  types.MacScope_MAC_SCOPE_STREAMING,
	ScopeKemStandard:                   types.KemScope_KEM_SCOPE_STANDARD,
	ScopeKemHybrid:                     types.KemScope_KEM_SCOPE_HYBRID,
	ScopeKeyAgreementStandard:          types.KeyAgreementScope_KEY_AGREEMENT_SCOPE_STANDARD,
	ScopeKeyAgreementHybrid:            types.KeyAgreementScope_KEY_AGREEMENT_SCOPE_HYBRID,
	ScopeKdfExtractExpand:              types.KdfScope_KDF_SCOPE_EXTRACT_EXPAND,
	ScopeKdfPassword:                   types.KdfScope_KDF_SCOPE_PASSWORD,
	ScopeKdfAgreement:                  types.KdfScope_KDF_SCOPE_AGREEMENT,
	ScopeKdfCounter:                    types.KdfScope_KDF_SCOPE_COUNTER,
	ScopeKdfTLS:                        types.KdfScope_KDF_SCOPE_TLS,
	ScopeKdfGost:                       types.KdfScope_KDF_SCOPE_GOST,
	ScopeKdfVendor:                     types.KdfScope_KDF_SCOPE_VENDOR,
	ScopeHashStandard:                  types.HashScope_HASH_SCOPE_STANDARD,
	ScopeHashXof:                       types.HashScope_HASH_SCOPE_XOF,
	ScopeKeyWrappingStandard:           types.KeyWrappingScope_KEY_WRAPPING_SCOPE_STANDARD,
	ScopeKeyWrappingWithPadding:        types.KeyWrappingScope_KEY_WRAPPING_SCOPE_WITH_PADDING,
	ScopeSymmetricCipherBlock:          types.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_BLOCK,
	ScopeSymmetricCipherStream:         types.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_STREAM,
	ScopeDiskEncryptionStandard:        types.DiskEncryptionScope_DISK_ENCRYPTION_SCOPE_STANDARD,
	ScopeGenericSecretStandard:         types.GenericSecretScope_GENERIC_SECRET_SCOPE_STANDARD,
}

var protoToScope map[any]Scope = func() map[any]Scope {
	m := make(map[any]Scope, len(scopeToProto))
	for k, v := range scopeToProto {
		m[v] = k
	}
	return m
}()

// ToProto returns the proto-layer enum value for this Scope.
// Because each primitive has its own proto enum type, the concrete type of the
// returned value varies; use a type switch to obtain it (e.g. types.Signature).
// Returns nil for an unknown Scope.
func (s Scope) ToProto() any {
	p, ok := scopeToProto[s]
	if !ok {
		return nil
	}
	return p
}

// ScopeFromProto converts a proto-layer  enum value to the corresponding SDK .
// The proto argument must be one of the per-primitive proto enum types defined in
// the types package (e.g. types.Signature, types.Aead).
// UNSPECIFIED values and unrecognised inputs return (0, false).
func ScopeFromProto(proto any) (Scope, bool) {
	scope, ok := protoToScope[proto]
	if !ok {
		return ScopeUnknown, false
	}
	return scope, true
}
