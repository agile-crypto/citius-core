package core

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// PrimitiveSpecificProperties groups properties that are specific to a given primitive
// and its associated scopes. For example, non-malleability and determinism are properties that
// can be applied to signature scopes but not to other primitives, while nonce-misuse resistance
// is a property that can be applied to AEAD scopes but not to other primitives.
//
// Scope-specific properties should be created with [NewPrimitiveSpecificProperties].
//
// Types implementing PrimitiveSpecificProperties:
//   - *[SignatureProperties] for signature scopes
//   - *[AEADProperties] for AEAD scopes
//   - *[KeyAgreementProperties] for key agreement scopes
//   - *[KDFProperties] for KDF scopes
type PrimitiveSpecificProperties interface {
	defaultPrimitiveSpecificProperties() PrimitiveSpecificProperties
	// Return the primitive of the scopes to which these scope-specific properties can be applied.
	GetPrimitive() Primitive
	// Return the scopes to which these scope-specific properties can be applied.
	// Equivalent to GetPrimitive().ListScopes()
	GetScopes() []Scope
}

// Creates a concrete instance of PrimitiveSpecificProperties based on the provided options.
// Options available depends on the [Primitive].
// Returns an error if conflicting options are provided (ie. options that apply to multiple primitives).
// Returns nil if no options are provided.
//
// Signature-specific options:
//   - WithNonMalleable: indicates that the signatures produced by the key should be non-malleable.
//   - WithDeterministic: indicates that the signatures produced by the key should be deterministic.
//
// AEAD-specific options:
//   - WithNonceMisuseResistance: indicates that the key should be resistant to nonce misuse.
//
// Key agreement-specific options:
//   - WithForwardSecrecy: indicates that the key should provide forward secrecy.
//
// KDF-specific options:
//   - WithMemoryHard: indicates that the key should be memory-hard.
func NewPrimitiveSpecificProperties(ctx context.Context, opts ...ScopeOption) (PrimitiveSpecificProperties, error) {
	const op = "core.NewPrimitiveSpecificProperties"
	opt := getOpts(opts...)
	resOpts := []PrimitiveSpecificProperties{}
	if opt.withNonMalleable || opt.withDeterministic {
		sigProps := &SignatureProperties{
			NonMalleable:  opt.withNonMalleable,
			Deterministic: opt.withDeterministic,
		}
		resOpts = append(resOpts, sigProps)
	}
	if opt.withNonceMisuseResistance {
		aeadProps := &AEADProperties{
			NonceMisuseResistant: opt.withNonceMisuseResistance,
		}
		resOpts = append(resOpts, aeadProps)
	}
	if opt.withForwardSecrecy {
		kaProps := &KeyAgreementProperties{
			ForwardSecrecy: opt.withForwardSecrecy,
		}
		resOpts = append(resOpts, kaProps)
	}
	if opt.withMemoryHard {
		kdfProps := &KDFProperties{
			MemoryHard: opt.withMemoryHard,
		}
		resOpts = append(resOpts, kdfProps)
	}
	if len(resOpts) == 0 {
		return nil, nil
	}
	if len(resOpts) > 1 {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "conflicting options provided for scope-specific properties: options apply to multiple primitives")
	}
	return resOpts[0], nil
}

type SignatureProperties struct {
	NonMalleable  bool
	Deterministic bool
	// AcceptedDigestHashes lists the digest hashes a prehashed scope accepts,
	// preferred first (proto: SignatureScopeSpec.accepted_digest_hashes).
	// On a template it is what the template can sign; on a request, a
	// requirement the template must satisfy; on a key version, what the
	// version accepts. Empty for non-prehashed scopes.
	AcceptedDigestHashes []types.HashAlgorithm
}

// IsPrehashed reports whether the scope's input is a digest rather than a
// message.
func (s Scope) IsPrehashed() bool {
	return s == ScopeSignaturePrehashed || s == ScopeSignaturePrehashedWithContext
}

// AcceptedDigestHashes returns the digest hashes recorded in a signature
// scope specification, or nil when there are none.
func (s *ScopeSpecification) AcceptedDigestHashes() []types.HashAlgorithm {
	if s == nil {
		return nil
	}
	if p, ok := s.PrimitiveSpecificProps.(*SignatureProperties); ok && p != nil {
		return p.AcceptedDigestHashes
	}
	return nil
}

// WithAcceptedDigestHashes returns a copy of s whose accepted digest hashes
// are hashes, keeping every other property. s is not modified.
func (s *ScopeSpecification) WithAcceptedDigestHashes(hashes []types.HashAlgorithm) *ScopeSpecification {
	res := *s
	props := &SignatureProperties{}
	if p, ok := s.PrimitiveSpecificProps.(*SignatureProperties); ok && p != nil {
		*props = *p
	}
	props.AcceptedDigestHashes = append([]types.HashAlgorithm(nil), hashes...)
	res.PrimitiveSpecificProps = props
	return &res
}

func (s *SignatureProperties) defaultPrimitiveSpecificProperties() PrimitiveSpecificProperties {
	return &SignatureProperties{}
}

func (s *SignatureProperties) GetPrimitive() Primitive {
	return PrimitiveSignature
}

func (s *SignatureProperties) GetScopes() []Scope {
	return s.GetPrimitive().ListScopes()
}

type AEADProperties struct {
	NonceMisuseResistant bool
}

func (a *AEADProperties) defaultPrimitiveSpecificProperties() PrimitiveSpecificProperties {
	return &AEADProperties{}
}

func (a *AEADProperties) GetPrimitive() Primitive {
	return PrimitiveAead
}

func (a *AEADProperties) GetScopes() []Scope {
	return a.GetPrimitive().ListScopes()
}

type KeyAgreementProperties struct {
	ForwardSecrecy bool
}

func (k *KeyAgreementProperties) defaultPrimitiveSpecificProperties() PrimitiveSpecificProperties {
	return &KeyAgreementProperties{}
}

func (k *KeyAgreementProperties) GetPrimitive() Primitive {
	return PrimitiveKeyAgreement
}

func (k *KeyAgreementProperties) GetScopes() []Scope {
	return k.GetPrimitive().ListScopes()
}

type KDFProperties struct {
	MemoryHard bool
}

func (k *KDFProperties) defaultPrimitiveSpecificProperties() PrimitiveSpecificProperties {
	return &KDFProperties{}
}

func (k *KDFProperties) GetPrimitive() Primitive {
	return PrimitiveKdf
}

func (k *KDFProperties) GetScopes() []Scope {
	return k.GetPrimitive().ListScopes()
}
