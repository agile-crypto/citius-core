package core

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/protobuf/proto"
)

type ScopeSpecification struct {
	Scope                  Scope
	SecurityProps          *SecurityProperties
	PrimitiveSpecificProps PrimitiveSpecificProperties
	AdditionalProps        map[string]string
}

// Creates a ScopeSpecification for the given scope and options. A scope specification behaves as
// a filter for listing keys or repositories, as a requirement for key generation (only keys matching the scope specification
// will be listed or generated), or as a set of properties for a given algorithm template. A scope specification is
// defined by a scope and a set of optional properties.
// Options available depends on the primitive associated with the scope. Options are not checked,
// meaning that it is possible to set signature-specific options (eg. non-malleability) on a non-signature scope,
// but such options will be ignored.
//
// Available options for all primitives:
//   - WithSecurityProperties: sets the security properties the key template must satisfy.
//   - WithAdditionalProperties: sets additional properties (eg. vendor-specific) to be sent with the request.
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
func NewScopeSpecification(ctx context.Context, scope Scope, securityProps *SecurityProperties, primitiveSpecificProps PrimitiveSpecificProperties,
	additionalProps map[string]string) (*ScopeSpecification, error) {
	const op = "core.NewScopeSpecification"
	if !scope.IsValid() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "invalid scope: %s", scope)
	}
	if primitiveSpecificProps != nil && scope.GetPrimitive() != primitiveSpecificProps.GetPrimitive() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "primitive (%s) for given scope (%s) does not match the primitive of the primitive-specific properties (%s)",
			scope.GetPrimitive(), scope, primitiveSpecificProps.GetPrimitive())
	}
	return &ScopeSpecification{
		Scope:                  scope,
		SecurityProps:          securityProps,
		PrimitiveSpecificProps: primitiveSpecificProps,
		AdditionalProps:        additionalProps,
	}, nil
}

type protoScopeSpec struct {
	scope           any
	securityProps   *types.UniversalSecurityProperties
	primitiveProps  PrimitiveSpecificProperties
	additionalProps map[string]string
}

func extractCommon(protoScope any, protoSecurityProps *types.UniversalSecurityProperties, additionalProps map[string]string) *protoScopeSpec {
	return &protoScopeSpec{
		scope:           protoScope,
		securityProps:   protoSecurityProps,
		primitiveProps:  nil,
		additionalProps: additionalProps,
	}
}

func extractAEAD(s *types.ScopeSpecification_Aead) *protoScopeSpec {
	res := &protoScopeSpec{
		scope:           s.Aead.Scope,
		securityProps:   s.Aead.Security,
		additionalProps: s.Aead.AdditionalProperties,
	}
	if s.Aead.NonceMisuseResistant != nil {
		res.primitiveProps = &AEADProperties{
			NonceMisuseResistant: *s.Aead.NonceMisuseResistant,
		}
	}
	return res
}

func extractKeyAgreement(s *types.ScopeSpecification_KeyAgreement) *protoScopeSpec {
	res := &protoScopeSpec{
		scope:           s.KeyAgreement.Scope,
		securityProps:   s.KeyAgreement.Security,
		additionalProps: s.KeyAgreement.AdditionalProperties,
	}
	if s.KeyAgreement.ForwardSecrecy != nil {
		res.primitiveProps = &KeyAgreementProperties{
			ForwardSecrecy: *s.KeyAgreement.ForwardSecrecy,
		}
	}
	return res
}

func extractKDF(s *types.ScopeSpecification_Kdf) *protoScopeSpec {
	res := &protoScopeSpec{
		scope:           s.Kdf.Scope,
		securityProps:   s.Kdf.Security,
		additionalProps: s.Kdf.AdditionalProperties,
	}
	if s.Kdf.MemoryHard != nil {
		res.primitiveProps = &KDFProperties{
			MemoryHard: *s.Kdf.MemoryHard,
		}
	}
	return res
}

func extractSignature(s *types.ScopeSpecification_Signature) *protoScopeSpec {
	res := &protoScopeSpec{
		scope:           s.Signature.Scope,
		securityProps:   s.Signature.Security,
		additionalProps: s.Signature.AdditionalProperties,
	}
	if s.Signature.NonMalleable != nil || s.Signature.Deterministic != nil || len(s.Signature.AcceptedDigestHashes) > 0 {
		res.primitiveProps = &SignatureProperties{
			NonMalleable:         s.Signature.NonMalleable != nil && *s.Signature.NonMalleable,
			Deterministic:        s.Signature.Deterministic != nil && *s.Signature.Deterministic,
			AcceptedDigestHashes: append([]types.HashAlgorithm(nil), s.Signature.AcceptedDigestHashes...),
		}
	}
	return res
}

func extractProtoScopeSpec(ctx context.Context, s *types.ScopeSpecification) (*protoScopeSpec, error) {
	const op = "core.extractProtoScopeSpec"
	switch v := s.ScopeSpec.(type) {
	case *types.ScopeSpecification_Aead:
		return extractAEAD(v), nil
	case *types.ScopeSpecification_DiskEncryption:
		return extractCommon(v.DiskEncryption.Scope, v.DiskEncryption.Security, v.DiskEncryption.AdditionalProperties), nil
	case *types.ScopeSpecification_GenericSecret:
		return extractCommon(v.GenericSecret.Scope, v.GenericSecret.Security, v.GenericSecret.AdditionalProperties), nil
	case *types.ScopeSpecification_KeyAgreement:
		return extractKeyAgreement(v), nil
	case *types.ScopeSpecification_Hash:
		return extractCommon(v.Hash.Scope, v.Hash.Security, v.Hash.AdditionalProperties), nil
	case *types.ScopeSpecification_Kdf:
		return extractKDF(v), nil
	case *types.ScopeSpecification_Kem:
		return extractCommon(v.Kem.Scope, v.Kem.Security, v.Kem.AdditionalProperties), nil
	case *types.ScopeSpecification_KeyWrapping:
		return extractCommon(v.KeyWrapping.Scope, v.KeyWrapping.Security, v.KeyWrapping.AdditionalProperties), nil
	case *types.ScopeSpecification_Mac:
		return extractCommon(v.Mac.Scope, v.Mac.Security, v.Mac.AdditionalProperties), nil
	case *types.ScopeSpecification_Signature:
		return extractSignature(v), nil
	case *types.ScopeSpecification_SymmetricCipher:
		return extractCommon(v.SymmetricCipher.Scope, v.SymmetricCipher.Security, v.SymmetricCipher.AdditionalProperties), nil
	default:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "invalid scope specification proto: missing or unrecognized scope")
	}
}

func ScopeSpecificationFromProto(ctx context.Context, s *types.ScopeSpecification) (*ScopeSpecification, error) {
	const op = "core.ScopeSpecificationFromProto"
	if s == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "scope specification proto is nil")
	}
	protoScopeSpec, err := extractProtoScopeSpec(ctx, s)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	scope, ok := ScopeFromProto(protoScopeSpec.scope)
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "invalid scope specification proto: unrecognized scope")
	}
	return &ScopeSpecification{
		Scope:                  scope,
		SecurityProps:          SecurityPropertiesFromProto(protoScopeSpec.securityProps),
		PrimitiveSpecificProps: protoScopeSpec.primitiveProps,
		AdditionalProps:        protoScopeSpec.additionalProps,
	}, nil
}

// If the pointer argument p is not nil, cast it to type T and apply the function f to it and return a pointer to its result. Otherwise, return nil.
// NB: This was ok to reduce the cyclomatic complexity of the ToProto function, but it may be better to have one toProto function per primitive type,
// to avoid the need for this helper function, which does not really reduce complexity, but just moves it to another function.
func computeIfNotNil[T PrimitiveSpecificProperties, V any](p PrimitiveSpecificProperties, f func(T) V) *V {
	if p != nil {
		t, ok := p.(T)
		if !ok {
			// if the type assertion fails, return nil. This should not happen if the code is used correctly.
			return nil
		}
		res := f(t)
		return &res
	}
	return nil
}

// trueOrNil is computeIfNotNil for a boolean property whose false value means
// "not required": it returns nil unless f(p) is true. A false property is left
// unset rather than recorded as false, so a spec that only carries other
// properties (such as accepted digest hashes) does not claim false for a
// property the template may well have.
func trueOrNil[T PrimitiveSpecificProperties](p PrimitiveSpecificProperties, f func(T) bool) *bool {
	if v := computeIfNotNil(p, f); v != nil && *v {
		return v
	}
	return nil
}

// Helper to build a protobuf [types.ScopeSpecification] from a scope and a list of options.
func (s *ScopeSpecification) ToProto(ctx context.Context) (*types.ScopeSpecification, error) {
	const op = "core.ScopeSpecification.ToProto"
	switch s.Scope.GetPrimitive() {
	case PrimitiveAead:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_Aead{
				Aead: &types.AeadScopeSpec{
					Scope:                s.Scope.ToProto().(types.AeadScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
					NonceMisuseResistant: computeIfNotNil(s.PrimitiveSpecificProps, func(p *AEADProperties) bool { return p.NonceMisuseResistant }),
				},
			},
		}, nil
	case PrimitiveDiskEncryption:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_DiskEncryption{
				DiskEncryption: &types.DiskEncryptionScopeSpec{
					Scope:                s.Scope.ToProto().(types.DiskEncryptionScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	case PrimitiveGenericSecret:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_GenericSecret{
				GenericSecret: &types.GenericSecretScopeSpec{
					Scope:                s.Scope.ToProto().(types.GenericSecretScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	case PrimitiveKeyAgreement:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_KeyAgreement{
				KeyAgreement: &types.KeyAgreementScopeSpec{
					Scope:                s.Scope.ToProto().(types.KeyAgreementScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
					ForwardSecrecy:       computeIfNotNil(s.PrimitiveSpecificProps, func(p *KeyAgreementProperties) bool { return p.ForwardSecrecy }),
				},
			},
		}, nil
	case PrimitiveHash:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_Hash{
				Hash: &types.HashScopeSpec{
					Scope:                s.Scope.ToProto().(types.HashScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	case PrimitiveKdf:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_Kdf{
				Kdf: &types.KdfScopeSpec{
					Scope:                s.Scope.ToProto().(types.KdfScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
					MemoryHard:           computeIfNotNil(s.PrimitiveSpecificProps, func(p *KDFProperties) bool { return p.MemoryHard }),
				},
			},
		}, nil
	case PrimitiveKem:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_Kem{
				Kem: &types.KemScopeSpec{
					Scope:                s.Scope.ToProto().(types.KemScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	case PrimitiveKeyWrapping:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_KeyWrapping{
				KeyWrapping: &types.KeyWrappingScopeSpec{
					Scope:                s.Scope.ToProto().(types.KeyWrappingScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	case PrimitiveMac:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_Mac{
				Mac: &types.MacScopeSpec{
					Scope:                s.Scope.ToProto().(types.MacScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	case PrimitiveSignature:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_Signature{
				Signature: &types.SignatureScopeSpec{
					Scope:                s.Scope.ToProto().(types.SignatureScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
					NonMalleable:         trueOrNil(s.PrimitiveSpecificProps, func(p *SignatureProperties) bool { return p.NonMalleable }),
					Deterministic:        trueOrNil(s.PrimitiveSpecificProps, func(p *SignatureProperties) bool { return p.Deterministic }),
					AcceptedDigestHashes: append([]types.HashAlgorithm(nil), s.AcceptedDigestHashes()...),
				},
			},
		}, nil
	case PrimitiveSymmetricCipher:
		return &types.ScopeSpecification{
			ScopeSpec: &types.ScopeSpecification_SymmetricCipher{
				SymmetricCipher: &types.SymmetricCipherScopeSpec{
					Scope:                s.Scope.ToProto().(types.SymmetricCipherScope),
					Security:             s.SecurityProps.ToProto(),
					AdditionalProperties: s.AdditionalProps,
				},
			},
		}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "missing or invalid scope")
	}
}

// Serialize the ScopeSpecification to bytes. The output is a protobuf-encoded [types.ScopeSpecification] message.
func (s *ScopeSpecification) Serialize(ctx context.Context) ([]byte, error) {
	const op errors.Op = "core.(ScopeSpecification).Serialize"
	protoSpec, err := s.ToProto(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	res, err := proto.Marshal(protoSpec)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err, errors.WithMessage("failed to marshal scope specification proto"))
	}
	return res, nil
}

// Deserialize a ScopeSpecification from bytes. The input is expected to be a protobuf-encoded [types.ScopeSpecification] message.
func (s *ScopeSpecification) Deserialize(ctx context.Context, data []byte) error {
	const op errors.Op = "core.(ScopeSpecification).Deserialize"
	if len(data) == 0 {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "empty data")
	}
	protoSpec := &types.ScopeSpecification{}
	if err := proto.Unmarshal(data, protoSpec); err != nil {
		return errors.Wrap(ctx, op, err, errors.WithMessage("failed to unmarshal scope specification proto"))
	}
	s0, err := ScopeSpecificationFromProto(ctx, protoSpec)
	if err != nil {
		return errors.Wrap(ctx, op, err, errors.WithMessage("failed to convert proto scope specification"))
	}
	if s0 == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "invalid scope specification proto: conversion resulted in nil")
	}
	*s = *s0
	return nil
}
