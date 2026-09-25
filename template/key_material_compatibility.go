package template

import (
	"fmt"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// KeyMaterialProfile is the normalized, key-defining portion of a template.
// MaterialFamily comes from TemplateInfo.key_material_family. Shape is derived
// exclusively from the typed algorithm arm; operation parameters such as hash,
// padding, nonce size, and signature encoding are intentionally excluded.
type KeyMaterialProfile struct {
	MaterialFamily string
	Shape          string
}

// KeyMaterialProfileFor returns the retained-key-material profile declared by
// tmpl. It fails closed for incomplete, mislabeled, or unsupported algorithms.
// CycloneDX algorithm_family is taxonomy metadata and is not part of this
// compatibility decision.
func KeyMaterialProfileFor(tmpl *Template) (KeyMaterialProfile, error) {
	if tmpl == nil {
		return KeyMaterialProfile{}, fmt.Errorf("key material profile: template is nil")
	}

	info := tmpl.Proto()
	if info == nil {
		return KeyMaterialProfile{}, fmt.Errorf("key material profile: template is nil")
	}
	prefix := fmt.Sprintf("key material profile for template %q", info.GetTemplateId())
	family := info.GetKeyMaterialFamily()
	if family == "" {
		return KeyMaterialProfile{}, fmt.Errorf("%s: key_material_family is required", prefix)
	}
	details := info.GetAlgorithm()
	if details == nil || details.GetAlgorithm() == nil {
		return KeyMaterialProfile{}, fmt.Errorf("%s: typed algorithm is required", prefix)
	}

	expectedFamily, shape, err := typedKeyMaterialShape(details)
	if err != nil {
		return KeyMaterialProfile{}, fmt.Errorf("%s: %w", prefix, err)
	}
	if family != expectedFamily {
		return KeyMaterialProfile{}, fmt.Errorf(
			"%s: key_material_family %q does not match typed algorithm family %q",
			prefix, family, expectedFamily,
		)
	}

	return KeyMaterialProfile{MaterialFamily: family, Shape: shape}, nil
}

// CompatibleKeyMaterial reports whether source and target describe the same
// reusable key material. Invalid catalog entries return an error; two valid but
// different profiles return false without an error. The operation is symmetric.
func CompatibleKeyMaterial(source, target *Template) (bool, error) {
	sourceProfile, err := KeyMaterialProfileFor(source)
	if err != nil {
		return false, fmt.Errorf("source template: %w", err)
	}
	targetProfile, err := KeyMaterialProfileFor(target)
	if err != nil {
		return false, fmt.Errorf("target template: %w", err)
	}
	return sourceProfile == targetProfile, nil
}

// shapeResolver derives a key shape for the algorithm arms it recognizes;
// handled is false for arms owned by another resolver.
type shapeResolver func(algorithm any) (family, shape string, handled bool, err error)

var shapeResolvers = []shapeResolver{asymmetricShape, symmetricShape, agreementShape}

func typedKeyMaterialShape(details *api.AlgorithmDetails) (family, shape string, err error) {
	algorithm := details.GetAlgorithm()
	for _, resolve := range shapeResolvers {
		if family, shape, handled, err := resolve(algorithm); handled {
			return family, shape, err
		}
	}
	return "", "", unsupportedShape(algorithm)
}

func handledShape(family, shape string, err error) (string, string, bool, error) {
	return family, shape, true, err
}

func asymmetricShape(a any) (string, string, bool, error) {
	switch algorithm := a.(type) {
	case *api.AlgorithmDetails_Ecdsa:
		return handledShape(enumShape("ECDSA", "curve", "curve", algorithm.Ecdsa.GetCurve(), api.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED))
	case *api.AlgorithmDetails_Ed25519:
		return handledShape(fixedShape("Ed25519", "Ed25519", algorithm.Ed25519 != nil))
	case *api.AlgorithmDetails_Ed448:
		return handledShape(fixedShape("Ed448", "Ed448", algorithm.Ed448 != nil))
	case *api.AlgorithmDetails_RsaPss:
		return handledShape(paramsSizedShape("RSA-PSS", algorithm.RsaPss != nil, "RSA", "modulus-bits", algorithm.RsaPss.GetKeySizeBits()))
	case *api.AlgorithmDetails_RsaPkcs1V15:
		return handledShape(paramsSizedShape("RSA-PKCS1-v1.5", algorithm.RsaPkcs1V15 != nil, "RSA", "modulus-bits", algorithm.RsaPkcs1V15.GetKeySizeBits()))
	case *api.AlgorithmDetails_RsaOaep:
		return handledShape(paramsSizedShape("RSA-OAEP", algorithm.RsaOaep != nil, "RSA", "modulus-bits", algorithm.RsaOaep.GetKeySizeBits()))
	case *api.AlgorithmDetails_MlDsa:
		return handledShape(enumShape("ML-DSA", "parameter-set", "parameter set", algorithm.MlDsa.GetParameterSet(), api.MlDsaParameterSet_ML_DSA_PARAMETER_SET_UNSPECIFIED))
	case *api.AlgorithmDetails_SlhDsa:
		return handledShape(slhDsaShape(algorithm.SlhDsa))
	case *api.AlgorithmDetails_MlKem:
		return handledShape(enumShape("ML-KEM", "parameter-set", "parameter set", algorithm.MlKem.GetParameterSet(), api.MlKemParameterSet_ML_KEM_PARAMETER_SET_UNSPECIFIED))
	}
	return "", "", false, nil
}

func symmetricShape(a any) (string, string, bool, error) {
	switch algorithm := a.(type) {
	case *api.AlgorithmDetails_AesGcm:
		return handledShape(paramsSizedShape("AES-GCM", algorithm.AesGcm != nil, "AES", "key-bits", algorithm.AesGcm.GetKeySizeBits()))
	case *api.AlgorithmDetails_AesCbc:
		return handledShape(paramsSizedShape("AES-CBC", algorithm.AesCbc != nil, "AES", "key-bits", algorithm.AesCbc.GetKeySizeBits()))
	case *api.AlgorithmDetails_AesCtr:
		return handledShape(paramsSizedShape("AES-CTR", algorithm.AesCtr != nil, "AES", "key-bits", algorithm.AesCtr.GetKeySizeBits()))
	case *api.AlgorithmDetails_AesCcm:
		return handledShape(paramsSizedShape("AES-CCM", algorithm.AesCcm != nil, "AES", "key-bits", algorithm.AesCcm.GetKeySizeBits()))
	case *api.AlgorithmDetails_AesKeyWrap:
		return handledShape(paramsSizedShape("AES key-wrap", algorithm.AesKeyWrap != nil, "AES", "key-bits", algorithm.AesKeyWrap.GetKeySizeBits()))
	case *api.AlgorithmDetails_AesXts:
		return handledShape(paramsSizedShape("AES-XTS", algorithm.AesXts != nil, "AES-XTS", "total-key-bits", algorithm.AesXts.GetKeySizeBits()))
	case *api.AlgorithmDetails_Chacha20Poly1305:
		return handledShape(fixedShape("ChaCha20-Poly1305", "ChaCha20", algorithm.Chacha20Poly1305 != nil))
	}
	return "", "", false, nil
}

func agreementShape(a any) (string, string, bool, error) {
	switch algorithm := a.(type) {
	case *api.AlgorithmDetails_Ecdh:
		return handledShape(enumShape("ECDH", "curve", "curve", algorithm.Ecdh.GetCurve(), api.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED))
	case *api.AlgorithmDetails_X25519:
		return handledShape(fixedShape("X25519", "X25519", algorithm.X25519 != nil))
	case *api.AlgorithmDetails_X448:
		return handledShape(fixedShape("X448", "X448", algorithm.X448 != nil))
	}
	return "", "", false, nil
}

func unsupportedShape(algorithm any) error {
	switch algorithm.(type) {
	case *api.AlgorithmDetails_Hmac:
		return fmt.Errorf("HMAC is unsupported: typed API has no key-material size constraint")
	case *api.AlgorithmDetails_Custom:
		return fmt.Errorf("custom algorithms are unsupported for retained key material")
	case *api.AlgorithmDetails_Hybrid:
		return fmt.Errorf("hybrid algorithms are unsupported for retained key material")
	default:
		return fmt.Errorf("typed algorithm %T is unsupported for retained key material", algorithm)
	}
}

// fixedShape describes families whose key shape is fully determined by the
// algorithm; present reports whether the typed parameters were supplied.
func fixedShape(name, family string, present bool) (string, string, error) {
	if !present {
		return "", "", fmt.Errorf("%s parameters are required", name)
	}
	return family, "fixed", nil
}

// paramsSizedShape requires typed parameters and a non-zero key size.
func paramsSizedShape(name string, present bool, family, label string, size uint32) (string, string, error) {
	if !present {
		return "", "", fmt.Errorf("%s parameters are required", name)
	}
	return sizedShape(family, label, size)
}

func slhDsaShape(params *api.SlhDsaParams) (string, string, error) {
	if params.GetHashType() == api.SlhDsaHashType_SLH_DSA_HASH_TYPE_UNSPECIFIED ||
		params.GetParameterSet() == api.SlhDsaParameterSet_SLH_DSA_PARAMETER_SET_UNSPECIFIED {
		return "", "", fmt.Errorf("SLH-DSA hash type and parameter set are required")
	}
	return "SLH-DSA", fmt.Sprintf("hash-type:%d/parameter-set:%d", params.GetHashType(), params.GetParameterSet()), nil
}

func sizedShape(family, label string, size uint32) (string, string, error) {
	if size == 0 {
		return "", "", fmt.Errorf("%s %s is required", family, label)
	}
	return family, fmt.Sprintf("%s:%d", label, size), nil
}

// enumShape requires a specified enum value; nil parameters yield the
// unspecified value through the generated getter and are rejected.
func enumShape[T ~int32](family, label, description string, value, unspecified T) (string, string, error) {
	if value == unspecified {
		return "", "", fmt.Errorf("%s %s is required", family, description)
	}
	return family, fmt.Sprintf("%s:%d", label, value), nil
}
