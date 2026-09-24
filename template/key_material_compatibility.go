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

func typedKeyMaterialShape(details *api.AlgorithmDetails) (family, shape string, err error) {
	switch algorithm := details.GetAlgorithm().(type) {
	case *api.AlgorithmDetails_Ecdsa:
		if algorithm.Ecdsa == nil || algorithm.Ecdsa.GetCurve() == api.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED {
			return "", "", fmt.Errorf("ECDSA curve is required")
		}
		return "ECDSA", enumShape("curve", algorithm.Ecdsa.GetCurve()), nil
	case *api.AlgorithmDetails_Ed25519:
		if algorithm.Ed25519 == nil {
			return "", "", fmt.Errorf("Ed25519 parameters are required")
		}
		return "Ed25519", "fixed", nil
	case *api.AlgorithmDetails_Ed448:
		if algorithm.Ed448 == nil {
			return "", "", fmt.Errorf("Ed448 parameters are required")
		}
		return "Ed448", "fixed", nil
	case *api.AlgorithmDetails_RsaPss:
		if algorithm.RsaPss == nil {
			return "", "", fmt.Errorf("RSA-PSS parameters are required")
		}
		return sizedShape("RSA", "modulus-bits", algorithm.RsaPss.GetKeySizeBits())
	case *api.AlgorithmDetails_RsaPkcs1V15:
		if algorithm.RsaPkcs1V15 == nil {
			return "", "", fmt.Errorf("RSA-PKCS1-v1.5 parameters are required")
		}
		return sizedShape("RSA", "modulus-bits", algorithm.RsaPkcs1V15.GetKeySizeBits())
	case *api.AlgorithmDetails_RsaOaep:
		if algorithm.RsaOaep == nil {
			return "", "", fmt.Errorf("RSA-OAEP parameters are required")
		}
		return sizedShape("RSA", "modulus-bits", algorithm.RsaOaep.GetKeySizeBits())
	case *api.AlgorithmDetails_MlDsa:
		if algorithm.MlDsa == nil || algorithm.MlDsa.GetParameterSet() == api.MlDsaParameterSet_ML_DSA_PARAMETER_SET_UNSPECIFIED {
			return "", "", fmt.Errorf("ML-DSA parameter set is required")
		}
		return "ML-DSA", enumShape("parameter-set", algorithm.MlDsa.GetParameterSet()), nil
	case *api.AlgorithmDetails_SlhDsa:
		if algorithm.SlhDsa == nil || algorithm.SlhDsa.GetHashType() == api.SlhDsaHashType_SLH_DSA_HASH_TYPE_UNSPECIFIED || algorithm.SlhDsa.GetParameterSet() == api.SlhDsaParameterSet_SLH_DSA_PARAMETER_SET_UNSPECIFIED {
			return "", "", fmt.Errorf("SLH-DSA hash type and parameter set are required")
		}
		return "SLH-DSA", fmt.Sprintf("hash-type:%d/parameter-set:%d", algorithm.SlhDsa.GetHashType(), algorithm.SlhDsa.GetParameterSet()), nil
	case *api.AlgorithmDetails_MlKem:
		if algorithm.MlKem == nil || algorithm.MlKem.GetParameterSet() == api.MlKemParameterSet_ML_KEM_PARAMETER_SET_UNSPECIFIED {
			return "", "", fmt.Errorf("ML-KEM parameter set is required")
		}
		return "ML-KEM", enumShape("parameter-set", algorithm.MlKem.GetParameterSet()), nil
	case *api.AlgorithmDetails_AesGcm:
		if algorithm.AesGcm == nil {
			return "", "", fmt.Errorf("AES-GCM parameters are required")
		}
		return sizedShape("AES", "key-bits", algorithm.AesGcm.GetKeySizeBits())
	case *api.AlgorithmDetails_AesCbc:
		if algorithm.AesCbc == nil {
			return "", "", fmt.Errorf("AES-CBC parameters are required")
		}
		return sizedShape("AES", "key-bits", algorithm.AesCbc.GetKeySizeBits())
	case *api.AlgorithmDetails_AesCtr:
		if algorithm.AesCtr == nil {
			return "", "", fmt.Errorf("AES-CTR parameters are required")
		}
		return sizedShape("AES", "key-bits", algorithm.AesCtr.GetKeySizeBits())
	case *api.AlgorithmDetails_AesCcm:
		if algorithm.AesCcm == nil {
			return "", "", fmt.Errorf("AES-CCM parameters are required")
		}
		return sizedShape("AES", "key-bits", algorithm.AesCcm.GetKeySizeBits())
	case *api.AlgorithmDetails_AesKeyWrap:
		if algorithm.AesKeyWrap == nil {
			return "", "", fmt.Errorf("AES key-wrap parameters are required")
		}
		return sizedShape("AES", "key-bits", algorithm.AesKeyWrap.GetKeySizeBits())
	case *api.AlgorithmDetails_AesXts:
		if algorithm.AesXts == nil {
			return "", "", fmt.Errorf("AES-XTS parameters are required")
		}
		return sizedShape("AES-XTS", "total-key-bits", algorithm.AesXts.GetKeySizeBits())
	case *api.AlgorithmDetails_Chacha20Poly1305:
		if algorithm.Chacha20Poly1305 == nil {
			return "", "", fmt.Errorf("ChaCha20-Poly1305 parameters are required")
		}
		return "ChaCha20", "fixed", nil
	case *api.AlgorithmDetails_Ecdh:
		if algorithm.Ecdh == nil || algorithm.Ecdh.GetCurve() == api.EllipticCurve_ELLIPTIC_CURVE_UNSPECIFIED {
			return "", "", fmt.Errorf("ECDH curve is required")
		}
		return "ECDH", enumShape("curve", algorithm.Ecdh.GetCurve()), nil
	case *api.AlgorithmDetails_X25519:
		if algorithm.X25519 == nil {
			return "", "", fmt.Errorf("X25519 parameters are required")
		}
		return "X25519", "fixed", nil
	case *api.AlgorithmDetails_X448:
		if algorithm.X448 == nil {
			return "", "", fmt.Errorf("X448 parameters are required")
		}
		return "X448", "fixed", nil
	case *api.AlgorithmDetails_Hmac:
		return "", "", fmt.Errorf("HMAC is unsupported: typed API has no key-material size constraint")
	case *api.AlgorithmDetails_Custom:
		return "", "", fmt.Errorf("custom algorithms are unsupported for retained key material")
	case *api.AlgorithmDetails_Hybrid:
		return "", "", fmt.Errorf("hybrid algorithms are unsupported for retained key material")
	default:
		return "", "", fmt.Errorf("typed algorithm %T is unsupported for retained key material", algorithm)
	}
}

func sizedShape(family, label string, size uint32) (string, string, error) {
	if size == 0 {
		return "", "", fmt.Errorf("%s %s is required", family, label)
	}
	return family, fmt.Sprintf("%s:%d", label, size), nil
}

func enumShape[T ~int32](label string, value T) string {
	return fmt.Sprintf("%s:%d", label, value)
}
