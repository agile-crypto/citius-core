package template_test

import (
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/template"
	"github.com/stretchr/testify/require"
)

func TestCompatibleKeyMaterial_supportedArms(t *testing.T) {
	p256 := api.EllipticCurve_ELLIPTIC_CURVE_P256
	p384 := api.EllipticCurve_ELLIPTIC_CURVE_P384

	tests := []struct {
		name         string
		source       *template.Template
		compatible   *template.Template
		incompatible *template.Template
	}{
		{
			name: "ECDSA compares only curve",
			source: tmpl("ECDSA", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{
				Curve: p256, Hash: api.HashAlgorithm(1), SignatureFormat: api.SignatureFormat(1), Deterministic: false,
			}}),
			compatible: tmpl("ECDSA", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{
				Curve: p256, Hash: api.HashAlgorithm(3), SignatureFormat: api.SignatureFormat(2), Deterministic: true,
			}}),
			incompatible: tmpl("ECDSA", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{Curve: p384}}),
		},
		{
			name:         "Ed25519 is fixed across variants",
			source:       tmpl("Ed25519", &api.AlgorithmDetails_Ed25519{Ed25519: &api.Ed25519Params{Variant: api.Ed25519Variant(1)}}),
			compatible:   tmpl("Ed25519", &api.AlgorithmDetails_Ed25519{Ed25519: &api.Ed25519Params{Variant: api.Ed25519Variant(2)}}),
			incompatible: tmpl("Ed448", &api.AlgorithmDetails_Ed448{Ed448: &api.Ed448Params{}}),
		},
		{
			name:         "Ed448 is fixed across variants",
			source:       tmpl("Ed448", &api.AlgorithmDetails_Ed448{Ed448: &api.Ed448Params{Variant: api.Ed448Variant(1)}}),
			compatible:   tmpl("Ed448", &api.AlgorithmDetails_Ed448{Ed448: &api.Ed448Params{Variant: api.Ed448Variant(2)}}),
			incompatible: tmpl("Ed25519", &api.AlgorithmDetails_Ed25519{Ed25519: &api.Ed25519Params{}}),
		},
		{
			name:         "RSA-PSS shares RSA material by modulus size",
			source:       tmpl("RSA", &api.AlgorithmDetails_RsaPss{RsaPss: &api.RsaPssParams{KeySizeBits: 2048, Hash: api.HashAlgorithm(1)}}),
			compatible:   tmpl("RSA", &api.AlgorithmDetails_RsaPkcs1V15{RsaPkcs1V15: &api.RsaPkcs1V15Params{KeySizeBits: 2048, Hash: api.HashAlgorithm(3)}}),
			incompatible: tmpl("RSA", &api.AlgorithmDetails_RsaOaep{RsaOaep: &api.RsaOaepParams{KeySizeBits: 3072}}),
		},
		{
			name:         "RSA-PKCS1 shares RSA material by modulus size",
			source:       tmpl("RSA", &api.AlgorithmDetails_RsaPkcs1V15{RsaPkcs1V15: &api.RsaPkcs1V15Params{KeySizeBits: 3072}}),
			compatible:   tmpl("RSA", &api.AlgorithmDetails_RsaOaep{RsaOaep: &api.RsaOaepParams{KeySizeBits: 3072, Hash: api.HashAlgorithm(2)}}),
			incompatible: tmpl("RSA", &api.AlgorithmDetails_RsaPss{RsaPss: &api.RsaPssParams{KeySizeBits: 4096}}),
		},
		{
			name:         "RSA-OAEP shares RSA material by modulus size",
			source:       tmpl("RSA", &api.AlgorithmDetails_RsaOaep{RsaOaep: &api.RsaOaepParams{KeySizeBits: 4096}}),
			compatible:   tmpl("RSA", &api.AlgorithmDetails_RsaPss{RsaPss: &api.RsaPssParams{KeySizeBits: 4096}}),
			incompatible: tmpl("RSA", &api.AlgorithmDetails_RsaPkcs1V15{RsaPkcs1V15: &api.RsaPkcs1V15Params{KeySizeBits: 2048}}),
		},
		{
			name:         "ML-DSA compares parameter set",
			source:       tmpl("ML-DSA", &api.AlgorithmDetails_MlDsa{MlDsa: &api.MlDsaParams{ParameterSet: api.MlDsaParameterSet_ML_DSA_65}}),
			compatible:   tmpl("ML-DSA", &api.AlgorithmDetails_MlDsa{MlDsa: &api.MlDsaParams{ParameterSet: api.MlDsaParameterSet_ML_DSA_65, Deterministic: true}}),
			incompatible: tmpl("ML-DSA", &api.AlgorithmDetails_MlDsa{MlDsa: &api.MlDsaParams{ParameterSet: api.MlDsaParameterSet_ML_DSA_87}}),
		},
		{
			name: "SLH-DSA compares hash type and parameter set",
			source: tmpl("SLH-DSA", &api.AlgorithmDetails_SlhDsa{SlhDsa: &api.SlhDsaParams{
				HashType: api.SlhDsaHashType_SLH_DSA_SHA2, ParameterSet: api.SlhDsaParameterSet_SLH_DSA_128S,
			}}),
			compatible: tmpl("SLH-DSA", &api.AlgorithmDetails_SlhDsa{SlhDsa: &api.SlhDsaParams{
				HashType: api.SlhDsaHashType_SLH_DSA_SHA2, ParameterSet: api.SlhDsaParameterSet_SLH_DSA_128S, Deterministic: true,
			}}),
			incompatible: tmpl("SLH-DSA", &api.AlgorithmDetails_SlhDsa{SlhDsa: &api.SlhDsaParams{
				HashType: api.SlhDsaHashType_SLH_DSA_SHAKE, ParameterSet: api.SlhDsaParameterSet_SLH_DSA_128S,
			}}),
		},
		{
			name:         "ML-KEM compares parameter set",
			source:       tmpl("ML-KEM", &api.AlgorithmDetails_MlKem{MlKem: &api.MlKemParams{ParameterSet: api.MlKemParameterSet_ML_KEM_768}}),
			compatible:   tmpl("ML-KEM", &api.AlgorithmDetails_MlKem{MlKem: &api.MlKemParams{ParameterSet: api.MlKemParameterSet_ML_KEM_768}}),
			incompatible: tmpl("ML-KEM", &api.AlgorithmDetails_MlKem{MlKem: &api.MlKemParams{ParameterSet: api.MlKemParameterSet_ML_KEM_1024}}),
		},
		{
			name:         "AES-GCM shares ordinary AES material by key size",
			source:       tmpl("AES", &api.AlgorithmDetails_AesGcm{AesGcm: &api.AesGcmParams{KeySizeBits: 256, IvSizeBits: 96}}),
			compatible:   tmpl("AES", &api.AlgorithmDetails_AesCbc{AesCbc: &api.AesCbcParams{KeySizeBits: 256, IvSizeBits: 128}}),
			incompatible: tmpl("AES", &api.AlgorithmDetails_AesCbc{AesCbc: &api.AesCbcParams{KeySizeBits: 128}}),
		},
		{
			name:         "AES-CBC shares ordinary AES material by key size",
			source:       tmpl("AES", &api.AlgorithmDetails_AesCbc{AesCbc: &api.AesCbcParams{KeySizeBits: 192}}),
			compatible:   tmpl("AES", &api.AlgorithmDetails_AesCtr{AesCtr: &api.AesCtrParams{KeySizeBits: 192}}),
			incompatible: tmpl("AES", &api.AlgorithmDetails_AesCtr{AesCtr: &api.AesCtrParams{KeySizeBits: 256}}),
		},
		{
			name:         "AES-CTR shares ordinary AES material by key size",
			source:       tmpl("AES", &api.AlgorithmDetails_AesCtr{AesCtr: &api.AesCtrParams{KeySizeBits: 128, CounterBits: 32}}),
			compatible:   tmpl("AES", &api.AlgorithmDetails_AesCcm{AesCcm: &api.AesCcmParams{KeySizeBits: 128}}),
			incompatible: tmpl("AES", &api.AlgorithmDetails_AesCcm{AesCcm: &api.AesCcmParams{KeySizeBits: 192}}),
		},
		{
			name:         "AES-CCM shares ordinary AES material by key size",
			source:       tmpl("AES", &api.AlgorithmDetails_AesCcm{AesCcm: &api.AesCcmParams{KeySizeBits: 256, TagSizeBits: 128}}),
			compatible:   tmpl("AES", &api.AlgorithmDetails_AesKeyWrap{AesKeyWrap: &api.AesKeyWrapParams{KeySizeBits: 256, WithPadding: true}}),
			incompatible: tmpl("AES", &api.AlgorithmDetails_AesKeyWrap{AesKeyWrap: &api.AesKeyWrapParams{KeySizeBits: 128}}),
		},
		{
			name:         "AES key-wrap shares ordinary AES material by key size",
			source:       tmpl("AES", &api.AlgorithmDetails_AesKeyWrap{AesKeyWrap: &api.AesKeyWrapParams{KeySizeBits: 192}}),
			compatible:   tmpl("AES", &api.AlgorithmDetails_AesGcm{AesGcm: &api.AesGcmParams{KeySizeBits: 192}}),
			incompatible: tmpl("AES", &api.AlgorithmDetails_AesGcm{AesGcm: &api.AesGcmParams{KeySizeBits: 256}}),
		},
		{
			name:         "AES-XTS uses separate family and total key size",
			source:       tmpl("AES-XTS", &api.AlgorithmDetails_AesXts{AesXts: &api.AesXtsParams{KeySizeBits: 512, TweakSizeBytes: 16}}),
			compatible:   tmpl("AES-XTS", &api.AlgorithmDetails_AesXts{AesXts: &api.AesXtsParams{KeySizeBits: 512, DataUnitSizeBytes: 4096}}),
			incompatible: tmpl("AES-XTS", &api.AlgorithmDetails_AesXts{AesXts: &api.AesXtsParams{KeySizeBits: 256}}),
		},
		{
			name:         "ChaCha20 is fixed across nonce variants",
			source:       tmpl("ChaCha20", &api.AlgorithmDetails_Chacha20Poly1305{Chacha20Poly1305: &api.ChaCha20Poly1305Params{NonceSizeBits: 96}}),
			compatible:   tmpl("ChaCha20", &api.AlgorithmDetails_Chacha20Poly1305{Chacha20Poly1305: &api.ChaCha20Poly1305Params{NonceSizeBits: 192, ExtendedNonce: true}}),
			incompatible: tmpl("AES", &api.AlgorithmDetails_AesGcm{AesGcm: &api.AesGcmParams{KeySizeBits: 256}}),
		},
		{
			name:         "ECDH compares only curve",
			source:       tmpl("ECDH", &api.AlgorithmDetails_Ecdh{Ecdh: &api.EcdhParams{Curve: p256, CofactorMode: false}}),
			compatible:   tmpl("ECDH", &api.AlgorithmDetails_Ecdh{Ecdh: &api.EcdhParams{Curve: p256, CofactorMode: true, Kdf: api.EcdhKdfType(1)}}),
			incompatible: tmpl("ECDH", &api.AlgorithmDetails_Ecdh{Ecdh: &api.EcdhParams{Curve: p384}}),
		},
		{
			name:         "X25519 is a distinct fixed family",
			source:       tmpl("X25519", &api.AlgorithmDetails_X25519{X25519: &api.X25519Params{}}),
			compatible:   tmpl("X25519", &api.AlgorithmDetails_X25519{X25519: &api.X25519Params{Kdf: api.EcdhKdfType(1)}}),
			incompatible: tmpl("X448", &api.AlgorithmDetails_X448{X448: &api.X448Params{}}),
		},
		{
			name:         "X448 is a distinct fixed family",
			source:       tmpl("X448", &api.AlgorithmDetails_X448{X448: &api.X448Params{}}),
			compatible:   tmpl("X448", &api.AlgorithmDetails_X448{X448: &api.X448Params{Kdf: api.EcdhKdfType(1)}}),
			incompatible: tmpl("X25519", &api.AlgorithmDetails_X25519{X25519: &api.X25519Params{}}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCompatibility(t, tt.source, tt.compatible, true)
			assertCompatibility(t, tt.compatible, tt.source, true)
			assertCompatibility(t, tt.source, tt.incompatible, false)
			assertCompatibility(t, tt.incompatible, tt.source, false)

			missingFamily := tt.source.Clone()
			missingFamily.Proto().KeyMaterialFamily = ""
			_, err := template.KeyMaterialProfileFor(missingFamily)
			require.ErrorContains(t, err, "key_material_family is required")

			mislabeled := tt.source.Clone()
			mislabeled.Proto().KeyMaterialFamily = "wrong-family"
			_, err = template.KeyMaterialProfileFor(mislabeled)
			require.ErrorContains(t, err, "does not match typed algorithm family")
		})
	}
}

func TestKeyMaterialProfileFor_failsClosed(t *testing.T) {
	tests := []struct {
		name string
		tmpl *template.Template
		want string
	}{
		{name: "nil template", tmpl: nil, want: "template is nil"},
		{name: "missing family", tmpl: tmpl("", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256}}), want: "key_material_family is required"},
		{name: "mislabeled family", tmpl: tmpl("RSA", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256}}), want: "does not match typed algorithm family"},
		{name: "nil algorithm", tmpl: template.NewTemplate(&api.TemplateInfo{TemplateId: "nil", KeyMaterialFamily: "ECDSA"}), want: "typed algorithm is required"},
		{name: "nil typed parameters", tmpl: tmpl("ECDSA", &api.AlgorithmDetails_Ecdsa{}), want: "ECDSA curve is required"},
		{name: "missing typed shape", tmpl: tmpl("RSA", &api.AlgorithmDetails_RsaPss{RsaPss: &api.RsaPssParams{}}), want: "RSA modulus-bits is required"},
		{name: "HMAC has no typed key size", tmpl: tmpl("HMAC", &api.AlgorithmDetails_Hmac{Hmac: &api.HmacParams{Hash: api.HashAlgorithm(1)}}), want: "HMAC is unsupported"},
		{name: "custom", tmpl: tmpl("vendor", &api.AlgorithmDetails_Custom{Custom: &api.CustomAlgorithm{}}), want: "custom algorithms are unsupported"},
		{name: "hybrid", tmpl: tmpl("hybrid", &api.AlgorithmDetails_Hybrid{Hybrid: &api.HybridAlgorithmParams{}}), want: "hybrid algorithms are unsupported"},
		{name: "unknown supported set", tmpl: tmpl("HKDF", &api.AlgorithmDetails_Hkdf{Hkdf: &api.HkdfParams{}}), want: "unsupported for retained key material"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := template.KeyMaterialProfileFor(tt.tmpl)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestCompatibleKeyMaterial_reportsInvalidSide(t *testing.T) {
	valid := tmpl("ECDSA", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256}})
	invalid := tmpl("", &api.AlgorithmDetails_Ecdsa{Ecdsa: &api.EcdsaParams{Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256}})

	compatible, err := template.CompatibleKeyMaterial(invalid, valid)
	require.False(t, compatible)
	require.ErrorContains(t, err, "source template")

	compatible, err = template.CompatibleKeyMaterial(valid, invalid)
	require.False(t, compatible)
	require.ErrorContains(t, err, "target template")
}

func TestCompatibleKeyMaterial_ignoresCycloneDXTaxonomy(t *testing.T) {
	source := tmpl("RSA", &api.AlgorithmDetails_RsaPss{RsaPss: &api.RsaPssParams{KeySizeBits: 2048}})
	target := tmpl("RSA", &api.AlgorithmDetails_RsaOaep{RsaOaep: &api.RsaOaepParams{KeySizeBits: 2048}})
	source.Proto().Cyclonedx = &api.CycloneDXAlgorithmProperties{AlgorithmFamily: "RSASSA-PSS"}
	target.Proto().Cyclonedx = &api.CycloneDXAlgorithmProperties{AlgorithmFamily: "RSAES-OAEP"}

	assertCompatibility(t, source, target, true)
}

func tmpl(family string, algorithm any) *template.Template {
	details := &api.AlgorithmDetails{}
	switch algorithm := algorithm.(type) {
	case *api.AlgorithmDetails_Ecdsa:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Ed25519:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Ed448:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_RsaPss:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_RsaPkcs1V15:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_RsaOaep:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_MlDsa:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_SlhDsa:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_MlKem:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_AesGcm:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_AesCbc:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_AesCtr:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_AesCcm:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_AesKeyWrap:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_AesXts:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Chacha20Poly1305:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Ecdh:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_X25519:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_X448:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Hmac:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Custom:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Hybrid:
		details.Algorithm = algorithm
	case *api.AlgorithmDetails_Hkdf:
		details.Algorithm = algorithm
	default:
		panic("unsupported test algorithm fixture")
	}
	return template.NewTemplate(&api.TemplateInfo{
		TemplateId:        "test-template",
		KeyMaterialFamily: family,
		Algorithm:         details,
	})
}

func assertCompatibility(t *testing.T, source, target *template.Template, want bool) {
	t.Helper()
	got, err := template.CompatibleKeyMaterial(source, target)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
