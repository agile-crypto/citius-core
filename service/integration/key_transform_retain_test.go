package integration_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	keysvc "github.com/agile-crypto/citius-core/service/key"
	"github.com/stretchr/testify/require"
)

// seedRetainPolicy allows key creation and the given crypto operations for
// templateIDs, so that both the source and target of a retain-mode transform
// are permitted.
func seedRetainPolicy(t *testing.T, ctx context.Context, pol policy.Engine, name string, templateIDs []string, ops ...core.Operation) {
	t.Helper()
	keyOps := []string{string(core.OperationCreateKey)}
	for _, op := range ops {
		keyOps = append(keyOps, string(op))
	}
	rulesJSON, err := json.Marshal(&policy.Rules{
		Version:           "1",
		AllowedTemplates:  templateIDs,
		AllowedOperations: &policy.OperationRule{KeyOperations: keyOps},
	})
	require.NoError(t, err)
	_, err = pol.CreatePolicy(ctx, policy.NewPolicy("pol_"+name, name, rulesJSON))
	require.NoError(t, err)
}

// TestTransformKey_retainBytes_ECDSADigestNarrowed retains a prehashed ECDSA
// key under the same template while narrowing its accepted digest hashes. The
// new version keeps the key pair (a version-1 digest signature verifies under
// version 2) and accepts only the narrowed hash; version 1 keeps its list.
func TestTransformKey_retainBytes_ECDSADigestNarrowed(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	const tmpl = "ecdsa-p256-prehashed-der"
	seedRetainPolicy(t, ctx, pol, "retain-ecdsa-digest", []string{tmpl},
		core.OperationDigestSign, core.OperationDigestVerify)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "retain-ecdsa-digest",
		TemplateID:         tmpl,
		PolicyID:           "retain-ecdsa-digest",
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed),
	})
	require.NoError(t, err)

	noContext := crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
	sha256Digest := sha256.Sum256([]byte("signed before transformation"))
	sha384Digest := sha512.Sum384([]byte("signed before transformation"))
	digestSign := func(hash types.HashAlgorithm, digest []byte) (crypto.SignResult, error) {
		return ops.DigestSign(ctx, crypto.DigestSignRequest{
			KeyName: created.Name, Digest: digest, HashAlgorithm: hash, SignatureScopeFields: noContext,
		})
	}
	digestVerify := func(sig crypto.SignResult, version uint32) bool {
		t.Helper()
		result, verifyErr := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
			KeyName:              created.Name,
			KeyVersion:           version,
			Digest:               sha256Digest[:],
			Signature:            sig.Signature,
			DigestHash:           sig.DigestHash,
			Output:               sig.Output,
			SignatureScopeFields: noContext,
		})
		require.NoError(t, verifyErr)
		return result.Valid
	}

	v1Sig, err := digestSign(types.HashAlgorithm_HASH_ALGORITHM_SHA256, sha256Digest[:])
	require.NoError(t, err)
	require.Equal(t, uint32(1), v1Sig.KeyVersion)
	v1SHA384Sig, err := digestSign(types.HashAlgorithm_HASH_ALGORITHM_SHA384, sha384Digest[:])
	require.NoError(t, err)
	require.Equal(t, types.HashAlgorithm_HASH_ALGORITHM_SHA384, v1SHA384Sig.DigestHash)

	md, err := keyOrch.TransformKey(ctx, keysvc.TransformKeySpec{
		KeyName:    created.Name,
		TemplateID: tmpl,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed).WithAcceptedDigestHashes(
			[]types.HashAlgorithm{types.HashAlgorithm_HASH_ALGORITHM_SHA256}),
		RetainBytes: true,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), md.Version)
	require.Equal(t, []types.HashAlgorithm{types.HashAlgorithm_HASH_ALGORITHM_SHA256}, md.ScopeSpec.AcceptedDigestHashes())

	require.True(t, digestVerify(v1Sig, 2), "version-1 signature must verify under the retained version-2 key")

	v2Sig, err := digestSign(types.HashAlgorithm_HASH_ALGORITHM_SHA256, sha256Digest[:])
	require.NoError(t, err)
	require.Equal(t, uint32(2), v2Sig.KeyVersion)
	require.True(t, digestVerify(v2Sig, 1), "version-2 signature must verify under version 1")

	_, err = digestSign(types.HashAlgorithm_HASH_ALGORITHM_SHA384, sha384Digest[:])
	require.True(t, errors.IsInvalidArgument(err), "version 2 accepts only SHA-256: %v", err)

	// Narrowing affects only new signatures. DigestVerify checks the hash
	// against the version that made the signature (metadata.key_version), so a
	// version-1 SHA-384 signature made before the transform still verifies.
	v1SHA384, verifyErr := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
		KeyName:              created.Name,
		KeyVersion:           v1SHA384Sig.KeyVersion,
		Digest:               sha384Digest[:],
		Signature:            v1SHA384Sig.Signature,
		DigestHash:           v1SHA384Sig.DigestHash,
		Output:               v1SHA384Sig.Output,
		SignatureScopeFields: noContext,
	})
	require.NoError(t, verifyErr)
	require.True(t, v1SHA384.Valid, "a version-1 SHA-384 signature must still verify after narrowing")

	v1, err := keyOrch.ReadKey(ctx, created.Name, 1)
	require.NoError(t, err)
	require.Len(t, v1.ScopeSpec.AcceptedDigestHashes(), 3, "version 1 keeps the catalog's list")
}

// TestTransformKey_retainBytes_RSA proves that a retained RSA-2048 key signs
// under the target PKCS#1 v1.5 template, while version 1 still verifies its
// RSA-PSS signature.
func TestTransformKey_retainBytes_RSA(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	const (
		source = "rsa-pss-sha256-mgf1-32-2048"
		target = "rsa-pkcs1v15-sha256-2048"
	)
	seedRetainPolicy(t, ctx, pol, "retain-rsa", []string{source, target},
		core.OperationSign, core.OperationVerify)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "retain-rsa",
		TemplateID:         source,
		PolicyID:           "retain-rsa",
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
	})
	require.NoError(t, err)

	message := []byte("signed across RSA schemes")
	noContext := crypto.SignatureScopeFields{NoContext: &types.NoParams{}}
	v1Sig, err := ops.Sign(ctx, crypto.SignRequest{KeyName: created.Name, Payload: message, SignatureScopeFields: noContext})
	require.NoError(t, err)
	require.Equal(t, uint32(1), v1Sig.KeyVersion)

	md, err := keyOrch.TransformKey(ctx, keysvc.TransformKeySpec{
		KeyName:            created.Name,
		TemplateID:         target,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
		RetainBytes:        true,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), md.Version)
	require.Equal(t, target, md.TemplateID)

	v2Sig, err := ops.Sign(ctx, crypto.SignRequest{KeyName: created.Name, Payload: message, SignatureScopeFields: noContext})
	require.NoError(t, err)
	require.Equal(t, uint32(2), v2Sig.KeyVersion)
	require.Equal(t, target, v2Sig.Algorithm)

	for _, sig := range []crypto.SignResult{v1Sig, v2Sig} {
		verified, verifyErr := ops.Verify(ctx, crypto.VerifyRequest{
			KeyName:              created.Name,
			KeyVersion:           sig.KeyVersion,
			Payload:              message,
			Signature:            sig.Signature,
			Output:               sig.Output,
			SignatureScopeFields: noContext,
		})
		require.NoError(t, verifyErr)
		require.True(t, verified.Valid, "version %d signature must verify", sig.KeyVersion)
	}
}

func TestTransformKey_retainBytes_rejectsIncompatibleMaterial(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		sourceScope core.Scope
		target      string
		targetScope core.Scope
	}{
		{"ECDSA P-256 to P-384", "ecdsa-p256-sha256-der", core.ScopeSignatureStandard, "ecdsa-p384-sha384-der", core.ScopeSignatureStandard},
		{"ECDSA to RSA", "ecdsa-p256-sha256-der", core.ScopeSignatureStandard, "rsa-pss-sha256-mgf1-32-2048", core.ScopeSignatureStandard},
		{"AES-128 to AES-256", "aes-128-gcm-128-96", core.ScopeAeadStandard, "aes-256-gcm-128-96", core.ScopeAeadStandard},
		// Same key material, but a transform must keep the key's scope.
		{"ECDSA standard to prehashed scope", "ecdsa-p256-sha256-der", core.ScopeSignatureStandard, "ecdsa-p256-prehashed-der", core.ScopeSignaturePrehashed},
		{"AES-GCM to AES-CBC scope", "aes-256-gcm-128-96", core.ScopeAeadStandard, "aes-256-cbc-pkcs7-128", core.ScopeSymmetricCipherBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, keyOrch, pol := setupCryptoOrchestratorFull(t)
			seedRetainPolicy(t, ctx, pol, "retain-reject", []string{tt.source, tt.target})
			created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
				Name:               "retain-reject",
				TemplateID:         tt.source,
				PolicyID:           "retain-reject",
				ScopeSpecification: scopeSpecWithScope(t, tt.sourceScope),
			})
			require.NoError(t, err)

			_, err = keyOrch.TransformKey(ctx, keysvc.TransformKeySpec{
				KeyName:            created.Name,
				TemplateID:         tt.target,
				ScopeSpecification: scopeSpecWithScope(t, tt.targetScope),
				RetainBytes:        true,
			})
			require.Error(t, err)
			var coreErr *errors.Error
			require.True(t, errors.As(err, &coreErr))
			require.Equal(t, errors.CodeFailedPrecondition, coreErr.Code, err.Error())

			current, err := keyOrch.ReadKey(ctx, created.Name, 0)
			require.NoError(t, err)
			require.Equal(t, uint32(1), current.Version, "rejected transform must not add a version")
		})
	}
}
