package crypto_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"slices"
	"testing"

	cryptosvc "github.com/agile-crypto/citius-core/service/crypto"
	keysvc "github.com/agile-crypto/citius-core/service/key"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
)

// digestSignPolicyName is the name of the policy that allows create_key,
// digest_sign, and digest_verify for ecdsa-p256-prehashed-der.
const digestSignPolicyName = "test-digest-sign-allow"

// seedDigestSignPolicy creates a policy that allows ecdsa-p256-prehashed-der
// with create_key, digest_sign, and digest_verify operations.
func seedDigestSignPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-prehashed-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationDigestSign),
				string(core.OperationDigestVerify),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testdigestsign", digestSignPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed digest-sign policy: %v", err)
	}
}

// setupDigestSignWithKey creates a wired cryptosvc.Orchestrator, seeds a policy
// that allows create_key + digest_sign + digest_verify for
// ecdsa-p256-prehashed-der, creates a key, and returns the cryptosvc.Orchestrator
// and the key's name.
//
// ECDSA is used (not ML-DSA) because the software provider's SignDigest is
// currently hard-coded to ECDSA-P256 only — the AlgorithmDetails-based
// dispatch is a later change.
func setupDigestSignWithKey(t *testing.T) (cryptosvc.Orchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedDigestSignPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "digest-sign-test-key",
		TemplateID:         "ecdsa-p256-prehashed-der",
		PolicyID:           digestSignPolicyName,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.Name
}

// ============================================================================
// DigestSign / DigestVerify Tests
// ============================================================================

func TestDigestSign_ECDSA_happyPath(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	digest := sha256.Sum256([]byte("pre-hashed by the caller"))

	result, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
	if result.KeyName != keyName {
		t.Errorf("KeyName: got %q want %q", result.KeyName, keyName)
	}
	if result.Output.GetAlgorithmOutput() == nil {
		t.Error("Output.algorithm_output must be set (provider contract)")
	}
	if result.DigestHash != types.HashAlgorithm_HASH_ALGORITHM_SHA256 {
		t.Errorf("DigestHash: got %s want SHA256", result.DigestHash)
	}
}

func TestDigestSign_DigestVerify_roundtrip(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	digest := sha256.Sum256([]byte("round-trip payload"))

	signResult, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	verifyResult, err := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Digest:               digest[:],
		Signature:            signResult.Signature,
		DigestHash:           signResult.DigestHash,
		Output:               signResult.Output,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("expected valid=true for a correctly round-tripped digest signature")
	}
	if verifyResult.KeyVersion != signResult.KeyVersion || verifyResult.KeyVersion == 0 {
		t.Errorf("KeyVersion: got %d want the version used (%d)", verifyResult.KeyVersion, signResult.KeyVersion)
	}
	if verifyResult.DigestHash != signResult.DigestHash {
		t.Errorf("DigestHash: got %s want the hash checked (%s)", verifyResult.DigestHash, signResult.DigestHash)
	}
}

func TestDigestVerify_tamperedDigest_returnsFalse(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	digest := sha256.Sum256([]byte("original payload"))
	signResult, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	tampered := sha256.Sum256([]byte("tampered payload"))
	verifyResult, err := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Digest:               tampered[:],
		Signature:            signResult.Signature,
		DigestHash:           signResult.DigestHash,
		Output:               signResult.Output,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	if verifyResult.Valid {
		t.Error("expected valid=false for a tampered digest")
	}
}

func TestDigestSign_keyNotFound_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	ctx := context.Background()

	_, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              "nonexistent-key",
		Digest:               []byte("digest"),
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestDigestSign_emptyDigest_returnsError(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	_, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for empty digest")
	}
}

// TestDigestSign_policyDeniesDigestSign_returnsError proves OperationDigestSign
// is a distinct, independently-grantable capability from OperationSign: a
// policy that grants "sign" but not "digest_sign" must deny DigestSign.
func TestDigestSign_policyDeniesDigestSign_returnsError(t *testing.T) {
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	ctx := context.Background()

	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-prehashed-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey), string(core.OperationSign)}, // no digest_sign
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	const signOnlyPolicy = "test-sign-only-no-digest"
	p := policy.NewPolicy("pol_signonly", signOnlyPolicy, rulesJSON)
	if _, err = pol.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("seed sign-only policy: %v", err)
	}

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "sign-only-key",
		TemplateID:         "ecdsa-p256-prehashed-der",
		PolicyID:           signOnlyPolicy,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	digest := sha256.Sum256([]byte("payload"))
	_, err = ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              created.Name,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected policy violation: digest_sign not granted by a sign-only policy")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

// TestDigestSign_acceptedDigestHashes checks that a prehashed key accepts only
// its version's digest hashes: the catalog's list by default, or the narrower
// list requested at creation.
func TestDigestSign_acceptedDigestHashes(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	seedDigestSignPolicy(t, ctx, pol)

	create := func(name string, hashes ...types.HashAlgorithm) *keysvc.Metadata {
		t.Helper()
		spec := scopeSpecWithScope(t, core.ScopeSignaturePrehashed)
		if len(hashes) > 0 {
			spec = spec.WithAcceptedDigestHashes(hashes)
		}
		md, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
			Name:               name,
			TemplateID:         "ecdsa-p256-prehashed-der",
			PolicyID:           digestSignPolicyName,
			ScopeSpecification: spec,
		})
		if err != nil {
			t.Fatalf("CreateKey(%s): %v", name, err)
		}
		return md
	}
	sign := func(keyName string, hash types.HashAlgorithm, digest []byte) (crypto.SignResult, error) {
		return ops.DigestSign(ctx, crypto.DigestSignRequest{
			KeyName:              keyName,
			Digest:               digest,
			HashAlgorithm:        hash,
			SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
		})
	}
	sha256Digest := sha256.Sum256([]byte("payload"))
	sha384Digest := sha512.Sum384([]byte("payload"))

	all := create("digest-hashes-catalog")
	wantAll := []types.HashAlgorithm{
		types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		types.HashAlgorithm_HASH_ALGORITHM_SHA384,
		types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	}
	if got := all.ScopeSpec.AcceptedDigestHashes(); !slices.Equal(got, wantAll) {
		t.Fatalf("catalog key: accepted digest hashes %v, want %v", got, wantAll)
	}
	if _, err := sign(all.Name, types.HashAlgorithm_HASH_ALGORITHM_SHA384, sha384Digest[:]); err != nil {
		t.Fatalf("DigestSign SHA-384 on catalog key: %v", err)
	}

	narrowed := create("digest-hashes-narrowed", types.HashAlgorithm_HASH_ALGORITHM_SHA256)
	if _, err := sign(narrowed.Name, types.HashAlgorithm_HASH_ALGORITHM_SHA384, sha384Digest[:]); !errors.IsInvalidArgument(err) {
		t.Fatalf("DigestSign SHA-384 on SHA-256-only key: want INVALID_ARGUMENT, got %v", err)
	}
	signed, err := sign(narrowed.Name, types.HashAlgorithm_HASH_ALGORITHM_SHA256, sha256Digest[:])
	if err != nil {
		t.Fatalf("DigestSign SHA-256 on SHA-256-only key: %v", err)
	}

	verify := func(hash types.HashAlgorithm) (crypto.VerifyResult, error) {
		return ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
			KeyName:              narrowed.Name,
			KeyVersion:           signed.KeyVersion,
			Digest:               sha256Digest[:],
			Signature:            signed.Signature,
			DigestHash:           hash,
			Output:               signed.Output,
			SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
		})
	}
	if _, err = verify(types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED); !errors.IsInvalidArgument(err) {
		t.Fatalf("DigestVerify without a digest hash: want INVALID_ARGUMENT, got %v", err)
	}
	if _, err = verify(types.HashAlgorithm_HASH_ALGORITHM_SHA384); !errors.IsInvalidArgument(err) {
		t.Fatalf("DigestVerify with an unaccepted digest hash: want INVALID_ARGUMENT, got %v", err)
	}

	if _, err = keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "digest-hashes-unoffered",
		TemplateID: "ecdsa-p256-prehashed-der",
		PolicyID:   digestSignPolicyName,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed).WithAcceptedDigestHashes(
			[]types.HashAlgorithm{types.HashAlgorithm_HASH_ALGORITHM_SHA3_256}),
	}); err == nil {
		t.Fatal("CreateKey with a digest hash the template does not accept must fail")
	}
}
