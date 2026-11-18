package software_test

import (
	"bytes"
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider/software"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// mlDSADetailsFor builds AlgorithmDetails for a parameter set, with the
// determinism flag under test — context handling has to work identically on
// both signing paths, and those are selected by that flag (see signMLDSA).
func mlDSADetailsFor(parameterSet types.MlDsaParameterSet, deterministic bool) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{ParameterSet: parameterSet, Deterministic: deterministic},
		},
	}
}

// signMLDSAWithContext signs payload under domainContext via the real
// provider, returning the signature.
func signMLDSAWithContext(t *testing.T, p *software.Provider, gen *providerpb.GenerateKeyResponse,
	alg *types.AlgorithmDetails, payload, domainContext []byte) []byte {
	t.Helper()
	req := &providerpb.SignRequest{
		KeyMaterial:         gen.GetKeyMaterial(),
		Input:               payload,
		Algorithm:           alg,
		KeyMaterialEncoding: gen.GetKeyMaterialEncoding(),
	}
	if domainContext != nil {
		req.ScopeParams = &providerpb.SignRequest_DomainContext{
			DomainContext: &types.SignatureDomainContext{Context: domainContext},
		}
	}
	resp, err := p.Sign(context.Background(), req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return resp.GetSignature()
}

// verifyMLDSAWithContext verifies signature under domainContext via the real
// provider. A nil domainContext sends no domain_context arm at all.
func verifyMLDSAWithContext(t *testing.T, p *software.Provider, gen *providerpb.GenerateKeyResponse,
	alg *types.AlgorithmDetails, payload, signature, domainContext []byte) bool {
	t.Helper()
	req := &providerpb.VerifyRequest{
		KeyMaterial: gen.GetPublicKeyBytes(),
		Input:       payload,
		Signature:   signature,
		Algorithm:   alg,
	}
	if domainContext != nil {
		req.ScopeParams = &providerpb.VerifyRequest_DomainContext{
			DomainContext: &types.SignatureDomainContext{Context: domainContext},
		}
	}
	resp, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return resp.GetValid()
}

// TestSignVerify_MLDSA_domainContext_isBound is the core guarantee of FIPS 204
// domain separation: a signature produced under one context must verify under
// that context and no other. Before the context was threaded through to CIRCL
// it was silently discarded, so a signature made under context "A" verified
// happily under context "B" — callers got no domain separation at all while
// believing they had asked for it.
//
// Both signing paths are exercised, since they reach CIRCL differently:
// deterministic=true goes through sign.Scheme.Sign, deterministic=false
// through the package-level SignTo.
func TestSignVerify_MLDSA_domainContext_isBound(t *testing.T) {
	for _, parameterSet := range []types.MlDsaParameterSet{
		types.MlDsaParameterSet_ML_DSA_44,
		types.MlDsaParameterSet_ML_DSA_65,
		types.MlDsaParameterSet_ML_DSA_87,
	} {
		for _, deterministic := range []bool{false, true} {
			name := parameterSet.String()
			if deterministic {
				name += "/deterministic"
			} else {
				name += "/randomized"
			}
			t.Run(name, func(t *testing.T) {
				alg := mlDSADetailsFor(parameterSet, deterministic)
				p, gen := genMLDSAKeyWithAlgorithm(t, alg)
				payload := []byte("domain separated payload")
				signingContext := []byte("context-A")

				sig := signMLDSAWithContext(t, p, gen, alg, payload, signingContext)

				if !verifyMLDSAWithContext(t, p, gen, alg, payload, sig, signingContext) {
					t.Error("same context: expected valid=true")
				}
				if verifyMLDSAWithContext(t, p, gen, alg, payload, sig, []byte("context-B")) {
					t.Error("different context: expected valid=false — the context is not bound into the signature")
				}
				if verifyMLDSAWithContext(t, p, gen, alg, payload, sig, nil) {
					t.Error("absent context: expected valid=false for a signature made under a context")
				}
			})
		}
	}
}

// TestSignVerify_MLDSA_emptyContext_equivalentToAbsent pins the FIPS 204 rule
// that an empty context and an absent context are the same value — so a
// signature made with one verifies under the other. This is why the provider
// does not (and cannot) distinguish them.
func TestSignVerify_MLDSA_emptyContext_equivalentToAbsent(t *testing.T) {
	alg := mlDSADetailsFor(types.MlDsaParameterSet_ML_DSA_65, false)
	p, gen := genMLDSAKeyWithAlgorithm(t, alg)
	payload := []byte("payload")

	sigEmpty := signMLDSAWithContext(t, p, gen, alg, payload, []byte{})
	if !verifyMLDSAWithContext(t, p, gen, alg, payload, sigEmpty, nil) {
		t.Error("signed with empty context, verified with absent context: expected valid=true")
	}

	sigAbsent := signMLDSAWithContext(t, p, gen, alg, payload, nil)
	if !verifyMLDSAWithContext(t, p, gen, alg, payload, sigAbsent, []byte{}) {
		t.Error("signed with absent context, verified with empty context: expected valid=true")
	}
}

// TestSignVerify_MLDSA_contextIsByteExact proves the context is compared as
// raw bytes rather than as text: it survives non-UTF-8 content unchanged
// (CIRCL's option type carries it as a Go string, which holds arbitrary
// bytes), and a single flipped byte invalidates the signature.
func TestSignVerify_MLDSA_contextIsByteExact(t *testing.T) {
	alg := mlDSADetailsFor(types.MlDsaParameterSet_ML_DSA_65, false)
	p, gen := genMLDSAKeyWithAlgorithm(t, alg)
	payload := []byte("payload")
	rawContext := []byte{0x00, 0xFF, 0xFE, 0x80, 0x7F}

	sig := signMLDSAWithContext(t, p, gen, alg, payload, rawContext)
	if !verifyMLDSAWithContext(t, p, gen, alg, payload, sig, rawContext) {
		t.Fatal("non-UTF-8 context did not survive the round trip")
	}

	flipped := bytes.Clone(rawContext)
	flipped[0] ^= 0x01
	if verifyMLDSAWithContext(t, p, gen, alg, payload, sig, flipped) {
		t.Error("context differing by one bit: expected valid=false")
	}
}

// TestSign_MLDSA_contextAtMaxLength_succeeds covers the boundary of the
// 255-byte limit SignatureDomainContext.context declares and FIPS 204 sets:
// exactly 255 bytes is legal, so it must sign and verify rather than being
// caught by an off-by-one.
func TestSign_MLDSA_contextAtMaxLength_succeeds(t *testing.T) {
	alg := mlDSADetailsFor(types.MlDsaParameterSet_ML_DSA_65, false)
	p, gen := genMLDSAKeyWithAlgorithm(t, alg)
	payload := []byte("payload")
	maxContext := bytes.Repeat([]byte("c"), 255)

	sig := signMLDSAWithContext(t, p, gen, alg, payload, maxContext)
	if !verifyMLDSAWithContext(t, p, gen, alg, payload, sig, maxContext) {
		t.Error("255-byte context: expected valid=true")
	}
}
