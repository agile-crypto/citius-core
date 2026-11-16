package key_test

import (
	"context"
	"testing"

	core "github.com/agile-crypto/citius-core"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"google.golang.org/protobuf/proto"
)

// TestCreateKey_generateKeyResponseOutput_survivesStorageRoundTrip is the
// second half of the Phase 0 closing gate: key_orchestrator_impl.go persists
// the ENTIRE GenerateKeyResponse (proto.Marshal) as the stored key version's
// key_material, not just the raw key bytes — so GenerateKeyResponse.output
// (added in Phase 0 to carry the key's encoding) must round-trip through
// that same storage path with no dedicated store field and no migration.
//
// This proves that claim against the real storage layer rather than
// asserting it from the proto shape alone.
func TestCreateKey_generateKeyResponseOutput_survivesStorageRoundTrip(t *testing.T) {
	orch, repo, _, _, _ := setupOrchestratorFull(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "output-roundtrip-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           testPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Read back the RAW stored bytes — bypassing the orchestrator entirely —
	// to prove persistence, not just that CreateKey's in-memory return value
	// happened to carry Output.
	kv, err := repo.GetCurrentVersion(ctx, created.KeyID)
	if err != nil {
		t.Fatalf("GetCurrentVersion: %v", err)
	}

	var genResp providerpb.GenerateKeyResponse
	if err := proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		t.Fatalf("proto.Unmarshal stored GenerateKeyResponse: %v", err)
	}

	if genResp.GetOutput().GetAlgorithmOutput() == nil {
		t.Fatal("stored GenerateKeyResponse.output.algorithm_output is nil after the storage round-trip")
	}
	// ML-DSA: private half is PKCS#8 wrapping the seed (see mldsa.go).
	if got := genResp.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8 {
		t.Errorf("stored encoding = %q, want %q", got, "pkcs8")
	}
}
