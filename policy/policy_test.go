package policy_test

import (
	"context"
	"testing"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/policy"
)

func TestPolicy_VetForWrite_Create_happyPath(t *testing.T) {
	p := policy.NewPolicy("pol_01HXYZ", "default-sig-policy", nil)
	if err := p.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPolicy_VetForWrite_Create_missingName(t *testing.T) {
	p := policy.NewPolicy("pol_01HXYZ", "", nil)
	err := p.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Name")
	}
}

func TestPolicy_Clone_independent(t *testing.T) {
	p := policy.NewPolicy("pol_01HXYZ", "policy-1", nil,
		policy.WithLabels(map[string]string{"team": "security"}),
	)
	c := p.Clone()
	c.StoredPolicy().Labels["team"] = "platform"
	if p.StoredPolicy().Labels["team"] != "security" {
		t.Error("Clone() did not produce an independent copy")
	}
}

// TODO: AllowsOperation and AllowsTemplate tests deferred.
// StoredPolicy uses an opaque `rules_json` blob (not discrete AllowedOperations/
// AllowedAlgorithms fields). These behavioural methods will be implemented when
// the policy rules engine parses rules_json in the PolicyEngine.

// Compile-time assertion.
var _ core.VetForWriter = (*policy.Policy)(nil)
