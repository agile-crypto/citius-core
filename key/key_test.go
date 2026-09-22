package key_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/stretchr/testify/require"
)

func TestKey_NewKey(t *testing.T) {
	tc := []struct {
		name     string
		withOpts bool
		keyName  string
		labels   map[string]string
		state    types.KeyLifecycleState
	}{
		{
			name:     "default_options",
			withOpts: false,
		},
		{
			name:     "set_options",
			withOpts: true,
			keyName:  "name",
			labels:   map[string]string{"label": "value"},
			state:    types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			sp, err := core.NewScopeSpecification(ctx, core.ScopeSignatureStandard, nil, nil, nil)
			require.NoError(t, err)
			var opts []key.Option
			if tt.withOpts {
				opts = append(opts, key.WithName(tt.keyName))
				opts = append(opts, key.WithLabels(tt.labels))
				opts = append(opts, key.WithState(tt.state))
			}
			k, err := key.NewKey(ctx, "id", "policyID", sp.Scope.GetPrimitive(), 13, opts...)
			require.NoError(t, err)
			require.Equal(t, k.PublicId, "id")
			require.Equal(t, k.PolicyId, "policyID")
			require.Equal(t, k.CurrentVersion, uint32(13))
			if tt.withOpts {
				require.Equal(t, k.Name, tt.keyName)
				require.Equal(t, k.Labels, tt.labels)
				require.Equal(t, k.State, tt.state)
			} else {
				// defaults for newly created keys
				require.Equal(t, k.Name, "id")
				require.Empty(t, k.Labels)
				require.Equal(t, k.State, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE)
			}
		})

	}

}
func TestKey_VetForWrite_Create_happyPath(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{
			PublicId:  "key_01HXYZ",
			Name:      "signing-key",
			Primitive: "signature",
			State:     types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
		},
	}
	if err := k.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("VetForWrite(Create): unexpected error: %v", err)
	}
}

func TestKey_VetForWrite_Create_missingPublicId(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{
			Name:      "signing-key",
			Primitive: "signature",
		},
	}
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing PublicId")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Create_missingName(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{
			PublicId:  "key_01HXYZ",
			Primitive: "signature",
		},
	}
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Name")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Create_missingPrimitive(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{
			PublicId: "key_01HXYZ",
			Name:     "signing-key",
		},
	}
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Primitive")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Update_allowsMissingCreateTime(t *testing.T) {
	// Update only checks PublicId, Name
	k := &key.Key{
		Key: &storepb.Key{
			PublicId: "key_01HXYZ",
			Name:     "signing-key",
		},
	}
	if err := k.VetForWrite(context.Background(), core.OpUpdate); err != nil {
		t.Errorf("VetForWrite(Update): unexpected error: %v", err)
	}
}

func TestKey_VetForWrite_Update_missingPublicId(t *testing.T) {
	k := &key.Key{&storepb.Key{Name: "signing-key"}}
	err := k.VetForWrite(context.Background(), core.OpUpdate)
	if err == nil {
		t.Fatal("expected error for missing PublicId on Update")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_Clone_independent(t *testing.T) {
	original := &key.Key{
		Key: &storepb.Key{
			PublicId: "key_01HXYZ",
			Name:     "signing-key",
			Labels:   map[string]string{"env": "prod"},
		},
	}
	cloned := original.Clone()
	// Mutate the clone
	cloned.Labels["env"] = "dev"
	// Original should be unchanged
	if original.Labels["env"] != "prod" {
		t.Error("Clone() did not produce an independent copy — mutations alias the original")
	}
}

func TestKey_PublicId_accessor(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{PublicId: "key_01HXYZ"},
	}
	if k.PublicId != "key_01HXYZ" {
		t.Errorf("PublicID(): got %q want %q", k.GetPublicId(), "key_01HXYZ")
	}
}

// Compile-time assertion.
var _ core.VetForWriter = (*key.Key)(nil)

//--- Behavioural Test ---//

func TestKey_CanRotate_active(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{
			PublicId: "key_01HXYZ", Name: "test", Primitive: "ecdsa-p256",
			State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
		},
	}
	if err := k.CanRotate(); err != nil {
		t.Errorf("CanRotate on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanRotate_suspended(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{
			PublicId: "key_01HXYZ", Name: "test", Primitive: "ecdsa-p256",
			State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED,
		},
	}
	if err := k.CanRotate(); err == nil {
		t.Error("CanRotate on SUSPENDED key should return error")
	}
}

// ---- Lifecycle Test ---//
func TestKey_TransitionTo_validTransitions(t *testing.T) {
	tests := []struct {
		from types.KeyLifecycleState
		to   types.KeyLifecycleState
	}{
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED},
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"→"+tt.to.String(), func(t *testing.T) {
			k := &key.Key{
				Key: &storepb.Key{
					PublicId: "key_01HXYZ", Name: "test", Primitive: "t",
					State: tt.from,
				},
			}
			if err := k.UpdateState(tt.to); err != nil {
				t.Errorf("valid transition %s→%s returned error: %v", tt.from, tt.to, err)
			}
			if k.GetState() != tt.to {
				t.Errorf("status not updated: got %v want %v", k.GetState(), tt.to)
			}
		})
	}
}

func TestKey_TransitionTo_invalidTransitions(t *testing.T) {
	tests := []struct {
		from types.KeyLifecycleState
		to   types.KeyLifecycleState
	}{
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},             // terminal → anything
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE}, // terminal → anything
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE},            // backwards
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},             // skip deactivated
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},         // must activate first
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"→"+tt.to.String(), func(t *testing.T) {
			k := &key.Key{
				Key: &storepb.Key{
					PublicId: "key_01HXYZ", Name: "test", Primitive: "t",
					State: tt.from,
				},
			}
			if err := k.UpdateState(tt.to); err == nil {
				t.Errorf("invalid transition %s→%s should return error", tt.from, tt.to)
			}
			// State should NOT have changed
			if k.GetState() != tt.from {
				t.Errorf("status should remain %v on invalid transition, got %v",
					tt.from, k.GetState())
			}
		})
	}
}

func TestKey_IsTerminal(t *testing.T) {
	destroyed := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
	}
	if !destroyed.IsTerminal() {
		t.Error("DESTROYED key should be terminal")
	}
	destroyedCompromised := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED},
	}
	if !destroyedCompromised.IsTerminal() {
		t.Error("DESTROYED_COMPROMISED key should be terminal")
	}
	active := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
	}
	if active.IsTerminal() {
		t.Error("ACTIVE key should not be terminal")
	}
}

// CanPerformOriginatingCrypto

func TestKey_CanPerformOriginatingCrypto_active_succeeds(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
	}
	if err := k.CanPerformOriginatingCrypto(); err != nil {
		t.Errorf("CanPerformOriginatingCrypto on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformOriginatingCrypto_suspended_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},
	}
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on SUSPENDED key: expected error, got nil")
	}
}

func TestKey_CanPerformOriginatingCrypto_deactivated_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
	}
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on DEACTIVATED key: expected error, got nil")
	}
}

func TestKey_CanPerformOriginatingCrypto_destroyed_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
	}
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on DESTROYED key: expected error, got nil")
	}
}

func TestKey_CanPerformOriginatingCrypto_compromised_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
	}
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on COMPROMISED key: expected error, got nil")
	}
}

// CanPerformReceivingCrypto

func TestKey_CanPerformReceivingCrypto_active_succeeds(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
	}
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformReceivingCrypto_suspended_succeeds(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},
	}
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto on SUSPENDED key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformReceivingCrypto_deactivated_succeeds(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
	}
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto on DEACTIVATED (legacy) key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformReceivingCrypto_destroyed_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
	}
	if err := k.CanPerformReceivingCrypto(); err == nil {
		t.Error("CanPerformReceivingCrypto on DESTROYED key: expected error, got nil")
	}
}

func TestKey_CanPerformReceivingCrypto_destroyedCompromised_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED},
	}
	if err := k.CanPerformReceivingCrypto(); err == nil {
		t.Error("CanPerformReceivingCrypto on DESTROYED_COMPROMISED key: expected error, got nil")
	}
}

func TestKey_CanPerformReceivingCrypto_compromised_fails(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
	}
	if err := k.CanPerformReceivingCrypto(); err == nil {
		t.Error("CanPerformReceivingCrypto on COMPROMISED key: expected error, got nil")
	}
}

// TestKey_OriginatingVsReceiving_asymmetry verifies the core invariant:
// deactivated keys permit receiving operations (Verify/Decrypt/Unwrap) but not
// originating operations (Sign/Encrypt/Wrap).
func TestKey_OriginatingVsReceiving_asymmetry(t *testing.T) {
	k := &key.Key{
		Key: &storepb.Key{State: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
	}
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto should fail on DEACTIVATED key")
	}
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto should succeed on DEACTIVATED key: %v", err)
	}
}
