package key

import (
	"context"
	"fmt"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
)

const (
	opKeyVet errors.Op = "key.(Key).VetForWrite"
)

// Key is the domain representation of a cryptographic key.
// It embeds *store.StoredKey and adds validation and copy semantics.
type Key struct {
	*storepb.Key
}

// NewKey creates a new [Key] with the given parameters.
//
// Available options:
//   - WithName: sets the Name field (defaults to the key ID if not provided)
//   - WithLabels: sets the Labels field (defaults to an empty map if not provided)
//   - WithState : sets the State field (defaults to [types.KeyLifecycleState_PRE_ACTIVE] if not provided)
func NewKey(ctx context.Context, id, policyID string, primitive core.Primitive, currentKeyVersion uint32, opt ...Option) (*Key, error) {
	const op = "key.newKey"
	if id == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "id is required")
	}
	if policyID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "policyId is required")
	}
	if !primitive.IsValid() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "primitive is required")
	}
	opts := getOpts(opt...)
	if opts.withName == "" {
		// if no name is provided, default to id
		opts.withName = id
	}
	if opts.withState == types.KeyLifecycleState_KEY_LIFECYCLE_STATE_UNSPECIFIED {
		// if no state is provided, default to PRE_ACTIVE
		opts.withState = types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE
	}
	k := &storepb.Key{
		PublicId:       id,
		Name:           opts.withName,
		PolicyId:       policyID,
		Primitive:      primitive.String(),
		CurrentVersion: currentKeyVersion,
		Labels:         opts.withLabels,
		State:          opts.withState,
	}
	return &Key{Key: k}, nil
}

// Clone returns a deep copy of the Key.
func (k *Key) Clone() *Key {
	return &Key{Key: proto.Clone(k.Key).(*storepb.Key)}
}

// VetForWrite validates the Key for the given storage operation.
// It returns an *errors.Error with CodeInvalidArgument if any required field is missing.
func (k *Key) VetForWrite(ctx context.Context, op core.WriteOp) error {
	const opCreate = opKeyVet
	switch op {
	case core.OpCreate:
		if k.GetPublicId() == "" {
			return errors.New(ctx, opCreate, errors.CodeInvalidArgument, "public_id is required")
		}
		if k.GetName() == "" {
			return errors.New(ctx, opCreate, errors.CodeInvalidArgument, "name is required")
		}
		if k.GetPrimitive() == "" {
			return errors.New(ctx, opCreate, errors.CodeInvalidArgument, "primitive is required")
		}
	case core.OpUpdate:
		if k.GetPublicId() == "" {
			return errors.New(ctx, opCreate, errors.CodeInvalidArgument, "public_id is required for update")
		}
		if k.GetName() == "" {
			return errors.New(ctx, opCreate, errors.CodeInvalidArgument, "name is required for update")
		}
	case core.OpDelete:
		// No additional validation required for delete.
	}
	return nil
}

// Behavioral Methods

// CanRotate returns an error if the key cannot be rotated in its current state.
// A key can only be rotated when it is ACTIVE.
func (k *Key) CanRotate() error {
	if k.GetState() != types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE {
		return fmt.Errorf("cannot rotate key in status %s: only ACTIVE keys can be rotated", k.GetState())
	}
	return nil
}

// CanPerformOriginatingCrypto reports whether the key may be used to originate
// new cryptographic protection (Sign, Encrypt, Wrap). Only ACTIVE keys may
// originate new protection.
func (k *Key) CanPerformOriginatingCrypto() error {
	if k.GetState() != types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE {
		return fmt.Errorf("key is in status %s: originating operations (Sign, Encrypt, Wrap) require ACTIVE status", k.GetState())
	}
	return nil
}

// CanPerformReceivingCrypto reports whether the key may be used to receive
// previously protected data (Verify, Decrypt, Unwrap). ACTIVE, SUSPENDED, and
// DEACTIVATED ("legacy") keys may still process existing ciphertext/signatures;
// terminal or COMPROMISED keys may not.
func (k *Key) CanPerformReceivingCrypto() error {
	switch k.GetState() {
	case types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
		types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED,
		types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED:
		return nil
	default:
		return fmt.Errorf("key is in status %s: receiving operations (Verify, Decrypt, Unwrap) require ACTIVE, SUSPENDED, or DEACTIVATED status", k.GetState())
	}
}

// TODO: CanExport deferred — requires `bool extractable` field to be added to
// StoredKey in key.proto. Will be implemented when key export support is added.

// CanDelete returns an error if the key cannot be deleted.
// Terminal keys (DESTROYED, DESTROYED_COMPROMISED) are already gone.
func (k *Key) CanDelete() error {
	if k.IsTerminal() {
		return fmt.Errorf("key is already in terminal state %s", k.GetState())
	}
	return nil
}

// Lifecycle State Machine
// The state machine table documents all legal lifecycle transitions in one place
// rather than scattering them across orchestrator methods.

// validTransitions defines the legal state machine for key lifecycle.
// Based on NIST SP 800-57 Part 1 Rev. 5 (8.2) key states:
//
//	PRE_ACTIVE:  ACTIVE, DESTROYED
//	ACTIVE:      SUSPENDED, DEACTIVATED, COMPROMISED
//	SUSPENDED:   ACTIVE, DEACTIVATED, COMPROMISED
//	DEACTIVATED: DESTROYED, COMPROMISED
//	COMPROMISED: DESTROYED, DESTROYED_COMPROMISED
//	DESTROYED:   (terminal)
//	DESTROYED_COMPROMISED: (terminal)
var validTransitions = map[types.KeyLifecycleState][]types.KeyLifecycleState{
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE:            {types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE:                {types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED:             {types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED:           {types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED:           {types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED},
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED:             {}, // terminal — no transitions out
	types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED: {}, // terminal — no transitions out
}

// UpdateState attempts to move the key to a new lifecycle status.
// Returns an error if the transition is not valid per the NIST SP 800-57 state machine.
// On success, updates the key's status in place.
func (k *Key) UpdateState(newStatus types.KeyLifecycleState) error {
	current := k.GetState()
	allowed, ok := validTransitions[current]
	if !ok {
		return fmt.Errorf("unknown current status %s", current)
	}
	for _, s := range allowed {
		if s == newStatus {
			k.State = newStatus
			return nil
		}
	}
	return fmt.Errorf("invalid lifecycle transition: %s → %s", current, newStatus)
}

// IsTerminal returns true if the key is in a terminal state (DESTROYED or DESTROYED_COMPROMISED).
func (k *Key) IsTerminal() bool {
	s := k.GetState()
	return s == types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED || s == types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED
}

// Compile-time assertion.
var _ core.VetForWriter = (*Key)(nil)
