package key

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
)

// Version is the domain representation of one version of a Key's material.
// It belongs to the Key aggregate: key.Orchestrator creates and reads versions;
// external callers access material only through KeyOrchestrator.GetKeyWithMaterial.
type Version struct {
	*storepb.KeyVersion
}

// NewVersion creates a new [Version] with the given parameters.
//
// Available options:
//   - WithState: sets the State field (defaults to [types.KeyVersionLifecycleState_PRE_ACTIVE] if not provided)
//   - WithWrappingKeyID: sets the WrappingKeyId field (defaults to empty string if not provided)
func NewVersion(ctx context.Context, publicID, keyID, templateID, providerID string, version uint32, keyMaterial []byte, scopeSpec *core.ScopeSpecification, opt ...Option) (*Version, error) {
	const op = "key.newKeyVersion"
	opts := getOpts(opt...)
	if len(keyMaterial) == 0 {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "key material is required")
	}
	if providerID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "provider ID is required")
	}
	if templateID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "template ID is required")
	}
	if keyID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "key ID is required")
	}
	if scopeSpec == nil || !scopeSpec.Scope.GetPrimitive().IsValid() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "scope specification is required")
	}
	scopeSpecBytes, err := scopeSpec.Serialize(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if opts.withState == types.KeyLifecycleState_KEY_LIFECYCLE_STATE_UNSPECIFIED {
		// if no state is provided, default to PRE_ACTIVE
		opts.withState = types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE
	}
	kv := &storepb.KeyVersion{
		PublicId:           publicID,
		KeyId:              keyID,
		Version:            version,
		ProviderId:         providerID,
		TemplateId:         templateID,
		KeyMaterial:        keyMaterial,
		WrappingKeyId:      opts.withWrappingKeyID,
		State:              opts.withState,
		ScopeSpecification: scopeSpecBytes,
	}
	return &Version{KeyVersion: kv}, nil

}

// Callers should use Clone() before mutating.
func (v *Version) Clone() *Version {
	return &Version{KeyVersion: proto.Clone(v.KeyVersion).(*storepb.KeyVersion)}
}

// VetForWrite validates the KeyVersion for the given storage operation.
func (v *Version) VetForWrite(ctx context.Context, op core.WriteOp) error {
	const opVet errors.Op = "key.(KeyVersion).VetForWrite"
	if op == core.OpCreate {
		if v.GetPublicId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "version_id is required")
		}
		if v.GetKeyId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "key_id is required")
		}
		if v.GetProviderId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "provider_id is required")
		}
		if len(v.GetScopeSpecification()) == 0 {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "scope_specification is required")
		}
	}
	return nil
}

// Compile-time assertion.
var _ core.VetForWriter = (*Version)(nil)
