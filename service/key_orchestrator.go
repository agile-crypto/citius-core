package service

import (
	"context"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
)

// KeyOrchestrator orchestrates key lifecycle workflows.
// Implementations coordinate template selection, provider dispatch, policy validation,
// and repository persistence crossing aggregate boundaries.
type KeyOrchestrator interface {
	CreateKey(ctx context.Context, spec core.KeyCreationSpec) (*KeyMetadata, error)

	// ReadKey returns the metadata for the named key at the given version.
	// Pass version=0 to read the current/latest version.
	ReadKey(ctx context.Context, keyName string, version uint32) (*KeyMetadata, error)
	ListKeys(ctx context.Context) ([]*KeyMetadata, error)
	DeleteKey(ctx context.Context, keyName string) error
	RotateKey(ctx context.Context, keyName string) (*KeyMetadata, error)
	SuspendKey(ctx context.Context, keyName string) error
	RestoreKey(ctx context.Context, keyName string) error
	DestroyKey(ctx context.Context, keyName string) error

	ImportKey(ctx context.Context, spec core.ImportKeySpec) (*KeyMetadata, error)

	// UpdateKeyPolicy changes the policy governing an existing key.
	// Policy changes take effect on the next crypto operation.
	// Returns ErrNotFound if the key does not exist.
	UpdateKeyPolicy(ctx context.Context, keyName string, policyName string) error

	// TransformKey transforms an existing key to a new template. The template is selected
	// with the following precedence:
	// 1. If spec.TemplateID is non-empty, the template with that ID is used.
	// 2. Otherwise, the key's scope specification and policy are used to find a matching
	// template. If multiple templates match, the one with the highest priority is used.
	// (TODO: Definition of highest priority)
	//
	// Retaining material requires an explicit compatible template. In that mode
	// the current provider and complete stored provider payload are preserved;
	// otherwise the provider generates new material for the target template.
	TransformKey(ctx context.Context, spec TransformKeySpec) (*KeyMetadata, error)
}

// KeyOrchestratorFactory builds the key-lifecycle orchestrator for one request.
//
// The orchestrator is always local to the process serving the request: what
// varies with deployment mode is its dependencies — a key repository that is
// Vault-backed, SQL-backed or a remote-custody client; a policy engine that is
// local or remote. All of that is captured by the closure, so this signature is
// identical in every mode. See policy.EngineFactory for the rules a factory
// must follow.
type KeyOrchestratorFactory func(ctx context.Context) (KeyOrchestrator, error)

type TransformKeySpec struct {
	KeyName            string
	ScopeSpecification *core.ScopeSpecification
	TemplateID         string
	RetainBytes        bool
}

func (s *TransformKeySpec) FromProto(ctx context.Context, protoReq *messagespb.TransformKeyRequest) error {
	const op = "service.(TransformKeySpec).FromProto"
	if protoReq == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "transform key request proto is nil")
	}
	res := &TransformKeySpec{
		KeyName:     protoReq.Name,
		RetainBytes: protoReq.RetainKeyBytes,
	}
	if protoReq.TemplateId != nil {
		res.TemplateID = *protoReq.TemplateId
	}
	if protoReq.ScopeSpec != nil {
		scopeSpec, err := core.ScopeSpecificationFromProto(ctx, protoReq.ScopeSpec)
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		res.ScopeSpecification = scopeSpec
	}
	*s = *res
	return nil
}
