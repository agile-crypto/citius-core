package service

import (
	"context"

	messages "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// KeyMetadata holds the metadata of a key as returned by CreateKey, ReadKey,
// RotateKey, TransformKey or ListKeys.
//
// It is an application-layer read model assembled from the key.Key aggregate,
// its current key.Version, and the associated template.Template. It lives in
// the service package because it is produced by KeyOrchestrator and consumed
// by the gRPC handler — both of which already depend on internal/service.
type KeyMetadata struct {
	Name       string
	Version    uint32
	KeyID      string
	Primitive  string // e.g. "signature", "encryption" — derived from ScopeSpec
	TemplateID string

	// The scope specification used to create this key.
	ScopeSpec        *core.ScopeSpecification
	Provider         string
	CreatedTime      *timestamppb.Timestamp
	UpdatedTime      *timestamppb.Timestamp
	Policy           string
	Labels           map[string]string
	ProviderMetadata map[string]string

	//TODO: Currently not populated deliberately
	TemplateInfo *template.Template

	// Whether the key material can be extracted from its provider.
	// False for non-extractable HSM keys.
	// Determines feasibility of EXTRACT_AND_IMPORT migration strategy.
	Extractable bool

	// Lifecycle state of the key (NIST SP 800-57, KMIP state machine).
	LifecycleState  types.KeyLifecycleState
	PublicKeyBytes  []byte           // Public-key material for asymmetric keys
	PublicKeyFormat *types.KeyFormat // Format of public key material (e.g., RAW, PKCS8, JWK)
}

// ToProto converts KeyMetadata to its protobuf representation.
// Returns nil if m is nil.
func (m *KeyMetadata) ToProto(ctx context.Context) (*messages.KeyMetadata, error) {
	const op = "service.(KeyMetadata).ToProto"
	if m == nil {
		return nil, nil
	}

	res := &messages.KeyMetadata{
		Name:                     m.Name,
		Version:                  m.Version,
		KeyId:                    m.KeyID,
		TemplateId:               m.TemplateID,
		ScopeSpec:                nil, // set below if m.ScopeSpec is not nil
		Provider:                 m.Provider,
		CreatedTime:              m.CreatedTime,
		UpdatedTime:              m.UpdatedTime,
		Policy:                   m.Policy,
		ProviderMetadata:         m.ProviderMetadata,
		TemplateInfo:             nil, // set below if m.TemplateInfo is not nil
		ImplementationProperties: nil, // TODO: Add to KeyMetadata if needed
		Extractable:              m.Extractable,
		LifecycleState:           m.LifecycleState,
		PublicKeyBytes:           m.PublicKeyBytes,
		PublicKeyFormat:          m.PublicKeyFormat,
	}
	if m.ScopeSpec != nil {
		scopeSpecProto, err := m.ScopeSpec.ToProto(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		res.ScopeSpec = scopeSpecProto
	}
	if m.TemplateInfo != nil {
		res.TemplateInfo = m.TemplateInfo.Proto()
	}
	return res, nil
}
