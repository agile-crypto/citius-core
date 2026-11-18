package key

import (
	"context"

	messages "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Metadata holds the metadata of a key as returned by CreateKey, ReadKey,
// RotateKey, TransformKey or ListKeys.
//
// It is an application-layer read model assembled from the key.Key aggregate,
// its current key.Version, and the associated template.Template. It lives in
// the service package because it is produced by Orchestrator and consumed
// by the gRPC handler — both of which already depend on internal/service.
type Metadata struct {
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

	// The version's template: what the key is, as the catalogue describes it.
	// Nil only if the template is no longer in the catalogue.
	TemplateInfo *template.Template

	// The security guarantees the template gives for the key's scope (see
	// template.SecurityGuaranteesFor). Not part of the KeyMetadata proto:
	// CreateKey reports them in its response.
	SecurityGuarantees *types.SecurityGuarantees

	// The current implementation properties of the provider instance holding
	// the version. Nil only if the instance is no longer registered.
	ImplementationProperties *types.ImplementationProperties

	// How the version's material first came into existence.
	Origin types.KeyOrigin

	// Whether this version's material may leave its provider in plaintext
	// (a stored payload or an export). False for material a provider keeps,
	// such as a non-extractable HSM key; once false, it stays false for that
	// material. Required for PROVIDER_SWITCH and EXTRACT_AND_IMPORT.
	Extractable bool

	// Lifecycle state of the key (NIST SP 800-57, KMIP state machine).
	LifecycleState  types.KeyLifecycleState
	PublicKeyBytes  []byte           // Public-key material for asymmetric keys
	PublicKeyFormat *types.KeyFormat // Format of public key material (e.g., RAW, PKCS8, JWK)
}

// ToProto converts Metadata to its protobuf representation.
// Returns nil if m is nil.
func (m *Metadata) ToProto(ctx context.Context) (*messages.KeyMetadata, error) {
	const op = "service.key.(Metadata).ToProto"
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
		CreatedTime:              proto.CloneOf(m.CreatedTime),
		UpdatedTime:              proto.CloneOf(m.UpdatedTime),
		Policy:                   m.Policy,
		ProviderMetadata:         m.ProviderMetadata,
		TemplateInfo:             nil, // set below if m.TemplateInfo is not nil
		ImplementationProperties: nil, // set below if m.ImplementationProperties is not nil
		Extractable:              m.Extractable,
		LifecycleState:           m.LifecycleState,
		PublicKeyBytes:           m.PublicKeyBytes,
		PublicKeyFormat:          m.PublicKeyFormat,
		Origin:                   m.Origin,
	}
	if m.ScopeSpec != nil {
		scopeSpecProto, err := m.ScopeSpec.ToProto(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		res.ScopeSpec = scopeSpecProto
	}
	if m.TemplateInfo != nil {
		// A copy: the catalogue's own message must never reach a response.
		res.TemplateInfo = proto.CloneOf(m.TemplateInfo.Proto())
	}
	if m.ImplementationProperties != nil {
		res.ImplementationProperties = proto.CloneOf(m.ImplementationProperties)
	}
	return res, nil
}
