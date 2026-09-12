package provider

import (
	storepb "github.com/agile-crypto/citius-server/gen/go/server/store"
	"google.golang.org/protobuf/proto"
)

// Instance is the domain representation of a registered crypto provider instance.
type Instance struct {
	stored *storepb.StoredProviderInstance
}

// NewInstance wraps a StoredProviderInstance.
func NewInstance(stored *storepb.StoredProviderInstance) *Instance {
	if stored == nil {
		stored = &storepb.StoredProviderInstance{}
	}
	return &Instance{stored: stored}
}

// StoredProviderInstance returns the embedded proto.
func (pi *Instance) StoredProviderInstance() *storepb.StoredProviderInstance {
	return pi.stored
}

func (pi *Instance) Clone() *Instance {
	return &Instance{
		stored: proto.Clone(pi.stored).(*storepb.StoredProviderInstance),
	}
}

func (pi *Instance) PublicID() string {
	return pi.stored.GetPublicId()
}

func (pi *Instance) Name() string {
	return pi.stored.GetName()
}

func (pi *Instance) ProviderType() string {
	return pi.stored.GetProviderType()
}
