package provider

import (
	"context"
	"sync"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/storage"
	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
)

const providerInstanceStoragePrefix = "provider_instance/"

var _ InstanceRepository = (*StorageRepository)(nil)

type StorageRepository struct {
	mu        *sync.RWMutex
	instances storage.Storage
}

func NewStorageRepository(ctx context.Context, store storage.Storage, opt ...Option) (*StorageRepository, error) {
	const op errors.Op = "provider.NewStorageRepository"
	if store == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := GetVaultOptions(opt...)
	return &StorageRepository{
		mu:        opts.Lock,
		instances: storage.NewView(store, providerInstanceStoragePrefix),
	}, nil
}

func (r *StorageRepository) PutProviderInstance(ctx context.Context, instance *Instance) error {
	const op errors.Op = "provider.(StorageRepository).PutProviderInstance"
	if instance == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "instance must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(instance.StoredProviderInstance())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &storage.Entry{Key: instance.PublicID(), Value: b}
	if err := r.instances.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *StorageRepository) GetProviderInstance(ctx context.Context, publicID string) (*Instance, error) {
	const op errors.Op = "provider.(StorageRepository).GetProviderInstance"
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, err := r.instances.Get(ctx, publicID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "provider instance not found: "+publicID)
	}
	stored := &storepb.StoredProviderInstance{}
	if err := proto.Unmarshal(entry.Value, stored); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewInstance(stored), nil
}

func (r *StorageRepository) DeleteProviderInstance(ctx context.Context, publicID string) error {
	const op errors.Op = "provider.(StorageRepository).DeleteProviderInstance"
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, err := r.instances.Get(ctx, publicID)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return errors.New(ctx, op, errors.CodeProviderNotFound, "provider instance not found: "+publicID)
	}
	return r.instances.Delete(ctx, publicID)
}

func (r *StorageRepository) ListProviderInstances(ctx context.Context) ([]string, error) {
	const op errors.Op = "provider.(StorageRepository).ListProviderInstances"
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.instances.List(ctx, "")
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}
