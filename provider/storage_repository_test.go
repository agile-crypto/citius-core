package provider_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/provider"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/storage"
	storepb "github.com/agile-crypto/citius-core/store"
)

func newTestProviderInstance(publicID, name, provType string) *provider.Instance {
	return provider.NewInstance(&storepb.StoredProviderInstance{
		PublicId:     publicID,
		Name:         name,
		ProviderType: provType,
	})
}

var repoFn = func() provider.InstanceRepository {
	store := &storage.InmemStorage{}
	r, err := provider.NewStorageRepository(context.Background(), store)
	if err != nil {
		panic("failed to create provider StorageRepository: " + err.Error())
	}
	return r
}

func Test_ProviderStorageRepository_PutGet_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	pi := newTestProviderInstance("prv_01", "software-default", "software")

	if err := r.PutProviderInstance(ctx, pi); err != nil {
		t.Fatalf("PutProviderInstance: %v", err)
	}
	got, err := r.GetProviderInstance(ctx, "prv_01")
	if err != nil {
		t.Fatalf("GetProviderInstance: %v", err)
	}
	if got.StoredProviderInstance().GetName() != "software-default" {
		t.Errorf("Name: got %q want %q", got.StoredProviderInstance().GetName(), "software-default")
	}
}

func Test_ProviderStorageRepository_GetProviderInstance_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetProviderInstance(context.Background(), "prv_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing provider instance")
	}
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected ProviderNotFound, got: %v", err)
	}
}

func Test_ProviderStorageRepository_PutProviderInstance_nil_returnsError(t *testing.T) {
	r := repoFn()
	if err := r.PutProviderInstance(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil instance")
	}
}

func Test_ProviderStorageRepository_DeleteProviderInstance_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutProviderInstance(ctx, newTestProviderInstance("prv_01", "sw", "software"))
	if err := r.DeleteProviderInstance(ctx, "prv_01"); err != nil {
		t.Fatalf("DeleteProviderInstance: %v", err)
	}
	_, err := r.GetProviderInstance(ctx, "prv_01")
	if !errors.IsProviderNotFound(err) {
		t.Errorf("expected ProviderNotFound after delete, got: %v", err)
	}
}

func Test_ProviderStorageRepository_ListProviderInstances(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutProviderInstance(ctx, newTestProviderInstance("prv_01", "sw1", "software"))
	_ = r.PutProviderInstance(ctx, newTestProviderInstance("prv_02", "sw2", "software"))

	ids, err := r.ListProviderInstances(ctx)
	if err != nil {
		t.Fatalf("ListProviderInstances: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("ListProviderInstances: got %d want 2", len(ids))
	}
}

func Test_ProviderStorageRepository_ListProviderInstances_empty(t *testing.T) {
	r := repoFn()
	ids, err := r.ListProviderInstances(context.Background())
	if err != nil {
		t.Fatalf("ListProviderInstances: %v", err)
	}
	if ids == nil {
		t.Error("ListProviderInstances should return empty slice, not nil")
	}
}

func Test_ProviderStorageRepository_GetProviderInstance_returnsClone(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutProviderInstance(ctx, newTestProviderInstance("prv_01", "original", "software"))
	got, _ := r.GetProviderInstance(ctx, "prv_01")
	got.StoredProviderInstance().Name = "mutated"
	got2, _ := r.GetProviderInstance(ctx, "prv_01")
	if got2.Name() != "original" {
		t.Error("GetProviderInstance should return an independent copy (proto round-trip)")
	}
}
