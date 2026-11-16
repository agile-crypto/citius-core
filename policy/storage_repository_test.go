package policy_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/policy"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPolicy(name string) *policy.Policy {
	return policy.NewPolicy("", name, nil)
}

var repoFn = func() policy.Repository {
	store := &storage.InmemStorage{}
	r, err := policy.NewStorageRepository(context.Background(), store)
	if err != nil {
		panic("failed to create policy StorageRepository: " + err.Error())
	}
	return r
}

func Test_PolicyStorageRepository_PutPolicy_GetPolicy_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	p := newTestPolicy("default-sig-policy")

	if err := r.PutPolicy(ctx, p); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, err := r.GetPolicy(ctx, "default-sig-policy")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name() != "default-sig-policy" {
		t.Errorf("Name: got %q want %q", got.Name(), "default-sig-policy")
	}
}

func Test_PolicyStorageRepository_GetPolicy_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetPolicy(context.Background(), "pol_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound, got: %v", err)
	}
}

func Test_PolicyStorageRepository_DeletePolicy_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutPolicy(ctx, newTestPolicy("p"))
	if err := r.DeletePolicy(ctx, "p"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	_, err := r.GetPolicy(ctx, "p")
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound after delete, got: %v", err)
	}
}

func Test_PolicyStorageRepository_ListPolicies_all(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutPolicy(ctx, newTestPolicy("p1"))
	_ = r.PutPolicy(ctx, newTestPolicy("p2"))

	names, err := r.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("ListPolicies: got %d want 2", len(names))
	}
}

func Test_PolicyStorageRepository_ListPolicies_empty(t *testing.T) {
	r := repoFn()
	names, err := r.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if names == nil {
		t.Error("ListPolicies should return empty slice, not nil")
	}
}

func Test_PolicyStorageRepository_ListPolicies_hierarchicalPaths_returnsAll(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	names := []string{
		"test/namespace1/test-policy",
		"test/namespace1/other-policy",
		"test/namespace2/test-policy",
		"prod/namespace1/test-policy",
		"prod/test-policy",
		"top-level-policy",
	}
	for _, n := range names {
		require.NoError(t, r.PutPolicy(ctx, newTestPolicy(n)))
	}

	got, err := r.ListPolicies(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, names, got)
}

func Test_PolicyStorageRepository_ListPoliciesWithPrefix(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	all := []string{
		"test/namespace1/test-policy",
		"test/namespace1/other-policy",
		"test/namespace2/test-policy",
		"test-policy",
		"testing/namespace1/test-policy",
		"prod/namespace1/test-policy",
		"prod/test-policy",
	}
	for _, n := range all {
		require.NoError(t, r.PutPolicy(ctx, newTestPolicy(n)))
	}

	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{"top-level folder", "test", []string{"test/namespace1/test-policy", "test/namespace1/other-policy", "test/namespace2/test-policy"}},
		{"trailing separator", "test/", []string{"test/namespace1/test-policy", "test/namespace1/other-policy", "test/namespace2/test-policy"}},
		{"nested folder", "test/namespace1", []string{"test/namespace1/test-policy", "test/namespace1/other-policy"}},
		{"nested folder with trailing separator", "test/namespace1/", []string{"test/namespace1/test-policy", "test/namespace1/other-policy"}},
		{"other branch", "prod", []string{"prod/namespace1/test-policy", "prod/test-policy"}},
		{"partial folder name", "tes", nil},
		{"partial nested folder name", "test/namespace", nil},
		{"full policy path is not a folder", "test/namespace1/test-policy", nil},
		{"unknown folder", "staging", nil},
		{"empty prefix returns all", "", all},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.ListPoliciesWithPrefix(ctx, tt.prefix)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func Test_PolicyStorageRepository_ListPoliciesWithPrefix_relativePath_rejected(t *testing.T) {
	r := repoFn()
	require.NoError(t, r.PutPolicy(context.Background(), newTestPolicy("test/namespace1/p")))

	_, err := r.ListPoliciesWithPrefix(context.Background(), "test/..")
	require.Error(t, err)
}

func Test_PolicyStorageRepository_PutPolicy_nil_returnsError(t *testing.T) {
	r := repoFn()
	if err := r.PutPolicy(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func Test_PolicyStorageRepository_GetPolicy_returnsClone(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutPolicy(ctx, newTestPolicy("original"))
	got, _ := r.GetPolicy(ctx, "original")
	got.StoredPolicy().Name = "mutated"
	got2, _ := r.GetPolicy(ctx, "original")
	if got2.Name() != "original" {
		t.Error("GetPolicy should return an independent copy (proto round-trip)")
	}
}
