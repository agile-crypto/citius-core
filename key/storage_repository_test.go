package key

import (
	"context"
	"fmt"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
)

// defaultKeyVersionID mirrors core/key's private helper of the same name —
// duplicated here since it's unexported and this is a different package now.
func defaultKeyVersionID(keyID string, version uint32) string {
	return fmt.Sprintf("%s:%d", keyID, version)
}

// helper: create a valid Key domain object.
func newTestKey(publicID, name string, scopeSpec *core.ScopeSpecification, opts ...Option) (*Key, error) {
	opts = append(opts, WithName(name))
	return NewKey(context.Background(), publicID, "policy-test", scopeSpec.Scope.GetPrimitive(), 1, opts...)
}

func signatureScopeSpec() *core.ScopeSpecification {
	return &core.ScopeSpecification{Scope: core.ScopeSignatureStandard}
}

func mustNewCreateKeyInputs(
	t *testing.T,
	ctx context.Context,
	publicID, name, templateID, providerID, policyID string,
	scopeSpec *core.ScopeSpecification,
	initialVersion uint32,
	keyMaterial []byte,
	status types.KeyLifecycleState,
) (*Key, *Version) {
	t.Helper()
	k, err := NewKey(ctx, publicID, policyID, scopeSpec.Scope.GetPrimitive(), initialVersion, WithName(name), WithState(status))
	if err != nil {
		t.Fatalf("newKey(%s): %v", publicID, err)
	}
	v, err := NewVersion(
		ctx,
		defaultKeyVersionID(publicID, initialVersion),
		publicID,
		templateID,
		providerID,
		initialVersion,
		keyMaterial,
		scopeSpec,
		WithState(status),
	)
	if err != nil {
		t.Fatalf("newVersion(%s,%d): %v", publicID, initialVersion, err)
	}
	return k, v
}

// helper: create a key+version in the store (for tests that need setup).
func mustCreateKey(t *testing.T, r Repository, publicID, name string, scope core.Scope) {
	t.Helper()
	ctx := context.Background()
	scopeSpec := &core.ScopeSpecification{
		Scope: scope,
	}
	k, v := mustNewCreateKeyInputs(t, ctx, publicID, name, "template-id", "software", "policy-test", scopeSpec, 1, []byte("fake-key-bytes"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	if err := r.CreateKey(ctx, k, v, WithInitialVersion(1)); err != nil {
		t.Fatalf("mustCreateKey(%s): %v", publicID, err)
	}
}

var repoFn = func() Repository {
	store := &storage.InmemStorage{}
	r, err := NewStorageRepository(context.Background(), store)
	if err != nil {
		panic("failed to create StorageRepository: " + err.Error())
	}
	return r
}

// ============================================================================
// CreateKey / GetKey
// ============================================================================

func Test_StorageRepository_CreateKey_GetKey_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()

	scopeSpec := &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
	}
	initialVersionNbr := uint32(1)
	k, v := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key", "template-id", "software", "policy-test", scopeSpec, initialVersionNbr, []byte("fake-key-bytes"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	if err := r.CreateKey(ctx, k, v, WithInitialVersion(initialVersionNbr)); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := r.GetKeyByID(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.PublicId != "key_01HXYZ" {
		t.Errorf("PublicID: got %q want %q", got.PublicId, "key_01HXYZ")
	}
	if got.Name != "signing-key" {
		t.Errorf("Name: got %q want %q", got.Name, "signing-key")
	}
	if got.CurrentVersion != initialVersionNbr {
		t.Errorf("CurrentVersion: got %d want %d", got.CurrentVersion, initialVersionNbr)
	}
}

func Test_StorageRepository_CreateKey_setsVersion1(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	scopeSpec := &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
	}
	k, v := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("fake-key-bytes"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	if err := r.CreateKey(ctx, k, v, WithInitialVersion(1)); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := r.GetVersion(ctx, "key_01HXYZ", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if got.Version != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.Version)
	}
}

func Test_StorageRepository_CreateKey_setsStatus(t *testing.T) {
	testCases := []struct {
		name       string
		keyID      string
		wantStatus types.KeyLifecycleState
	}{
		{"default_status", "kc01", types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
		{"explicit_active", "kc02", types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
		{"explicit_compromised", "kc03", types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
	}
	r := repoFn()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			km := []byte("fake-key-bytes")
			k, v := mustNewCreateKeyInputs(t, ctx, tc.keyID, tc.keyID, "template-id", "software", "policy-test", &core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
			}, 0, km, tc.wantStatus)
			err := r.CreateKey(ctx, k, v, WithInitialVersion(0))
			require.NoErrorf(err, "CreateKey error for key %s: %v", tc.keyID, err)
			v0, err := r.GetCurrentVersion(ctx, tc.keyID)
			require.NoErrorf(err, "GetCurrentVersion error for key %s: %v", tc.keyID, err)
			assert.Equal(uint32(0), v0.Version, "initial version should be 0")
			assert.Equal(tc.wantStatus, v0.GetState(), "version should have expected status")
		})
	}

}
func Test_StorageRepository_GetKey_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetKeyByID(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func Test_StorageRepository_CreateKey_duplicate_returnsError(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	scopeSpec := &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
	}
	k1, v1 := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("fake-key-bytes"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	_ = r.CreateKey(ctx, k1, v1, WithInitialVersion(1))
	k2, v2 := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key2", "template-id2", "software", "policy-test2", scopeSpec, 1, []byte("fake-key-bytes2"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	err := r.CreateKey(ctx, k2, v2, WithInitialVersion(1))
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected AlreadyExists, got: %v", err)
	}
}

func Test_StorageRepository_GetKey_returnsClone(t *testing.T) {
	// Mutating the returned key should NOT affect the stored copy.
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "original", core.ScopeSignatureStandard)

	got, _ := r.GetKeyByID(ctx, "key_01HXYZ")
	got.Name = "mutated"

	got2, _ := r.GetKeyByID(ctx, "key_01HXYZ")
	if got2.Name != "original" {
		t.Errorf("stored key was mutated: got %q want %q", got2.Name, "original")
	}
}

// ============================================================================
// DeleteKey (cascading)
// ============================================================================

func Test_StorageRepository_DeleteKey_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "k", core.ScopeSignatureStandard)

	if err := r.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	_, err := r.GetKeyByID(ctx, "key_01HXYZ")
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound after delete, got: %v", err)
	}
}

func Test_StorageRepository_DeleteKey_cascadesVersions(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	r := repoFn()
	ctx := context.Background()
	kid := "key_01HXYZ"
	mustCreateKey(t, r, kid, "k", core.ScopeSignatureStandard)
	v, err := r.GetCurrentVersion(ctx, kid)
	if err != nil {
		t.Errorf("unexpected error while getting current version of key %s", kid)
	}
	v2 := v.Clone()
	v2.Version = v.Version + 1
	v2.PublicId = "ver_02"
	vNext, err := NewVersion(ctx, defaultKeyVersionID(kid, 2), kid, "template", "software", 2, []byte("key_version_1"), signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(err, "error creating key version 2")
	err = r.AddVersion(ctx, vNext)
	if err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	vNext2, err := NewVersion(ctx, defaultKeyVersionID(kid, 3), kid, "template", "software", 3, []byte("key_version_2"), signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(err, "error creating key version 3")
	err = r.AddVersion(ctx, vNext2)
	require.NoError(err, "got error when adding second version")
	k, err := r.GetKeyByID(ctx, kid)
	require.NoErrorf(err, "error when getting key with id=%s", kid)
	assert.Equal(uint32(v2.Version+1), k.CurrentVersion, "current version should be 2")
	err = r.DeleteKey(ctx, "key_01HXYZ")
	require.NoError(err, "DeleteKey should not return error")
	_, err = r.GetKeyByID(ctx, "key_01HXYZ")
	require.True(errors.IsKeyNotFound(err), "expected KeyNotFound after delete, got: %v", err)
	// Both versions should be gone.
	_, err = r.GetVersion(ctx, "key_01HXYZ", 1)
	require.True(errors.IsKeyNotFound(err), "expected VersionNotFound for version 1 after cascading delete")
	_, err = r.GetVersion(ctx, "key_01HXYZ", 2)
	require.True(errors.IsKeyNotFound(err), "expected VersionNotFound for version 2 after cascading delete")
}

func Test_StorageRepository_DeleteKey_notFound_returnsError(t *testing.T) {
	r := repoFn()
	err := r.DeleteKey(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for deleting non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

// ============================================================================
// ListKeys
// ============================================================================

func Test_StorageRepository_ListKeys_all(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k1", core.ScopeSignatureStandard)
	mustCreateKey(t, r, "key_02", "k2", core.ScopeSignatureStandard)

	keys, err := r.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys: got %d want 2", len(keys))
	}
	// Verify full Key objects are returned, not just names.
	for _, k := range keys {
		if k.PublicId == "" {
			t.Error("ListKeys returned key with empty PublicID")
		}
	}
}

func Test_StorageRepository_ListKeys_multipleKeys(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k1", core.ScopeSignatureStandard)
	mustCreateKey(t, r, "key_02", "k2", core.ScopeSignatureStandard)
	mustCreateKey(t, r, "key_03", "k3", core.ScopeSignatureStandard)

	keys, err := r.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("ListKeys: got %d want 3", len(keys))
	}
}

func Test_StorageRepository_ListKeys_hierarchicalPaths_returnsAll(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	paths := []string{
		"test/namespace1/test-key",
		"test/namespace1/other-key",
		"test/namespace2/test-key",
		"prod/namespace1/test-key",
		"prod/test-key",
		"top-level-key",
	}
	for _, p := range paths {
		mustCreateKey(t, r, p, p, core.ScopeSignatureStandard)
	}

	keys, err := r.ListKeys(ctx)
	require.NoError(t, err)

	var gotIDs, gotNames []string
	for _, k := range keys {
		gotIDs = append(gotIDs, k.PublicId)
		gotNames = append(gotNames, k.Name)
	}
	assert.ElementsMatch(t, paths, gotIDs)
	assert.ElementsMatch(t, paths, gotNames)
}

func Test_StorageRepository_ListKeysWithPrefix(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	for _, p := range []string{
		"test/namespace1/test-key",
		"test/namespace1/other-key",
		"test/namespace2/test-key",
		"test-key",
		"testing/namespace1/test-key",
		"prod/namespace1/test-key",
		"prod/test-key",
	} {
		mustCreateKey(t, r, p, p, core.ScopeSignatureStandard)
	}

	all := []string{
		"test/namespace1/test-key", "test/namespace1/other-key", "test/namespace2/test-key",
		"test-key", "testing/namespace1/test-key", "prod/namespace1/test-key", "prod/test-key",
	}
	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{"top-level folder", "test", []string{"test/namespace1/test-key", "test/namespace1/other-key", "test/namespace2/test-key"}},
		{"trailing separator", "test/", []string{"test/namespace1/test-key", "test/namespace1/other-key", "test/namespace2/test-key"}},
		{"nested folder", "test/namespace1", []string{"test/namespace1/test-key", "test/namespace1/other-key"}},
		{"nested folder with trailing separator", "test/namespace1/", []string{"test/namespace1/test-key", "test/namespace1/other-key"}},
		{"other branch", "prod", []string{"prod/namespace1/test-key", "prod/test-key"}},
		{"partial folder name", "tes", nil},
		{"partial nested folder name", "test/namespace", nil},
		{"full key path is not a folder", "test/namespace1/test-key", nil},
		{"unknown folder", "staging", nil},
		{"empty prefix returns all", "", all},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := r.ListKeysWithPrefix(ctx, tt.prefix)
			require.NoError(t, err)
			require.NotNil(t, keys)
			got := make([]string, 0, len(keys))
			for _, k := range keys {
				got = append(got, k.PublicId)
			}
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func Test_StorageRepository_ListKeysWithPrefix_relativePath_rejected(t *testing.T) {
	r := repoFn()
	mustCreateKey(t, r, "test/namespace1/test-key", "k", core.ScopeSignatureStandard)

	_, err := r.ListKeysWithPrefix(context.Background(), "test/..")
	require.Error(t, err)
}

func Test_StorageRepository_ListKeys_empty(t *testing.T) {
	r := repoFn()
	keys, err := r.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if keys == nil {
		t.Error("ListKeys should return empty slice, not nil")
	}
}

// ============================================================================
// UpdateKey
// ============================================================================

func Test_StorageRepository_UpdateKey_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "signing-key", core.ScopeSignatureStandard)

	got, err := r.GetKeyByID(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey after update: %v", err)
	}
	// Same key but state is different
	updated, err := NewKey(ctx, got.PublicId, got.PolicyId, core.PrimitiveSignature, got.CurrentVersion, WithName(got.Name),
		WithLabels(got.Labels), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED))
	require.NoError(t, err)
	if err = r.UpdateKey(ctx, updated); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	got, err = r.GetKeyByID(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey after update: %v", err)
	}
	if got.GetState() != types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED {
		t.Errorf("status: got %v want SUSPENDED", got.GetState())
	}
}

func Test_StorageRepository_UpdateKey_notFound_returnsError(t *testing.T) {
	r := repoFn()
	k, err := newTestKey("id", "signing-key", &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
	})
	require.NoError(t, err, "error when creating key")
	err = r.UpdateKey(context.Background(), k)
	require.NotNil(t, err)
	require.Truef(t, errors.IsKeyNotFound(err), "expected KeyNotFound, got: %v", err)
}

func Test_StorageRepository_UpdateKey_nil_returnsError(t *testing.T) {
	r := repoFn()
	err := r.UpdateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

// ============================================================================
// AddVersion / GetVersion
// ============================================================================

func Test_StorageRepository_AddVersion_GetVersion_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", core.ScopeSignatureStandard)

	v, err := NewVersion(ctx, defaultKeyVersionID("key_01", 2), "key_01", "template", "software", 2, []byte("key_version_2"), signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err, "error creating key version input")
	err = r.AddVersion(ctx, v)
	require.NoErrorf(t, err, "error when adding version (%s,%d)", "key_01", 2)

	got, err := r.GetVersion(ctx, "key_01", 2)
	require.NoErrorf(t, err, "error when getting version (%s,%d)", "key_01", 2)
	assert.Equal(t, "key_01", got.KeyId)
	assert.Equal(t, uint32(2), got.Version)
}

func Test_StorageRepository_AddVersion_GetOldVersion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", core.ScopeSignatureStandard)

	v, err := NewVersion(ctx, defaultKeyVersionID("key_01", 2), "key_01", "template", "software", 2, []byte("key_version_2"), signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err, "error creating key version input")
	err = r.AddVersion(ctx, v)
	if err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := r.GetVersion(ctx, "key_01", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if got.Version != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.Version)
	}
	if got.Version != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.Version)
	}
}

func Test_StorageRepository_GetVersion_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetVersion(context.Background(), "key_01", 99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func Test_StorageRepository_AddVersion_returnsClone(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", core.ScopeSignatureStandard)

	// Fetch version 1 (created by CreateKey) and mutate the returned clone.
	got, _ := r.GetVersion(ctx, "key_01", 1)
	got.ProviderId = "mutated"

	// Re-fetch — should still have original value.
	got2, _ := r.GetVersion(ctx, "key_01", 1)
	if got2.ProviderId != "software" {
		t.Error("GetVersion should return a clone — stored value was mutated")
	}
}

func Test_StorageRepository_AddVersion_keyNotFound_returnsError(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	v, err := NewVersion(ctx, defaultKeyVersionID("key_missing", 1), "key_missing", "template", "software", 1, []byte("key_material"), signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err, "error creating key version input")
	err = r.AddVersion(ctx, v)
	if err == nil {
		t.Fatal("expected error for adding version to non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

// ============================================================================
// GetKeyByName
// ============================================================================

func Test_StorageRepository_GetKeyByName_existing(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "my-key", core.ScopeSignatureStandard)

	got, err := r.GetKeyByName(ctx, "my-key")
	require.NoError(t, err)
	assert.Equal(t, "key_01", got.PublicId)
	assert.Equal(t, "my-key", got.Name)
}

func Test_StorageRepository_GetKeyByName_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetKeyByName(context.Background(), "does-not-exist")
	require.Error(t, err)
	require.True(t, errors.IsKeyNotFound(err), "expected KeyNotFound, got: %v", err)
}

func Test_StorageRepository_GetKeyByName_multipleKeys_returnsCorrectOne(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "alpha", core.ScopeSignatureStandard)
	mustCreateKey(t, r, "key_02", "beta", core.ScopeSignatureStandard)

	got, err := r.GetKeyByName(ctx, "beta")
	require.NoError(t, err)
	assert.Equal(t, "key_02", got.PublicId)
}

// ============================================================================
// Name-to-ID mapping: storage and caching through key lifecycle
// ============================================================================

func Test_StorageRepository_GetKeyByName_afterUpdate_stillResolvable(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", core.ScopeSignatureStandard)

	got, err := r.GetKeyByName(ctx, "signing-key")
	require.NoError(t, err)
	// Same key but state is different
	updated, err := NewKey(ctx, got.PublicId, got.PolicyId, core.PrimitiveSignature, got.CurrentVersion, WithName(got.Name),
		WithLabels(got.Labels), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED))
	require.NoError(t, err)
	err = r.UpdateKey(ctx, updated)
	require.NoError(t, err)

	got, err = r.GetKeyByName(ctx, "signing-key")
	require.NoError(t, err)
	assert.Equal(t, "key_01", got.PublicId)
	assert.Equal(t, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED, got.GetState())
}

func Test_StorageRepository_GetKeyByName_afterDeletion_notFound(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", core.ScopeSignatureStandard)

	require.NoError(t, r.DeleteKey(ctx, "key_01"))

	_, err := r.GetKeyByName(ctx, "signing-key")
	require.Error(t, err)
	require.True(t, errors.IsKeyNotFound(err), "expected KeyNotFound after deletion, got: %v", err)
}

func Test_StorageRepository_CreateKey_duplicateName_notAllowed(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", core.ScopeSignatureStandard)

	scopeSpec := &core.ScopeSpecification{
		Scope: core.ScopeSignatureStandard,
	}
	k2, v2 := mustNewCreateKeyInputs(t, ctx, "key_02", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("other-key-bytes"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	err := r.CreateKey(ctx, k2, v2, WithInitialVersion(1))
	require.Error(t, err)
	require.True(t, errors.IsAlreadyExists(err), "expected AlreadyExists for duplicate name, got: %v", err)
}

func Test_StorageRepository_CreateKey_sameNameAllowedAfterDeletion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", core.ScopeSignatureStandard)
	require.NoError(t, r.DeleteKey(ctx, "key_01"))

	scopeSpec := &core.ScopeSpecification{Scope: core.ScopeSignatureStandard}
	k2, v2 := mustNewCreateKeyInputs(t, ctx, "key_02", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("new-key-bytes"), types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
	require.NoError(t, r.CreateKey(ctx, k2, v2, WithInitialVersion(1)))

	got, err := r.GetKeyByName(ctx, "signing-key")
	require.NoError(t, err)
	assert.Equal(t, "key_02", got.PublicId)
}

func Test_StorageRepository_UpdateKey_nameChange_notAllowed(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "original-name", core.ScopeSignatureStandard)

	got, err := r.GetKeyByName(ctx, "original-name")
	require.NoError(t, err)
	// Same key but state is different
	renamed, err := NewKey(ctx, got.PublicId, got.PolicyId, core.PrimitiveSignature, got.CurrentVersion, WithName("new-name"),
		WithLabels(got.Labels), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED))
	require.NoError(t, err)
	err = r.UpdateKey(ctx, renamed)
	require.Error(t, err)
	require.True(t, errors.IsInvalidArgument(err), "expected InvalidArgument for name change, got: %v", err)
}

func Test_StorageRepository_GetKeyByName_afterAddVersion_returnsUpdatedCurrentVersion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "my-key", core.ScopeSignatureStandard)

	v2, err := NewVersion(ctx, defaultKeyVersionID("key_01", 2), "key_01", "template", "software", 2, []byte("key-v2-bytes"), signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err)
	require.NoError(t, r.AddVersion(ctx, v2))

	got, err := r.GetKeyByName(ctx, "my-key")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), got.CurrentVersion)

	current, err := r.GetCurrentVersion(ctx, got.PublicId)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), current.Version)
}

func Test_StorageRepository_GetCurrentVersion(t *testing.T) {
	testCases := []struct {
		keyID              string
		additionalVersions int
	}{
		{"key_01", 1},
		{"key_02", 3},
		{"key_03", 25},
	}
	r := repoFn()
	for _, tc := range testCases {
		t.Run(tc.keyID, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			km := []byte("fake-key-bytes")
			k, v := mustNewCreateKeyInputs(t, ctx, tc.keyID, tc.keyID, "template-id", "software", "policy-test", &core.ScopeSpecification{
				Scope: core.ScopeSignatureStandard,
			}, 0, km, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE)
			err := r.CreateKey(ctx, k, v, WithInitialVersion(0))
			require.NoErrorf(err, "CreateKey error for key %s: %v", tc.keyID, err)
			v0, err := r.GetCurrentVersion(ctx, tc.keyID)
			require.NoErrorf(err, "GetCurrentVersion error for key %s: %v", tc.keyID, err)
			assert.Equal(uint32(0), v0.Version, "initial version should be 0")
			for i := 1; i < tc.additionalVersions; i++ {
				nextVersion, err := NewVersion(ctx, defaultKeyVersionID(tc.keyID, uint32(i)), tc.keyID, "template", "software", uint32(i), km, signatureScopeSpec(), WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
				require.NoErrorf(err, "newVersion error for version %d of key %s: %v", i, tc.keyID, err)
				err = r.AddVersion(ctx, nextVersion)
				require.NoErrorf(err, "AddVersion error for version %d of key %s: %v", i, tc.keyID, err)
				current, err := r.GetCurrentVersion(ctx, tc.keyID)
				require.NoErrorf(err, "GetCurrentVersion error after adding version %d for key %s: %v", i, tc.keyID, err)
				assert.Equal(uint32(i), current.Version, "current version should be updated to %d after adding new version", i)
			}
		})
	}
}
