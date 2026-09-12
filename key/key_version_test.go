package key_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/key"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/stretchr/testify/require"
)

func TestKeyVersion_NewVersion(t *testing.T) {
	tc := []struct {
		name          string
		withOpts      bool
		state         types.KeyLifecycleState
		wrappingKeyID string
	}{
		{name: "without options", withOpts: false},
		{name: "with options", withOpts: true, state: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, wrappingKeyID: "wrapping-key-01"},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			opts := []key.Option{}
			if tt.withOpts {
				opts = append(opts, key.WithState(tt.state), key.WithWrappingKeyID(tt.wrappingKeyID))
			}
			v, err := key.NewVersion(ctx, "ver_01HXYZ", "key_01HXYZ", "template_01", "software", 1, []byte("key-material"), opts...)
			require.NoError(t, err)
			require.Equal(t, "ver_01HXYZ", v.PublicId)
			require.Equal(t, "key_01HXYZ", v.KeyId)
			require.Equal(t, "template_01", v.TemplateId)
			require.Equal(t, "software", v.ProviderId)
			require.Equal(t, uint32(1), v.Version)
			require.Equal(t, []byte("key-material"), v.KeyMaterial)
			if tt.withOpts {
				require.Equal(t, tt.state, v.State)
				require.Equal(t, tt.wrappingKeyID, v.WrappingKeyId)
			} else {
				require.Equal(t, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE, v.State)
				require.Equal(t, "", v.WrappingKeyId)
			}
		})
	}
}
func TestKeyVersion_VetForWrite_Create_happyPath(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId:   "ver_01HXYZ",
		KeyId:      "key_01HXYZ",
		Version:    1,
		ProviderId: "software",
		Digest:     []byte("mac"),
	}}
	if err := v.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestKeyVersion_VetForWrite_Create_missingKeyId(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId:   "ver_01HXYZ",
		ProviderId: "software",
		Digest:     []byte("mac"),
	}}
	err := v.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing KeyId")
	}
}

func TestKeyVersion_VetForWrite_Create_missingProviderId(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId: "ver_01HXYZ",
		KeyId:    "key_01HXYZ",
		Digest:   []byte("mac"),
	}}
	err := v.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing ProviderId")
	}
}

func TestKeyVersion_Clone_independent(t *testing.T) {
	original := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId: "ver_01HXYZ",
		KeyId:    "key_01HXYZ",
	}}
	cloned := original.Clone()
	if original.KeyId != cloned.KeyId || original.PublicId != cloned.PublicId {
		t.Error("Clone() did not produce an independent copy — mutations alias the original")
	}
}

func TestKeyVersion_Version_accessor(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{Version: 3}}
	if v.Version != 3 {
		t.Errorf("Version(): got %d want 3", v.GetVersion())
	}
}
