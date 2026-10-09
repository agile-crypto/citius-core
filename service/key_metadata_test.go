package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	storepb "github.com/agile-crypto/citius-core/store"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ReadKey reports everything the server knows about a key: its times, its
// template, its provider's implementation, its material's origin and its
// public key.
func TestReadKey_reportsEverythingKnownAboutTheKey(t *testing.T) {
	f := newMigrateFixture(t)
	created := timestamppb.Now()
	f.repo.key.CreateTime = created
	f.repo.key.UpdateTime = created
	setOrigin(f.repo.versions[1], storepb.KeyOriginKind_KEY_ORIGIN_KIND_GENERATED, 0)

	md, err := f.orchestrator.ReadKey(context.Background(), transformKeyName, 0)
	require.NoError(t, err)
	got, err := md.ToProto(context.Background())
	require.NoError(t, err)

	require.True(t, proto.Equal(created, got.GetCreatedTime()))
	require.True(t, proto.Equal(created, got.GetUpdatedTime()))
	require.Equal(t, f.template.TemplateID(), got.GetTemplateInfo().GetTemplateId())
	require.NotSame(t, f.template.Proto(), got.GetTemplateInfo(), "the catalogue's message is copied, never shared")
	require.True(t, proto.Equal(f.backends[migrateSourceInstance].ImplementationProperties(), got.GetImplementationProperties()))
	require.Equal(t, types.KeyOrigin_KEY_ORIGIN_GENERATED, got.GetOrigin())
	require.Equal(t, []byte("source-public"), got.GetPublicKeyBytes())
	require.Nil(t, got.PublicKeyFormat, "the fixture's provider did not record the public key's encoding")
}

// Material a version retained or had transferred keeps the origin of the
// version it came from, however many steps back.
func TestReadKey_originFollowsKeptMaterialBackToItsCreation(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	setOrigin(f.repo.versions[1], storepb.KeyOriginKind_KEY_ORIGIN_KIND_GENERATED, 0)
	addVersion(t, f, 2, storepb.KeyOriginKind_KEY_ORIGIN_KIND_RETAINED, 1)
	addVersion(t, f, 3, storepb.KeyOriginKind_KEY_ORIGIN_KIND_TRANSFERRED, 2)

	md, err := f.orchestrator.ReadKey(ctx, transformKeyName, 3)
	require.NoError(t, err)
	require.Equal(t, types.KeyOrigin_KEY_ORIGIN_GENERATED, md.Origin)

	// A version that recorded no origin says nothing about it.
	setOrigin(f.repo.versions[1], storepb.KeyOriginKind_KEY_ORIGIN_KIND_UNSPECIFIED, 0)
	md, err = f.orchestrator.ReadKey(ctx, transformKeyName, 3)
	require.NoError(t, err)
	require.Equal(t, types.KeyOrigin_KEY_ORIGIN_UNSPECIFIED, md.Origin)

	// A version cannot keep material from itself or a later version.
	setOrigin(f.repo.versions[3], storepb.KeyOriginKind_KEY_ORIGIN_KIND_RETAINED, 3)
	_, err = f.orchestrator.ReadKey(ctx, transformKeyName, 3)
	require.Error(t, err)
	require.Equal(t, codes.Internal, errors.GRPCCode(err), "got %v", err)
}

// The public key's format is the provider's recorded encoding; a symmetric
// key has no public key at all.
func TestPublicKeyOf(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		stored     *providerpb.GenerateKeyResponse
		wantBytes  []byte
		wantFormat *types.KeyFormat
	}{
		{name: "symmetric", stored: &providerpb.GenerateKeyResponse{KeyMaterial: []byte("secret")}},
		{
			name:       "SPKI",
			stored:     &providerpb.GenerateKeyResponse{PublicKeyBytes: []byte("spki"), PublicKeyEncoding: providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI},
			wantBytes:  []byte("spki"),
			wantFormat: types.KeyFormat_KEY_FORMAT_SPKI.Enum(),
		},
		{
			name:       "raw",
			stored:     &providerpb.GenerateKeyResponse{PublicKeyBytes: []byte("raw"), PublicKeyEncoding: providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW},
			wantBytes:  []byte("raw"),
			wantFormat: types.KeyFormat_KEY_FORMAT_RAW.Enum(),
		},
		{
			name:       "PEM",
			stored:     &providerpb.GenerateKeyResponse{PublicKeyBytes: []byte("pem"), PublicKeyEncoding: providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_PEM},
			wantBytes:  []byte("pem"),
			wantFormat: types.KeyFormat_KEY_FORMAT_PEM.Enum(),
		},
		{
			name:      "encoding not recorded",
			stored:    &providerpb.GenerateKeyResponse{PublicKeyBytes: []byte("bytes")},
			wantBytes: []byte("bytes"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			material, err := proto.Marshal(tc.stored)
			require.NoError(t, err)
			v := &key.Version{KeyVersion: &storepb.KeyVersion{KeyMaterial: material}}
			gotBytes, gotFormat, err := publicKeyOf(ctx, v)
			require.NoError(t, err)
			require.Equal(t, tc.wantBytes, gotBytes)
			require.Equal(t, tc.wantFormat, gotFormat)
		})
	}
}

// A template gone from the catalogue, or a provider instance no longer
// registered, leaves its field unset rather than failing the read; any other
// lookup failure is an error.
func TestReadKey_missingTemplateOrProviderLeavesItsFieldUnset(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	delete(f.templates.templates, f.template.TemplateID())
	delete(f.providers.backends, migrateSourceInstance)

	md, err := f.orchestrator.ReadKey(ctx, transformKeyName, 0)
	require.NoError(t, err)
	require.Nil(t, md.TemplateInfo)
	require.Nil(t, md.ImplementationProperties)
	require.Equal(t, f.template.TemplateID(), md.TemplateID, "the version still names its template")

	f.providers.getErr = errors.New(ctx, "fake.Get", errors.CodeInternal, "registry unavailable")
	_, err = f.orchestrator.ReadKey(ctx, transformKeyName, 0)
	require.Error(t, err)
}

func setOrigin(v *key.Version, kind storepb.KeyOriginKind, source uint32) {
	v.Origin = &storepb.KeyOrigin{Kind: kind, SourceVersion: source}
}

// addVersion adds version n to the fixture's key, with the first version's
// material and the given origin.
func addVersion(t *testing.T, f *migrateFixture, n uint32, kind storepb.KeyOriginKind, source uint32) {
	t.Helper()
	first := f.repo.versions[1]
	v, err := key.NewVersion(context.Background(), computeVersionID(transformKeyID, n), transformKeyID,
		first.GetTemplateId(), first.GetProviderId(), n, first.GetKeyMaterial(),
		&core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE),
		key.WithProvenance(key.Provenance{Origin: &storepb.KeyOrigin{Kind: kind, SourceVersion: source}}))
	require.NoError(t, err)
	f.repo.versions[n] = v
	f.repo.key.CurrentVersion = n
}
