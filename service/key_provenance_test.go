package service

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/provider"
	storepb "github.com/agile-crypto/citius-core/store"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
)

var sec1StoredPayload = provider.Transfer{
	Emit:   provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1}},
	Accept: provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1}},
}

func fipsLevel1() *types.ImplementationProperties {
	return &types.ImplementationProperties{Fips_140: &types.Fips140Certification{
		Certified: true, Level: types.Fips140Level_FIPS_140_LEVEL_1,
	}}
}

func TestGeneratedProvenance(t *testing.T) {
	tmpl := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)
	tests := []struct {
		name            string
		backend         *namedBackend
		extractable     bool
		approvedLineage bool
	}{
		{"no advertisement", &namedBackend{name: "plain"}, false, false},
		{"releases stored material", &namedBackend{name: "software", transfer: sec1StoredPayload}, true, false},
		{"validated module releasing material", &namedBackend{name: "fips", transfer: sec1StoredPayload, implementation: fipsLevel1()}, true, true},
		{"validated module keeping material", &namedBackend{name: "hsm", implementation: fipsLevel1()}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generatedProvenance(tt.backend, tmpl)
			require.Equal(t, tt.extractable, got.Extractable)
			require.Equal(t, tt.approvedLineage, got.ApprovedLineage)
			require.Equal(t, storepb.KeyOriginKind_KEY_ORIGIN_KIND_GENERATED, got.Origin.GetKind())
		})
	}
}

func TestKeptProvenance_neverRegainsExtractabilityOrLineage(t *testing.T) {
	ctx := context.Background()
	tmpl := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)
	source := func(extractable, lineage bool) *key.Version {
		v, err := key.NewVersion(ctx, "ver_1", "key_1", tmpl.TemplateID(), "source", 3, []byte("m"),
			&core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
			key.WithProvenance(key.Provenance{Extractable: extractable, ApprovedLineage: lineage}))
		require.NoError(t, err)
		return v
	}
	fips := &namedBackend{name: "fips", transfer: sec1StoredPayload, implementation: fipsLevel1()}
	software := &namedBackend{name: "software", transfer: sec1StoredPayload}

	tests := []struct {
		name            string
		source          *key.Version
		target          *namedBackend
		extractable     bool
		approvedLineage bool
	}{
		{"validated to validated keeps both", source(true, true), fips, true, true},
		{"validated to non-validated loses the lineage", source(true, true), software, true, false},
		{"into a validated module does not create a lineage", source(true, false), fips, true, false},
		{"non-extractable material stays non-extractable", source(false, true), fips, false, true},
		{"a target that keeps material makes it non-extractable", source(true, true), &namedBackend{name: "hsm", implementation: fipsLevel1()}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keptProvenance(tt.source, tt.target, tmpl,
				storepb.KeyOriginKind_KEY_ORIGIN_KIND_TRANSFERRED, storepb.KeyTransferChannel_KEY_TRANSFER_CHANNEL_STORED_PAYLOAD)
			require.Equal(t, tt.extractable, got.Extractable)
			require.Equal(t, tt.approvedLineage, got.ApprovedLineage)
			require.Equal(t, &storepb.KeyOrigin{
				Kind:             storepb.KeyOriginKind_KEY_ORIGIN_KIND_TRANSFERRED,
				SourceVersion:    3,
				SourceProviderId: "source",
				Channel:          storepb.KeyTransferChannel_KEY_TRANSFER_CHANNEL_STORED_PAYLOAD,
			}, got.Origin)
		})
	}
}

func TestReadKey_reportsExtractability(t *testing.T) {
	ctx := context.Background()
	f := newMigrateFixture(t)
	for _, extractable := range []bool{true, false} {
		f.repo.versions[1].Extractable = extractable
		md, err := f.orchestrator.ReadKey(ctx, transformKeyName, 1)
		require.NoError(t, err)
		require.Equal(t, extractable, md.Extractable)
		resp, err := md.ToProto(ctx)
		require.NoError(t, err)
		require.Equal(t, extractable, resp.GetExtractable())
	}
}
