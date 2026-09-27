package service

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/provider"
)

func planVersion(t *testing.T, extractable bool, encoding providerpb.PrivateKeyEncoding) *key.Version {
	t.Helper()
	stored, err := proto.Marshal(&providerpb.GenerateKeyResponse{
		KeyMaterial:         []byte("private"),
		KeyMaterialEncoding: encoding,
	})
	require.NoError(t, err)
	v, err := key.NewVersion(context.Background(), "v1", "k1", "ecdsa-p256", "source", 1, stored,
		&core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
		key.WithProvenance(key.Provenance{Extractable: extractable}))
	require.NoError(t, err)
	return v
}

func TestTransferFeasibility(t *testing.T) {
	const (
		switchS  = messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH
		extractS = messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT
		wrapS    = messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER
		archiveS = messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE
		destroyS = messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_DESTROY
		sec1     = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
		pkcs8    = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		none     = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED
	)
	tmpl := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)
	pkcs8Only := provider.Transfer{
		Emit:   provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{pkcs8}},
		Accept: provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{pkcs8}},
	}
	emitOnly := provider.Transfer{Emit: sec1StoredPayload.Emit}
	allChannels := provider.Transfer{
		Emit:   provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{sec1}, Plaintext: []providerpb.PrivateKeyEncoding{pkcs8}, Wrapped: []string{"aes-kwp"}},
		Accept: provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{sec1}, Plaintext: []providerpb.PrivateKeyEncoding{pkcs8}, Wrapped: []string{"aes-kwp"}},
	}
	fipsLevel3 := &types.ImplementationProperties{Fips_140: &types.Fips140Certification{
		Certified: true, Level: types.Fips140Level_FIPS_140_LEVEL_3,
	}}
	fipsNoLevel := &types.ImplementationProperties{Fips_140: &types.Fips140Certification{Certified: true}}

	software := &namedBackend{name: "software", transfer: sec1StoredPayload}
	full := &namedBackend{name: "full", transfer: allChannels}
	tests := []struct {
		name        string
		strategy    messagespb.MigrationStrategy
		source      provider.Backend
		target      provider.Backend
		extractable bool
		encoding    providerpb.PrivateKeyEncoding
		feasible    bool
		reason      string
	}{
		{"switch with a shared stored encoding", switchS, software, &namedBackend{name: "openssl", transfer: sec1StoredPayload}, true, sec1, true, ""},
		{"switch into a level 1 module", switchS, software, &namedBackend{name: "fips", transfer: sec1StoredPayload, implementation: fipsLevel1()}, true, sec1, true, ""},
		{"switch from an unregistered source", switchS, nil, software, true, sec1, false, `source provider instance "source" is not registered`},
		{"switch of non-extractable material", switchS, software, software, false, sec1, false, "is not extractable"},
		{"switch of a payload without an encoding", switchS, software, software, true, none, false, "does not record the encoding"},
		{"switch from a source that keeps its material", switchS, &namedBackend{name: "hsm"}, software, true, sec1, false, `"hsm" does not release`},
		{"switch to a target that reads another encoding", switchS, software, &namedBackend{name: "other", transfer: pkcs8Only}, true, sec1, false, `"other" does not accept`},
		{"switch to a target that only emits", switchS, software, &namedBackend{name: "emitter", transfer: emitOnly}, true, sec1, false, `"emitter" does not accept`},
		{"switch into a level 3 module", switchS, software, &namedBackend{name: "l3", transfer: sec1StoredPayload, implementation: fipsLevel3}, true, sec1, false, `"l3" does not accept`},
		{"switch into a module with no level", switchS, software, &namedBackend{name: "nolevel", transfer: sec1StoredPayload, implementation: fipsNoLevel}, true, sec1, false, `"nolevel" does not accept`},
		{"switch out of a level 3 module", switchS, &namedBackend{name: "l3", transfer: sec1StoredPayload, implementation: fipsLevel3}, software, true, sec1, false, `"l3" does not release`},
		{"extract with a shared plaintext encoding", extractS, full, full, true, sec1, true, ""},
		{"extract from a source that exports nothing", extractS, software, full, true, sec1, false, `"software" exports no key`},
		{"extract without a shared encoding", extractS, full, &namedBackend{name: "other", transfer: pkcs8Only}, true, sec1, false, "share no plaintext key encoding"},
		{"extract of non-extractable material", extractS, full, full, false, sec1, false, "is not extractable"},
		{"wrap with a shared mechanism", wrapS, full, full, false, none, true, ""},
		{"wrap out of a level 3 module", wrapS, &namedBackend{name: "l3", transfer: allChannels, implementation: fipsLevel3}, full, false, none, true, ""},
		{"wrap from a source that wraps nothing", wrapS, software, full, true, sec1, false, `"software" wraps no key`},
		{"wrap without a shared mechanism", wrapS, full, software, true, sec1, false, "share no key-wrapping mechanism"},
		{"rekey and archive", archiveS, nil, &namedBackend{name: "hsm"}, false, none, true, ""},
		{"rekey and destroy", destroyS, nil, &namedBackend{name: "hsm"}, false, none, true, ""},
		{"unspecified strategy", messagespb.MigrationStrategy_MIGRATION_STRATEGY_UNSPECIFIED, software, software, true, sec1, false, "unknown migration strategy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feasible, reason := transferFeasibility(tt.strategy, tt.source, tt.target, planVersion(t, tt.extractable, tt.encoding), tmpl)
			require.Equal(t, tt.feasible, feasible, reason)
			if tt.feasible {
				require.Empty(t, reason)
			} else {
				require.Contains(t, reason, tt.reason)
			}
		})
	}
}

func TestTransferFeasibility_payloadThatDoesNotParse(t *testing.T) {
	tmpl := ecdsaTemplate("ecdsa-p256", types.EllipticCurve_ELLIPTIC_CURVE_P256, false)
	software := &namedBackend{name: "software", transfer: sec1StoredPayload}
	v := planVersion(t, true, providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1)
	v.KeyMaterial = []byte{0xff}

	feasible, reason := transferFeasibility(messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH, software, software, v, tmpl)
	require.False(t, feasible)
	require.Contains(t, reason, "does not parse")
}
