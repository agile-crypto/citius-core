package provider_test

import (
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/stretchr/testify/require"
)

// transferringProvider adds TransferDescriber to describingProvider.
type transferringProvider struct {
	describingProvider
	transfer provider.Transfer
}

func (p *transferringProvider) TransferCapabilities(*types.AlgorithmDetails) provider.Transfer {
	return p.transfer
}

var _ provider.TransferDescriber = (*transferringProvider)(nil)

func TestTransferOf(t *testing.T) {
	sec1 := []providerpb.PrivateKeyEncoding{providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1}
	everything := provider.Transfer{
		Emit:   provider.Channels{StoredPayload: sec1, Plaintext: sec1, Wrapped: []string{"aes-kwp"}},
		Accept: provider.Channels{StoredPayload: sec1, Plaintext: sec1, Wrapped: []string{"aes-kwp"}},
	}
	wrappedOnly := provider.Transfer{
		Emit:   provider.Channels{Wrapped: []string{"aes-kwp"}},
		Accept: provider.Channels{Wrapped: []string{"aes-kwp"}},
	}
	fips := func(level types.Fips140Level) *types.ImplementationProperties {
		return &types.ImplementationProperties{Fips_140: &types.Fips140Certification{Certified: true, Level: level}}
	}

	tests := []struct {
		name  string
		props *types.ImplementationProperties
		want  provider.Transfer
	}{
		{"not certified: as advertised", nil, everything},
		{"FIPS 140 level 1: plaintext keys permitted", fips(types.Fips140Level_FIPS_140_LEVEL_1), everything},
		{"FIPS 140 level 2: plaintext keys permitted", fips(types.Fips140Level_FIPS_140_LEVEL_2), everything},
		{"FIPS 140 level 3: wrapped only", fips(types.Fips140Level_FIPS_140_LEVEL_3), wrappedOnly},
		{"FIPS 140 level 4: wrapped only", fips(types.Fips140Level_FIPS_140_LEVEL_4), wrappedOnly},
		{"certified without a level: fail closed to wrapped only", fips(types.Fips140Level_FIPS_140_LEVEL_UNSPECIFIED), wrappedOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &transferringProvider{describingProvider: describingProvider{props: tt.props}, transfer: everything}
			require.Equal(t, tt.want, provider.TransferOf(p, nil))
		})
	}
}

func TestTransferOf_noAdvertisementMeansNoTransfer(t *testing.T) {
	require.Equal(t, provider.Transfer{}, provider.TransferOf(nil, nil), "an unregistered provider")
	require.Equal(t, provider.Transfer{}, provider.TransferOf(&capableProvider{name: "stub"}, nil),
		"a provider without TransferDescriber")
}
