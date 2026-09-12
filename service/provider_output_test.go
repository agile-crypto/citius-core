package service

import (
	"context"
	"testing"

	metapb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	"github.com/agile-crypto/citius-core/provider"
)

func TestRequireProviderOutput(t *testing.T) {
	ctx := context.Background()
	const op = "test.requireProviderOutput"

	tests := []struct {
		name    string
		out     *metapb.ProviderOutput
		wantErr bool
	}{
		{"nil ProviderOutput", nil, true},
		{"algorithm_output unset", &metapb.ProviderOutput{}, true},
		{"NoOutput with encoding", provider.NoOutput("der"), false},
		{"NoOutputUnencoded", provider.NoOutputUnencoded(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireProviderOutput(ctx, op, tt.out)
			if (err != nil) != tt.wantErr {
				t.Errorf("requireProviderOutput(%+v) error = %v, wantErr %v", tt.out, err, tt.wantErr)
			}
		})
	}
}
