package provider_test

import (
	"testing"

	metapb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	"github.com/agile-crypto/citius-core/provider"
	"google.golang.org/protobuf/proto"
)

func TestNoOutput_setsNoOutputArmAndEncoding(t *testing.T) {
	got := provider.NoOutput("der")

	if _, ok := got.GetAlgorithmOutput().(*metapb.ProviderOutput_NoOutput); !ok {
		t.Fatalf("AlgorithmOutput = %T, want *metapb.ProviderOutput_NoOutput", got.GetAlgorithmOutput())
	}
	if got.GetNoOutput() == nil {
		t.Error("GetNoOutput() = nil, want non-nil NoAlgorithmOutput")
	}
	if got.GetEncoding() != "der" {
		t.Errorf("GetEncoding() = %q, want %q", got.GetEncoding(), "der")
	}
}

func TestNoOutput_roundTripsThroughMarshal(t *testing.T) {
	want := provider.NoOutput("raw")

	b, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	got := new(metapb.ProviderOutput)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	if got.GetAlgorithmOutput() == nil {
		t.Error("algorithm_output nil after round-trip")
	}
	if got.GetEncoding() != "raw" {
		t.Errorf("GetEncoding() = %q, want %q", got.GetEncoding(), "raw")
	}
}

func TestNoOutputUnencoded_setsNoOutputArmAndEmptyEncoding(t *testing.T) {
	got := provider.NoOutputUnencoded()

	if _, ok := got.GetAlgorithmOutput().(*metapb.ProviderOutput_NoOutput); !ok {
		t.Fatalf("AlgorithmOutput = %T, want *metapb.ProviderOutput_NoOutput", got.GetAlgorithmOutput())
	}
	if got.GetNoOutput() == nil {
		t.Error("GetNoOutput() = nil, want non-nil NoAlgorithmOutput")
	}
	if got.GetEncoding() != "" {
		t.Errorf("GetEncoding() = %q, want empty string", got.GetEncoding())
	}
}

func TestNoOutputUnencoded_roundTripsThroughMarshal(t *testing.T) {
	want := provider.NoOutputUnencoded()

	b, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	got := new(metapb.ProviderOutput)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}

	// The point of this test: an empty encoding must NOT collapse the
	// algorithm_output oneof itself.  Only algorithm_output being unset is a
	// provider-contract violation — an empty encoding is not.
	if got.GetAlgorithmOutput() == nil {
		t.Error("algorithm_output nil after round-trip — empty encoding must not be conflated with unset algorithm_output")
	}
	if got.GetEncoding() != "" {
		t.Errorf("GetEncoding() = %q, want empty string", got.GetEncoding())
	}
}
