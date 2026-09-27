package core_test

import (
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/protobuf/proto"
)

func TestProviderRequirementsFromProto(t *testing.T) {
	got, err := core.ProviderRequirementsFromProto(t.Context(), &types.ProviderRequirements{
		Fips_140Certified:         proto.Bool(true),
		MinFipsLevel:              types.Fips140Level_FIPS_140_LEVEL_2,
		CommonCriteriaCertified:   proto.Bool(true),
		FormallyVerified:          proto.Bool(true),
		MemorySafe:                proto.Bool(true),
		ConstantTime:              proto.Bool(true),
		SideChannelHardened:       proto.Bool(true),
		NoKnownCve:                proto.Bool(true),
		PreferHardwareAccelerated: proto.Bool(true),
	})
	if err != nil {
		t.Fatalf("ProviderRequirementsFromProto: %v", err)
	}
	want := core.ProviderRequirements{
		FIPS140Certified:          true,
		MinFIPS140Level:           2,
		CommonCriteriaCertified:   true,
		FormallyVerified:          true,
		MemorySafe:                true,
		ConstantTime:              true,
		SideChannelHardened:       true,
		NoKnownCVE:                true,
		PreferHardwareAccelerated: true,
	}
	if got != want {
		t.Errorf("ProviderRequirementsFromProto = %+v, want %+v", got, want)
	}
}

func TestProviderRequirementsFromProto_nilAndFalseRequireNothing(t *testing.T) {
	for name, p := range map[string]*types.ProviderRequirements{
		"nil":   nil,
		"empty": {},
		"false": {Fips_140Certified: proto.Bool(false), MemorySafe: proto.Bool(false)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := core.ProviderRequirementsFromProto(t.Context(), p)
			if err != nil {
				t.Fatalf("ProviderRequirementsFromProto: %v", err)
			}
			if !got.IsZero() {
				t.Errorf("ProviderRequirementsFromProto = %+v, want zero", got)
			}
		})
	}
}

func TestProviderRequirementsFromProto_rejectsWhatItCannotEnforce(t *testing.T) {
	for name, p := range map[string]*types.ProviderRequirements{
		"additional":     {Additional: map[string]string{"vendor": "acme"}},
		"unknown level":  {MinFipsLevel: types.Fips140Level(5)},
		"negative level": {MinFipsLevel: types.Fips140Level(-1)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := core.ProviderRequirementsFromProto(t.Context(), p)
			if !errors.IsInvalidArgument(err) {
				t.Errorf("ProviderRequirementsFromProto error = %v, want invalid argument", err)
			}
		})
	}
}

func TestProviderRequirements_Merge(t *testing.T) {
	request := core.ProviderRequirements{MemorySafe: true, MinFIPS140Level: 1, PreferHardwareAccelerated: true}
	policy := core.ProviderRequirements{FIPS140Certified: true, MinFIPS140Level: 3, ApprovedGeneration: true}
	want := core.ProviderRequirements{
		FIPS140Certified:          true,
		MinFIPS140Level:           3,
		MemorySafe:                true,
		ApprovedGeneration:        true,
		PreferHardwareAccelerated: true,
	}
	if got := request.Merge(policy); got != want {
		t.Errorf("Merge = %+v, want %+v", got, want)
	}
	if got := policy.Merge(request); got != want {
		t.Errorf("Merge is not symmetric: %+v, want %+v", got, want)
	}
	if got := request.Merge(core.ProviderRequirements{}); got != request {
		t.Errorf("Merge with zero = %+v, want %+v", got, request)
	}
}
