package provider

import (
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"google.golang.org/protobuf/proto"
)

func TestSatisfies(t *testing.T) {
	everything := &types.ImplementationProperties{
		Fips_140:                &types.Fips140Certification{Certified: true, Level: types.Fips140Level_FIPS_140_LEVEL_2},
		CommonCriteriaCertified: proto.Bool(true),
		FormallyVerified:        proto.Bool(true),
		MemorySafeLanguage:      proto.Bool(true),
		ConstantTime:            proto.Bool(true),
		SideChannelHardened:     proto.Bool(true),
		NoKnownCve:              proto.Bool(true),
	}
	requirements := map[string]core.ProviderRequirements{
		"FIPS 140 certified":        {FIPS140Certified: true},
		"FIPS 140 level":            {MinFIPS140Level: 2},
		"Common Criteria certified": {CommonCriteriaCertified: true},
		"formally verified":         {FormallyVerified: true},
		"memory safe":               {MemorySafe: true},
		"constant time":             {ConstantTime: true},
		"side-channel hardened":     {SideChannelHardened: true},
		"no known CVE":              {NoKnownCVE: true},
		"approved generation":       {ApprovedGeneration: true},
	}
	for name, required := range requirements {
		t.Run(name, func(t *testing.T) {
			if !satisfies(everything, required) {
				t.Error("a provider reporting the property must satisfy the requirement")
			}
			if satisfies(nil, required) {
				t.Error("a provider reporting nothing must not satisfy the requirement")
			}
			if satisfies(&types.ImplementationProperties{}, required) {
				t.Error("a provider not reporting the property must not satisfy the requirement")
			}
		})
	}

	if !satisfies(nil, core.ProviderRequirements{PreferHardwareAccelerated: true}) {
		t.Error("a preference must not exclude a provider")
	}
	if !satisfies(nil, core.ProviderRequirements{}) {
		t.Error("no requirement must not exclude a provider")
	}
}

func TestSatisfies_fipsLevel(t *testing.T) {
	level := func(certified bool, l types.Fips140Level) *types.ImplementationProperties {
		return &types.ImplementationProperties{Fips_140: &types.Fips140Certification{Certified: certified, Level: l}}
	}
	tests := []struct {
		name  string
		props *types.ImplementationProperties
		min   uint32
		want  bool
	}{
		{"level met exactly", level(true, types.Fips140Level_FIPS_140_LEVEL_2), 2, true},
		{"level exceeded", level(true, types.Fips140Level_FIPS_140_LEVEL_3), 2, true},
		{"level too low", level(true, types.Fips140Level_FIPS_140_LEVEL_1), 2, false},
		{"certified but level not reported", level(true, types.Fips140Level_FIPS_140_LEVEL_UNSPECIFIED), 1, false},
		{"level reported but not certified", level(false, types.Fips140Level_FIPS_140_LEVEL_4), 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := satisfies(tt.props, core.ProviderRequirements{MinFIPS140Level: tt.min}); got != tt.want {
				t.Errorf("satisfies = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSatisfies_noKnownCVE_rejectsListedCVEs(t *testing.T) {
	props := &types.ImplementationProperties{NoKnownCve: proto.Bool(true), UnpatchedCves: []string{"CVE-2026-0001"}}
	if satisfies(props, core.ProviderRequirements{NoKnownCVE: true}) {
		t.Error("a provider listing an unpatched CVE must not satisfy no_known_cve, whatever its flag says")
	}
}

func TestPreferred(t *testing.T) {
	accelerated := &types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)}
	prefer := core.ProviderRequirements{PreferHardwareAccelerated: true}
	tests := []struct {
		name     string
		props    *types.ImplementationProperties
		required core.ProviderRequirements
		want     bool
	}{
		{"preferred property", accelerated, prefer, true},
		{"property not reported", &types.ImplementationProperties{}, prefer, false},
		{"no props", nil, prefer, false},
		{"no preference", accelerated, core.ProviderRequirements{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Preferred(tt.props, tt.required); got != tt.want {
				t.Errorf("Preferred = %v, want %v", got, tt.want)
			}
		})
	}
}
