package provider

import (
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"google.golang.org/protobuf/proto"
)

func fipsCertified() *types.ImplementationProperties {
	return &types.ImplementationProperties{
		Fips_140: &types.Fips140Certification{Certified: true},
	}
}

func TestScore_hardFilter(t *testing.T) {
	fipsRequired := core.ProviderRequirements{FIPS140Certified: true}

	tests := []struct {
		name     string
		props    *types.ImplementationProperties
		required core.ProviderRequirements
		wantOK   bool
	}{
		{"no requirement, no props", nil, core.ProviderRequirements{}, true},
		{"no requirement, FIPS props", fipsCertified(), core.ProviderRequirements{}, true},
		{"FIPS required, no props at all (no ImplementationDescriber)", nil, fipsRequired, false},
		{"FIPS required, props present but not FIPS-certified", &types.ImplementationProperties{}, fipsRequired, false},
		{"FIPS required, Fips_140 present but Certified false", &types.ImplementationProperties{Fips_140: &types.Fips140Certification{Certified: false}}, fipsRequired, false},
		{"FIPS required, FIPS-certified props", fipsCertified(), fipsRequired, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := score(tt.props, tt.required)
			if ok != tt.wantOK {
				t.Errorf("score(%+v, %+v) ok = %v, want %v", tt.props, tt.required, ok, tt.wantOK)
			}
		})
	}
}

func TestScore_softScore(t *testing.T) {
	tests := []struct {
		name  string
		props *types.ImplementationProperties
		want  int
	}{
		{"nil props scores neutral", nil, 0},
		{"empty props scores neutral", &types.ImplementationProperties{}, 0},
		{"FIPS-certified only", fipsCertified(), 2},
		{"constant-time only", &types.ImplementationProperties{ConstantTime: proto.Bool(true)}, 1},
		{"hardware-accelerated only", &types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)}, 1},
		{"memory-safe only", &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)}, 1},
		{
			"all properties set",
			&types.ImplementationProperties{
				Fips_140:            &types.Fips140Certification{Certified: true},
				ConstantTime:        proto.Bool(true),
				HardwareAccelerated: proto.Bool(true),
				MemorySafeLanguage:  proto.Bool(true),
			},
			5,
		},
		{
			// software-shaped: memory-safe only.
			"software-shaped",
			&types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)},
			1,
		},
		{
			// openssl default-mode-shaped: hardware-accelerated, not memory-safe, no FIPS.
			"openssl default-mode-shaped",
			&types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)},
			1,
		},
		{
			// openssl FIPS-mode-shaped: hardware-accelerated + FIPS-certified.
			"openssl FIPS-mode-shaped",
			&types.ImplementationProperties{
				Fips_140:            &types.Fips140Certification{Certified: true},
				HardwareAccelerated: proto.Bool(true),
			},
			3,
		},
		{
			// A false-valued *bool must not be treated as "set" — only true counts.
			"explicit false values score nothing",
			&types.ImplementationProperties{
				ConstantTime:        proto.Bool(false),
				HardwareAccelerated: proto.Bool(false),
				MemorySafeLanguage:  proto.Bool(false),
			},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := score(tt.props, core.ProviderRequirements{})
			if !ok {
				t.Fatalf("score(%+v): ok = false, want true (no hard requirement)", tt.props)
			}
			if got != tt.want {
				t.Errorf("score(%+v) = %d, want %d", tt.props, got, tt.want)
			}
		})
	}
}

// TestScore_openSSLFIPSOutranksDefaultMode is the scenario the plan's B5
// item exists to prove end-to-end: when FIPS 140 certification is required,
// the FIPS-mode
// instance must outscore (and, via the hard filter, be the only survivor
// among) an otherwise-identical default-mode instance.
func TestScore_openSSLFIPSOutranksDefaultMode(t *testing.T) {
	defaultMode := &types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)}
	fipsMode := &types.ImplementationProperties{
		Fips_140:            &types.Fips140Certification{Certified: true},
		HardwareAccelerated: proto.Bool(true),
	}
	required := core.ProviderRequirements{FIPS140Certified: true}

	if _, ok := score(defaultMode, required); ok {
		t.Error("default-mode instance: expected hard filter to reject when FIPS is required")
	}

	fipsScore, ok := score(fipsMode, required)
	if !ok {
		t.Fatal("FIPS-mode instance: expected hard filter to pass when FIPS is required")
	}
	if fipsScore != 3 {
		t.Errorf("FIPS-mode instance score = %d, want 3", fipsScore)
	}
}

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

func TestScore_preferenceOutranksEverySoftSignal(t *testing.T) {
	prefer := core.ProviderRequirements{PreferHardwareAccelerated: true}
	everythingButAcceleration := &types.ImplementationProperties{
		Fips_140:           &types.Fips140Certification{Certified: true},
		ConstantTime:       proto.Bool(true),
		MemorySafeLanguage: proto.Bool(true),
	}
	onlyAcceleration := &types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)}

	other, _ := score(everythingButAcceleration, prefer)
	preferred, _ := score(onlyAcceleration, prefer)
	if preferred <= other {
		t.Errorf("preferred provider scores %d, not above %d", preferred, other)
	}
}
