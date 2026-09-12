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
	fipsRequired := &core.SecurityProperties{FipsApproved: true}

	tests := []struct {
		name     string
		props    *types.ImplementationProperties
		required *core.SecurityProperties
		wantOK   bool
	}{
		{"no requirement, no props", nil, nil, true},
		{"no requirement, FIPS props", fipsCertified(), nil, true},
		{"requirement not FIPS, no props", nil, &core.SecurityProperties{}, true},
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
			got, ok := score(tt.props, nil)
			if !ok {
				t.Fatalf("score(%+v, nil): ok = false, want true (no hard requirement)", tt.props)
			}
			if got != tt.want {
				t.Errorf("score(%+v, nil) = %d, want %d", tt.props, got, tt.want)
			}
		})
	}
}

// TestScore_openSSLFIPSOutranksDefaultMode is the scenario the plan's B5
// item exists to prove end-to-end: when FIPS is required, the FIPS-mode
// instance must outscore (and, via the hard filter, be the only survivor
// among) an otherwise-identical default-mode instance.
func TestScore_openSSLFIPSOutranksDefaultMode(t *testing.T) {
	defaultMode := &types.ImplementationProperties{HardwareAccelerated: proto.Bool(true)}
	fipsMode := &types.ImplementationProperties{
		Fips_140:            &types.Fips140Certification{Certified: true},
		HardwareAccelerated: proto.Bool(true),
	}
	required := &core.SecurityProperties{FipsApproved: true}

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
