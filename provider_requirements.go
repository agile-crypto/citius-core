package core

import (
	"context"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// MaxFIPS140Level is the highest FIPS 140 security level.
const MaxFIPS140Level = 4

// ProviderRequirements are properties the provider implementation holding a
// key must have. They constrain which provider instance serves a key; they
// never influence which algorithm template is chosen.
//
// Every bool except PreferHardwareAccelerated is a hard requirement when true
// and no requirement when false. MinFIPS140Level is a FIPS 140 security level
// from 1 to 4, or 0 for none; a non-zero level also requires FIPS 140
// certification. PreferHardwareAccelerated ranks hardware-accelerated
// providers first but excludes none.
//
// ApprovedGeneration requires more than the provider: the version's material
// must have been generated in a FIPS 140 validated module and held only by
// validated modules since. Of a provider it requires FIPS 140 certification;
// the orchestrator checks the material's lineage when it keeps existing
// material. Only a policy sets it: a lineage constraint must outlive
// creation.
//
// The zero value requires nothing.
type ProviderRequirements struct {
	FIPS140Certified          bool
	MinFIPS140Level           uint32
	CommonCriteriaCertified   bool
	FormallyVerified          bool
	MemorySafe                bool
	ConstantTime              bool
	SideChannelHardened       bool
	NoKnownCVE                bool
	ApprovedGeneration        bool
	PreferHardwareAccelerated bool
}

// IsZero reports whether r requires and prefers nothing.
func (r ProviderRequirements) IsZero() bool {
	return r == ProviderRequirements{}
}

// Merge returns the requirements a provider meets only if it meets both r
// and o: every requirement or preference of either, and the higher minimum
// FIPS 140 level.
func (r ProviderRequirements) Merge(o ProviderRequirements) ProviderRequirements {
	return ProviderRequirements{
		FIPS140Certified:          r.FIPS140Certified || o.FIPS140Certified,
		MinFIPS140Level:           max(r.MinFIPS140Level, o.MinFIPS140Level),
		CommonCriteriaCertified:   r.CommonCriteriaCertified || o.CommonCriteriaCertified,
		FormallyVerified:          r.FormallyVerified || o.FormallyVerified,
		MemorySafe:                r.MemorySafe || o.MemorySafe,
		ConstantTime:              r.ConstantTime || o.ConstantTime,
		SideChannelHardened:       r.SideChannelHardened || o.SideChannelHardened,
		NoKnownCVE:                r.NoKnownCVE || o.NoKnownCVE,
		ApprovedGeneration:        r.ApprovedGeneration || o.ApprovedGeneration,
		PreferHardwareAccelerated: r.PreferHardwareAccelerated || o.PreferHardwareAccelerated,
	}
}

// ProviderRequirementsFromProto converts p, which may be nil, to
// ProviderRequirements. It rejects what it cannot enforce rather than
// ignoring it: an unknown FIPS 140 level, and any additional requirement.
func ProviderRequirementsFromProto(ctx context.Context, p *types.ProviderRequirements) (ProviderRequirements, error) {
	const op = "core.ProviderRequirementsFromProto"
	if len(p.GetAdditional()) > 0 {
		return ProviderRequirements{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"additional provider requirements are not supported")
	}
	level := p.GetMinFipsLevel()
	if level < 0 || level > MaxFIPS140Level {
		return ProviderRequirements{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"minimum FIPS 140 level %d is not a level from 1 to %d", level, MaxFIPS140Level)
	}
	return ProviderRequirements{
		FIPS140Certified:          p.GetFips_140Certified(),
		MinFIPS140Level:           uint32(level),
		CommonCriteriaCertified:   p.GetCommonCriteriaCertified(),
		FormallyVerified:          p.GetFormallyVerified(),
		MemorySafe:                p.GetMemorySafe(),
		ConstantTime:              p.GetConstantTime(),
		SideChannelHardened:       p.GetSideChannelHardened(),
		NoKnownCVE:                p.GetNoKnownCve(),
		PreferHardwareAccelerated: p.GetPreferHardwareAccelerated(),
	}, nil
}
