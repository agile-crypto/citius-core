package provider

import (
	"google.golang.org/protobuf/proto"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
)

// ImplementationOf returns a copy of p's ImplementationProperties, or nil if
// p does not implement ImplementationDescriber. The copy is the caller's: a
// result that reports it cannot alias, and so cannot change, what the
// provider holds. Every accessor on the result is a nil-safe proto getter,
// so nil reports every property as unset.
func ImplementationOf(p Backend) *types.ImplementationProperties {
	if id, ok := p.(ImplementationDescriber); ok {
		if props := id.ImplementationProperties(); props != nil {
			return proto.CloneOf(props)
		}
	}
	return nil
}

// Requirement is one hard requirement of core.ProviderRequirements. Unmet
// reports the ones a provider misses.
type Requirement int

// The hard requirements, in the order of core.ProviderRequirements.
const (
	RequirementFIPS140Certified Requirement = iota + 1
	RequirementMinFIPS140Level
	RequirementCommonCriteriaCertified
	RequirementFormallyVerified
	RequirementMemorySafe
	RequirementConstantTime
	RequirementSideChannelHardened
	RequirementNoKnownCVE
	RequirementApprovedGeneration
)

// String is the name of the ProviderRequirements proto field that sets r,
// or approved_generation, which a crypto policy sets.
func (r Requirement) String() string {
	switch r {
	case RequirementFIPS140Certified:
		return "fips_140_certified"
	case RequirementMinFIPS140Level:
		return "min_fips_level"
	case RequirementCommonCriteriaCertified:
		return "common_criteria_certified"
	case RequirementFormallyVerified:
		return "formally_verified"
	case RequirementMemorySafe:
		return "memory_safe"
	case RequirementConstantTime:
		return "constant_time"
	case RequirementSideChannelHardened:
		return "side_channel_hardened"
	case RequirementNoKnownCVE:
		return "no_known_cve"
	case RequirementApprovedGeneration:
		return "approved_generation"
	default:
		return "unknown"
	}
}

// Preferred reports whether props have a property required prefers. A
// preference ranks providers; it never excludes one.
func Preferred(props *types.ImplementationProperties, required core.ProviderRequirements) bool {
	return required.PreferHardwareAccelerated && props.GetHardwareAccelerated()
}

// Meets reports whether p meets every hard requirement in required, judged
// on the implementation properties it reports. It is the check Match applies
// to each candidate.
func Meets(p Backend, required core.ProviderRequirements) bool {
	return len(Unmet(ImplementationOf(p), required)) == 0
}

// Unmet returns the hard requirements in required that props do not meet,
// in the order of core.ProviderRequirements; none means props meet them
// all. A property the provider does not report, including every property of
// a provider with nil props, counts as not met: requirements fail closed.
// This is the one definition of "meets the provider requirements": Match,
// Meets and Rank all apply it.
func Unmet(props *types.ImplementationProperties, required core.ProviderRequirements) []Requirement {
	fips := props.GetFips_140()
	checks := []struct {
		requirement   Requirement
		required, met bool
	}{
		{RequirementFIPS140Certified, required.FIPS140Certified, fips.GetCertified()},
		{RequirementMinFIPS140Level, required.MinFIPS140Level > 0,
			fips.GetCertified() && int64(fips.GetLevel()) >= int64(required.MinFIPS140Level)},
		{RequirementCommonCriteriaCertified, required.CommonCriteriaCertified, props.GetCommonCriteriaCertified()},
		{RequirementFormallyVerified, required.FormallyVerified, props.GetFormallyVerified()},
		{RequirementMemorySafe, required.MemorySafe, props.GetMemorySafeLanguage()},
		{RequirementConstantTime, required.ConstantTime, props.GetConstantTime()},
		{RequirementSideChannelHardened, required.SideChannelHardened, props.GetSideChannelHardened()},
		{RequirementNoKnownCVE, required.NoKnownCVE, props.GetNoKnownCve() && len(props.GetUnpatchedCves()) == 0},
		// Material generated or held here keeps an approved lineage only in a
		// validated module.
		{RequirementApprovedGeneration, required.ApprovedGeneration, fips.GetCertified()},
	}
	var unmet []Requirement
	for _, c := range checks {
		if c.required && !c.met {
			unmet = append(unmet, c.requirement)
		}
	}
	return unmet
}

// satisfies reports whether props meet every hard requirement in required.
func satisfies(props *types.ImplementationProperties, required core.ProviderRequirements) bool {
	return len(Unmet(props, required)) == 0
}

// Candidate is one provider judged against Requirements by Rank.
type Candidate struct {
	Backend Backend
	// Implementation is a copy of the properties the judgement used.
	Implementation *types.ImplementationProperties
	// Advertises reports whether the provider declares the requirements'
	// template. It is true for every provider when no template is given.
	Advertises bool
	// Unmet lists the hard requirements the provider misses.
	Unmet []Requirement
	// Preferred reports whether the provider has a property the
	// requirements prefer.
	Preferred bool
}

// Eligible reports whether c can serve the requirements it was judged
// against: it advertises the template and meets every hard requirement.
func (c Candidate) Eligible() bool {
	return c.Advertises && len(c.Unmet) == 0
}

// Rank judges each of backends against req and orders them the way Match
// chooses: eligible providers with a preferred property, then the other
// eligible providers, then the ineligible ones, each group in the order of
// backends. So the first candidate, if eligible, is the provider Match
// returns for req when req names none. req.ProviderName is not applied;
// nil backends are skipped.
func Rank(backends []Backend, req Requirements) []Candidate {
	var preferred, eligible, ineligible []Candidate
	for _, b := range backends {
		if b == nil {
			continue
		}
		props := ImplementationOf(b)
		c := Candidate{
			Backend:        b,
			Implementation: props,
			Advertises:     req.TemplateID == "" || advertisesTemplate(b, req.TemplateID),
			Unmet:          Unmet(props, req.Implementation),
			Preferred:      Preferred(props, req.Implementation),
		}
		switch {
		case c.Eligible() && c.Preferred:
			preferred = append(preferred, c)
		case c.Eligible():
			eligible = append(eligible, c)
		default:
			ineligible = append(ineligible, c)
		}
	}
	return append(append(preferred, eligible...), ineligible...)
}
