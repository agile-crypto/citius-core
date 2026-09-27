package provider

import (
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
)

// score computes a provider's match score against required security
// properties, in two distinct steps:
//
//  1. Hard filter (the returned bool): a required property the provider
//     cannot satisfy eliminates it outright. Today this checks only
//     required.FipsApproved — a provider whose ImplementationProperties (or
//     the lack of an ImplementationDescriber at all) cannot substantiate an
//     active FIPS module fails the filter. When required has no hard
//     requirement (nil, or FipsApproved false), every provider passes
//     regardless of what it can report.
//  2. Soft score (the returned int) ranks survivors against each other. The
//     weights are a judgement call, not a derived truth: FIPS certification
//     (+2) outweighs the rest because it is itself a hard-filterable
//     requirement elsewhere in this function and the strongest
//     externally-auditable signal available; constant-time (+1),
//     hardware-accelerated (+1), and memory-safe language (+1) are weighted
//     equally as independent, non-competing quality signals with no
//     comparable external certification behind them. A provider with no
//     ImplementationDescriber — props is then nil — or one that reports
//     nothing scores 0: neutral, not penalised, per
//     ImplementationDescriber's own doc comment.
//
// props is nil for a provider that does not implement
// ImplementationDescriber; every accessor below is a nil-safe proto getter,
// so a nil props reports every property as unset rather than panicking.
// required is nil when the caller has no security requirement at all.
//
// This is a pure function — no registry, no provider — specifically so it
// stays table-testable on its own. Ranking a template's full candidate set
// and breaking ties by registration order is a caller's job, not this
// function's.
func score(props *types.ImplementationProperties, required *core.SecurityProperties) (int, bool) {
	if required != nil && required.FipsApproved && !props.GetFips_140().GetCertified() {
		return 0, false
	}

	s := 0
	if props.GetFips_140().GetCertified() {
		s += 2
	}
	if props.GetConstantTime() {
		s++
	}
	if props.GetHardwareAccelerated() {
		s++
	}
	if props.GetMemorySafeLanguage() {
		s++
	}
	return s, true
}

// scoreProvider extracts p's ImplementationProperties — nil if p does not
// implement ImplementationDescriber — and scores them against req: the
// scope's security properties, then req.Implementation's hard requirements
// (see satisfies) and its hardware-acceleration preference.
// The one place Registry.Match needs to know about ImplementationDescriber
// at all; score itself stays independent of Backend.
func scoreProvider(p Backend, req Requirements) (int, bool) {
	var props *types.ImplementationProperties
	if id, ok := p.(ImplementationDescriber); ok {
		props = id.ImplementationProperties()
	}
	s, ok := score(props, req.Security)
	if !ok || !satisfies(props, req.Implementation) {
		return 0, false
	}
	if req.Implementation.PreferHardwareAccelerated && props.GetHardwareAccelerated() {
		s += preferenceWeight
	}
	return s, true
}

// preferenceWeight outranks every soft signal of score combined (at most 5),
// so a provider with a preferred property always ranks above one without.
const preferenceWeight = 6

// satisfies reports whether props meet every hard requirement in required.
// A property the provider does not report, including every property of a
// provider with nil props, counts as not met: requirements fail closed.
func satisfies(props *types.ImplementationProperties, required core.ProviderRequirements) bool {
	fips := props.GetFips_140()
	checks := []struct{ required, met bool }{
		{required.FIPS140Certified, fips.GetCertified()},
		{required.MinFIPS140Level > 0, fips.GetCertified() && int64(fips.GetLevel()) >= int64(required.MinFIPS140Level)},
		{required.CommonCriteriaCertified, props.GetCommonCriteriaCertified()},
		{required.FormallyVerified, props.GetFormallyVerified()},
		{required.MemorySafe, props.GetMemorySafeLanguage()},
		{required.ConstantTime, props.GetConstantTime()},
		{required.SideChannelHardened, props.GetSideChannelHardened()},
		{required.NoKnownCVE, props.GetNoKnownCve() && len(props.GetUnpatchedCves()) == 0},
	}
	for _, c := range checks {
		if c.required && !c.met {
			return false
		}
	}
	return true
}
