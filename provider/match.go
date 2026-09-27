package provider

import (
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
)

// implementationProperties returns p's ImplementationProperties, or nil if p
// does not implement ImplementationDescriber. Every accessor on the result is
// a nil-safe proto getter, so nil reports every property as unset.
func implementationProperties(p Backend) *types.ImplementationProperties {
	if id, ok := p.(ImplementationDescriber); ok {
		return id.ImplementationProperties()
	}
	return nil
}

// prefers reports whether props have a property required prefers. A
// preference ranks providers; it never excludes one.
func prefers(props *types.ImplementationProperties, required core.ProviderRequirements) bool {
	return required.PreferHardwareAccelerated && props.GetHardwareAccelerated()
}

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
		// Material generated or held here keeps an approved lineage only in a
		// validated module.
		{required.ApprovedGeneration, fips.GetCertified()},
	}
	for _, c := range checks {
		if c.required && !c.met {
			return false
		}
	}
	return true
}
