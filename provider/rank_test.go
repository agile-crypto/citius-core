package provider_test

import (
	"context"
	"slices"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/provider"
	"google.golang.org/protobuf/proto"
)

func TestUnmet_listsEachMissedRequirementInOrder(t *testing.T) {
	props := &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)}
	required := core.ProviderRequirements{
		FIPS140Certified:          true,
		MemorySafe:                true,
		NoKnownCVE:                true,
		PreferHardwareAccelerated: true,
	}
	got := provider.Unmet(props, required)
	want := []provider.Requirement{provider.RequirementFIPS140Certified, provider.RequirementNoKnownCVE}
	if !slices.Equal(got, want) {
		t.Fatalf("Unmet = %v, want %v", got, want)
	}
	if got[0].String() != "fips_140_certified" || got[1].String() != "no_known_cve" {
		t.Errorf("names = %v, want the proto field names", got)
	}
	if len(provider.Unmet(nil, core.ProviderRequirements{PreferHardwareAccelerated: true})) != 0 {
		t.Error("a preference must never be unmet")
	}
}

func TestRequirement_String_namesEveryRequirement(t *testing.T) {
	seen := map[string]bool{}
	for r := provider.RequirementFIPS140Certified; r <= provider.RequirementApprovedGeneration; r++ {
		name := r.String()
		if name == "unknown" || seen[name] {
			t.Errorf("requirement %d has name %q, want a distinct name", r, name)
		}
		seen[name] = true
	}
	if provider.Requirement(0).String() != "unknown" {
		t.Error("the zero requirement must be unknown")
	}
}

func TestRank_ordersAsMatchChooses(t *testing.T) {
	const tmpl = "aes-256-gcm"
	accelerated := &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true), HardwareAccelerated: proto.Bool(true)}
	safe := &types.ImplementationProperties{MemorySafeLanguage: proto.Bool(true)}
	backend := func(name string, props *types.ImplementationProperties, algs ...string) provider.Backend {
		return &describingProvider{capableProvider: capableProvider{name: name, algorithms: algs}, props: props}
	}
	backends := []provider.Backend{
		backend("unsafe", &types.ImplementationProperties{}, tmpl),
		backend("safe", safe, tmpl),
		nil,
		backend("other-template", accelerated, "ml-dsa-65"),
		backend("fast", accelerated, tmpl),
	}
	req := provider.Requirements{
		TemplateID:     tmpl,
		Implementation: core.ProviderRequirements{MemorySafe: true, PreferHardwareAccelerated: true},
	}

	ranked := provider.Rank(backends, req)

	var names []string
	for _, c := range ranked {
		names = append(names, c.Backend.Name())
	}
	if want := []string{"fast", "safe", "unsafe", "other-template"}; !slices.Equal(names, want) {
		t.Fatalf("order = %v, want %v", names, want)
	}
	if !ranked[0].Eligible() || !ranked[0].Preferred || !ranked[1].Eligible() || ranked[1].Preferred {
		t.Errorf("eligible candidates judged wrongly: %+v %+v", ranked[0], ranked[1])
	}
	if ranked[2].Eligible() || !slices.Equal(ranked[2].Unmet, []provider.Requirement{provider.RequirementMemorySafe}) {
		t.Errorf("unsafe: Unmet = %v, want memory_safe", ranked[2].Unmet)
	}
	if ranked[3].Advertises || ranked[3].Eligible() {
		t.Error("a provider not advertising the template must be ineligible")
	}

	r := provider.NewRegistry()
	for _, b := range backends {
		if b != nil {
			if err := r.Register(context.Background(), b); err != nil {
				t.Fatal(err)
			}
		}
	}
	chosen, err := r.Match(context.Background(), req)
	if err != nil || chosen.Name() != ranked[0].Backend.Name() {
		t.Errorf("Match = %v, %v; want Rank's first candidate %q", chosen, err, ranked[0].Backend.Name())
	}
}

func TestRank_noTemplateAdvertisesEveryProvider(t *testing.T) {
	ranked := provider.Rank([]provider.Backend{&capableProvider{name: "p"}}, provider.Requirements{})
	if len(ranked) != 1 || !ranked[0].Eligible() {
		t.Errorf("Rank with no template = %+v, want one eligible candidate", ranked)
	}
}
