package provider_test

import (
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
)

func TestImplementationOf_returnsACopy(t *testing.T) {
	held := &types.ImplementationProperties{ImplementationLanguage: "go"}
	p := &describingProvider{capableProvider: capableProvider{name: "p"}, props: held}

	got := provider.ImplementationOf(p)
	got.ImplementationLanguage = "changed"

	if held.GetImplementationLanguage() != "go" {
		t.Error("changing the result of ImplementationOf changed what the provider holds")
	}
	if provider.ImplementationOf(&capableProvider{name: "q"}) != nil {
		t.Error("a provider without ImplementationDescriber must report nil")
	}
	if provider.ImplementationOf(&describingProvider{capableProvider: capableProvider{name: "r"}}) != nil {
		t.Error("a describer reporting nil must report nil")
	}
}
