package crypto_test

import (
	"path/filepath"
	"runtime"
	"testing"

	core "github.com/agile-crypto/citius-core"
)

func defaultScopeSpec(t *testing.T) *core.ScopeSpecification {
	return scopeSpecWithScope(t, core.ScopeSignatureStandard)
}

func scopeSpecWithScope(t *testing.T, scope core.Scope) *core.ScopeSpecification {
	t.Helper()
	scopeSpec := &core.ScopeSpecification{
		Scope: scope,
	}
	return scopeSpec
}

// catalogPath returns the absolute path to the standard_algorithms.json catalog.
func catalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "data", "standard_algorithms.json")
}
