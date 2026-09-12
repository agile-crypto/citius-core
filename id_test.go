package core_test

import (
	"strings"
	"sync"
	"testing"

	core "github.com/agile-crypto/citius-core"
)

func TestNewID_hasPrefix(t *testing.T) {
	got := core.NewID(core.KeyPrefix)
	if !strings.HasPrefix(got, "key_") {
		t.Errorf("NewID(\"key\") = %q; want prefix \"key_\"", got)
	}
}

func TestNewID_emptyPrefix_stillValid(t *testing.T) {
	got := core.NewID("")
	if got == "" {
		t.Error("NewID(\"\") must not return empty string")
	}
	// Without prefix, should be raw 26-char ULID
	if len(got) != 26 {
		t.Errorf("NewID(\"\") len = %d; want 26 (got %q)", len(got), got)
	}
}

func TestNewID_unique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		v := core.NewID("key")
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate ID after %d iterations: %s", i, v)
		}
		seen[v] = struct{}{}
	}
}

func TestNewID_ulidSuffixLength(t *testing.T) {
	// ULID is 26 characters; with "key_" prefix total = 30
	got := core.NewID(core.KeyPrefix)
	const wantLen = len(core.KeyPrefix) + 26
	if len(got) != wantLen {
		t.Errorf("len(NewID(%q)) = %d; want %d (got %q)", core.KeyPrefix, len(got), wantLen, got)
	}
}

func TestNewID_differentPrefixesAreDistinct(t *testing.T) {
	key := core.NewID(core.KeyPrefix)
	pol := core.NewID(core.PolicyPrefix)
	if strings.HasPrefix(pol, core.KeyPrefix) {
		t.Errorf("pol ID should not have key_ prefix: %q", pol)
	}
	_ = key
}

func TestNewID_concurrentSafety(t *testing.T) {
	// Verify that concurrent calls don't panic or produce duplicates.
	// Run with -race to detect data races.
	const goroutines = 50
	const idsPerGoroutine = 100

	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*idsPerGoroutine)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			local := make([]string, 0, idsPerGoroutine)
			for i := 0; i < idsPerGoroutine; i++ {
				local = append(local, core.NewID(core.KeyPrefix))
			}
			mu.Lock()
			for _, id := range local {
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate ID in concurrent test: %s", id)
				}
				seen[id] = struct{}{}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
}

func TestKeyPrefix(t *testing.T) {
	if core.KeyPrefix != "key_" {
		t.Errorf("KeyPrefix = %q; want \"key_\"", core.KeyPrefix)
	}
}

func TestVersionPrefix(t *testing.T) {
	if core.VersionPrefix != "ver_" {
		t.Errorf("VersionPrefix = %q; want \"ver_\"", core.VersionPrefix)
	}
}

func TestPolicyPrefix(t *testing.T) {
	if core.PolicyPrefix != "pol_" {
		t.Errorf("PolicyPrefix = %q; want \"pol_\"", core.PolicyPrefix)
	}
}

func TestProviderInstancePrefix(t *testing.T) {
	if core.ProviderInstancePrefix != "prv_" {
		t.Errorf("ProviderInstancePrefix = %q; want \"prv_\"", core.ProviderInstancePrefix)
	}
}

func TestSessionPrefix(t *testing.T) {
	if core.SessionPrefix != "ses_" {
		t.Errorf("SessionPrefix = %q; want \"ses_\"", core.SessionPrefix)
	}
}
