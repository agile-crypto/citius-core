package core

import (
	"crypto/rand"
	"sync"
	"time"

	ulid "github.com/oklog/ulid/v2"
)

// Prefix constants for all core entity types.
const (
	KeyPrefix              = "key_"
	VersionPrefix          = "ver_"
	PolicyPrefix           = "pol_"
	ProviderInstancePrefix = "prv_"
	SessionPrefix          = "ses_"
)

// idGen holds the mutex-protected monotonic entropy source for ULID generation.
// ulid.Monotonic is not goroutine-safe, so all access is serialized through mu.
var idGen struct {
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

func init() {
	idGen.entropy = ulid.Monotonic(rand.Reader, 0)
}

// NewID returns a new identifier in the format "<prefix><ULID>".
// The prefix is typically one of the Prefix constants above.
// If prefix is empty, only the ULID is returned.
// Safe for concurrent use by multiple goroutines.
func NewID(prefix string) string {
	idGen.mu.Lock()
	u := ulid.MustNew(ulid.Timestamp(time.Now()), idGen.entropy)
	idGen.mu.Unlock()
	if prefix == "" {
		return u.String()
	}
	return prefix + u.String()
}
