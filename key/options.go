package key

import (
	"sync"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLock            *sync.RWMutex
	withTemplateID      string
	withState           types.KeyLifecycleState
	withLabels          map[string]string
	withName            string
	withWrappingKeyID   string
	withPublicID        string
	withDigestAlgorithm string
	withCurrentVersion  uint32
	withInitialVersion  uint32
	withVetForWrite     bool
}

func getDefaultOptions() options {
	return options{
		withLock:            &sync.RWMutex{},
		withState:           types.KeyLifecycleState_KEY_LIFECYCLE_STATE_UNSPECIFIED,
		withLabels:          nil,
		withDigestAlgorithm: "HMAC-SHA256",
		withCurrentVersion:  0,
		withVetForWrite:     true, // default: vet for write
		withInitialVersion:  1,
	}
}

// WithLock provides an optional reference to a lock
func WithLock(lock *sync.RWMutex) Option {
	return func(o *options) {
		o.withLock = lock
	}
}

// WithTemplateID provides an optional template ID.
func WithTemplateID(templateID string) Option {
	return func(o *options) {
		o.withTemplateID = templateID
	}
}

// WithState provides an optional status.
func WithState(state types.KeyLifecycleState) Option {
	return func(o *options) {
		o.withState = state
	}
}

// WithLabels provides optional labels.
func WithLabels(labels map[string]string) Option {
	return func(o *options) {
		o.withLabels = labels
	}
}

// WithName provides an optional name for a key
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

func WithWrappingKeyID(wrappingKeyID string) Option {
	return func(o *options) {
		o.withWrappingKeyID = wrappingKeyID
	}
}

func WithKeyVersionID(versionID string) Option {
	return func(o *options) {
		o.withPublicID = versionID
	}
}

func WithCurrentVersion(version uint32) Option {
	return func(o *options) {
		o.withCurrentVersion = version
	}
}

func WithInitialVersion(version uint32) Option {
	return func(o *options) {
		o.withInitialVersion = version
	}
}

func WithVetForWrite(vet bool) Option {
	return func(o *options) {
		o.withVetForWrite = vet
	}
}

// VaultOptions is the subset of resolved options needed by Vault-backed
// adapters that live outside this package (see internal/key).
type VaultOptions struct {
	Lock           *sync.RWMutex
	VetForWrite    bool
	InitialVersion uint32
}

// GetVaultOptions resolves Option values for use by out-of-package Vault adapters.
func GetVaultOptions(opt ...Option) VaultOptions {
	opts := getOpts(opt...)
	return VaultOptions{
		Lock:           opts.withLock,
		VetForWrite:    opts.withVetForWrite,
		InitialVersion: opts.withInitialVersion,
	}
}
