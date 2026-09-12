package policy

import "sync"

func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option configures optional parameters for Policy or VaultRepository construction.
type Option func(*options)

type options struct {
	withLock   *sync.RWMutex
	withLabels map[string]string
}

func getDefaultOptions() options {
	return options{
		withLock: &sync.RWMutex{},
	}
}

// WithLock provides an optional reference to a lock (used by VaultRepository).
func WithLock(lock *sync.RWMutex) Option {
	return func(o *options) {
		o.withLock = lock
	}
}

// WithLabels provides optional labels for a policy.
func WithLabels(labels map[string]string) Option {
	return func(o *options) {
		o.withLabels = labels
	}
}

// VaultOptions is the subset of resolved options needed by Vault-backed
// adapters that live outside this package (see internal/policy).
type VaultOptions struct {
	Lock *sync.RWMutex
}

// GetVaultOptions resolves Option values for use by out-of-package Vault adapters.
func GetVaultOptions(opt ...Option) VaultOptions {
	opts := getOpts(opt...)
	return VaultOptions{Lock: opts.withLock}
}
