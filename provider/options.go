package provider

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

type Option func(*options)

type options struct {
	withLock *sync.RWMutex
}

func getDefaultOptions() options {
	return options{
		withLock: &sync.RWMutex{},
	}
}

// WithLock provides an optional reference to a lock
func WithLock(lock *sync.RWMutex) Option {
	return func(o *options) {
		o.withLock = lock
	}
}

// VaultOptions is the subset of resolved options needed by Vault-backed
// adapters that live outside this package (see internal/provider).
type VaultOptions struct {
	Lock *sync.RWMutex
}

// GetVaultOptions resolves Option values for use by out-of-package Vault adapters.
func GetVaultOptions(opt ...Option) VaultOptions {
	opts := getOpts(opt...)
	return VaultOptions{Lock: opts.withLock}
}
