package core

func getOpts(opt ...ScopeOption) scopeOptions {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// ScopeOption configures optional parameters for Policy or VaultRepository construction.
type ScopeOption func(*scopeOptions)

type scopeOptions struct {
	withSecurityProperties   *SecurityProperties
	withAdditionalProperties map[string]string
	// Signature-specific options
	withNonMalleable  bool
	withDeterministic bool

	// AEAD-specific options
	withNonceMisuseResistance bool

	// KeyAgreement-specific options
	withForwardSecrecy bool

	// KDF-specific options
	withMemoryHard bool // Indicates that the derived key should be memory-hard, which is a desirable property for password-based KDFs to resist brute-force attacks.
}

func getDefaultOptions() scopeOptions {
	return scopeOptions{
		withSecurityProperties:    nil,
		withAdditionalProperties:  nil,
		withNonMalleable:          false,
		withDeterministic:         false,
		withNonceMisuseResistance: false,
		withForwardSecrecy:        false,
		withMemoryHard:            false,
	}
}

// WithSecurityProperties sets the security properties the the request's key target
// must satisfy.
func WithSecurityProperties(s *SecurityProperties) ScopeOption {
	return func(o *scopeOptions) {
		o.withSecurityProperties = s
	}
}

// WithAdditionalProperties sets additional properties (eg. vendor-specific) to be sent with the request.
func WithAdditionalProperties(props map[string]string) ScopeOption {
	return func(o *scopeOptions) {
		o.withAdditionalProperties = props
	}
}

// WithNonMalleable sets the non-malleable option for signature keys, indicating that the signatures produced
// by the key should be non-malleable. This is relevant for certain signature schemes where malleability is a concern.
func WithNonMalleable() ScopeOption {
	return func(o *scopeOptions) {
		o.withNonMalleable = true
	}
}

// WithDeterministic sets the deterministic option for signature keys, indicating that the signatures produced
// by the key should be deterministic. This is relevant for certain signature schemes where deterministic signatures are desired.
func WithDeterministic() ScopeOption {
	return func(o *scopeOptions) {
		o.withDeterministic = true
	}
}

// WithNonceMisuseResistance sets the nonce-misuse resistance option for AEAD keys, indicating that the key should be resistant to nonce reuse attacks.
func WithNonceMisuseResistance() ScopeOption {
	return func(o *scopeOptions) {
		o.withNonceMisuseResistance = true
	}
}

// WithForwardSecrecy sets the forward secrecy option for key agreement keys, indicating that the key should provide forward secrecy.
func WithForwardSecrecy() ScopeOption {
	return func(o *scopeOptions) {
		o.withForwardSecrecy = true
	}
}

// WithMemoryHard sets the memory-hard option for KDF operations, indicating that the derived key should be memory-hard.
func WithMemoryHard() ScopeOption {
	return func(o *scopeOptions) {
		o.withMemoryHard = true
	}
}
