package provider

import (
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// Channels lists, for one algorithm, what a provider can emit (or accept) on
// each transfer channel. An empty list closes the channel.
//
// Key material is opaque to the core, so only a provider can say whether
// its material can leave it or enter it. The core derives the migration
// strategies a source and target can carry out from what the source emits
// and the target accepts.
type Channels struct {
	// StoredPayload lists the private-key encodings in which the stored
	// material is self-contained bytes (not a handle) that another provider
	// may use, or that this provider can use when it came from another one.
	// It carries MIGRATION_STRATEGY_PROVIDER_SWITCH.
	StoredPayload []providerpb.PrivateKeyEncoding
	// Plaintext lists the encodings in which the provider exports (or
	// imports) a key. It carries MIGRATION_STRATEGY_EXTRACT_AND_IMPORT. No
	// provider implements export or import yet.
	Plaintext []providerpb.PrivateKeyEncoding
	// Wrapped lists the key-wrapping mechanisms with which the provider wraps
	// a key under a transport key (or unwraps one). It carries
	// MIGRATION_STRATEGY_WRAPPED_TRANSFER. No provider implements it yet.
	Wrapped []string
}

// Transfer is what a provider can emit and accept for one algorithm.
type Transfer struct {
	Emit   Channels
	Accept Channels
}

// TransferDescriber is an optional interface through which a provider
// advertises how key material for an algorithm may leave and enter it.
//
// A provider that does not implement it can take part in no transfer: keys
// can still be rekeyed onto or off it, which needs only key generation.
// Execution remains the final authority: a provider may still refuse a
// particular key.
type TransferDescriber interface {
	TransferCapabilities(algorithm *types.AlgorithmDetails) Transfer
}

// TransferOf returns what p emits and accepts for algorithm, as the core
// acts on it: nothing for a nil provider or one that does not implement
// TransferDescriber.
//
// It also never trusts an advertisement that contradicts the provider's
// FIPS 140 certification. At security levels 3 and 4 secret keys may enter
// and leave a module only encrypted, so a certified provider that reports
// such a level, or no level at all, has its stored-payload and plaintext
// channels closed: it keeps only wrapped transfer.
func TransferOf(p Backend, algorithm *types.AlgorithmDetails) Transfer {
	if p == nil {
		return Transfer{}
	}
	d, ok := p.(TransferDescriber)
	if !ok {
		return Transfer{}
	}
	t := d.TransferCapabilities(algorithm)
	if fips := implementationProperties(p).GetFips_140(); fips.GetCertified() && !permitsPlaintextKeys(fips.GetLevel()) {
		t.Emit.StoredPayload, t.Emit.Plaintext = nil, nil
		t.Accept.StoredPayload, t.Accept.Plaintext = nil, nil
	}
	return t
}

// permitsPlaintextKeys reports whether FIPS 140 permits electronic entry and
// output of plaintext secret keys at level.
func permitsPlaintextKeys(level types.Fips140Level) bool {
	return level == types.Fips140Level_FIPS_140_LEVEL_1 || level == types.Fips140Level_FIPS_140_LEVEL_2
}
