package service

import (
	"fmt"
	"slices"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"google.golang.org/protobuf/proto"

	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/template"
)

// transferFeasibility reports whether strategy can move version's material
// from source to target for tmpl, and if not, why: sourceFeasibility, then
// targetFeasibility.
//
// source is nil when the version's provider instance is no longer
// registered. Only what the providers advertise (see provider.TransferOf)
// and what the version records are checked: target resolution, policy and
// whether the strategy is implemented are checked elsewhere, and a provider
// may still refuse a particular key when the transfer runs.
//
// The rekey strategies generate new material on the target, which needs no
// transfer, so they are always feasible here.
func transferFeasibility(strategy messagespb.MigrationStrategy, source, target provider.Backend,
	version *key.Version, tmpl *template.Template) (bool, string) {
	if ok, reason := sourceFeasibility(strategy, source, version, tmpl); !ok {
		return false, reason
	}
	return targetFeasibility(strategy, source, target, version, tmpl)
}

// sourceFeasibility is the part of transferFeasibility that version and its
// source decide, whatever the target.
func sourceFeasibility(strategy messagespb.MigrationStrategy, source provider.Backend,
	version *key.Version, tmpl *template.Template) (bool, string) {
	switch strategy {
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_DESTROY:
		return true, ""
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER:
	default:
		return false, fmt.Sprintf("unknown migration strategy %s", strategy)
	}

	if source == nil {
		return false, fmt.Sprintf("source provider instance %q is not registered, so nothing vouches for its material",
			version.GetProviderId())
	}
	emit := provider.TransferOf(source, tmpl.GetAlgorithm()).Emit
	if strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER {
		if len(emit.Wrapped) == 0 {
			return false, fmt.Sprintf("provider instance %q wraps no key for template %q", source.Name(), tmpl.TemplateID())
		}
		return true, ""
	}

	// The two plaintext channels need material that may leave its provider.
	if !version.GetExtractable() {
		return false, fmt.Sprintf("version %d of the key is not extractable", version.GetVersion())
	}
	if strategy == messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT {
		if len(emit.Plaintext) == 0 {
			return false, fmt.Sprintf("provider instance %q exports no key for template %q", source.Name(), tmpl.TemplateID())
		}
		return true, ""
	}

	encoding, err := storedEncoding(version)
	switch {
	case err != nil:
		return false, fmt.Sprintf("the stored material of version %d of the key does not parse", version.GetVersion())
	case encoding == providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED:
		return false, fmt.Sprintf("version %d of the key does not record the encoding of its stored material", version.GetVersion())
	case !slices.Contains(emit.StoredPayload, encoding):
		return false, fmt.Sprintf("provider instance %q does not release %s stored material for template %q",
			source.Name(), encoding, tmpl.TemplateID())
	}
	return true, ""
}

// targetFeasibility is the part of transferFeasibility that depends on the
// target: whether it accepts what source emits. It assumes sourceFeasibility
// holds.
func targetFeasibility(strategy messagespb.MigrationStrategy, source, target provider.Backend,
	version *key.Version, tmpl *template.Template) (bool, string) {
	emit := provider.TransferOf(source, tmpl.GetAlgorithm()).Emit
	accept := provider.TransferOf(target, tmpl.GetAlgorithm()).Accept
	switch strategy {
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_DESTROY:
		return true, ""
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER:
		if !sharesAny(emit.Wrapped, accept.Wrapped) {
			return false, fmt.Sprintf("provider instances %q and %q share no key-wrapping mechanism for template %q",
				source.Name(), target.Name(), tmpl.TemplateID())
		}
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT:
		if !sharesAny(emit.Plaintext, accept.Plaintext) {
			return false, fmt.Sprintf("provider instances %q and %q share no plaintext key encoding for template %q",
				source.Name(), target.Name(), tmpl.TemplateID())
		}
	case messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH:
		if encoding, _ := storedEncoding(version); !slices.Contains(accept.StoredPayload, encoding) {
			return false, fmt.Sprintf("provider instance %q does not accept %s stored material for template %q",
				target.Name(), encoding, tmpl.TemplateID())
		}
	default:
		return false, fmt.Sprintf("unknown migration strategy %s", strategy)
	}
	return true, ""
}

// retainFeasibility reports whether prov accepts version's stored material
// for tmpl, and if not, why. TransformKey retaining material uses the
// stored-payload channel with prov as both source and target; the material
// never leaves prov, so only acceptance is checked.
func retainFeasibility(prov provider.Backend, version *key.Version, tmpl *template.Template) (bool, string) {
	encoding, err := storedEncoding(version)
	switch {
	case err != nil:
		return false, fmt.Sprintf("the stored material of version %d of the key does not parse", version.GetVersion())
	case encoding == providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED:
		return false, fmt.Sprintf("version %d of the key does not record the encoding of its stored material", version.GetVersion())
	case !slices.Contains(provider.TransferOf(prov, tmpl.GetAlgorithm()).Accept.StoredPayload, encoding):
		return false, fmt.Sprintf("provider instance %q does not accept %s stored material for template %q",
			prov.Name(), encoding, tmpl.TemplateID())
	}
	return true, ""
}

// storedEncoding returns the private-key encoding version's stored payload
// records, or an error when the payload does not parse.
func storedEncoding(version *key.Version) (providerpb.PrivateKeyEncoding, error) {
	var stored providerpb.GenerateKeyResponse
	if err := proto.Unmarshal(version.GetKeyMaterial(), &stored); err != nil {
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED, err
	}
	return stored.GetKeyMaterialEncoding(), nil
}

// sharesAny reports whether a and b have an element in common.
func sharesAny[T comparable](a, b []T) bool {
	return slices.ContainsFunc(a, func(x T) bool { return slices.Contains(b, x) })
}
