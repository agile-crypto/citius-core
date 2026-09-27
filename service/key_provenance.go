package service

import (
	"context"

	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/provider"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/agile-crypto/citius-core/template"
)

// approvedGeneration is the provider requirement a module must meet for
// material it generates or holds to keep an approved lineage.
var approvedGeneration = core.ProviderRequirements{ApprovedGeneration: true}

// releasesMaterial reports whether a provider advertising t lets material
// for the algorithm leave it in plaintext: as a stored payload or an export.
func releasesMaterial(t provider.Transfer) bool {
	return len(t.Emit.StoredPayload) > 0 || len(t.Emit.Plaintext) > 0
}

// generatedProvenance is the provenance of material prov has just generated
// for tmpl.
//
// TODO: extractability is inferred from prov's advertisement for the
// algorithm (D2). A provider that can generate some keys non-extractable
// needs to report it per key, in GenerateKeyResponse.
func generatedProvenance(prov provider.Backend, tmpl *template.Template) key.Provenance {
	return key.Provenance{
		Extractable:     releasesMaterial(provider.TransferOf(prov, tmpl.GetAlgorithm())),
		ApprovedLineage: provider.Meets(prov, approvedGeneration),
		Origin:          &storepb.KeyOrigin{Kind: storepb.KeyOriginKind_KEY_ORIGIN_KIND_GENERATED},
	}
}

// keptProvenance is the provenance of source's material once prov holds it
// for tmpl. Material that was not extractable, or had lost its approved
// lineage, never regains either. kind says whether the material stayed on
// its provider (RETAINED) or moved to another (TRANSFERRED), and channel how.
func keptProvenance(source *key.Version, prov provider.Backend, tmpl *template.Template,
	kind storepb.KeyOriginKind, channel storepb.KeyTransferChannel) key.Provenance {
	return key.Provenance{
		Extractable:     source.GetExtractable() && releasesMaterial(provider.TransferOf(prov, tmpl.GetAlgorithm())),
		ApprovedLineage: source.GetApprovedLineage() && provider.Meets(prov, approvedGeneration),
		Origin: &storepb.KeyOrigin{
			Kind:             kind,
			SourceVersion:    source.GetVersion(),
			SourceProviderId: source.GetProviderId(),
			Channel:          channel,
		},
	}
}

// requireKeptLineage refuses to keep source's material under a policy
// requiring approved generation (see core.ProviderRequirements) unless the
// material has an approved lineage. Matching the target provider already
// ensures it meets the requirement; this ensures the material does too,
// since kept material carries its history with it.
func requireKeptLineage(ctx context.Context, custody provider.Requirements, source *key.Version) error {
	const op = "service.requireKeptLineage"
	if custody.Implementation.ApprovedGeneration && !source.GetApprovedLineage() {
		return errors.New(ctx, op, errors.CodeFailedPrecondition,
			"the key's policy requires approved generation, and the material of version %d was not generated and kept only by approved modules; rekey instead",
			source.GetVersion())
	}
	return nil
}
