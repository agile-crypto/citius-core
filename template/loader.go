package template

import (
	"context"
	"os"

	protovalidate "buf.build/go/protovalidate"
	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/protobuf/encoding/protojson"
)

// ParseStandardCatalog parses proto-JSON data into a StandardAlgorithmCatalog.
// Useful when the catalog JSON is embedded or loaded from a non-file source.
func ParseStandardCatalog(ctx context.Context, data []byte) (*api.StandardAlgorithmCatalog, error) {
	const op = "template.ParseStandardCatalog"
	catalog := &api.StandardAlgorithmCatalog{}
	if err := protojson.Unmarshal(data, catalog); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return catalog, nil
}

// LoadStandardCatalog reads a proto-JSON catalog file, parses it, validates
// every entry against its declared CEL/buf.validate constraints, and
// registers all templates into the given Registry.
//
// The catalog file must conform to the StandardAlgorithmCatalog proto-JSON
// format (see proto/standard_algorithms.json). Each entry in the catalog's
// templates map is validated, then wrapped via NewTemplate() and registered
// into r.
//
// Validation happens here, not in ParseStandardCatalog: nothing else in this
// server enforces these constraints at runtime - callers of a template's AlgorithmDetails (e.g. the
// software provider) treat it as pre-validated, trusted input. A malformed
// catalog entry (e.g. a typo like tag_size_bits: 127, not one of AesGcmParams'
// declared {96,104,112,120,128}) would otherwise load successfully and only
// surface as a defensive rejection deep inside provider code, or worse,
// silently misbehave if no such defensive check exists for that field. This
// is the single choke point every catalog entry passes through before
// becoming reachable, so it is the right place to fail fast and loud instead.
//
// An empty catalog (no templates) is not an error.
func LoadStandardCatalog(ctx context.Context, catalogPath string, r Registry) error {
	const op = "template.LoadStandardCatalog"
	data, err := os.ReadFile(catalogPath)
	if err != nil {
		return errors.Wrap(ctx, op, err, errors.WithMessage("failed to read catalog file %s", catalogPath))
	}

	catalog, err := ParseStandardCatalog(ctx, data)
	if err != nil {
		return errors.Wrap(ctx, op, err, errors.WithMessage("failed to parse catalog %s", catalogPath))
	}

	validator, err := protovalidate.New()
	if err != nil {
		return errors.Wrap(ctx, op, err, errors.WithMessage("failed to construct protovalidate validator"))
	}

	for templateID, info := range catalog.GetTemplates() {
		if valErr := validator.Validate(info); valErr != nil {
			return errors.Wrap(ctx, op, valErr, errors.WithMessage("template %s failed constraint validation", templateID))
		}
		tmpl := NewTemplate(info)
		if hashErr := ValidateAcceptedDigestHashes(ctx, tmpl); hashErr != nil {
			return errors.Wrap(ctx, op, hashErr, errors.WithMessage("template %s failed constraint validation", templateID))
		}
		if regErr := r.Register(ctx, tmpl); regErr != nil {
			return errors.Wrap(ctx, op, regErr, errors.WithMessage("failed to register template %s from catalog", tmpl.TemplateID()))
		}
	}
	return nil
}
