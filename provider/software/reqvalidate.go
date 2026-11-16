package software

import (
	"context"
	"sync"

	protovalidate "buf.build/go/protovalidate"
	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/protobuf/proto"
)

// requestValidator is built once and reused across requests — protovalidate.New
// compiles the CEL expressions behind every buf.validate constraint, so
// constructing it per-request would repeat that compilation on every Sign,
// Encrypt, etc. call. Construction depends only on the compiled-in proto
// types, never on request data, so a single shared instance is safe to reuse
// across concurrent requests and Provider instances.
var (
	requestValidatorOnce sync.Once
	requestValidator     protovalidate.Validator
	requestValidatorErr  error
)

func getRequestValidator() (protovalidate.Validator, error) {
	requestValidatorOnce.Do(func() {
		requestValidator, requestValidatorErr = protovalidate.New()
	})
	return requestValidator, requestValidatorErr
}

// validateRequest enforces the buf.validate CEL constraints declared on a
// providerpb request message (e.g. key_material/plaintext/signature
// bytes.min_len = 1, algorithm required = true).
//
// Nothing else in the live call path checks these: the orchestrator layer
// validates its own caller-facing request shape (internal/crypto.*Request)
// before ever constructing a providerpb request, so this is not primarily a
// malicious-caller defense — it is the same class of fix as
// template.LoadStandardCatalog's catalog-load-time validation, catching a
// providerpb request the orchestrator builds incorrectly (e.g. forgetting to
// set Algorithm) before it reaches provider dispatch logic that assumes a
// well-formed request.
func validateRequest(ctx context.Context, op errors.Op, req proto.Message) error {
	v, err := getRequestValidator()
	if err != nil {
		return errors.Wrap(ctx, op, err, errors.WithMessage("failed to construct protovalidate validator"))
	}
	if valErr := v.Validate(req); valErr != nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "request failed constraint validation: %v", valErr)
	}
	return nil
}
