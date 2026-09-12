package service

import (
	"context"

	metapb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	"github.com/agile-crypto/citius-core/errors"
)

// requireProviderOutput enforces the ProviderOutput contract from
// metadata.proto: every successful provider response MUST set
// algorithm_output explicitly.  An unset oneof means the provider forgot to
// set it — a provider-contract violation, not a caller error — so the core
// rejects the response rather than passing a malformed OperationMetadata
// downstream.
//
// This distinguishes "nothing to report" (NoOutput / NoOutputUnencoded,
// always present) from "provider bug" (algorithm_output left nil).
func requireProviderOutput(ctx context.Context, op errors.Op, out *metapb.ProviderOutput) error {
	if out == nil || out.GetAlgorithmOutput() == nil {
		return errors.New(ctx, op, errors.CodeInternal,
			"provider returned no algorithm_output — provider contract violation")
	}
	return nil
}
