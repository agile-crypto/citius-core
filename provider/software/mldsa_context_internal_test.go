// This file is in package software rather than software_test — the rest of
// this package's tests exercise the exported Provider surface, but the check
// under test here is unreachable through it: Provider.Sign runs the request's
// declared constraints first, and those already reject an over-long domain
// context. Calling signMLDSA/verifyMLDSA directly is the only way to cover
// the case the check actually exists for, which is a caller that does not go
// through Provider.Sign.
package software

import (
	"bytes"
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// TestSignVerifyMLDSA_contextOverMaxLength_errorsRatherThanPanics pins the
// reason checkMLDSAContextLength exists.
//
// CIRCL's two signing paths report an over-long context differently: the
// package-level SignTo returns an error, but sign.Scheme.Sign — the
// deterministic path — panics. A panic here would take down the process on
// what is only a malformed request, so the length is checked before either
// path runs. This became reachable when signing started carrying a
// caller-supplied context at all; while the context was hardcoded nil, no
// input could trigger it.
func TestSignVerifyMLDSA_contextOverMaxLength_errorsRatherThanPanics(t *testing.T) {
	ctx := context.Background()
	pubBytes, privBytes, err := generateMLDSAKey(ctx, types.MlDsaParameterSet_ML_DSA_65)
	if err != nil {
		t.Fatalf("generateMLDSAKey: %v", err)
	}
	overLong := bytes.Repeat([]byte("c"), mldsaMaxContextLen+1)

	for _, deterministic := range []bool{false, true} {
		name := "sign/randomized"
		if deterministic {
			name = "sign/deterministic"
		}
		t.Run(name, func(t *testing.T) {
			// A panic here fails the test rather than being recovered: the
			// point of the check is that this input never reaches CIRCL.
			_, signErr := signMLDSA(ctx, privBytes, []byte("payload"), overLong,
				providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
				types.MlDsaParameterSet_ML_DSA_65, deterministic)
			if signErr == nil {
				t.Fatal("expected an over-long context to be rejected")
			}
			if !errors.IsInvalidArgument(signErr) {
				t.Errorf("expected CodeInvalidArgument, got: %v", signErr)
			}
		})
	}

	t.Run("verify", func(t *testing.T) {
		_, verifyErr := verifyMLDSA(ctx, pubBytes, []byte("payload"), make([]byte, 3309),
			overLong, types.MlDsaParameterSet_ML_DSA_65)
		if verifyErr == nil {
			t.Fatal("expected an over-long context to be rejected")
		}
		if !errors.IsInvalidArgument(verifyErr) {
			t.Errorf("expected CodeInvalidArgument, got: %v", verifyErr)
		}
	})
}
