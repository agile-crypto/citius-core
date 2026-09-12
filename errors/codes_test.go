package errors_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/grpc/codes"
)

func TestIsKeyNotFound_true(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeKeyNotFound, "not found")
	if !errors.IsKeyNotFound(err) {
		t.Error("expected IsKeyNotFound=true")
	}
}

func TestIsKeyNotFound_false_wrongCode(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodePolicyViolation, "denied")
	if errors.IsKeyNotFound(err) {
		t.Error("expected IsKeyNotFound=false for CodePolicyViolation")
	}
}

func TestIsKeyNotFound_false_nonCoreError(t *testing.T) {
	err := stderrors.New("plain error")
	if errors.IsKeyNotFound(err) {
		t.Error("expected IsKeyNotFound=false for plain error")
	}
}

func TestIsPolicyViolation_true(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodePolicyViolation, "denied")
	if !errors.IsPolicyViolation(err) {
		t.Error("expected IsPolicyViolation=true")
	}
}

func TestIsNotFound_true_forKeyNotFound(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeKeyNotFound, "missing")
	if !errors.IsNotFound(err) {
		t.Error("CodeKeyNotFound should satisfy IsNotFound")
	}
}

func TestIsNotFound_true_forPolicyNotFound(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodePolicyNotFound, "missing")
	if !errors.IsNotFound(err) {
		t.Error("CodePolicyNotFound should satisfy IsNotFound")
	}
}

func TestGRPCCode_keyNotFound_mapsToNotFound(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeKeyNotFound, "x")
	if c := errors.GRPCCode(err); c != codes.NotFound {
		t.Errorf("GRPCCode: got %v want %v", c, codes.NotFound)
	}
}

func TestGRPCCode_policyViolation_mapsToPermissionDenied(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodePolicyViolation, "denied")
	if c := errors.GRPCCode(err); c != codes.PermissionDenied {
		t.Errorf("GRPCCode: got %v want %v", c, codes.PermissionDenied)
	}
}

func TestGRPCCode_invalidArgument_mapsToInvalidArgument(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeInvalidArgument, "bad param")
	if c := errors.GRPCCode(err); c != codes.InvalidArgument {
		t.Errorf("GRPCCode: got %v want %v", c, codes.InvalidArgument)
	}
}

func TestGRPCCode_notImplemented_mapsToUnimplemented(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeNotImplemented, "todo")
	if c := errors.GRPCCode(err); c != codes.Unimplemented {
		t.Errorf("GRPCCode: got %v want %v", c, codes.Unimplemented)
	}
}

func TestGRPCCode_nonCoreError_mapsToInternal(t *testing.T) {
	err := stderrors.New("raw error")
	if c := errors.GRPCCode(err); c != codes.Internal {
		t.Errorf("GRPCCode for raw error: got %v want %v", c, codes.Internal)
	}
}
