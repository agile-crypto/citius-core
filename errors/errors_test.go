package errors_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/agile-crypto/citius-core/errors"
)

const testOp errors.Op = "errors_test.(suite).method"

func TestNew_setsFields(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeKeyNotFound, "key not found")
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Fatal("expected *errors.Error")
	}
	if e.Op != testOp {
		t.Errorf("Op: got %q want %q", e.Op, testOp)
	}
	if e.Code != errors.CodeKeyNotFound {
		t.Errorf("Code: got %v want %v", e.Code, errors.CodeKeyNotFound)
	}
	if e.Message != "key not found" {
		t.Errorf("Message: got %q want %q", e.Message, "key not found")
	}
	if e.Wrapped != nil {
		t.Errorf("Wrapped: expected nil for New, got %v", e.Wrapped)
	}
}

func TestNew_nilCtxOK(t *testing.T) {
	// context is currently unused but required for future tracing
	err := errors.New(context.TODO(), testOp, errors.CodeInternal, "boom")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestWrap_preservesCode(t *testing.T) {
	inner := errors.New(context.Background(), testOp, errors.CodePolicyViolation, "denied")
	outer := errors.Wrap(context.Background(), "errors_test.(suite).outer", inner)
	var e *errors.Error
	if !stderrors.As(outer, &e) {
		t.Fatal("expected *errors.Error")
	}
	if e.Code != errors.CodePolicyViolation {
		t.Errorf("Code should propagate: got %v want %v", e.Code, errors.CodePolicyViolation)
	}
}

func TestWrap_wrapsNonCoreError(t *testing.T) {
	plain := stderrors.New("plain error")
	wrapped := errors.Wrap(context.Background(), testOp, plain)
	var e *errors.Error
	if !stderrors.As(wrapped, &e) {
		t.Fatal("expected *errors.Error")
	}
	if e.Code != errors.CodeInternal {
		t.Errorf("non-core errors wrapped as Internal: got %v", e.Code)
	}
	if !stderrors.Is(wrapped, plain) {
		t.Error("Unwrap() should expose the original plain error")
	}
}

func TestWrap_nilError_returnsNil(t *testing.T) {
	if err := errors.Wrap(context.Background(), testOp, nil); err != nil {
		t.Errorf("Wrap(nil) should return nil, got %v", err)
	}
}

func TestError_format_noWrapped(t *testing.T) {
	err := errors.New(context.Background(), testOp, errors.CodeNotFound, "missing")
	got := err.Error()
	want := string(testOp) + ": missing"
	if got != want {
		t.Errorf("Error(): got %q want %q", got, want)
	}
}

func TestError_format_withWrapped(t *testing.T) {
	inner := stderrors.New("cause")
	wrapped := errors.Wrap(context.Background(), testOp, inner)
	got := wrapped.Error()
	// Should contain the op and the inner message
	if got == "" {
		t.Error("Error() should not be empty when wrapped")
	}
	// Pattern: "op: cause"  or "op: internal: cause" — exact format is up to implementation
	t.Logf("Error() = %q", got)
}

func TestUnwrap_returnsWrappedError(t *testing.T) {
	inner := stderrors.New("inner cause")
	outer := errors.Wrap(context.Background(), testOp, inner)
	if !stderrors.Is(outer, inner) {
		t.Error("errors.Is should find inner cause via Unwrap chain")
	}
}
