package errors

import "google.golang.org/grpc/codes"

// Code is a typed enumeration of core error codes.
// Mirrors gRPC status codes but is decoupled from the transport.
type Code int

const (
	CodeInternal           Code = iota // 0 — unexpected internal error
	CodeInvalidArgument                // 1 — caller provided invalid input
	CodeNotFound                       // 2 — generic not-found (use specific variants below)
	CodeKeyNotFound                    // 3
	CodePolicyNotFound                 // 4
	CodeTemplateNotFound               // 5
	CodeProviderNotFound               // 6
	CodePolicyViolation                // 7 — operation denied by policy
	CodeAlreadyExists                  // 8 — resource already exists
	CodeNotImplemented                 // 9 — stub / future feature
	CodeUnauthenticated                // 10 — missing / invalid credentials
	CodeUnavailable                    // 11 — provider temporarily unavailable
	CodeDataLoss                       // 12 — data corruption detected
	CodeFailedPrecondition             // 13 — lifecycle / state precondition not met
)

// GRPCCode maps an core Code to the nearest gRPC status code.
// For non-core errors (e.g. wrapped stdlib errors), returns codes.Internal.
func GRPCCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	var e *Error
	if !stderrsAs(err, &e) {
		return codes.Internal
	}
	switch e.Code {
	case CodeKeyNotFound, CodePolicyNotFound, CodeTemplateNotFound,
		CodeProviderNotFound, CodeNotFound:
		return codes.NotFound
	case CodePolicyViolation:
		return codes.PermissionDenied
	case CodeInvalidArgument:
		return codes.InvalidArgument
	case CodeAlreadyExists:
		return codes.AlreadyExists
	case CodeNotImplemented:
		return codes.Unimplemented
	case CodeUnauthenticated:
		return codes.Unauthenticated
	case CodeUnavailable:
		return codes.Unavailable
	case CodeDataLoss:
		return codes.DataLoss
	case CodeFailedPrecondition:
		return codes.FailedPrecondition
	default:
		return codes.Internal
	}
}

// IsKeyNotFound reports whether err was caused by a missing key.
func IsKeyNotFound(err error) bool { return hasCode(err, CodeKeyNotFound) }

// IsPolicyNotFound reports whether err was caused by a missing policy.
func IsPolicyNotFound(err error) bool { return hasCode(err, CodePolicyNotFound) }

// IsProviderNotFound reports whether err was caused by a missing provider.
func IsProviderNotFound(err error) bool { return hasCode(err, CodeProviderNotFound) }

// IsPolicyViolation reports whether err was caused by a policy denial.
func IsPolicyViolation(err error) bool { return hasCode(err, CodePolicyViolation) }

// IsNotFound reports whether err is any "not found" variant.
func IsNotFound(err error) bool {
	return hasCode(err, CodeNotFound, CodeKeyNotFound, CodePolicyNotFound,
		CodeTemplateNotFound, CodeProviderNotFound)
}

// IsNotImplemented reports whether the operation is a stub.
func IsNotImplemented(err error) bool { return hasCode(err, CodeNotImplemented) }

// IsAlreadyExists reports whether the resource already exists.
func IsAlreadyExists(err error) bool { return hasCode(err, CodeAlreadyExists) }

// IsInvalidArgument reports whether err was caused by invalid input.
func IsInvalidArgument(err error) bool { return hasCode(err, CodeInvalidArgument) }

// IsFailedPrecondition reports whether err was caused by a lifecycle/state precondition not being met.
func IsFailedPrecondition(err error) bool { return hasCode(err, CodeFailedPrecondition) }

// hasCode returns true if any error in the chain is an *Error with one of the given codes.
func hasCode(err error, codes ...Code) bool {
	var e *Error
	if !stderrsAs(err, &e) {
		return false
	}
	for _, c := range codes {
		if e.Code == c {
			return true
		}
	}
	return false
}
