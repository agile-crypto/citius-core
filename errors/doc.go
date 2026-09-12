// Package errors provides the structured error type used throughout the core.
//
// Errors carry an operation chain (Op), a typed code (Code), and an optional
// wrapped cause, enabling root-cause attribution without stack traces.
//
// The Op chain reads like a call stack: "core.(Service).ForStorage: store.Insert: duplicate key"
// but is built explicitly by each function, not via runtime reflection.
//
// Error codes (Code) are domain-specific (e.g., CodeKeyNotFound, CodePolicyViolation)
// and map to gRPC status codes via GRPCCode() at the transport boundary.
//
// This package deliberately shadows the stdlib "errors" package within the module.
// For stdlib error functions, use the aliases in go_compat.go (stderrs.As, stderrs.Is).
package errors
