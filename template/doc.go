// Package template contains the Template domain type and the Registry
// interface for algorithm template management.
//
// Domain type:
//   - Template wraps *api.TemplateInfo as a pragmatic trade-off, NOT the
//     same domain driven design pattern as key.Key / policy.Policy / provider.Instance.
//     Those types wrap storage protos (caas.storage.v1) at the Repository
//     boundary. Template wraps an API-surface proto (caas.crypto.v1)
//     because TemplateInfo has multiple deeply nested algorithm/scope types
//     that would be costly to replicate as Go structs for zero behavioral
//     benefit. Templates are immutable reference data loaded from
//     proto-JSON at startup, never persisted to durable storage.
//   - Proto() exposes the embedded TemplateInfo
//     (there is no storage proto for templates).
//   - Proto types do NOT escape beyond this package boundary: all other
//     packages interact with Template through domain-typed accessors
//     and core.ScopeSpec.
//
// Interface:
//   - Registry (domain service): Register, Get, List, and Select.
//     Select picks the best template for a given ScopeSpec, honouring
//     policy constraints and preferred properties.
//
// Proto -> Domain conversion:
//   - scopeSpecFromProto (unexported, vault_registry.go) converts
//     *api.ScopeSpecification => core.ScopeSpec for internal use by
//     Select, MatchesScope, and PrimaryScopeSpec. This is NOT an
//     Anti-Corruption Layer - it is a localised conversion that
//     interprets the template's own proto capabilities in domain terms.
//
// Domain-level scope APIs (for cross-package use):
//   - Template.PrimaryScopeSpec() (template.go) returns the core.ScopeSpec
//     derived from the template's first ScopedCapability.
//   - ParseScopeSpecification() (scope.go) converts proto-encoded []byte =>
//     core.ScopeSpec. This is the exported entry point for callers who
//     receive scope data as proto wire bytes (e.g. the service layer
//     deserializing core.KeyCreationSpec.Scope from a gRPC request).
//     It lives in this package, rather than in core, because the
//     conversion requires knowledge of the api.ScopeSpecification proto
//     oneof structure, which core must not import.

package template
