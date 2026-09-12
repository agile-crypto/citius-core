// Package core is the shared vocabulary leaf for the cryptographic service.
//
// This package defines value types shared across all domain aggregates:
//   - Operation, WriteOp      - typed enums for crypto and storage operations
//   - KeyCreationSpec          - cross-aggregate DTO for CreateKey
//   - ImportKeySpec            - cross-aggregate DTO for ImportKey
//   - Primitive, Scope          - typed enums for cryptographic primitives and scope variants
//   - ScopeSpec                - (Primitive, Scope) pair for template selection
//   - KeyMaterial              - raw key bytes container
//   - VetForWriter             - pre-write validation interface
//   - NewID(prefix)            - prefixed ULID generator
//
// Import policy:
//   - internal/core/ MUST NOT import any domain package
//     (internal/key/, internal/policy/, internal/service/, etc.).
//   - internal/core/ MUST NOT import generated code from gen/.
//   - internal/core/ imports only internal/errors (absolute leaf).
//   - Every domain package imports core as its shared vocabulary.
//
// Application service interfaces (KeyOrchestrator, CryptoOrchestrator) live
// in internal/service/. The Service facade and factory types live in
// internal/app/.
package core
