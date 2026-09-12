// Package service defines application-layer use-case orchestrator interfaces.
//
// Application services coordinate multiple domain aggregates (key, policy, template,
// provider) to fulfil user-facing workflows like CreateKey, Sign, and Encrypt.
// They are distinct from domain services (policy.Engine, template.Registry,
// provider.Registry) which contain pure domain logic scoped to a single aggregate.
//
// Interfaces defined here:
//   - KeyOrchestrator:    key lifecycle workflows (create, rotate, destroy, ...)
//   - CryptoOrchestrator: cryptographic operation workflows (sign, verify, encrypt, ...)
//
// Implementations will live alongside the interfaces in this package
// (e.g., key_orchestrator_impl.go, crypto_orchestrator_impl.go).

package service
