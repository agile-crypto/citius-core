// Package service defines application-layer use-case orchestrator interfaces.
//
// Application services coordinate multiple domain aggregates (key, policy, template,
// provider) to fulfil user-facing workflows like CreateKey, Sign, and Encrypt.
// They are distinct from domain services (policy.Engine, template.Registry,
// provider.Registry) which contain pure domain logic scoped to a single aggregate.
//
// Orchestrators live in subpackages, each next to its implementation:
//   - service/key.Orchestrator:    key lifecycle workflows (create, rotate, destroy, ...)
//   - service/crypto.Orchestrator: cryptographic operation workflows (sign, verify, encrypt, ...)

package service
