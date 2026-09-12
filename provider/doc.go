// Package provider contains the provider bounded context: domain types,
// interfaces, and provider-level request/result value objects.
//
// Domain type:
//   - Instance embeds *storepb.StoredProviderInstance -- the persisted
//     record of a registered crypto backend.
//
// Interfaces:
//   - Backend (port): the Go interface every crypto backend must implement
//     (GenerateKey, Sign, Verify, etc.). Concrete providers (software,
//     loopback, remote) live in sub-packages.
//   - Registry (domain service): manages available Backend implementations,
//     algorithm index, and template-based provider matching.
//   - InstanceRepository: persistence contract for provider instance records;
//     implementations live in internal/storage/.
//   - InstanceManager (domain service): CRUD operations over persisted
//     provider instance records.
//
// Provider-level value objects (backend.go):
//   - GenerateKeyRequest / GenerateKeyResult
//   - SignRequest / SignResult
//   - VerifyRequest / VerifyResult
package provider
