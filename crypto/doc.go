// Package crypto contains request/result value objects for cryptographic
// operations and the Session domain type for multi-part streaming.
//
// Value objects (types.go):
//   - SignRequest / SignResult
//   - VerifyRequest / VerifyResult
//   - EncryptRequest / EncryptResult
//   - DecryptRequest / DecryptResult
//   - WrapKeyRequest / WrapKeyResult
//   - UnwrapKeyRequest / UnwrapKeyResult
//   - DeriveKeyRequest
//   - MacRequest / MacResult / VerifyMacRequest / VerifyMacResult
//   - DigestRequest / DigestResult
//
// These VOs cross the boundary between service.CryptoOrchestrator (which
// accepts them) and provider.Backend (which works with provider-level VOs).
//
// Session (session.go) represents a multi-part streaming session (e.g.,
// streaming sign/verify/encrypt/decrypt). It embeds *storepb.StoredSession.
//
// SessionRepository (session_repository.go) defines the persistence
// contract for sessions; implementations live in internal/storage/.
package crypto
