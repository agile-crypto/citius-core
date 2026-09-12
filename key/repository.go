package key

import (
	"context"
)

// ReadOnlyRepository is the read-only persistence contract for the Key aggregate.
// It returns full domain objects (Key aggregate roots and Version entities)
// so that callers enforce invariants by invoking aggregate methods rather
// than inspecting flattened data.
//
// Any application service that only reads keys (e.g. CryptoOrchestrator)
// should depend on ReadOnlyRepository rather than the full Repository.
type ReadOnlyRepository interface {
	// GetKeyByID retrieves a key by public ID (metadata only, no material).
	GetKeyByID(ctx context.Context, id string) (*Key, error)

	// GetKeyByName retrieves a key by name (metadata only, no material).
	GetKeyByName(ctx context.Context, name string) (*Key, error)

	// ListKeys returns all stored keys as full domain objects.
	ListKeys(ctx context.Context) ([]*Key, error)

	// GetVersion retrieves a specific version of a key by version number.
	GetVersion(ctx context.Context, keyID string, versionNum uint32) (*Version, error)

	// GetCurrentVersion retrieves the current version of a key by public ID.
	GetCurrentVersion(ctx context.Context, keyID string) (*Version, error)
}

// WriteOnlyRepository is the mutating persistence contract for the Key aggregate.
//
// All write operations follow the aggregate-root pattern: the calling
// application service loads the Key via ReadOnlyRepository, enforces domain invariants
// on the aggregate, and then persists the result through WriteOnlyRepository.
type WriteOnlyRepository interface {
	// CreateKey atomically persists a key along with its initial current version
	// in storage. The version number of the initial version must match the
	// current version of the key.
	//
	// Returns CodeAlreadyExists if a key with the same PublicID already exists.
	//
	// Implementation contract:
	//   - In-memory store: single lock covers both key + version insert
	//   - SQL store: single transaction (INSERT key + INSERT version)
	//
	// This enforces the aggregate invariant: no Key can exist without at
	// least one Version.
	//
	// Allowed options:
	//   - withVetForWrite (optional): defaults to true
	CreateKey(ctx context.Context, key *Key, initialVersion *Version, opt ...Option) error

	// UpdateKey replaces the stored key metadata. The key must already exist.
	UpdateKey(ctx context.Context, k *Key, opt ...Option) error

	// AddVersion stores a key version. The parent key must already exist. By
	// default, the new version becomes the current version of the parent key.
	// The version number must be exactly 1 greater than the current version.
	//
	// Used by RotateKey to add subsequent versions to an existing key.
	// For the first version, use CreateKey instead.
	//
	// Implementation contract:
	//   - In-memory store: hold lock across read + write
	//   - SQL store: use a transaction (SELECT FOR UPDATE + INSERT + UPDATE)
	//
	// Allowed options:
	//   - withVetForWrite (optional): defaults to true
	AddVersion(ctx context.Context, version *Version, opt ...Option) error

	// DeleteKey removes a key AND all its associated versions (cascade).
	DeleteKey(ctx context.Context, id string) error
}

// Repository is the full persistence contract for the Key aggregate.
// It is the union of Reader and Writer; existing implementations and
// callers that need both read and write access depend on Repository unchanged.
//
// Key is the aggregate root; Version is an entity within that aggregate.
// The repository exposes aggregate-level operations — there is no way to
// create a Version without an associated Key (enforced by CreateKey).
type Repository interface {
	ReadOnlyRepository
	WriteOnlyRepository
}
