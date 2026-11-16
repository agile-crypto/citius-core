// Package storage defines the key/value storage port used by the
// vault-storage repositories, together with an in-memory implementation and
// a prefixed view.
//
// The interface mirrors the method set of Vault's logical.Storage (List, Get,
// Put, Delete) with its own Entry type, so this module carries no dependency
// on the Vault SDK. A Vault plugin adapts its request storage to this
// interface at the plugin boundary.
package storage

import (
	"context"
	"errors"
)

// ErrRelativePath is returned when a key or prefix contains "..".
var ErrRelativePath = errors.New("relative paths not supported")

// ErrNilEntry is returned when Put is called with a nil entry.
var ErrNilEntry = errors.New("cannot write nil entry")

// ErrStorageFull is returned when the storage has reached its capacitiy limit
var ErrStorageFull = errors.New("storage is full")

// ErrValueTooLarge is returned when the byte-value to store exceeds the limit
var ErrValueTooLarge = errors.New("byte-value is too large")

// Folder separator in the key-value store. Keys are hierarchical paths.
const FolderSeparator byte = '/'

// Entry is one item in a Storage.
type Entry struct {
	Key   string
	Value []byte
	// SealWrap asks a Vault backend to seal-wrap the value at rest. It is
	// passed through to Vault by the logical.Storage adapter. InmemStorage
	// stores and returns it but has no other use for it (unlike Vault's
	// logical.InmemStorage, which drops it).
	SealWrap bool
}

// Storage is a hierarchical key/value store, with "/" as the folder
// separator.
//
// Semantics (identical to Vault's logical.Storage):
//   - Get returns (nil, nil) when the key does not exist.
//   - Put creates or overwrites the entry.
//   - Delete of a missing key is not an error.
//   - List returns the keys starting with prefix, with prefix removed, in
//     lexicographic order. Only one level is returned: when the remainder
//     still contains "/", it is truncated just after the first "/" and
//     de-duplicated, so sub-folders appear as "name/".
type Storage interface {
	List(ctx context.Context, prefix string) ([]string, error)
	Get(ctx context.Context, key string) (*Entry, error)
	Put(ctx context.Context, entry *Entry) error
	Delete(ctx context.Context, key string) error
}
