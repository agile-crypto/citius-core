package storage

import (
	"context"
	"slices"
	"strings"
	"sync"
)

// InmemStorage is an in-memory Storage backed by a flat map. The zero value
// is ready to use and it is safe for concurrent use.
//
// Values are copied on Put and on Get, so callers never share memory with the
// store (Vault's InmemStorage does not copy).
type InmemStorage struct {
	mu      sync.RWMutex
	entries map[string]Entry

	maxValueSize int // maximal size for an entry's value buffer, 0 means unbounded
	maxEntries   int // maximal number of keys, 0 means unbounded
}

var _ Storage = (*InmemStorage)(nil)

// NewInmemStorage returns an empty InmemStorage.
// Available options:
//   - WithMaxValueSize(int): set the maximal size for an entry's value, default: 0 (unbounded)
//   - WithMaxEntries(int): set the maximal number of entries, default: 0 (unbounded)
func NewInmemStorage(opt ...Option) *InmemStorage {
	opts := getOpts(opt...)
	return &InmemStorage{maxValueSize: opts.withMaxValueSize, maxEntries: opts.withMaxEntries}
}

// Get implements Storage.
func (s *InmemStorage) Get(ctx context.Context, key string) (*Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[key]
	if !ok {
		return nil, nil
	}
	e.Value = clone(e.Value)
	return &e, nil
}

// Put implements Storage.
func (s *InmemStorage) Put(ctx context.Context, entry *Entry) error {
	if entry == nil {
		return ErrNilEntry
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.entries == nil {
		s.entries = make(map[string]Entry)
	}
	s.entries[entry.Key] = Entry{Key: entry.Key, Value: clone(entry.Value), SealWrap: entry.SealWrap}
	return nil
}

// Delete implements Storage.
func (s *InmemStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	return nil
}

// List implements Storage.
func (s *InmemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	matches := make([]string, 0, len(s.entries))
	for k := range s.entries {
		if strings.HasPrefix(k, prefix) {
			matches = append(matches, k[len(prefix):])
		}
	}
	s.mu.RUnlock()

	// Sorting the full remainders before truncation yields the same order as
	// Vault's radix-tree walk.
	slices.Sort(matches)

	var out []string
	seen := make(map[string]struct{})
	for _, rest := range matches {
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			folder := rest[:i+1]
			if _, ok := seen[folder]; ok {
				continue
			}
			seen[folder] = struct{}{}
			rest = folder
		}
		out = append(out, rest)
	}
	return out, nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return slices.Clone(b)
}
