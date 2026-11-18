package storage

import (
	"context"
	"strings"
)

// View is a Storage that transparently prefixes every key of an underlying
// Storage. It behaves like Vault's logical.StorageView.
type View struct {
	storage Storage
	prefix  string
}

var _ Storage = (*View)(nil)

// NewView returns a View of s rooted at prefix.
func NewView(s Storage, prefix string) *View {
	return &View{storage: s, prefix: prefix}
}

// Prefix returns the view's prefix.
func (v *View) Prefix() string { return v.prefix }

// SubView returns a View nested under this one.
func (v *View) SubView(prefix string) *View {
	return NewView(v.storage, v.prefix+prefix)
}

// List implements Storage.
func (v *View) List(ctx context.Context, prefix string) ([]string, error) {
	if err := sanityCheck(prefix); err != nil {
		return nil, err
	}
	return v.storage.List(ctx, v.prefix+prefix)
}

// Get implements Storage.
func (v *View) Get(ctx context.Context, key string) (*Entry, error) {
	if err := sanityCheck(key); err != nil {
		return nil, err
	}
	entry, err := v.storage.Get(ctx, v.prefix+key)
	if err != nil || entry == nil {
		return nil, err
	}
	return &Entry{Key: strings.TrimPrefix(entry.Key, v.prefix), Value: entry.Value, SealWrap: entry.SealWrap}, nil
}

// Put implements Storage.
func (v *View) Put(ctx context.Context, entry *Entry) error {
	if entry == nil {
		return ErrNilEntry
	}
	if err := sanityCheck(entry.Key); err != nil {
		return err
	}
	return v.storage.Put(ctx, &Entry{Key: v.prefix + entry.Key, Value: entry.Value, SealWrap: entry.SealWrap})
}

// Delete implements Storage.
func (v *View) Delete(ctx context.Context, key string) error {
	if err := sanityCheck(key); err != nil {
		return err
	}
	return v.storage.Delete(ctx, v.prefix+key)
}

func sanityCheck(key string) error {
	if strings.Contains(key, "..") {
		return ErrRelativePath
	}
	return nil
}
