package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/agile-crypto/citius-core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func put(t *testing.T, s storage.Storage, keys ...string) {
	t.Helper()
	for _, k := range keys {
		require.NoError(t, s.Put(context.Background(), &storage.Entry{Key: k, Value: []byte(k)}))
	}
}

func TestInmem_zeroValue_usable(t *testing.T) {
	ctx := context.Background()
	var s storage.InmemStorage

	e, err := s.Get(ctx, "missing")
	require.NoError(t, err)
	assert.Nil(t, e)

	l, err := s.List(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, l)

	require.NoError(t, s.Delete(ctx, "missing"))
	put(t, &s, "a")
}

func TestInmem_getPutDelete(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage()

	put(t, s, "k")
	e, err := s.Get(ctx, "k")
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "k", e.Key)
	assert.Equal(t, []byte("k"), e.Value)

	require.NoError(t, s.Put(ctx, &storage.Entry{Key: "k", Value: []byte("v2")}))
	e, err = s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), e.Value)

	require.NoError(t, s.Delete(ctx, "k"))
	e, err = s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Nil(t, e)
}

func TestInmem_put_nilEntry_returnsError(t *testing.T) {
	err := storage.NewInmemStorage().Put(context.Background(), nil)
	assert.True(t, errors.Is(err, storage.ErrNilEntry))
}

func TestInmem_valuesAreCopied(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage()

	v := []byte("abc")
	require.NoError(t, s.Put(ctx, &storage.Entry{Key: "k", Value: v}))
	v[0] = 'X'

	e, err := s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("abc"), e.Value)

	e.Value[0] = 'Y'
	e, err = s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("abc"), e.Value)
}

func TestInmem_list(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage()
	put(t, s, "b", "a", "a/x", "a/y/z", "a0", "c/d", "c/e", "id1:1", "id1:2", "id10:1")

	tests := []struct {
		prefix string
		want   []string
	}{
		{"", []string{"a", "a/", "a0", "b", "c/", "id10:1", "id1:1", "id1:2"}},
		{"a/", []string{"x", "y/"}},
		{"a/y/", []string{"z"}},
		{"c/", []string{"d", "e"}},
		{"id1:", []string{"1", "2"}},
		{"none/", nil},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got, err := s.List(ctx, tt.prefix)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInmem_canceledContext_returnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := storage.NewInmemStorage().List(ctx, "")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestView_prefixesKeys(t *testing.T) {
	ctx := context.Background()
	base := storage.NewInmemStorage()
	v := storage.NewView(base, "key/")

	put(t, v, "k1", "k2")
	put(t, base, "other/k3")

	e, err := base.Get(ctx, "key/k1")
	require.NoError(t, err)
	require.NotNil(t, e)

	e, err = v.Get(ctx, "k1")
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "k1", e.Key)

	l, err := v.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"k1", "k2"}, l)

	l, err = v.SubView("k").List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"1", "2"}, l)

	require.NoError(t, v.Delete(ctx, "k1"))
	e, err = base.Get(ctx, "key/k1")
	require.NoError(t, err)
	assert.Nil(t, e)
}

func TestView_relativePath_rejected(t *testing.T) {
	ctx := context.Background()
	v := storage.NewView(storage.NewInmemStorage(), "key/")

	_, err := v.Get(ctx, "../x")
	assert.ErrorIs(t, err, storage.ErrRelativePath)
	_, err = v.List(ctx, "..")
	assert.ErrorIs(t, err, storage.ErrRelativePath)
	assert.ErrorIs(t, v.Put(ctx, &storage.Entry{Key: "a/../b"}), storage.ErrRelativePath)
	assert.ErrorIs(t, v.Delete(ctx, ".."), storage.ErrRelativePath)
	assert.ErrorIs(t, v.Put(ctx, nil), storage.ErrNilEntry)
}

func TestSealWrap_preservedThroughInmemAndView(t *testing.T) {
	ctx := context.Background()
	base := storage.NewInmemStorage()
	v := storage.NewView(base, "p/")

	require.NoError(t, v.Put(ctx, &storage.Entry{Key: "k", Value: []byte("v"), SealWrap: true}))

	e, err := base.Get(ctx, "p/k")
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.True(t, e.SealWrap)

	e, err = v.Get(ctx, "k")
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.True(t, e.SealWrap)

	require.NoError(t, v.Put(ctx, &storage.Entry{Key: "k", Value: []byte("v")}))
	e, err = v.Get(ctx, "k")
	require.NoError(t, err)
	assert.False(t, e.SealWrap)
}

func TestListAll_descendsIntoFolders(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage()
	put(t, s, "a", "b/c", "b/d/e", "b/d/f", "bx")

	tests := []struct {
		prefix string
		want   []string
	}{
		{"", []string{"a", "b/c", "b/d/e", "b/d/f", "bx"}},
		{"b/", []string{"b/c", "b/d/e", "b/d/f"}},
		{"b/d/", []string{"b/d/e", "b/d/f"}},
		{"none/", nil},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got, err := storage.ListAll(ctx, s, tt.prefix)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFolderPrefix(t *testing.T) {
	tests := map[string]string{
		"":       "",
		"/":      "",
		"test":   "test/",
		"test/":  "test/",
		"test//": "test/",
		"a/b":    "a/b/",
	}
	for in, want := range tests {
		assert.Equal(t, want, storage.FolderPrefix(in), "FolderPrefix(%q)", in)
	}
}

func TestNewInmemStorage_optionsPassedThrough(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage(storage.WithMaxValueSize(3))

	require.NoError(t, s.Put(ctx, &storage.Entry{Key: "ok", Value: []byte("abc")}))
	err := s.Put(ctx, &storage.Entry{Key: "big", Value: []byte("abcd")})
	assert.ErrorIs(t, err, storage.ErrValueTooLarge)
}

func TestInmem_put_valueSizeBound(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		max     int
		size    int
		wantErr error
	}{
		{"under limit", 4, 3, nil},
		{"at limit", 4, 4, nil},
		{"over limit", 4, 5, storage.ErrValueTooLarge},
		{"zero means unbounded", 0, 1 << 16, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := storage.NewInmemStorage(storage.WithMaxValueSize(tt.max))
			err := s.Put(ctx, &storage.Entry{Key: "k", Value: make([]byte, tt.size)})
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestInmem_put_valueTooLarge_notStored(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage(storage.WithMaxValueSize(2))

	require.ErrorIs(t, s.Put(ctx, &storage.Entry{Key: "k", Value: []byte("abc")}), storage.ErrValueTooLarge)
	e, err := s.Get(ctx, "k")
	require.NoError(t, err)
	assert.Nil(t, e)
}

func TestInmem_put_entryBound(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		max     int
		keys    int
		wantErr error
	}{
		{"under limit", 3, 2, nil},
		{"at limit", 2, 2, nil},
		{"over limit", 2, 3, storage.ErrStorageFull},
		{"zero means unbounded", 0, 50, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := storage.NewInmemStorage(storage.WithMaxEntries(tt.max))
			for i := 0; i < tt.keys-1; i++ {
				require.NoError(t, s.Put(ctx, &storage.Entry{Key: string(rune('a' + i)), Value: []byte("v")}))
			}
			err := s.Put(ctx, &storage.Entry{Key: "last", Value: []byte("v")})
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestInmem_put_entryBound_overwriteAtCapacity(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage(storage.WithMaxEntries(2))
	put(t, s, "a", "b")

	require.NoError(t, s.Put(ctx, &storage.Entry{Key: "a", Value: []byte("v2")}))
	e, err := s.Get(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), e.Value)
}

func TestInmem_put_entryRejected_notStored(t *testing.T) {
	ctx := context.Background()
	s := storage.NewInmemStorage(storage.WithMaxEntries(1))
	put(t, s, "a")

	require.ErrorIs(t, s.Put(ctx, &storage.Entry{Key: "b", Value: []byte("v")}), storage.ErrStorageFull)
	e, err := s.Get(ctx, "b")
	require.NoError(t, err)
	assert.Nil(t, e)
}
