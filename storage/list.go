package storage

import (
	"context"
	"strings"
)

// ListAll returns the names (storage paths relative to s, prefix included) of all
// entries under prefix, descending into folders. It returns names only, not entry
// contents. Storage.List only returns the immediate children of a prefix, with nested
// entries collapsed into a single "folder/" item.
func ListAll(ctx context.Context, s Storage, prefix string) ([]string, error) {
	children, err := s.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, child := range children {
		if strings.HasSuffix(child, string(FolderSeparator)) {
			nested, err := ListAll(ctx, s, prefix+child)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		out = append(out, prefix+child)
	}
	return out, nil
}

// FolderPrefix turns a folder path into a List prefix: trailing separators are
// stripped and exactly one is appended ("test", "test/" and "test//" all become
// "test/"). An empty path stays empty, meaning the root.
func FolderPrefix(folder string) string {
	folder = strings.TrimRight(folder, string(FolderSeparator))
	if folder == "" {
		return ""
	}
	return folder + string(FolderSeparator)
}
