package spauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

// fileCache persists MSAL's token cache to a single JSON file with restrictive
// permissions. The file format is opaque (managed by MSAL); we just shuttle
// bytes.
type fileCache struct {
	path string
}

func newFileCache(path string) *fileCache {
	return &fileCache{path: path}
}

func (c *fileCache) Replace(ctx context.Context, target cache.Unmarshaler, hints cache.ReplaceHints) error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading token cache: %w", err)
	}
	return target.Unmarshal(data)
}

func (c *fileCache) Export(ctx context.Context, source cache.Marshaler, hints cache.ExportHints) error {
	data, err := source.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling token cache: %w", err)
	}
	return writeCacheFile(c.path, data)
}

// writeCacheFile replaces path with data in a single rename. The cache is
// rewritten on every token refresh, and a plain whole-file write that is
// interrupted — by a crash, a signal, or a second process writing the same
// file — leaves a truncated JSON document that MSAL cannot read, which costs
// every tool sharing the file its session. Writing to a sibling temp file and
// renaming it over the old one means a reader sees either the previous cache
// or the new one. The temp file is created 0600, so the refresh token is never
// readable by others even for the instant before the rename.
func writeCacheFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing token cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("syncing token cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing token cache: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replacing token cache: %w", err)
	}
	return nil
}
