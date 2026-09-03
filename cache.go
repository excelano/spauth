package spauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

// cacheFileName is the token cache's basename, the same in the shared
// location and in every legacy per-tool directory.
const cacheFileName = "sp-token.json"

// CachePath returns the token cache every tool on the registration shares:
// $XDG_CONFIG_HOME/excelano/sp-token.json, or ~/.config/excelano/sp-token.json.
// The directory is named for the registration rather than for either repo,
// because xql is not an xfiles tool and the cache belongs to neither.
func CachePath() string {
	return filepath.Join(configHome(), "excelano", cacheFileName)
}

func configHome() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".config"
	}
	return filepath.Join(home, ".config")
}

// fileCache persists MSAL's token cache to a single JSON file with restrictive
// permissions. The file format is opaque (managed by MSAL); we just shuttle
// bytes.
//
// legacy, when set, names the per-tool cache a consumer kept before the family
// shared one. The first time the shared file is found absent the legacy file
// is copied into place, so a user who had signed in to any one tool is signed
// in to all of them without doing it again. The legacy file is left where it
// was: an older binary can still use it, and the consumer's uninstaller is
// what removes it.
type fileCache struct {
	path   string
	legacy string
}

func newFileCache(path, legacy string) *fileCache {
	return &fileCache{path: path, legacy: legacy}
}

func (c *fileCache) Replace(ctx context.Context, target cache.Unmarshaler, hints cache.ReplaceHints) error {
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) && c.legacy != "" {
		data, err = c.migrate()
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading token cache: %w", err)
	}
	return target.Unmarshal(data)
}

// migrate copies the legacy cache to the shared path and returns its bytes.
// A missing legacy file is reported as os.ErrNotExist, the same answer an
// empty cache gives. The copy is written explicitly rather than left to the
// next Export, because MSAL only exports when the cache changed, and a still-
// valid access token means it need not change for an hour.
func (c *fileCache) migrate() ([]byte, error) {
	data, err := os.ReadFile(c.legacy)
	if err != nil {
		return nil, err
	}
	if err := writeCacheFile(c.path, data); err != nil {
		return nil, fmt.Errorf("migrating token cache from %s: %w", c.legacy, err)
	}
	return data, nil
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
