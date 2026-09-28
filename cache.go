// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

package spauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/excelano/atrest"
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

// sealName labels the cache to atrest, which binds it into the protection.
// Changing it makes every sealed cache unreadable, costing each user a
// sign-in.
const sealName = "excelano/sp-token"

// The atrest calls are variables so tests can stand in a sealing platform on
// hosts that have none.
var (
	sealAvailable = atrest.Available
	seal          = atrest.Seal
	open          = atrest.Open
)

// fileCache persists MSAL's token cache to a single file, sealed with the
// operating system's data protection where atrest has one and plaintext
// elsewhere. MSAL's format is opaque to us; we seal and shuttle bytes.
//
// A plaintext cache is read as it is and stored sealed straight away, so an
// upgrade costs nobody a sign-in. That covers a cache from a build before
// sealing, and one an older build wrote back after reading a sealed cache as
// empty, which it does because the envelope is a JSON object MSAL does not
// recognise. The write happens on read rather than at the next Export,
// because MSAL only exports when the cache changed, and a still-valid access
// token means it need not change for an hour.
//
// A sealed cache that cannot be opened here, such as one sealed by another
// user or on another machine, is treated as absent: the user signs in again
// and the next Export replaces it.
//
// legacy, when set, names the per-tool cache a consumer kept before the family
// shared one. The first time the shared file is found absent the legacy file
// is read and stored at the shared path, so a user who had signed in to any
// one tool is signed in to all of them without doing it again. Where the
// cache is sealed, the legacy file is deleted as soon as its contents are
// stored sealed, because leaving it would keep a plaintext copy of the same
// refresh token beside the sealed one; a binary old enough to read it asks
// for one sign-in. Where nothing seals, it is left for such a binary to use,
// and the consumer's uninstaller is what removes it.
type fileCache struct {
	path   string
	legacy string
}

func newFileCache(path, legacy string) *fileCache {
	return &fileCache{path: path, legacy: legacy}
}

func (c *fileCache) Replace(ctx context.Context, target cache.Unmarshaler, hints cache.ReplaceHints) error {
	data, err := c.read()
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, atrest.ErrCannotOpen) {
		return nil
	}
	if err != nil {
		return err
	}
	return target.Unmarshal(data)
}

// read returns the cache's plaintext, falling back to the legacy file when
// the shared one is absent, and stores it sealed when it was found unsealed
// or at the legacy path. A missing cache is reported as os.ErrNotExist.
func (c *fileCache) read() ([]byte, error) {
	stored, err := os.ReadFile(c.path)
	fromLegacy := false
	if errors.Is(err, os.ErrNotExist) && c.legacy != "" {
		stored, err = os.ReadFile(c.legacy)
		fromLegacy = true
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("reading token cache: %w", err)
	}
	plain, sealed, err := open(sealName, stored)
	if err != nil {
		return nil, err
	}
	if fromLegacy || (!sealed && sealAvailable()) {
		wroteSealed, err := c.write(plain)
		if err != nil {
			return nil, fmt.Errorf("storing token cache sealed: %w", err)
		}
		// Gated on what this write actually did, not on sealAvailable():
		// availability is a platform property, and a call can still fall
		// back to plaintext when nothing is reachable at the moment (no
		// session bus, a locked Keychain). Deleting the legacy file then
		// would trade a plaintext copy at the old path for one at the new
		// path, not remove a redundant one beside a sealed one.
		if wroteSealed {
			c.removeLegacy()
		}
	}
	return plain, nil
}

// removeLegacy deletes the legacy cache. Called only once the shared cache is
// confirmed sealed, so a failure here costs nothing but the uninstaller's
// purge step doing the removal instead.
func (c *fileCache) removeLegacy() {
	if c.legacy != "" {
		os.Remove(c.legacy)
	}
}

func (c *fileCache) Export(ctx context.Context, source cache.Marshaler, hints cache.ExportHints) error {
	data, err := source.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling token cache: %w", err)
	}
	_, err = c.write(data)
	return err
}

// write seals plain if it can and writes the result, reporting whether the
// stored bytes actually ended up sealed. Seal itself reports no such thing —
// it can fall back to returning its input unchanged — so that is read back
// here by comparing what went in against what came out.
func (c *fileCache) write(plain []byte) (sealed bool, err error) {
	stored, err := seal(sealName, plain)
	if err != nil {
		return false, err
	}
	if err := writeCacheFile(c.path, stored); err != nil {
		return false, err
	}
	return !bytes.Equal(stored, plain), nil
}

// writeCacheFile replaces path with data in a single rename. The cache is
// rewritten on every token refresh, and a plain whole-file write that is
// interrupted — by a crash, a signal, or a second process writing the same
// file — leaves a truncated JSON document that MSAL cannot read, which costs
// every tool sharing the file its session. Writing to a sibling temp file and
// renaming it over the old one means a reader sees either the previous cache
// or the new one. The temp file is created 0600, so no other account on the
// host can read it even before the rename. File modes stop other accounts and
// nothing more; keeping the contents useless once copied elsewhere is what
// sealing in write is for.
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
