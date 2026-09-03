package spauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

// writeCacheFile has to leave either the old cache or the new one on disk,
// never a partial file, and the file it leaves must be private. The rename
// itself cannot be interrupted from a test, so what is checked is the
// observable contract: content replaced in full, mode 0600, and no temp file
// left behind in the directory.
func TestWriteCacheFileReplacesAtomically(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")
	path := filepath.Join(dir, "sp-token.json")

	if err := writeCacheFile(path, []byte(`{"v":1}`)); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeCacheFile(path, []byte(`{"v":2}`)); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if string(got) != `{"v":2}` {
		t.Errorf("content = %q, want the second write", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("mode = %o, want 0600", perm)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("cache dir holds %v, want only sp-token.json (no temp file left behind)", names)
	}
}

// The first read against an absent shared cache adopts the legacy per-tool
// cache, so an upgrade does not cost the user a sign-in. Once the shared file
// exists the legacy one is ignored, and a consumer with no legacy file gets
// an empty cache rather than an error.
func TestReplaceMigratesLegacyCacheOnce(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "excelano", "sp-token.json")
	legacy := filepath.Join(dir, "xftp", "sp-token.json")
	if err := writeCacheFile(legacy, []byte(`{"from":"legacy"}`)); err != nil {
		t.Fatal(err)
	}

	got, err := readThrough(newFileCache(shared, legacy))
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if got != `{"from":"legacy"}` {
		t.Errorf("first read returned %q, want the legacy cache", got)
	}
	if data, err := os.ReadFile(shared); err != nil || string(data) != `{"from":"legacy"}` {
		t.Errorf("shared cache after migration = %q, %v; want a copy of the legacy cache", data, err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("legacy cache should be left in place: %v", err)
	}

	// The shared file now wins even if the legacy one changes underneath.
	if err := writeCacheFile(legacy, []byte(`{"from":"stale"}`)); err != nil {
		t.Fatal(err)
	}
	got, err = readThrough(newFileCache(shared, legacy))
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if got != `{"from":"legacy"}` {
		t.Errorf("second read returned %q, want the shared cache untouched", got)
	}

	got, err = readThrough(newFileCache(filepath.Join(dir, "none", "sp-token.json"), filepath.Join(dir, "missing", "sp-token.json")))
	if err != nil || got != "" {
		t.Errorf("read with neither file = %q, %v; want an empty cache and no error", got, err)
	}
}

// readThrough drives Replace the way MSAL does and hands back what the cache
// delivered, or "" when it delivered nothing.
func readThrough(c *fileCache) (string, error) {
	var sink captureUnmarshaler
	if err := c.Replace(context.Background(), &sink, cache.ReplaceHints{}); err != nil {
		return "", err
	}
	return sink.data, nil
}

type captureUnmarshaler struct{ data string }

func (u *captureUnmarshaler) Unmarshal(b []byte) error {
	u.data = string(b)
	return nil
}

// One path for the family, honouring XDG_CONFIG_HOME the way the xfiles tools
// already did for their own directories.
func TestCachePathHonoursXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	if got, want := CachePath(), filepath.Join("/tmp/xdg-test", "excelano", "sp-token.json"); got != want {
		t.Errorf("CachePath() = %q, want %q", got, want)
	}
}
