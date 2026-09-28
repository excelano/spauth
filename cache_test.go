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
	"runtime"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/excelano/atrest"
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
	// Windows has no Unix mode bits, and Go reports any writable file there
	// as 0666; the profile's ACL keeps other accounts out instead.
	if perm := info.Mode().Perm(); perm != 0600 && runtime.GOOS != "windows" {
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
	withoutSealing(t)
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

// withFakeSealing stands in a sealing platform, so the paths that only run on
// Windows run here. Sealed bytes carry a "sealed:" prefix; bytes beginning
// "foreign:" are an envelope this host cannot open.
func withFakeSealing(t *testing.T) {
	t.Helper()
	savedAvailable, savedSeal, savedOpen := sealAvailable, seal, open
	sealAvailable = func() bool { return true }
	seal = func(name string, data []byte) ([]byte, error) {
		return append([]byte("sealed:"), data...), nil
	}
	open = func(name string, data []byte) ([]byte, bool, error) {
		if rest, ok := bytes.CutPrefix(data, []byte("sealed:")); ok {
			return rest, true, nil
		}
		if bytes.HasPrefix(data, []byte("foreign:")) {
			return nil, false, fmt.Errorf("%w: test", atrest.ErrCannotOpen)
		}
		return data, false, nil
	}
	t.Cleanup(func() { sealAvailable, seal, open = savedAvailable, savedSeal, savedOpen })
}

func TestExportSealsAndReplaceOpens(t *testing.T) {
	withFakeSealing(t)
	path := filepath.Join(t.TempDir(), "sp-token.json")
	c := newFileCache(path, "")
	if err := c.Export(context.Background(), marshaler(`{"rt":1}`), cache.ExportHints{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != `sealed:{"rt":1}` {
		t.Errorf("stored = %q; want it sealed", data)
	}
	if got, err := readThrough(c); err != nil || got != `{"rt":1}` {
		t.Errorf("read = %q, %v; want the plaintext", got, err)
	}
}

// A plaintext cache, from a build before sealing or written back by one, is
// used as it is and stored sealed on the same read, so nobody signs in again
// and the plaintext does not wait on MSAL's next Export.
func TestReplaceSealsPlaintextCache(t *testing.T) {
	withFakeSealing(t)
	path := filepath.Join(t.TempDir(), "sp-token.json")
	if err := writeCacheFile(path, []byte(`{"rt":1}`)); err != nil {
		t.Fatal(err)
	}
	if got, err := readThrough(newFileCache(path, "")); err != nil || got != `{"rt":1}` {
		t.Errorf("read = %q, %v; want the plaintext cache", got, err)
	}
	if data, _ := os.ReadFile(path); string(data) != `sealed:{"rt":1}` {
		t.Errorf("stored after read = %q; want it sealed", data)
	}
}

func TestReplaceSealsMigratedLegacyCache(t *testing.T) {
	withFakeSealing(t)
	dir := t.TempDir()
	shared := filepath.Join(dir, "excelano", "sp-token.json")
	legacy := filepath.Join(dir, "xftp", "sp-token.json")
	if err := writeCacheFile(legacy, []byte(`{"from":"legacy"}`)); err != nil {
		t.Fatal(err)
	}
	if got, err := readThrough(newFileCache(shared, legacy)); err != nil || got != `{"from":"legacy"}` {
		t.Errorf("read = %q, %v; want the legacy cache", got, err)
	}
	if data, _ := os.ReadFile(shared); string(data) != `sealed:{"from":"legacy"}` {
		t.Errorf("shared cache = %q; want the legacy cache, sealed", data)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy cache still present after a sealed migration: %v", err)
	}
}

// A user whose shared cache was copied from the legacy one before sealing
// existed still has the plaintext legacy file. Sealing the shared cache is
// what removes it.
// withAvailableButUnreachableSealing stands in a platform that has a
// facility (Available() true, the Linux/macOS case) but cannot reach it on
// this call — no session bus, a locked Keychain — so Seal falls back to
// plaintext exactly like atrest itself does in that situation.
func withAvailableButUnreachableSealing(t *testing.T) {
	t.Helper()
	savedAvailable, savedSeal, savedOpen := sealAvailable, seal, open
	sealAvailable = func() bool { return true }
	seal = func(name string, data []byte) ([]byte, error) { return data, nil }
	open = func(name string, data []byte) ([]byte, bool, error) { return data, false, nil }
	t.Cleanup(func() { sealAvailable, seal, open = savedAvailable, savedSeal, savedOpen })
}

// A platform can report sealing available while this particular call cannot
// reach a key store — no session bus, a locked Keychain — the gap that opened
// once Linux and macOS could fall back mid-call the way Windows never did.
// Migrating a legacy cache in that state must not delete it: the shared copy
// just written is plaintext too, so deleting the legacy file would relocate
// the same exposure rather than remove a redundant one beside a sealed cache.
func TestReplaceKeepsLegacyWhenSealingUnavailableThisCall(t *testing.T) {
	withAvailableButUnreachableSealing(t)
	dir := t.TempDir()
	shared := filepath.Join(dir, "excelano", "sp-token.json")
	legacy := filepath.Join(dir, "xftp", "sp-token.json")
	if err := writeCacheFile(legacy, []byte(`{"from":"legacy"}`)); err != nil {
		t.Fatal(err)
	}
	if got, err := readThrough(newFileCache(shared, legacy)); err != nil || got != `{"from":"legacy"}` {
		t.Errorf("read = %q, %v; want the legacy cache", got, err)
	}
	if data, _ := os.ReadFile(shared); string(data) != `{"from":"legacy"}` {
		t.Errorf("shared cache = %q; want the legacy cache, plaintext", data)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("legacy cache should be left in place, since the shared copy is not sealed: %v", err)
	}
}

func TestReplaceRemovesLegacyWhenSealingEarlierMigration(t *testing.T) {
	withFakeSealing(t)
	dir := t.TempDir()
	shared := filepath.Join(dir, "excelano", "sp-token.json")
	legacy := filepath.Join(dir, "xftp", "sp-token.json")
	for _, p := range []string{shared, legacy} {
		if err := writeCacheFile(p, []byte(`{"rt":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readThrough(newFileCache(shared, legacy)); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := os.Stat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy cache still present after sealing the shared one: %v", err)
	}
}

// A cache sealed by another user or machine costs a sign-in, not an error that
// would fail every call until someone deletes the file.
func TestReplaceTreatsUnopenableCacheAsEmpty(t *testing.T) {
	withFakeSealing(t)
	path := filepath.Join(t.TempDir(), "sp-token.json")
	if err := writeCacheFile(path, []byte("foreign:xyz")); err != nil {
		t.Fatal(err)
	}
	if got, err := readThrough(newFileCache(path, "")); err != nil || got != "" {
		t.Errorf("read = %q, %v; want an empty cache and no error", got, err)
	}
}

// withoutSealing stands in a platform with nothing to seal with, so the
// plaintext paths are tested on Windows as well.
func withoutSealing(t *testing.T) {
	t.Helper()
	savedAvailable, savedSeal, savedOpen := sealAvailable, seal, open
	sealAvailable = func() bool { return false }
	seal = func(name string, data []byte) ([]byte, error) { return data, nil }
	open = func(name string, data []byte) ([]byte, bool, error) { return data, false, nil }
	t.Cleanup(func() { sealAvailable, seal, open = savedAvailable, savedSeal, savedOpen })
}

// TestExportSealsForRealOnThisMachine drives fileCache through the real
// atrest package, not the fakeProtector every other test in this file
// stands in, so a break in the wiring between spauth and atrest — the wrong
// package var, the wrong seal name, an argument swapped — shows up here
// rather than only after a release. What it can prove depends on what this
// machine actually offers: a Windows or a Linux box with a reachable key
// store proves sealing works, and a machine offering none proves the
// fallback is exactly the pre-sealing behaviour instead of an error.
func TestExportSealsForRealOnThisMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp-token.json")
	c := newFileCache(path, "")
	const plain = `{"real":1}`
	if err := c.Export(context.Background(), marshaler(plain), cache.ExportHints{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gotPlain, sealed, err := atrest.Open(sealName, stored)
	if err != nil {
		t.Fatalf("atrest.Open of what Export wrote: %v", err)
	}
	if string(gotPlain) != plain {
		t.Errorf("round trip = %q, want %q", gotPlain, plain)
	}
	if sealed != (string(stored) != plain) {
		t.Errorf("sealed=%v but stored bytes %s the plaintext", sealed, map[bool]string{true: "equal", false: "differ from"}[string(stored) == plain])
	}
	t.Logf("on this machine, Export sealed=%v (stored: %s)", sealed, stored)

	got, err := readThrough(newFileCache(path, ""))
	if err != nil || got != plain {
		t.Errorf("read back through Replace = %q, %v; want %q", got, err, plain)
	}
}

type marshaler string

func (m marshaler) Marshal() ([]byte, error) { return []byte(m), nil }

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
