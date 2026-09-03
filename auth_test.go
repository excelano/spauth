package spauth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Authenticate must refuse the device-code fallback when no terminal is
// attached. Device code is a polling flow, so without this guard an unattended
// caller prints a code nobody can see and then blocks until it expires. The
// error has to arrive immediately and carry the remedy.
func TestAuthenticateRefusesDeviceCodeWithoutTerminal(t *testing.T) {
	restore := interactive
	interactive = func() bool { return false }
	t.Cleanup(func() { interactive = restore })

	// A client over an empty cache has no accounts, so silent acquisition is
	// skipped and control reaches the guard without any network call. A
	// zero-value public.Client cannot stand in here — MSAL dereferences its
	// internals and panics.
	client, err := NewPublicClient(filepath.Join(t.TempDir(), "sp-token.json"), "")
	if err != nil {
		t.Fatalf("NewPublicClient: %v", err)
	}

	_, err = Authenticate(context.Background(), client)
	if err == nil {
		t.Fatal("Authenticate succeeded with no terminal; want refusal before the device-code flow")
	}
	if !errors.Is(err, ErrNoTerminal) {
		t.Errorf("error %q is not ErrNoTerminal; the guard should precede the device-code flow", err)
	}

	msg := err.Error()
	for _, want := range []string{"no cached token, and no terminal is attached", "interactive terminal"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// The hint table is matched by substring, so the longer code has to win when
// one code is a prefix of another.
func TestHintForAuthErrorPrefersLongestCode(t *testing.T) {
	got := HintForAuthError(errors.New("AADSTS7000218: public client disabled"))
	if !strings.Contains(got, "(AADSTS7000218)") {
		t.Errorf("hint = %q, want the AADSTS7000218 entry, not its AADSTS70002 prefix", got)
	}
	if HintForAuthError(nil) != "" {
		t.Error("nil error should produce no hint")
	}
	if HintForAuthError(errors.New("something else")) != "" {
		t.Error("an error without a known code should produce no hint")
	}
}
