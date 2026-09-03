package spauth

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// MSAL records "common" as the realm of an account signed in through the
// /common authority, so the tenant has to come from the home account ID.
func TestTenantOfReadsHomeAccountID(t *testing.T) {
	acct := public.Account{HomeAccountID: "user-oid.tenant-id", Realm: "common"}
	if got := tenantOf(acct); got != "tenant-id" {
		t.Errorf("tenantOf = %q, want the id after the dot", got)
	}
	if got := tenantOf(public.Account{Realm: "fallback"}); got != "fallback" {
		t.Errorf("tenantOf with no home account id = %q, want the realm", got)
	}
}

func TestUntilPhrase(t *testing.T) {
	cases := map[time.Duration]string{
		-time.Minute:               "lapsed",
		45 * time.Minute:           "in 45m",
		time.Hour + 19*time.Minute: "in 1h19m",
		2 * time.Hour:              "in 2h",
		time.Hour + 5*time.Minute + 29*time.Second: "in 1h05m",
	}
	for d, want := range cases {
		if got := untilPhrase(d); got != want {
			t.Errorf("untilPhrase(%v) = %q, want %q", d, got, want)
		}
	}
}

// With nothing cached the answer comes from the cache alone: not signed in,
// a reason, no error, and no sign-in started.
func TestCheckStatusWithNoAccount(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "sp-token.json")
	client, err := NewPublicClient(cache, "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := CheckStatus(context.Background(), client, cache)
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if st.SignedIn {
		t.Error("SignedIn = true over an empty cache")
	}
	if st.Reason == "" {
		t.Error("an absent session should carry a reason")
	}
	if st.Cache != cache {
		t.Errorf("Cache = %q, want %q", st.Cache, cache)
	}
}

// The bare command exits 0 whether or not a session exists, says so in
// prose or as JSON, and treats a bad invocation as the caller's fault.
func TestAuthCommand(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx := context.Background()

	var out, errOut bytes.Buffer
	if code := AuthCommand(ctx, "xftp", "", nil, &out, &errOut); code != 0 {
		t.Fatalf("exit %d with no session, want 0; stderr: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "Not signed in") {
		t.Errorf("report = %q, want it to open with the state", out.String())
	}
	if !strings.Contains(out.String(), "interactive terminal") {
		t.Errorf("report %q does not say how to sign in", out.String())
	}

	out.Reset()
	if code := AuthCommand(ctx, "xftp", "", []string{"--json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d for --json, want 0; stderr: %s", code, errOut.String())
	}
	var st Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, out.String())
	}
	if st.SignedIn || st.Reason == "" || st.Cache != CachePath() {
		t.Errorf("--json report = %+v, want signed_in false with a reason and the shared cache path", st)
	}
	if strings.Contains(out.String(), "token_expires") {
		t.Errorf("--json report carries a zero token_expires: %s", out.String())
	}

	out.Reset()
	if code := AuthCommand(ctx, "xftp", "", []string{"-h"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "Usage: xftp auth") {
		t.Errorf("-h: exit %d, stdout %q; want 0 and usage on stdout", code, out.String())
	}
	if code := AuthCommand(ctx, "xftp", "", []string{"--bogus"}, &out, &errOut); code != 2 {
		t.Errorf("unknown flag: exit %d, want 2", code)
	}
	if code := AuthCommand(ctx, "xftp", "", []string{"extra"}, &out, &errOut); code != 2 {
		t.Errorf("stray argument: exit %d, want 2", code)
	}
}

// The signed-in layout cannot be produced from a test without a real token,
// so the renderer is checked on a fabricated status.
func TestWriteStatusSignedIn(t *testing.T) {
	var out bytes.Buffer
	WriteStatus(&out, Status{
		SignedIn:     true,
		Account:      "someone@example.com",
		Tenant:       "00000000-0000-0000-0000-000000000000",
		TokenExpires: time.Now().Add(45 * time.Minute),
		Scopes:       []string{"https://graph.microsoft.com/Sites.ReadWrite.All"},
		Cache:        "/home/x/.config/excelano/sp-token.json",
	})
	for _, want := range []string{"Signed in as   someone@example.com", "Tenant         00000000", "in 45m", "Sites.ReadWrite.All", "Cache          /home/x"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
}
