//go:build live

package spauth

// Live tests run against a real tenant through the normal token cache. They are
// the pre-release pass: CI cannot hold a token (device-code needs a human, and a
// refresh token in a public repo's secrets would be a live credential to the
// tenant), so these run locally, on a machine that has signed in once.
//
//	SPAUTH_LIVE_SITE=https://<tenant>.sharepoint.com/sites/<test-site> go test -tags live ./...
//
// The site's default document library is the fixture. Every test owns what it
// creates under a folder named for the run and removes it on the way out, so
// nothing accumulates and nothing outside that folder is touched.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// liveSite returns the fixture site URL or fails the test with the instruction.
// A silent skip would read as a pass to the person running the release loop.
func liveSite(t *testing.T) *url.URL {
	t.Helper()
	raw := os.Getenv("SPAUTH_LIVE_SITE")
	if raw == "" {
		t.Fatal("SPAUTH_LIVE_SITE is not set; point it at a SharePoint test site to run the live tests")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		t.Fatalf("SPAUTH_LIVE_SITE %q is not a URL", raw)
	}
	return u
}

// liveClient signs in through the shared cache. It refuses to start a
// device-code flow, so the machine has to have signed in once already.
func liveClient(t *testing.T) (public.Client, public.AuthResult) {
	t.Helper()
	client, err := NewPublicClient(CachePath(), "")
	if err != nil {
		t.Fatal(err)
	}
	restore := interactive
	interactive = func() bool { return false }
	t.Cleanup(func() { interactive = restore })
	result, err := Authenticate(context.Background(), client)
	if err != nil {
		t.Fatalf("no usable session in %s; sign in with any Excelano SharePoint tool first: %v", CachePath(), err)
	}
	return client, result
}

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestLiveStatusIsSignedIn(t *testing.T) {
	client, _ := liveClient(t)
	st, err := CheckStatus(context.Background(), client, CachePath())
	if err != nil {
		t.Fatal(err)
	}
	if !st.SignedIn {
		t.Fatalf("not signed in: %s", st.Reason)
	}
	if !guidRe.MatchString(st.Tenant) {
		t.Errorf("tenant = %q, want a tenant ID", st.Tenant)
	}
	if !strings.Contains(strings.Join(st.Scopes, " "), "Sites.ReadWrite.All") {
		t.Errorf("scopes %v do not include Sites.ReadWrite.All", st.Scopes)
	}
	if time.Until(st.TokenExpires) <= 0 {
		t.Errorf("token expiry %v is in the past", st.TokenExpires)
	}
}

// One pass through every request shape the Graph client offers, against the
// fixture library: resolve the site (Get), list its drives (GetAll, which is
// also the pagination path), upload (PutRaw), rename (Patch), download
// (GetStream, which follows the pre-authenticated redirect), and delete.
func TestLiveGraphClientRoundTrip(t *testing.T) {
	site := liveSite(t)
	client, result := liveClient(t)
	ctx := context.Background()
	g := NewGraphClient(client, result.Account)

	body, err := g.Get(ctx, fmt.Sprintf("/sites/%s:%s", site.Host, site.Path), nil)
	if err != nil {
		t.Fatalf("resolving site: %v", err)
	}
	var siteInfo struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &siteInfo); err != nil || siteInfo.ID == "" {
		t.Fatalf("site response has no id: %v\n%s", err, body)
	}

	drives, err := g.GetAll(ctx, "/sites/"+siteInfo.ID+"/drives", nil)
	if err != nil {
		t.Fatalf("listing drives: %v", err)
	}
	if len(drives) == 0 {
		t.Fatal("site has no document libraries")
	}
	var drive struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(drives[0], &drive); err != nil || drive.ID == "" {
		t.Fatalf("drive entry has no id: %v", err)
	}

	folder := fmt.Sprintf("spauth-live-%d", time.Now().UnixNano())
	name := "probe.txt"
	content := []byte("spauth live probe " + folder + "\n")
	itemPath := func(n string) string {
		return fmt.Sprintf("/drives/%s/root:/%s/%s", drive.ID, folder, url.PathEscape(n))
	}
	t.Cleanup(func() {
		if err := g.Delete(ctx, fmt.Sprintf("/drives/%s/root:/%s", drive.ID, folder)); err != nil {
			t.Errorf("cleanup: removing %s: %v", folder, err)
		}
	})

	if _, err := g.PutRaw(ctx, itemPath(name)+":/content", "text/plain", content); err != nil {
		t.Fatalf("PutRaw: %v", err)
	}

	renamed := "probe-renamed.txt"
	if _, err := g.Patch(ctx, itemPath(name), map[string]string{"name": renamed}); err != nil {
		t.Fatalf("Patch rename: %v", err)
	}

	rc, err := g.GetStream(ctx, itemPath(renamed)+":/content")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q, want %q", got, content)
	}

	if err := g.Delete(ctx, itemPath(renamed)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := g.Get(ctx, itemPath(renamed), nil); err == nil {
		t.Error("item still resolves after Delete")
	}
}
