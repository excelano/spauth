// Package spauth is the SharePoint sign-in layer shared by the Excelano
// SharePoint tools: xql's sp backend and the five xfiles commands (xftp, xcp,
// xsync, xfind, xtree). It holds the device-code OAuth flow over MSAL, the
// on-disk token cache those tools share, the refusal that keeps an unattended
// caller from hanging on a code nobody will read, the AADSTS hint table, and a
// thin authenticated Microsoft Graph HTTP client.
//
// The six binaries have always shared one app registration and one delegated
// scope, so consent carried across them. What they did not share was the
// session: each kept its own cache and asked for its own sign-in. This module
// exists so that one sign-in covers the family, and so that a fix to the flow
// lands once. Before it, the code lived as two drifting copies in
// xql/internal/sp and xfiles/internal/spauth.
//
// blick-cli is not a consumer. It hand-rolls x/oauth2 against per-tenant
// mailbox scopes, a deliberately different design, and should stay that way.
package spauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"golang.org/x/term"
)

// Azure app registration "Excelano SharePoint tools"
// (client 13be0775-ed76-4407-bb2c-b7a07a189bf6), multi-tenant, in Excelano's
// tenant. Every consumer of this module signs in against it, which is what
// lets consent and the cached session carry across the tools. To use your own
// registration instead, change these constants and rebuild the consumers.
const (
	defaultClientID  = "13be0775-ed76-4407-bb2c-b7a07a189bf6"
	defaultAuthority = "https://login.microsoftonline.com/common"
)

// defaultScopes lists only resource-specific scopes. MSAL Go automatically
// appends openid, offline_access, and profile via AppendDefaultScopes, and
// flags any user-supplied scope absent from the response as "declined".
// Since Azure doesn't echo offline_access back in the scope claim (it's a
// modifier that just unlocks refresh-token issuance), adding it here triggers
// a spurious "declined scopes" failure even when refresh works correctly.
//
// Sites.ReadWrite.All covers list items and document-library content alike,
// so it is the one scope the whole family needs. Changing it invalidates the
// consent every existing user has granted.
var defaultScopes = []string{
	"https://graph.microsoft.com/Sites.ReadWrite.All",
}

// NewPublicClient constructs the MSAL public client used for both silent and
// device code token acquisition. Refresh tokens are persisted at cachePath
// across runs; consumers pass CachePath() so the family shares one session.
// legacyPath names the per-tool cache the consumer kept before the cache was
// shared, or "" if it never had one; when cachePath does not exist yet and
// the legacy file does, the legacy file is read once and copied into place.
func NewPublicClient(cachePath, legacyPath string) (public.Client, error) {
	c, err := public.New(
		defaultClientID,
		public.WithAuthority(defaultAuthority),
		public.WithCache(newFileCache(cachePath, legacyPath)),
	)
	if err != nil {
		return public.Client{}, fmt.Errorf("creating MSAL public client: %w", err)
	}
	return c, nil
}

// interactive reports whether a human is present to read the device code and
// complete the browser flow. A variable rather than a function so tests can
// drive both branches of Authenticate without a terminal.
//
// stderr is the file descriptor that decides it, because that is where the
// instructions print: a run whose stderr is redirected to a log has nobody to
// read the code even when the shell itself is interactive, while the common
// `xql sp … > out.csv` keeps stderr on the terminal and still works. Testing
// for a character device instead would also match /dev/null and make the guard
// misfire under redirect or cron.
var interactive = func() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// ErrNoTerminal is the refusal Authenticate returns when sign-in is needed and
// nobody is there to complete it. The first sentence is the fact and the
// second is the remedy, in that order, so the remedy sits in the first line a
// caller prints. Consumers' documentation quotes the opening clause; keep it
// stable.
var ErrNoTerminal = errors.New(
	"no cached token, and no terminal is attached to complete device-code sign-in. " +
		"Run this command once from an interactive terminal to sign in; the session is shared by " +
		"every Excelano SharePoint tool, so one sign-in covers them all")

// Authenticate returns a usable AuthResult, attempting silent refresh against
// any cached account first and falling back to interactive device code flow.
// Device code instructions are printed to stderr so they don't pollute
// stdout-bound results.
//
// The fallback is refused outright when no terminal is attached. Device code
// is a polling flow: it would print a code nobody can see and then block until
// the code expires, which for an unattended caller — a script, cron, or a
// coding agent — is a multi-minute hang ending in failure. Failing in the first
// second with the step that fixes it is strictly better. Only that path is
// gated: a cached refresh token still renews unattended.
func Authenticate(ctx context.Context, client public.Client) (public.AuthResult, error) {
	accounts, err := client.Accounts(ctx)
	if err == nil && len(accounts) > 0 {
		result, err := client.AcquireTokenSilent(ctx, defaultScopes, public.WithSilentAccount(accounts[0]))
		if err == nil {
			return result, nil
		}
		// Silent failed (refresh token expired, scopes changed, account
		// invalidated). Fall through to device code.
	}

	if !interactive() {
		return public.AuthResult{}, ErrNoTerminal
	}

	dc, err := client.AcquireTokenByDeviceCode(ctx, defaultScopes)
	if err != nil {
		return public.AuthResult{}, fmt.Errorf("initiating device code flow: %w", err)
	}

	fmt.Fprintln(os.Stderr, dc.Result.Message)

	result, err := dc.AuthenticationResult(ctx)
	if err != nil {
		return public.AuthResult{}, fmt.Errorf("device code authentication: %w", err)
	}
	return result, nil
}

// aadstsHints maps the most common AADSTS error codes to one-line actionable
// guidance. Keys are matched as substrings against the auth error message.
var aadstsHints = map[string]string{
	"AADSTS70002":   "Public client flows are disabled in the App Registration. Azure portal → Authentication → Allow public client flows → Yes.",
	"AADSTS7000218": "Public client flows are disabled in the App Registration. Azure portal → Authentication → Allow public client flows → Yes.",
	"AADSTS65001":   "User or admin has not consented to the application. Azure portal → API permissions → Grant admin consent.",
	"AADSTS50105":   "Admin consent is required for one or more permissions. Azure portal → API permissions → Grant admin consent.",
	"AADSTS50194":   "App is not registered as multi-tenant in this tenant. Re-check the App Registration's supported account types.",
	"AADSTS90094":   "Admin consent required for the requested permissions. Azure portal → API permissions → Grant admin consent.",
	"AADSTS900561":  "Token request endpoint mismatch. If self-hosting, verify the App Registration matches defaultClientID in the spauth module.",
}

// HintForAuthError returns a "\nHint (CODE): …" string suffix matching the
// first AADSTS code found in err's message, or "" if none match (or err is
// nil). Codes are tested in length-descending order so AADSTS7000218 is
// matched ahead of the prefix-shared AADSTS70002.
func HintForAuthError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	for _, code := range aadstsCodesByLength {
		if strings.Contains(s, code) {
			return fmt.Sprintf("\nHint (%s): %s", code, aadstsHints[code])
		}
	}
	return ""
}

// aadstsCodesByLength holds aadstsHints' keys sorted longest-first so we
// match the most specific code when one is a prefix of another.
var aadstsCodesByLength = sortedAADSTSCodes()

func sortedAADSTSCodes() []string {
	codes := make([]string, 0, len(aadstsHints))
	for c := range aadstsHints {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool { return len(codes[i]) > len(codes[j]) })
	return codes
}
