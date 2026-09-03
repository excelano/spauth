package spauth

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// familyTools names every binary that shares the session, for the messages
// that tell a caller where a sign-in can be done.
const familyTools = "xql sp, xftp, xcp, xfind, xsync and xtree"

// Status is the state of the shared session, as the family's bare `auth`
// command reports it. An absent session is an answer, not a failure, so the
// zero SignedIn carries a Reason rather than an error.
type Status struct {
	SignedIn bool   `json:"signed_in"`
	Account  string `json:"account,omitempty"`
	Tenant   string `json:"tenant,omitempty"`
	// TokenExpires is when the current access token lapses. The session
	// outlives it: MSAL renews the token from the cached refresh token
	// without a prompt for as long as the refresh token is honoured.
	TokenExpires time.Time `json:"token_expires,omitzero"`
	Scopes       []string  `json:"scopes,omitempty"`
	// Reason says why SignedIn is false, in words a caller can print.
	Reason string `json:"reason,omitempty"`
	Cache  string `json:"cache"`
}

// CheckStatus reports the state of the session cached at cachePath. It never
// starts a sign-in, so it is safe unattended: with no cached account it
// answers offline, and with one it asks MSAL for a token silently, which
// proves the refresh token still works and costs one round trip when the
// access token has lapsed.
//
// The error is non-nil only when the answer could not be determined — the
// cache is unreadable, or the sign-in server could not be reached. A server
// that answers and rejects the session is a determined answer: not signed in,
// with the rejection as the reason.
func CheckStatus(ctx context.Context, client public.Client, cachePath string) (Status, error) {
	st := Status{Cache: cachePath}

	accounts, err := client.Accounts(ctx)
	if err != nil {
		return st, fmt.Errorf("reading the token cache: %w", err)
	}
	if len(accounts) == 0 {
		st.Reason = "no cached account"
		return st, nil
	}
	account := accounts[0]
	st.Account = account.PreferredUsername
	st.Tenant = account.Realm

	result, err := client.AcquireTokenSilent(ctx, defaultScopes, public.WithSilentAccount(account))
	if err != nil {
		var call msalerrors.CallErr
		if errors.As(err, &call) && call.Resp != nil {
			st.Reason = "the sign-in server rejected the cached session: " + err.Error()
			return st, nil
		}
		return st, fmt.Errorf("renewing the cached session: %w", err)
	}

	st.SignedIn = true
	st.Account = result.Account.PreferredUsername
	st.Tenant = result.Account.Realm
	st.TokenExpires = result.ExpiresOn
	st.Scopes = result.GrantedScopes
	return st, nil
}

// WriteStatus renders st for a human. The layout is the same in every tool of
// the family so a reader learns it once.
func WriteStatus(w io.Writer, st Status) {
	if !st.SignedIn {
		fmt.Fprintf(w, "Not signed in: %s\n", st.Reason)
		fmt.Fprintf(w, "Cache          %s\n", st.Cache)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Run any Excelano SharePoint tool once from an interactive terminal to sign in;\none session covers %s.\n", familyTools)
		return
	}
	fmt.Fprintf(w, "Signed in as   %s\n", st.Account)
	fmt.Fprintf(w, "Tenant         %s\n", st.Tenant)
	fmt.Fprintf(w, "Token expires  %s (%s; renews silently while the session lasts)\n",
		st.TokenExpires.Local().Format("2006-01-02 15:04:05 MST"), untilPhrase(time.Until(st.TokenExpires)))
	fmt.Fprintf(w, "Scopes         %s\n", strings.Join(st.Scopes, " "))
	fmt.Fprintf(w, "Cache          %s\n", st.Cache)
}

func untilPhrase(d time.Duration) string {
	if d <= 0 {
		return "lapsed"
	}
	return "in " + d.Round(time.Minute).String()
}

// AuthCommand is the family's bare `auth` subcommand: it reports the shared
// session and exits 0 whether or not one exists, so a caller can ask before it
// tries rather than learning the state from a failed attempt. args are the
// arguments after the subcommand name; the one flag is --json. tool is the
// binary's name, for the usage text. legacyCachePath is the per-tool cache the
// binary kept before the cache was shared, adopted here the same way it is on
// a real run, so `xftp auth` after an upgrade reports the session it inherits.
//
// Exit codes follow the family's contract: 0 reported, 1 the state could not
// be determined, 2 bad invocation.
func AuthCommand(ctx context.Context, tool, legacyCachePath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(tool+" auth", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the report as a JSON object")
	usage := func(w io.Writer) {
		fmt.Fprintf(w, "Usage: %s auth [--json]\n\n", tool)
		fmt.Fprintf(w, "Reports the SharePoint session shared by %s:\naccount, tenant, token expiry and scopes. Exits 0 whether or not a session\nexists; the report is the answer. Signing in is not this command's job: run any\ntool in the family once from an interactive terminal.\n\n", familyTools)
		fmt.Fprintln(w, "Flags:")
		fmt.Fprintln(w, "  --json  print the report as a JSON object")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Exit codes:")
		fmt.Fprintln(w, "  0  reported, signed in or not")
		fmt.Fprintln(w, "  1  the state could not be determined (cache unreadable, sign-in server unreachable)")
		fmt.Fprintln(w, "  2  bad invocation")
	}
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s auth: unexpected argument %q\n", tool, fs.Arg(0))
		usage(stderr)
		return 2
	}

	client, err := NewPublicClient(CachePath(), legacyCachePath)
	if err != nil {
		fmt.Fprintf(stderr, "%s auth: %v\n", tool, err)
		return 1
	}
	st, err := CheckStatus(ctx, client, CachePath())
	if err != nil {
		fmt.Fprintf(stderr, "%s auth: could not determine the session state: %v%s\n", tool, err, HintForAuthError(err))
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(st); err != nil {
			fmt.Fprintf(stderr, "%s auth: %v\n", tool, err)
			return 1
		}
		return 0
	}
	WriteStatus(stdout, st)
	return 0
}
