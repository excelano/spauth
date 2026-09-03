# spauth

The SharePoint sign-in layer shared by the Excelano SharePoint tools: [xql](https://github.com/excelano/xql)'s `sp` backend and the five [xfiles](https://github.com/excelano/xfiles) commands (`xftp`, `xcp`, `xsync`, `xfind`, `xtree`). It carries the device-code OAuth flow over MSAL, the on-disk token cache those tools share, the refusal that keeps an unattended caller from hanging on a code nobody will read, a table of AADSTS error hints, and a thin authenticated Microsoft Graph HTTP client.

It is a library for that family, not a general Graph SDK. The client ID, authority and scope are constants: every consumer signs in against the one "Excelano SharePoint tools" app registration, which is what lets consent and the cached session carry across all six binaries. To self-host, change the constants and rebuild the consumers.

## Install

```
go get github.com/excelano/spauth
```

## Usage

```go
import "github.com/excelano/spauth"

client, err := spauth.NewPublicClient(spauth.CachePath(), legacyCachePath)
if err != nil { /* setup failure */ }

result, err := spauth.Authenticate(ctx, client)
if err != nil {
    fmt.Fprintf(os.Stderr, "authentication failed: %v%s\n", err, spauth.HintForAuthError(err))
    os.Exit(1)
}

graph := spauth.NewGraphClient(client, result.Account)
body, err := graph.Get(ctx, "/sites/"+siteID+"/lists", nil)
```

`Authenticate` tries a silent refresh against the cached account first and falls back to device code, printing the code and URL on stderr. When that fallback would be needed and stderr is not a terminal it returns `ErrNoTerminal` at once instead of polling for fifteen minutes: the remedy is in the message, and a cached refresh token still renews unattended, so the guard only ever bites the first sign-in.

`NewGraphClient` takes options. `WithTimeout` bounds each request; the default of five minutes is sized for file content. `WithHeader` adds a header to every authenticated request, which is how xql sends the `Prefer` header SharePoint needs before it will `$filter` on non-indexed list columns.

## The token cache

`CachePath` is `~/.config/excelano/sp-token.json` (under `$XDG_CONFIG_HOME` when that is set), one file for the whole family, so signing in with any tool signs in all of them. The second argument to `NewPublicClient` names the per-tool cache a consumer kept before the cache was shared; when the shared file does not exist yet and that one does, it is copied into place on first use and nobody signs in again. Pass `""` for a consumer that never had one.

The file is MSAL's own format, written 0600 in a 0700 directory. Writes go through a temp file and a rename, so a crash or a second process writing the same file leaves the previous cache intact rather than a truncated one.

## Testing against a tenant

`go test ./...` covers the cache, the refusal, the hints and the state command without a token. The Graph client is covered by a live suite behind a build tag, which runs on a machine that has signed in once and needs a test site to work in:

```
SPAUTH_LIVE_SITE=https://<tenant>.sharepoint.com/sites/<test-site> go test -tags live ./...
```

Every request shape the client offers runs once against that site's default library, in a folder the test creates and removes. It does not run in CI: device-code sign-in needs a human, and a refresh token in a public repository's secrets would be a live credential to the tenant.

## The state command

Every tool in the family answers a bare `auth` with the state of the shared session — account, tenant, token expiry and scopes — and exits 0 whether or not one exists, so a caller that would rather ask than find out can branch on the report instead of on a failed attempt. `AuthCommand` is that subcommand, flag parsing and rendering included, so the six binaries agree by construction; `CheckStatus` is the underlying question for a program that wants the `Status` value. Neither starts a sign-in: with no cached account the answer is offline, and with one it is a silent token renewal, which proves the refresh token still works. `--json` prints the same fields as an object.

## Not a consumer

blick-cli hand-rolls `x/oauth2` against per-tenant mailbox scopes. That is a different design on purpose and should not be folded in here.

## License

MIT. Author: David M. Anderson. Built with AI assistance (Claude, Anthropic).
