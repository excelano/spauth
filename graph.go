package spauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const graphBaseURL = "https://graph.microsoft.com/v1.0"

// GraphClient is a thin authenticated HTTP wrapper for the small Graph surface
// the SharePoint tools use: JSON requests against list and drive resources,
// streamed downloads, and the upload-session protocol for large files. Token
// refresh is delegated to MSAL on every request.
type GraphClient struct {
	msal       public.Client
	account    public.Account
	headers    http.Header
	httpClient *http.Client
}

// Option adjusts a GraphClient at construction.
type Option func(*GraphClient)

// WithTimeout bounds each request, body read included. The default is five
// minutes, sized for file content moving through PutRaw and GetStream; a
// consumer that only exchanges JSON can set something shorter.
func WithTimeout(d time.Duration) Option {
	return func(g *GraphClient) { g.httpClient.Timeout = d }
}

// WithHeader adds a header to every authenticated request. xql uses it for
// the Prefer header that SharePoint requires before it will $filter on
// non-indexed list columns; the drive endpoints the xfiles tools call have no
// use for it, so it is a consumer's choice rather than a default.
func WithHeader(name, value string) Option {
	return func(g *GraphClient) { g.headers.Set(name, value) }
}

func NewGraphClient(msal public.Client, account public.Account, opts ...Option) *GraphClient {
	g := &GraphClient{
		msal:       msal,
		account:    account,
		headers:    http.Header{},
		httpClient: &http.Client{Timeout: 5 * time.Minute},
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// token returns a fresh access token, refreshing silently via the cached refresh
// token if needed.
func (g *GraphClient) token(ctx context.Context) (string, error) {
	result, err := g.msal.AcquireTokenSilent(ctx, defaultScopes, public.WithSilentAccount(g.account))
	if err != nil {
		return "", fmt.Errorf("acquiring token: %w", err)
	}
	return result.AccessToken, nil
}

// authorize attaches the bearer token and the client's standing headers.
func (g *GraphClient) authorize(ctx context.Context, req *http.Request) error {
	tok, err := g.token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	for name, values := range g.headers {
		req.Header[name] = values
	}
	return nil
}

// Get issues an authenticated GET. path is everything after graphBaseURL.
// It also serves file downloads: a GET to an item's /content endpoint returns
// a 302 to a pre-authenticated download URL, which the http client follows
// (Go strips our Authorization header on the cross-host hop, which is correct
// — the redirect target is already signed).
func (g *GraphClient) Get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	u := graphBaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return g.doWithRetry(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	})
}

// GetStream issues an authenticated GET and returns the response body unread,
// for streaming large downloads straight to disk. Used for file content: a GET
// to an item's /content endpoint 302s to a pre-authed URL, which the http
// client follows (dropping our Authorization header on the cross-host hop, as
// intended). The caller must Close the returned reader. Unlike Get, this does
// not retry on 429 — content reads through a signed CDN URL, where throttling
// is rare.
func (g *GraphClient) GetStream(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, graphBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if err := g.authorize(ctx, req); err != nil {
		return nil, err
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("graph GET %s returned %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return resp.Body, nil
}

// Patch issues an authenticated PATCH with a JSON body.
func (g *GraphClient) Patch(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return g.bodyReq(ctx, http.MethodPatch, path, body)
}

// Post issues an authenticated POST with a JSON body.
func (g *GraphClient) Post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return g.bodyReq(ctx, http.MethodPost, path, body)
}

// Delete issues an authenticated DELETE.
func (g *GraphClient) Delete(ctx context.Context, path string) error {
	_, err := g.doWithRetry(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodDelete, graphBaseURL+path, nil)
	})
	return err
}

// PutRaw issues an authenticated PUT with an arbitrary byte body and content
// type. Used for simple (<=250MB) file uploads to an item's /content endpoint.
// Larger files go through an upload session (UploadChunk).
func (g *GraphClient) PutRaw(ctx context.Context, path, contentType string, data []byte) ([]byte, error) {
	return g.doWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, graphBaseURL+path, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		return req, nil
	})
}

// UploadChunk PUTs one byte range of a file to a pre-authenticated upload-session
// URL (returned by a createUploadSession POST). That URL is already signed, so no
// Authorization header is sent. start is the zero-based offset of this chunk and
// total the full file size; Graph reads the Content-Range header to assemble the
// file and to recognize the final chunk. The returned status is 202 while more
// chunks are expected and 200/201 once the upload is complete (body is then the
// finished driveItem). Transient 429/5xx responses are retried with backoff;
// re-sending the same range is how an interrupted session resumes.
func (g *GraphClient) UploadChunk(ctx context.Context, uploadURL string, chunk []byte, start, total int64) (int, []byte, error) {
	const maxRetries = 3
	end := start + int64(len(chunk)) - 1
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(chunk))
		if err != nil {
			return 0, nil, err
		}
		req.ContentLength = int64(len(chunk))
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))

		resp, err := g.httpClient.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("uploading chunk: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return 0, nil, fmt.Errorf("reading chunk response: %w", readErr)
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < maxRetries {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp.StatusCode, body, fmt.Errorf("chunk upload returned %d: %s", resp.StatusCode, string(body))
		}
		return resp.StatusCode, body, nil
	}
	return 0, nil, fmt.Errorf("chunk upload exhausted retries")
}

// CancelUploadSession best-effort deletes an in-progress upload session so an
// aborted large upload doesn't leave a dangling session on the server. The URL
// is pre-authenticated; errors are ignored since this is cleanup.
func (g *GraphClient) CancelUploadSession(ctx context.Context, uploadURL string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uploadURL, nil)
	if err != nil {
		return
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (g *GraphClient) bodyReq(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request body: %w", err)
	}
	return g.doWithRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, graphBaseURL+path, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
}

// GetAll follows @odata.nextLink and returns the concatenated value array as
// raw JSON messages. Caller unmarshals each entry as needed.
func (g *GraphClient) GetAll(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	nextURL := graphBaseURL + path
	if len(query) > 0 {
		nextURL += "?" + query.Encode()
	}

	var all []json.RawMessage
	for nextURL != "" {
		body, err := g.doWithRetry(ctx, func() (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		})
		if err != nil {
			return nil, err
		}
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decoding paginated response: %w", err)
		}
		all = append(all, page.Value...)
		nextURL = page.NextLink
	}
	return all, nil
}

// doWithRetry runs the request through MSAL auth and handles 429 backoff.
// The build closure produces a fresh *http.Request on each attempt so request
// bodies remain readable on retry.
func (g *GraphClient) doWithRetry(ctx context.Context, build func() (*http.Request, error)) ([]byte, error) {
	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}
		if err := g.authorize(ctx, req); err != nil {
			return nil, err
		}

		resp, err := g.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP request: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("graph %s %s returned %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
		}
		return body, nil
	}
	return nil, fmt.Errorf("graph request exhausted retries")
}

func retryAfter(h string) time.Duration {
	if h == "" {
		return 5 * time.Second
	}
	if secs, err := strconv.Atoi(h); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
		return 0
	}
	return 5 * time.Second
}
