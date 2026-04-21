// Package secweb: small security-focused web helpers inlined into this app.
// Previously lived in a shared homelab-commons module; now self-contained
// so the app has no external-module dependencies beyond vendored libraries.
package secweb

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/microcosm-cc/bluemonday"
)

// DefaultMaxBody caps external-fetch response sizes at 32 MiB to prevent
// memory exhaustion from a hostile or runaway upstream.
const DefaultMaxBody int64 = 32 << 20

// ErrResponseTooLarge is returned when an HTTP body exceeds the cap.
var ErrResponseTooLarge = errors.New("response body exceeded size cap")

// HTTPClient returns a stdlib client with sensible timeouts + TLS enforced.
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// FetchCapped does a GET and returns the body up to maxBytes. Returns
// ErrResponseTooLarge if the body overran.
func FetchCapped(client *http.Client, url string, maxBytes int64) ([]byte, *http.Response, error) {
	if client == nil {
		client = HTTPClient()
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBody
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, resp, fmt.Errorf("read response: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, resp, ErrResponseTooLarge
	}
	return data, resp, nil
}

// SanitiseHTML runs HTML (e.g. rendered Markdown) through a strict policy.
// Used on every piece of user-visible content that originated upstream
// (fetched release notes, etc.) so no upstream-supplied script or onclick
// attribute gets rendered in our UI.
func SanitiseHTML(html string) string {
	p := bluemonday.UGCPolicy()
	p.RequireNoFollowOnLinks(true)
	p.RequireNoReferrerOnLinks(true)
	p.AllowURLSchemes("http", "https", "mailto")
	return p.Sanitize(html)
}
