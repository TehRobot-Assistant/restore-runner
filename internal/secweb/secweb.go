// Package secweb: small security-focused web helpers.
package secweb

import (
	"net/http"
	"time"
)

// HTTPClient returns a stdlib client with sensible timeouts.
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
