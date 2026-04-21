// Package previewproxy reverse-proxies the sandboxed container's WebUI
// back through RestoreRunner, so the end user can preview it in an
// iframe (or a new tab) without the sandbox ever being reachable on
// the host network.
//
// Design points:
//
//   - One proxy instance per run. The resolver is called lazily on
//     first request; once we have the sandbox's IP + port, we cache it
//     for the run's lifetime.
//
//   - httputil.NewSingleHostReverseProxy handles the bulk of the work,
//     including automatic WebSocket upgrades when the request carries
//     an Upgrade: websocket header + Connection: upgrade. The only
//     thing we tweak is the Director (strip the /run/{id}/preview
//     prefix and force the outbound Host header to the sandbox) and a
//     ModifyResponse hook that strips framing headers so our iframe
//     can render the response.
//
//   - Request path safety: before we hand anything to the proxy we
//     normalise the incoming URL path with path.Clean to collapse any
//     "../", and we refuse anything that still contains ".." after
//     cleaning. ReverseProxy's Director already re-writes the URL onto
//     the fixed backend, so SSRF via path-traversal is structurally
//     impossible — but belt-and-braces.
package previewproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// IPResolver returns the sandbox container's internal IPv4 address.
// Typically wraps sandbox.Client.InspectIP.
type IPResolver func(ctx context.Context, containerID string) (string, error)

// Target pairs a container ID with the WebUI port we should proxy to.
type Target struct {
	ContainerID string
	WebUIPort   int
}

// Proxy is one reverse proxy tied to one run.
type Proxy struct {
	target   Target
	resolve  IPResolver
	pathPref string // e.g. "/run/<id>/preview"

	once     sync.Once
	backend  *url.URL
	rp       *httputil.ReverseProxy
	buildErr error
}

// New creates a proxy but does NOT dial the backend. The first request
// triggers IP resolution.
func New(target Target, pathPrefix string, resolve IPResolver) (*Proxy, error) {
	if target.ContainerID == "" {
		return nil, errors.New("proxy: empty container id")
	}
	if target.WebUIPort <= 0 {
		return nil, errors.New("proxy: webui port required")
	}
	if resolve == nil {
		return nil, errors.New("proxy: nil resolver")
	}
	// Strip any trailing slash so joinPath math is uniform.
	pathPrefix = strings.TrimRight(pathPrefix, "/")
	return &Proxy{
		target:   target,
		resolve:  resolve,
		pathPref: pathPrefix,
	}, nil
}

// lazyBuild resolves the backend URL + constructs the ReverseProxy on
// the first request. Subsequent requests reuse the cached value.
func (p *Proxy) lazyBuild(ctx context.Context) error {
	p.once.Do(func() {
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ip, err := p.resolve(resolveCtx, p.target.ContainerID)
		if err != nil {
			p.buildErr = fmt.Errorf("resolve sandbox ip: %w", err)
			return
		}
		backend, err := url.Parse(fmt.Sprintf("http://%s:%d", ip, p.target.WebUIPort))
		if err != nil {
			p.buildErr = fmt.Errorf("parse backend url: %w", err)
			return
		}
		p.backend = backend
		rp := httputil.NewSingleHostReverseProxy(backend)

		// httputil's default Director already rewrites the scheme/host
		// onto the backend. We layer our own Director in front of it
		// to strip the /run/<id>/preview prefix from the path.
		defaultDirector := rp.Director
		rp.Director = func(r *http.Request) {
			// 1. Strip the prefix lexically.
			orig := r.URL.Path
			trimmed := strings.TrimPrefix(orig, p.pathPref)
			// 2. Normalise the path. path.Clean collapses any "../"
			//    traversal attempt. We still reject any request whose
			//    cleaned path escapes "/" — shouldn't be possible, but
			//    defence-in-depth.
			cleaned := path.Clean("/" + strings.TrimPrefix(trimmed, "/"))
			if strings.Contains(cleaned, "..") {
				cleaned = "/"
			}
			r.URL.Path = cleaned
			r.URL.RawPath = ""

			// 3. Call the built-in director so scheme/host are rewritten
			//    onto the backend URL.
			defaultDirector(r)
			// Force the outbound Host header to the backend so the
			// sandboxed app sees consistent Host/URL.Host (some apps
			// reject requests whose Host header doesn't match their
			// expected bind — e.g. strict virtual-host checks).
			r.Host = backend.Host

			// 4. X-Forwarded-Prefix helps some WebUIs build relative
			//    links correctly. Harmless if the app ignores it.
			r.Header.Set("X-Forwarded-Prefix", p.pathPref)

			// 5. DO NOT leak RestoreRunner's session cookie or
			//    Authorization header to the sandboxed container.
			//    Even though the sandbox has no internet egress, we
			//    don't want a malicious restored image to log or
			//    compare the cookie. The sandbox is a *separate*
			//    origin from the user's perspective; auth to it is
			//    the sandbox's own problem, not ours.
			r.Header.Del("Cookie")
			r.Header.Del("Authorization")
		}

		// Strip/rewrite response headers that would block iframing, AND
		// strip Set-Cookie so a malicious sandbox can't overwrite
		// RestoreRunner's own session cookie on the shared origin.
		// (The preview is served from the RR origin via this proxy, so
		// any cookie the backend sets would land in the user's cookie
		// jar for the RR origin — trivial session-fixation otherwise.)
		rp.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Set-Cookie")
			if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
				resp.Header.Set("Content-Security-Policy",
					stripFrameAncestors(csp))
			}
			// Same for CSP-Report-Only — don't let it masquerade as a
			// non-report CSP downstream.
			if csp := resp.Header.Get("Content-Security-Policy-Report-Only"); csp != "" {
				resp.Header.Set("Content-Security-Policy-Report-Only",
					stripFrameAncestors(csp))
			}
			return nil
		}

		// ErrorHandler lets us surface a friendly 502 if the sandbox
		// isn't ready yet (common race: user clicks preview before the
		// container's HTTP server has started listening).
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("RestoreRunner: sandboxed WebUI not reachable yet.\n" +
				"The container may still be starting up, or the app isn't listening on the expected port.\n" +
				"Sandbox has no internet access — some apps show network errors on first boot.\n"))
		}

		p.rp = rp
	})
	return p.buildErr
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := p.lazyBuild(r.Context()); err != nil {
		http.Error(w, "preview unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	p.rp.ServeHTTP(w, r)
}

// stripFrameAncestors removes the `frame-ancestors` directive from a
// CSP header so the response can be iframed. We preserve every other
// directive verbatim.
func stripFrameAncestors(csp string) string {
	parts := strings.Split(csp, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		low := strings.ToLower(trimmed)
		if strings.HasPrefix(low, "frame-ancestors") {
			continue
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "; ")
}
