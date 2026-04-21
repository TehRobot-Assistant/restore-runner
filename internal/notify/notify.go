// Package notify wraps the apprise CLI for sending failure/degraded
// notifications to whatever endpoints the user configured in Settings.
// apprise supports 110+ services (ntfy, Discord, Slack, webhooks, email)
// via URL schemes — we just shell out and let it handle the rest.
package notify

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// Client is a fire-and-forget notifier. Construct with New; call Send
// on events of interest. Missing apprise binary just no-ops.
type Client struct {
	binary string
	urls   []string
	logger *slog.Logger
}

// New returns a Client configured with the given URLs. If apprise isn't
// on PATH, Send becomes a no-op so the rest of the app keeps working.
func New(urls []string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Client{urls: filterEmpty(urls), logger: logger}
	if path, err := exec.LookPath("apprise"); err == nil {
		c.binary = path
	}
	return c
}

// Send delivers a titled body to every configured URL. Each URL is a
// separate apprise invocation so one bad endpoint doesn't drop the
// others. 20s per-URL timeout keeps a hung webhook from stalling the
// rehearsal scheduler.
func (c *Client) Send(ctx context.Context, title, body string) {
	if c == nil || c.binary == "" || len(c.urls) == 0 {
		return
	}
	for _, u := range c.urls {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := c.sendOne(cctx, u, title, body)
		cancel()
		if err != nil {
			c.logger.Warn("apprise send failed", "url", redactURL(u), "err", err)
		}
	}
}

func (c *Client) sendOne(ctx context.Context, url, title, body string) error {
	cmd := exec.CommandContext(ctx, c.binary,
		"--title", title,
		"--body", body,
		url,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func filterEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// redactURL strips obvious secrets from an apprise URL for logging.
// Apprise URLs often have credentials in the user:pass@ portion.
func redactURL(u string) string {
	if i := strings.Index(u, "@"); i > 0 {
		if j := strings.Index(u, "://"); j >= 0 && j < i {
			return u[:j+3] + "***@" + u[i+1:]
		}
	}
	return u
}
