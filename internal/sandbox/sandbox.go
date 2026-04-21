// Package sandbox wraps the Docker Engine API for RestoreRunner's single
// job: spin up one container from an extracted Unraid backup, stream its
// logs, and tear it down on request.
//
// v0.4 security posture (hardened):
//
//   - Sandbox containers are attached to a dedicated internal bridge
//     network (rr-sandbox-net, --internal) so they can neither reach the
//     host LAN nor the public internet. RestoreRunner itself joins the
//     same network on startup so it can proxy the sandbox's WebUI.
//
//   - Zero host-port publishing. No HostConfig.PortBindings — the
//     sandbox is reachable only via the internal network. The UI
//     reverse-proxies the WebUI to the end user via /run/{id}/preview/.
//
//   - Every bind mount is rewritten to point at the extracted upload
//     tree inside /config/uploads/<runID>/extracted/<subdir>/. A sanity
//     assertion refuses to start the container if any mount source still
//     resolves to a live host path (notably /mnt/user/appdata/*), so a
//     careless or malicious upload can never corrupt the host's real
//     appdata.
//
//   - Resource caps (--memory, --cpus), cap-drop=ALL, no-new-privileges,
//     AutoRemove=false (we keep logs after exit), RestartPolicy=no.
//
// We DELIBERATELY do NOT pass the host docker socket through to the
// sandboxed container. If the image needs it, the container will fail
// and we surface that in the logs. Granting docker-in-docker to a
// restored-from-backup container would be trivial host compromise.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"

	"github.com/trstudios/restore-runner/internal/unraidxml"
)

// SandboxNetworkName is the name of the docker network every sandbox
// container (and RestoreRunner itself) joins. --internal means the
// bridge has no route to the host LAN or the internet.
const SandboxNetworkName = "rr-sandbox-net"

// Client wraps the Docker API client with the subset of operations we need.
type Client struct {
	api *client.Client
}

// NewClient returns a docker client talking to the given socket path.
// The socket path should be of the form /var/run/docker.sock (no unix://).
func NewClient(socketPath string) (*Client, error) {
	api, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &Client{api: api}, nil
}

// Ping checks the docker socket is reachable.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.api.Ping(ctx)
	return err
}

// RunResult captures the outcome of a successful Run.
type RunResult struct {
	ContainerID   string
	ContainerName string
	// WebUIPort is the container-internal port of the primary WebUI.
	// There is no host port — the UI reverse-proxies via the internal
	// sandbox network.
	WebUIPort int
}

// RunOpts is what Run takes. ExtractedDir is the root of the uploaded
// archive's extract (everything the sandbox can bind lives under here).
type RunOpts struct {
	ContainerName string
	Template      *unraidxml.Template
	ExtractedDir  string // absolute path inside OUR container (under /config/uploads/<uuid>/extracted)
	MemoryBytes   int64
	CPUs          float64

	// ExtraHostDeny is an optional list of host path prefixes that must
	// never appear as mount sources (in addition to the built-in
	// /mnt/user/appdata/ check). Populated from RR_HOST_DENY_PREFIXES.
	ExtraHostDeny []string
}

// Run pulls the image, constructs the container spec, and starts it on
// the internal sandbox network. Returns the new container ID and the
// XML-declared WebUI container port (for the proxy to target).
func (c *Client) Run(ctx context.Context, opts RunOpts) (*RunResult, error) {
	if opts.Template == nil || opts.Template.Repository == "" {
		return nil, errors.New("template has no repository")
	}
	if opts.ExtractedDir == "" {
		return nil, errors.New("extracted dir required")
	}
	// Best-effort: ensure the sandbox network exists before we try to
	// attach. EnsureSandboxNetwork is idempotent.
	if err := c.EnsureSandboxNetwork(ctx); err != nil {
		return nil, fmt.Errorf("ensure sandbox net: %w", err)
	}

	// --- Pull the image (streaming discarded; Docker caches it). ---
	pullCtx, pullCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer pullCancel()
	rc, err := c.api.ImagePull(pullCtx, opts.Template.Repository, image.PullOptions{})
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", opts.Template.Repository, err)
	}
	_, _ = io.Copy(io.Discard, rc)
	rc.Close()

	// --- Expose XML-declared container ports on the internal network,
	// but do NOT publish them to the host. No PortBindings. ---
	exposedPorts := nat.PortSet{}
	webuiPort := 0
	for i, p := range opts.Template.Ports {
		proto := p.Mode
		if proto == "" {
			proto = "tcp"
		}
		natPort := nat.Port(fmt.Sprintf("%d/%s", p.ContainerPort, proto))
		exposedPorts[natPort] = struct{}{}
		if i == 0 {
			webuiPort = p.ContainerPort
		}
	}
	// Prefer a WebUI-tag-derived port if the XML tells us one.
	if wp := unraidxml.WebUIPort(opts.Template.WebUI); wp > 0 {
		webuiPort = wp
	}

	// --- Build bind mounts, always rooted inside the extract tree. ---
	mounts, err := buildMounts(opts)
	if err != nil {
		return nil, err
	}
	if err := assertMountsSafe(mounts, opts.ExtractedDir, opts.ExtraHostDeny); err != nil {
		return nil, err
	}

	// --- Env vars from the XML. Defaults only — no user-supplied secrets
	// at this stage. A restore is meant to reproduce what was captured.
	envList := make([]string, 0, len(opts.Template.Env))
	for _, e := range opts.Template.Env {
		envList = append(envList, e.Name+"="+e.Value)
	}

	// --- Resource caps and security posture. ---
	memory := opts.MemoryBytes
	if memory <= 0 {
		memory = 1 << 30 // 1 GiB default
	}
	cpus := opts.CPUs
	if cpus <= 0 {
		cpus = 1.0
	}
	nanoCPUs := int64(cpus * 1e9)

	hostCfg := &container.HostConfig{
		// NO PortBindings — the sandbox is isolated from the host.
		Mounts:      mounts,
		AutoRemove:  false,
		SecurityOpt: []string{"no-new-privileges"},
		CapDrop:     []string{"ALL"},
		Resources: container.Resources{
			Memory:   memory,
			NanoCPUs: nanoCPUs,
		},
		RestartPolicy: container.RestartPolicy{Name: "no"},
		// NetworkMode must match the attached endpoint below so docker
		// doesn't also attach the container to the default bridge.
		NetworkMode: container.NetworkMode(SandboxNetworkName),
	}

	cfg := &container.Config{
		Image:        opts.Template.Repository,
		Env:          envList,
		ExposedPorts: exposedPorts,
		Labels: map[string]string{
			"com.trstudios.restorerunner":      "1",
			"com.trstudios.restorerunner.name": opts.ContainerName,
		},
	}

	netCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			SandboxNetworkName: {},
		},
	}

	created, err := c.api.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, opts.ContainerName)
	if err != nil {
		return nil, fmt.Errorf("container create: %w", err)
	}
	if err := c.api.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		// Best-effort cleanup before we return the error.
		_ = c.api.ContainerRemove(context.Background(), created.ID,
			container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("container start: %w", err)
	}

	return &RunResult{
		ContainerID:   created.ID,
		ContainerName: opts.ContainerName,
		WebUIPort:     webuiPort,
	}, nil
}

// Stop stops + removes a container. Idempotent — missing containers
// return nil.
func (c *Client) Stop(ctx context.Context, containerID string) error {
	if containerID == "" {
		return nil
	}
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	timeout := 10 // seconds
	err := c.api.ContainerStop(stopCtx, containerID, container.StopOptions{Timeout: &timeout})
	if err != nil && !client.IsErrNotFound(err) {
		return fmt.Errorf("stop: %w", err)
	}
	if err := c.api.ContainerRemove(ctx, containerID,
		container.RemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
		if client.IsErrNotFound(err) {
			return nil
		}
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

// Logs opens a streaming log reader for the container. Caller must Close
// the returned reader. Stdout + stderr are demultiplexed into a single
// stream.
func (c *Client) Logs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	rc, err := c.api.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "all",
		Timestamps: false,
	})
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer rc.Close()
		_, _ = stdcopy.StdCopy(pw, pw, rc)
	}()
	return pr, nil
}

// InspectIP returns the sandbox container's IPv4 address on the
// rr-sandbox-net network, or "" if it isn't attached yet.
func (c *Client) InspectIP(ctx context.Context, containerID string) (string, error) {
	j, err := c.api.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", err
	}
	if j.NetworkSettings == nil || j.NetworkSettings.Networks == nil {
		return "", errors.New("no network settings")
	}
	ep, ok := j.NetworkSettings.Networks[SandboxNetworkName]
	if !ok || ep == nil {
		return "", fmt.Errorf("container not attached to %s", SandboxNetworkName)
	}
	if ep.IPAddress == "" {
		return "", errors.New("ip address not yet assigned")
	}
	return ep.IPAddress, nil
}

// SweepOrphans looks for any container we previously created (identified
// by the com.trstudios.restorerunner=1 label we stamp on every sandbox
// container) that isn't in keepIDs. Used on startup to clean up from a
// crash or restart.
func (c *Client) SweepOrphans(ctx context.Context, keepIDs map[string]bool) ([]string, error) {
	list, err := c.api.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, ctr := range list {
		if ctr.Labels["com.trstudios.restorerunner"] != "1" {
			continue
		}
		if keepIDs[ctr.ID] {
			continue
		}
		name := ""
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}
		timeout := 5
		_ = c.api.ContainerStop(ctx, ctr.ID, container.StopOptions{Timeout: &timeout})
		if err := c.api.ContainerRemove(ctx, ctr.ID,
			container.RemoveOptions{Force: true, RemoveVolumes: true}); err == nil {
			removed = append(removed, name)
		}
	}
	return removed, nil
}

// EnsureSandboxNetwork creates (idempotently) the internal bridge network
// used by every sandbox. The --internal flag (Internal: true) means the
// network has no route to the host LAN or the public internet.
//
// Concurrent calls from multiple processes are fine: docker's network
// create returns an "already exists" error we swallow. We defend against
// racing-create by also re-listing if create fails.
func (c *Client) EnsureSandboxNetwork(ctx context.Context) error {
	// Cheap existence check first.
	list, err := c.api.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", SandboxNetworkName)),
	})
	if err == nil {
		for _, n := range list {
			if n.Name == SandboxNetworkName {
				return nil
			}
		}
	}
	_, err = c.api.NetworkCreate(ctx, SandboxNetworkName, network.CreateOptions{
		Driver:   "bridge",
		Internal: true,
		Labels:   map[string]string{"com.trstudios.restorerunner.net": "1"},
	})
	if err != nil {
		// Race: another RestoreRunner or docker process created it
		// between our list and our create. Re-list to confirm.
		list2, listErr := c.api.NetworkList(ctx, network.ListOptions{
			Filters: filters.NewArgs(filters.Arg("name", SandboxNetworkName)),
		})
		if listErr == nil {
			for _, n := range list2 {
				if n.Name == SandboxNetworkName {
					return nil
				}
			}
		}
		return fmt.Errorf("network create: %w", err)
	}
	return nil
}

// ConnectSelf attaches our own container to the sandbox network so we
// can reach sandbox containers on their internal IPs. selfID should be
// os.Hostname() inside the container (docker sets it to the short
// container id by default). If selfID is empty or detection fails, the
// caller can log a warning — the proxy will still work in many host
// topologies where docker0's bridge gives us line-of-sight.
//
// Idempotent: the API returns an error containing "already exists" when
// we're already attached; we swallow that.
func (c *Client) ConnectSelf(ctx context.Context, selfID string) error {
	if selfID == "" {
		return errors.New("empty self id")
	}
	// The short ID docker sets as HOSTNAME is a prefix of the full
	// container ID, which docker's API accepts directly.
	if err := c.api.NetworkConnect(ctx, SandboxNetworkName, selfID, nil); err != nil {
		msg := err.Error()
		low := strings.ToLower(msg)
		if strings.Contains(low, "already exists") ||
			strings.Contains(low, "already attached") ||
			strings.Contains(low, "endpoint with name") {
			return nil
		}
		return fmt.Errorf("network connect: %w", err)
	}
	return nil
}

// Close tears down the underlying Docker client.
func (c *Client) Close() error {
	return c.api.Close()
}

// --- mount construction ---------------------------------------------------

// buildMounts turns the XML's <Path> entries into docker bind mounts,
// with every source rewritten to live inside the run's extracted dir.
// The XML's original host path (e.g. /mnt/user/appdata/sonarr) is used
// ONLY as a hint for the subdir name within our extract tree — it is
// NEVER used as a mount source.
func buildMounts(opts RunOpts) ([]mount.Mount, error) {
	var mounts []mount.Mount
	for _, pm := range opts.Template.Paths {
		// Skip the docker socket entry if someone captured it in their
		// backup — we refuse to pass the host socket through.
		if strings.TrimSpace(pm.ContainerPath) == "/var/run/docker.sock" {
			continue
		}
		subdir, err := resolveExtractSubdir(opts.ExtractedDir, pm.HostPath, pm.ContainerPath)
		if err != nil {
			return nil, err
		}
		if subdir == "" {
			continue
		}
		mounts = append(mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   subdir,
			Target:   pm.ContainerPath,
			ReadOnly: pm.Mode == "ro",
		})
	}
	return mounts, nil
}

// resolveExtractSubdir picks a directory inside extractedDir that matches
// the XML <Path>. AppData Backup archives typically nest container
// appdata under appdata/<container-name>/; we prefer that layout when
// the XML target is /config (the Unraid convention for appdata).
//
// Matching strategy (best-first):
//  1. appdata/<basename>/ — AppData Backup layout
//  2. <basename>/         — older/manual layouts
//  3. if the extract has exactly one top-level dir, use that
//  4. fall back to the extract root
//
// In every case the returned path is guaranteed to resolve (after
// symlink evaluation) to a path inside extractedDir. If it escapes, we
// return an error rather than silently falling back.
func resolveExtractSubdir(extractedDir, hostPath, containerPath string) (string, error) {
	absExtract, err := filepath.Abs(extractedDir)
	if err != nil {
		return "", err
	}
	absExtract = filepath.Clean(absExtract)

	base := filepath.Base(strings.TrimRight(hostPath, "/"))
	// Reject pathological or traversal basenames. These would either
	// re-resolve to the extract root (safe but useless as a hint) or,
	// worse, feed back into a filepath.Join where Clean could collapse
	// the result somewhere unexpected. Safer to drop the hint and fall
	// back to single-top-level / extract-root resolution.
	if base == "" || base == "." || base == "/" || base == ".." ||
		strings.Contains(base, string(os.PathSeparator)) {
		base = ""
	}

	tryCandidates := []string{}
	if base != "" {
		tryCandidates = append(tryCandidates,
			filepath.Join(absExtract, "appdata", base),
			filepath.Join(absExtract, base),
		)
	}
	if only := onlyTopLevelDir(absExtract); only != "" {
		tryCandidates = append(tryCandidates, only)
	}
	tryCandidates = append(tryCandidates, absExtract)

	for _, cand := range tryCandidates {
		ok, err := isDirInside(cand, absExtract)
		if err != nil {
			return "", err
		}
		if ok {
			return cand, nil
		}
	}
	return absExtract, nil
}

// isDirInside returns (true, nil) if p exists as a directory and, after
// symlink evaluation, still lives inside root. If p doesn't exist,
// returns (false, nil). Any symlink escape returns an error.
func isDirInside(p, root string) (bool, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return false, nil
	}
	if !fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false, nil
	}
	absResolved, err := filepath.Abs(resolved)
	if err != nil {
		return false, err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	if absResolved != absRoot &&
		!strings.HasPrefix(absResolved+string(os.PathSeparator), absRoot+string(os.PathSeparator)) {
		return false, fmt.Errorf("extract subdir %q escapes extract root %q", p, root)
	}
	st, err := os.Stat(absResolved)
	if err != nil || !st.IsDir() {
		return false, nil
	}
	return true, nil
}

// onlyTopLevelDir returns the absolute path to the single top-level
// directory under extractedDir, or "" if there isn't exactly one.
func onlyTopLevelDir(extractedDir string) string {
	entries, err := os.ReadDir(extractedDir)
	if err != nil {
		return ""
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(extractedDir, e.Name()))
		}
	}
	if len(dirs) == 1 {
		return dirs[0]
	}
	return ""
}

// assertMountsSafe refuses to start a container if ANY mount source
// resolves to a live-host path that would collide with production data.
// Built-in denylist covers the Unraid appdata, share, boot, and
// /var/run/docker.sock paths; ExtraHostDeny (from env) adds more.
//
// Every source MUST live inside extractRoot — defence-in-depth against a
// path-rewriter bug. If ANY mount source starts with a denied prefix, we
// refuse to start and surface a clear error to the user.
func assertMountsSafe(mounts []mount.Mount, extractRoot string, extraDeny []string) error {
	absExtract, err := filepath.Abs(extractRoot)
	if err != nil {
		return err
	}
	absExtract = filepath.Clean(absExtract)

	deny := []string{
		"/mnt/user/appdata/",
		"/mnt/user/appdata", // exact match as well
		"/mnt/user0/appdata/",
		"/mnt/cache/appdata/",
		"/mnt/disks/",
		"/mnt/user/",
		"/boot/",
		"/etc/",
		"/var/run/docker.sock",
		"/var/lib/docker/",
	}
	for _, p := range extraDeny {
		p = strings.TrimSpace(p)
		if p != "" {
			deny = append(deny, p)
		}
	}
	for _, m := range mounts {
		if m.Type != mount.TypeBind {
			continue
		}
		src := filepath.Clean(m.Source)

		// 1. Must be absolute.
		if !filepath.IsAbs(src) {
			return fmt.Errorf("refusing to start: mount source %q is not absolute", m.Source)
		}

		// 2. Must not match any denylist prefix.
		for _, d := range deny {
			if src == strings.TrimRight(d, "/") ||
				strings.HasPrefix(src+string(os.PathSeparator), d) ||
				src == d {
				return fmt.Errorf("refusing to start: mount source %q collides with protected host path %q — the sandbox must never touch live host data", m.Source, d)
			}
		}

		// 3. Must resolve inside the extract root.
		resolved, err := filepath.EvalSymlinks(src)
		if err != nil {
			// Allow paths that don't yet exist only if lexically under
			// extract root (edge case: AppData Backup sometimes stores
			// empty dirs that don't survive round-tripping).
			if !strings.HasPrefix(src+string(os.PathSeparator), absExtract+string(os.PathSeparator)) && src != absExtract {
				return fmt.Errorf("refusing to start: mount source %q is outside extract root", m.Source)
			}
			continue
		}
		absResolved, err := filepath.Abs(resolved)
		if err != nil {
			return err
		}
		if absResolved != absExtract &&
			!strings.HasPrefix(absResolved+string(os.PathSeparator), absExtract+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to start: mount source %q resolves to %q — escape of extract root", m.Source, absResolved)
		}
	}
	return nil
}
