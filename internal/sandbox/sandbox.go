// Package sandbox wraps the Docker Engine API for RestoreRunner's single
// job: spin up one container from an extracted Unraid backup, stream its
// logs, and tear it down on request.
//
// Every container we start has:
//
//   - A random unused host port for each XML-declared container port
//   - Resource caps (--memory=1g --cpus=1.0) so a runaway container can't
//     DoS the host
//   - no-new-privileges + cap-drop=ALL (no SYS_ADMIN, no NET_RAW, etc)
//   - AutoRemove=false — we want to collect final logs even after exit
//   - Explicit bind mounts only for the paths declared in the XML, rooted
//     inside the already-extracted uploads dir (never arbitrary host paths)
//
// We DELIBERATELY do NOT pass the host docker socket through to the
// sandboxed container. If the image needs it, the container will fail and
// we surface that in the logs. Granting docker-in-docker would give a
// restored malicious backup full host compromise.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"

	"github.com/trstudios/restore-runner/internal/unraidxml"
)

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
	HostPort      int // the assigned host port for the primary XML port
}

// RunOpts is what Run takes. ExtractedDir is the root of the uploaded
// archive's extract (everything lives under here). MountBase maps each
// XML Path entry's HostPath (wherever the Unraid user had it, e.g.
// /mnt/user/appdata/sonarr) to a subdir of ExtractedDir.
type RunOpts struct {
	ContainerName string
	Template      *unraidxml.Template
	ExtractedDir  string // absolute path inside OUR container (under /config/uploads/<uuid>/extracted)
	MemoryBytes   int64
	CPUs          float64
}

// Run pulls the image, constructs the container spec, and starts it.
// Returns the new container ID + the assigned host port for the primary
// XML-declared port (the first <Config Type="Port">).
func (c *Client) Run(ctx context.Context, opts RunOpts) (*RunResult, error) {
	if opts.Template == nil || opts.Template.Repository == "" {
		return nil, errors.New("template has no repository")
	}
	if opts.ExtractedDir == "" {
		return nil, errors.New("extracted dir required")
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

	// --- Pick free host ports for every XML-declared port. ---
	portBindings := nat.PortMap{}
	exposedPorts := nat.PortSet{}
	primaryHostPort := 0
	for i, p := range opts.Template.Ports {
		proto := p.Mode
		if proto == "" {
			proto = "tcp"
		}
		hostPort, err := freePort()
		if err != nil {
			return nil, fmt.Errorf("free port for %d/%s: %w", p.ContainerPort, proto, err)
		}
		natPort := nat.Port(fmt.Sprintf("%d/%s", p.ContainerPort, proto))
		exposedPorts[natPort] = struct{}{}
		portBindings[natPort] = []nat.PortBinding{{
			HostIP:   "0.0.0.0",
			HostPort: fmt.Sprintf("%d", hostPort),
		}}
		if i == 0 {
			primaryHostPort = hostPort
		}
	}

	// --- Build bind mounts. Each <Path> entry gets a bind mount rooted
	// inside our extracted dir. The original Unraid HostPath (e.g.
	// /mnt/user/appdata/sonarr) is used only as a hint for the subdir
	// name within our extract tree — we NEVER mount arbitrary host paths.
	var mounts []mount.Mount
	for _, pm := range opts.Template.Paths {
		subdir := subdirForPath(opts.ExtractedDir, pm.HostPath)
		if subdir == "" {
			continue // no matching subdir in the extract; skip
		}
		mounts = append(mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   subdir,
			Target:   pm.ContainerPath,
			ReadOnly: pm.Mode == "ro",
		})
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
		PortBindings:   portBindings,
		Mounts:         mounts,
		AutoRemove:     false,
		SecurityOpt:    []string{"no-new-privileges"},
		CapDrop:        []string{"ALL"},
		Resources: container.Resources{
			Memory:   memory,
			NanoCPUs: nanoCPUs,
		},
		// RestartPolicy is "no" — we want one-shot behaviour.
		RestartPolicy: container.RestartPolicy{Name: "no"},
	}

	cfg := &container.Config{
		Image:        opts.Template.Repository,
		Env:          envList,
		ExposedPorts: exposedPorts,
		Labels: map[string]string{
			"com.trstudios.restorerunner": "1",
			"com.trstudios.restorerunner.name": opts.ContainerName,
		},
	}

	created, err := c.api.ContainerCreate(ctx, cfg, hostCfg, nil, nil, opts.ContainerName)
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
		HostPort:      primaryHostPort,
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
	// The Docker Engine log stream is a framed multiplexed protocol
	// (8-byte header per chunk). Demux into a single plain stream.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer rc.Close()
		_, _ = stdcopy.StdCopy(pw, pw, rc)
	}()
	return pr, nil
}

// SweepOrphans looks for any container we previously created (identified
// by the com.trstudios.restorerunner=1 label we stamp on every sandbox
// container) that isn't in keepIDs. Used on startup to clean up from a
// crash or restart.
//
// Label-based filtering (not name prefix) is important: a friendly-looking
// name like "rr-something" could easily collide with a user's host
// container — and the sweep would then nuke the RestoreRunner instance
// itself during startup, which we discovered the hard way.
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
		// Best-effort stop + remove.
		timeout := 5
		_ = c.api.ContainerStop(ctx, ctr.ID, container.StopOptions{Timeout: &timeout})
		if err := c.api.ContainerRemove(ctx, ctr.ID,
			container.RemoveOptions{Force: true, RemoveVolumes: true}); err == nil {
			removed = append(removed, name)
		}
	}
	return removed, nil
}

// Close tears down the underlying Docker client.
func (c *Client) Close() error {
	return c.api.Close()
}

// --- helpers ---------------------------------------------------------------

// freePort asks the kernel for a free TCP port by listening on :0.
// There's a race between close and actual reuse but for our single-user
// homelab use it's fine — and it's the only way to get a guaranteed-free
// ephemeral port without parsing /proc/net/tcp.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// subdirForPath picks a directory inside extractedDir that matches the
// basename of the Unraid-declared host path. AppData Backup archives
// typically contain a single top-level dir named after the container
// (e.g. extracted/sonarr/), which is what we want to bind.
//
// Matching strategy (best-first):
//   1. Exact basename match: extractedDir/<basename>
//   2. If no match, and the extract only has one top-level dir, use that.
//   3. Otherwise, fall back to the extract root itself.
func subdirForPath(extractedDir, hostPath string) string {
	base := filepath.Base(strings.TrimRight(hostPath, "/"))
	if base == "" || base == "." || base == "/" {
		return extractedDir
	}
	candidate := filepath.Join(extractedDir, base)
	if st, err := statDir(candidate); err == nil && st {
		return candidate
	}
	if only := onlyTopLevelDir(extractedDir); only != "" {
		return only
	}
	return extractedDir
}

func statDir(p string) (bool, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
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
