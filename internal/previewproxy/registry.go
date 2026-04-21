package previewproxy

import (
	"sync"
)

// Registry maps a run ID to the proxy instance serving that run's
// sandboxed WebUI. All exported methods are safe for concurrent use.
type Registry struct {
	mu sync.RWMutex
	m  map[string]*Proxy
}

// NewRegistry returns a ready-to-use Registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[string]*Proxy)}
}

// Set replaces any proxy already registered for runID.
func (r *Registry) Set(runID string, p *Proxy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[runID] = p
}

// Get returns the proxy for runID, or (nil, false).
func (r *Registry) Get(runID string) (*Proxy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.m[runID]
	return p, ok
}

// Delete removes the proxy for runID. Called from Stop/Delete/Relaunch
// handlers so stale state from a prior run can't leak into a new one
// (e.g. when the user relaunches, we want a fresh IP lookup).
func (r *Registry) Delete(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, runID)
}
