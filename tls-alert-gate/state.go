package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type sourceState struct {
	Version int              `json:"version"`
	Node    string           `json:"node"`
	Sources map[string]int64 `json:"sources"`
}
type sourceMemory struct {
	mu                        sync.Mutex
	node, path, blackholePath string
	sources, released         map[string]int64
	dirty                     bool
}

func loadSources(node, path, bhpath string) (*sourceMemory, error) {
	m := &sourceMemory{node: node, path: path, blackholePath: bhpath, sources: map[string]int64{}, released: map[string]int64{}}
	s, e := os.Lstat(path)
	if os.IsNotExist(e) {
		if e = m.refreshReleased(); e != nil {
			return nil, e
		}
		return m, nil
	}
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() > 16<<20 {
		return nil, errors.New("unsafe known-source state")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var v sourceState
	if e = json.NewDecoder(io.LimitReader(f, 16<<20)).Decode(&v); e != nil {
		return nil, e
	}
	if v.Version != 1 || v.Node != node || len(v.Sources) > 65536 {
		return nil, errors.New("invalid known-source state")
	}
	for ip, at := range v.Sources {
		a, e := netip.ParseAddr(ip)
		if e != nil || a.Unmap().String() != ip || at <= 0 {
			return nil, errors.New("invalid remembered address or time")
		}
		m.sources[ip] = at
	}
	if e = m.refreshReleased(); e != nil {
		return nil, e
	}
	return m, nil
}
func (m *sourceMemory) refreshReleased() error {
	if m.blackholePath == "" {
		return nil
	}
	s, e := os.Lstat(m.blackholePath)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() > 32<<20 {
		return errors.New("unsafe blackhole state")
	}
	f, e := os.Open(m.blackholePath)
	if e != nil {
		return e
	}
	defer f.Close()
	var v struct {
		Node     string           `json:"node"`
		Released map[string]int64 `json:"released_at"`
		TLS      map[string]int64 `json:"tls_sources"`
	}
	if e = json.NewDecoder(io.LimitReader(f, 32<<20)).Decode(&v); e != nil {
		return e
	}
	if v.Node != m.node || len(v.Released) > 65536 || len(v.TLS) > 65536 {
		return errors.New("invalid blackhole release state")
	}
	for ip, first := range v.TLS {
		addr, err := netip.ParseAddr(ip)
		if err != nil || addr.Unmap().String() != ip || first <= 0 || first > time.Now().Unix()+5 {
			return errors.New("invalid migrated TLS source")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.released = v.Released
	if m.released == nil {
		m.released = map[string]int64{}
	}
	changed := false
	for ip, first := range v.TLS {
		if first <= m.released[ip] || first <= m.sources[ip] {
			continue
		}
		if _, ok := m.sources[ip]; !ok && len(m.sources) >= 65536 {
			return errors.New("migrated TLS source capacity")
		}
		m.sources[ip] = first
		m.dirty = true
		changed = true
	}
	if changed {
		return m.persistLocked()
	}
	return nil
}

func (m *sourceMemory) ensureFile() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.persistLocked()
}

// The caller holds m.mu. A failed durable write remains eligible for retry
// even when no further scanner reaches the gate after storage recovers.
func (m *sourceMemory) persistLocked() error {
	err := privateWrite(m.path, sourceState{Version: 1, Node: m.node, Sources: m.sources})
	m.dirty = err != nil
	return err
}

func (m *sourceMemory) retryPersistence() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dirty {
		return nil
	}
	return m.persistLocked()
}
func (m *sourceMemory) contains(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	first, ok := m.sources[ip]
	return ok && first > m.released[ip]
}
func (m *sourceMemory) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for ip, first := range m.sources {
		if first > m.released[ip] {
			n++
		}
	}
	return n
}

func (m *sourceMemory) releaseChanges(seen map[string]int64) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := []string{}
	for ip, at := range m.released {
		if at > seen[ip] {
			seen[ip] = at
			changed = append(changed, ip)
		}
	}
	return changed
}
func privateWrite(path string, value any) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	s, e := os.Lstat(dir)
	if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe state directory")
	}
	f, e := os.CreateTemp(dir, ".tls-alert-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if e = json.NewEncoder(f).Encode(value); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	directory, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer directory.Close()
	return directory.Sync()
}
func (m *sourceMemory) remember(ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if first, ok := m.sources[ip]; ok && first > m.released[ip] {
		return false, nil
	}
	if _, ok := m.sources[ip]; !ok && len(m.sources) >= 65536 {
		return false, errors.New("known-source capacity reached")
	}
	now := time.Now().Unix()
	if now <= m.released[ip] {
		now = m.released[ip] + 1
	}
	m.sources[ip] = now
	// The classification remains in memory if persistence fails; it must never
	// turn into forwarding this same source to the VPN backend on a disk error.
	return true, m.persistLocked()
}
