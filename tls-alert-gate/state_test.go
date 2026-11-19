package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRememberPersistsPrivateStateAndManualRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known.json")
	bh := filepath.Join(dir, "blackhole.json")
	m, e := loadSources("test", path, bh)
	if e != nil {
		t.Fatal(e)
	}
	if m.contains("192.0.2.20") {
		t.Fatal("unseen source exists")
	}
	if _, e = m.remember("192.0.2.20"); e != nil {
		t.Fatal(e)
	}
	loaded, e := loadSources("test", path, bh)
	if e != nil || !loaded.contains("192.0.2.20") {
		t.Fatalf("persistent memory lost:%v", e)
	}
	s, _ := os.Stat(path)
	if s.Mode().Perm() != 0600 {
		t.Fatal("state permissions")
	}
	first := loaded.sources["192.0.2.20"]
	// Existing blackhole unban wins, including an unban in the same second.
	v := map[string]any{"node": "test", "released_at": map[string]int64{"192.0.2.20": first}}
	if e = privateWrite(bh, v); e != nil {
		t.Fatal(e)
	}
	if e = loaded.refreshReleased(); e != nil {
		t.Fatal(e)
	}
	if loaded.contains("192.0.2.20") {
		t.Fatal("manual release ignored")
	}
	if _, e = loaded.remember("192.0.2.20"); e != nil {
		t.Fatal(e)
	}
	if !loaded.contains("192.0.2.20") || loaded.sources["192.0.2.20"] <= first {
		t.Fatal("fresh matching probe did not supersede release")
	}
	raw, _ := os.ReadFile(path)
	var decoded sourceState
	if e = json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.Sources["192.0.2.20"] > time.Now().Unix()+1 {
		t.Fatal("remembered time escaped bounded same-second adjustment")
	}
}
func TestPersistentStateOwnershipNodeAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known.json")
	if e := privateWrite(path, sourceState{Version: 1, Node: "other", Sources: map[string]int64{}}); e != nil {
		t.Fatal(e)
	}
	if _, e := loadSources("test", path, ""); e == nil {
		t.Fatal("foreign node state accepted")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(dir, "missing"), path)
	if _, e := loadSources("test", path, ""); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestPersistenceFailureRetainsInMemoryClassification(t *testing.T) {
	m := &sourceMemory{node: "test", path: filepath.Join(t.TempDir(), "not-dir", "known.json"), sources: map[string]int64{}, released: map[string]int64{}}
	os.WriteFile(filepath.Dir(m.path), []byte("x"), 0600)
	if _, e := m.remember("192.0.2.20"); e == nil {
		t.Fatal("expected persistence failure")
	}
	if !m.contains("192.0.2.20") {
		t.Fatal("disk failure would forward recognized scanner")
	}
	if !m.dirty || m.retryPersistence() == nil {
		t.Fatal("failed state write lost its retry requirement")
	}
	if err := os.Remove(filepath.Dir(m.path)); err != nil {
		t.Fatal(err)
	}
	if err := m.retryPersistence(); err != nil {
		t.Fatalf("state did not persist after storage recovered: %v", err)
	}
	if m.dirty {
		t.Fatal("successful retry retained dirty state")
	}
	loaded, err := loadSources("test", m.path, "")
	if err != nil || !loaded.contains("192.0.2.20") {
		t.Fatalf("classification did not survive recovered persistence: %v", err)
	}
	before, err := os.Stat(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.retryPersistence(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(m.path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("clean retry rewrote the state unnecessarily: %v", err)
	}
}
func TestPendingBounds(t *testing.T) {
	g := &gate{cfg: config{MaxPending: 2, MaxPendingPerIP: 1}, pending: map[string]int{}}
	if !g.beginPending("one") || g.beginPending("one") || !g.beginPending("two") || g.beginPending("three") {
		t.Fatal("pending caps not enforced")
	}
	g.endPending("one")
	if !g.beginPending("three") {
		t.Fatal("pending slot not reclaimed")
	}
}

func TestMigratedTLSClassificationIsSeededAndManualUnbanClearsBuckets(t *testing.T) {
	dir := t.TempDir()
	bh := filepath.Join(dir, "bh.json")
	known := filepath.Join(dir, "known.json")
	first := time.Now().Unix() - 10
	if e := privateWrite(bh, map[string]any{"node": "test", "tls_sources": map[string]int64{"192.0.2.20": first}, "released_at": map[string]int64{}}); e != nil {
		t.Fatal(e)
	}
	m, e := loadSources("test", known, bh)
	if e != nil || !m.contains("192.0.2.20") {
		t.Fatalf("migration failed:%v", e)
	}
	d := newDetector()
	d.observe("192.0.2.20", normalizedFeature("x", baselineCaps()), 1000)
	d.forget("192.0.2.20")
	n, _ := d.status()
	if n != 0 {
		t.Fatal("released source retained accumulated profiles")
	}
	seen := map[string]int64{}
	if len(m.releaseChanges(seen)) != 0 {
		t.Fatal("unexpected release")
	}
	if e = privateWrite(bh, map[string]any{"node": "test", "tls_sources": map[string]int64{"192.0.2.20": first}, "released_at": map[string]int64{"192.0.2.20": first + 1}}); e != nil {
		t.Fatal(e)
	}
	if e = m.refreshReleased(); e != nil {
		t.Fatal(e)
	}
	if m.contains("192.0.2.20") {
		t.Fatal("unban did not win")
	}
	if len(m.releaseChanges(seen)) != 1 || len(m.releaseChanges(seen)) != 0 {
		t.Fatal("release changes not edge-triggered")
	}
}
func TestDisabledListenerFamilyAllowsEmptyBackend(t *testing.T) {
	c := defaults()
	c.Node = "test"
	c.ListenV6 = ""
	c.BackendV6 = ""
	if e := validateConfig(c); e != nil {
		t.Fatal(e)
	}
	c.ListenV6 = "[::]:14443"
	if e := validateConfig(c); e == nil {
		t.Fatal("enabled family accepted empty backend")
	}
}
