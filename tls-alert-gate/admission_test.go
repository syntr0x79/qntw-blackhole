package main

import "testing"

func TestPerSourceActiveLimitLeavesCapacityForOtherSources(t *testing.T) {
	c := defaults()
	c.MaxConnections = 4
	c.MaxConnectionsPerIP = 2
	g := &gate{cfg: c, trusted: map[string]bool{}, slots: make(chan struct{}, c.MaxConnections), activePerIP: map[string]int{}}
	if !g.beginConnection("192.0.2.1") || !g.beginConnection("192.0.2.1") {
		t.Fatal("permitted source connections refused")
	}
	if g.beginConnection("192.0.2.1") {
		t.Fatal("source consumed another source's remaining capacity")
	}
	if !g.beginConnection("192.0.2.2") || !g.beginConnection("192.0.2.2") {
		t.Fatal("one source prevented another source from connecting")
	}
	if g.beginConnection("192.0.2.3") {
		t.Fatal("global capacity exceeded")
	}
	g.endConnection("192.0.2.1")
	if !g.beginConnection("192.0.2.1") {
		t.Fatal("completed source connection retained its allowance")
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.2"} {
		g.endConnection(ip)
	}
	if g.counts.Active.Load() != 0 || len(g.activePerIP) != 0 || len(g.slots) != 0 {
		t.Fatal("active admission state leaked after release")
	}
	if g.counts.SourceCapacity.Load() != 1 {
		t.Fatal("per-source capacity rejection was not recorded")
	}
}

func TestTrustedSourcesRetainGlobalConnectionLimit(t *testing.T) {
	c := defaults()
	c.MaxConnections = 2
	c.MaxConnectionsPerIP = 1
	g := &gate{cfg: c, trusted: map[string]bool{"192.0.2.1": true}, slots: make(chan struct{}, c.MaxConnections), activePerIP: map[string]int{}}
	if !g.beginConnection("192.0.2.1") || !g.beginConnection("192.0.2.1") {
		t.Fatal("trusted source was restricted by the per-IP limit")
	}
	if g.beginConnection("192.0.2.1") {
		t.Fatal("trusted source exceeded global capacity")
	}
	g.endConnection("192.0.2.1")
	g.endConnection("192.0.2.1")
}

func TestPerSourceActiveLimitDefaultsAndValidation(t *testing.T) {
	c := defaults()
	c.Node = "test"
	if c.connectionLimitPerIP() != 256 {
		t.Fatal("automatic per-source limit did not reserve capacity")
	}
	c.MaxConnections = 4
	if c.connectionLimitPerIP() != 4 {
		t.Fatal("automatic source limit exceeds global capacity")
	}
	c.MaxPending = 4
	c.MaxPendingPerIP = 4
	for _, value := range []int{-1, 5} {
		c.MaxConnectionsPerIP = value
		if err := validateConfig(c); err == nil {
			t.Fatalf("invalid per-IP connection limit %d accepted", value)
		}
	}
	for _, value := range []int{0, 1, 4} {
		c.MaxConnectionsPerIP = value
		if err := validateConfig(c); err != nil {
			t.Fatalf("valid per-IP connection limit %d rejected: %v", value, err)
		}
	}
}
