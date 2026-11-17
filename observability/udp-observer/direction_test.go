package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"testing"
	"time"
)

func directionObserver() *observer {
	return &observer{local: map[string]bool{"192.0.2.1": true, "2001:db8::1": true}, known: map[string]bool{}, counts: map[string]uint64{}, sensors: map[string]int{}, events: make(chan obj, 64), decode: make(chan decodePacket, 16), flows: map[string]*flow{}, origins: map[string]origin{}, directionReady: true, directionSeed: time.Now()}
}
func feed(o *observer, src, dst string, sp, dp uint16, v6 bool) {
	b := udpPacket(src, dst, sp, dp, []byte{0}, v6)
	o.packet(b, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(b), Length: len(b)})
}

func TestConntrackOriginalReplyAndSNAT(t *testing.T) {
	o := directionObserver()
	for _, line := range []string{
		"ipv4 2 udp 17 100 src=192.0.2.1 dst=198.51.100.53 sport=55000 dport=53 src=198.51.100.53 dst=192.0.2.1 sport=53 dport=55000 [ASSURED] mark=0 use=1",
		"ipv4 2 udp 17 100 src=203.0.113.4 dst=198.51.100.53 sport=12345 dport=443 src=198.51.100.53 dst=192.0.2.1 sport=443 dport=55001 [ASSURED] mark=0 use=1",
		"ipv6 10 udp 17 100 src=2001:db8::1 dst=2001:db8::2 sport=55002 dport=443 src=2001:db8::2 dst=2001:db8::1 sport=443 dport=55002 [ASSURED] mark=0 use=1",
	} {
		k, v, ok := conntrackOrigin(line, o.local, time.Now())
		if !ok || v.Inbound {
			t.Fatal(k, v, ok)
		}
		o.origins[k] = v
	}
	feed(o, "198.51.100.53", "192.0.2.1", 53, 55000, false)
	feed(o, "198.51.100.53", "192.0.2.1", 443, 55001, false)
	feed(o, "2001:db8::2", "2001:db8::1", 443, 55002, true)
	if len(o.events) != 0 || len(o.flows) != 0 || o.counts["excluded_reply"] != 3 {
		t.Fatal("restart replies became probes", o.counts)
	}
}
func TestFirstOutgoingIncludingBoundServicePortSuppressesReplies(t *testing.T) {
	o := directionObserver()
	for _, ports := range [][2]uint16{{55000, 53}, {55001, 443}, {443, 443}} {
		feed(o, "192.0.2.1", "198.51.100.2", ports[0], ports[1], false)
		feed(o, "198.51.100.2", "192.0.2.1", ports[1], ports[0], false)
	}
	if len(o.events) != 0 || len(o.flows) != 0 || o.counts["excluded_reply"] != 3 {
		t.Fatal(o.counts)
	}
}
func TestUnsolicitedHighPortAndIncomingReply(t *testing.T) {
	o := directionObserver()
	// Do not replace original direction with a source/destination-port heuristic.
	feed(o, "198.51.100.2", "192.0.2.1", 53, 55000, false)
	feed(o, "192.0.2.1", "198.51.100.2", 55000, 53, false)
	if len(o.events) != 2 {
		t.Fatal(len(o.events))
	}
	a, b := <-o.events, <-o.events
	if a["direction"] != "ingress" || a["origin_basis"] != "first_seen_incoming" || b["direction"] != "egress_reply" {
		t.Fatal(a, b)
	}
	// Already-open inbound session: its first observed packet may be a response.
	k, v, ok := conntrackOrigin("udp 17 120 src=198.51.100.3 dst=192.0.2.1 sport=1234 dport=443 src=192.0.2.1 dst=198.51.100.3 sport=443 dport=1234", o.local, time.Now())
	if !ok || !v.Inbound {
		t.Fatal(v)
	}
	o.origins[k] = v
	feed(o, "192.0.2.1", "198.51.100.3", 443, 1234, false)
	if d := <-o.events; d["direction"] != "egress_reply" || d["origin_basis"] != "conntrack_original" {
		t.Fatal(d)
	}
}
func TestUnavailableSeedDoesNotGuessAndDoesNotExposeEgress(t *testing.T) {
	o := directionObserver()
	o.directionReady = false
	feed(o, "198.51.100.53", "192.0.2.1", 53, 55000, false)
	if len(o.events) != 0 || o.counts["direction_wait_packets"] != 1 {
		t.Fatal(o.counts)
	}
	feed(o, "192.0.2.1", "198.51.100.53", 55000, 53, false)
	o.applyOrigins(originSnapshot{entries: map[string]origin{}})
	feed(o, "198.51.100.53", "192.0.2.1", 53, 55000, false)
	if len(o.events) != 0 || o.counts["excluded_reply"] != 1 {
		t.Fatal(o.counts)
	}
	feed(o, "198.51.100.4", "192.0.2.1", 1234, 1701, false)
	if len(o.events) != 1 {
		t.Fatal("pre-DROP probe missing")
	}
	b, _ := json.Marshal(<-o.events)
	if string(b) == "" {
		t.Fatal("no metadata")
	}
}
