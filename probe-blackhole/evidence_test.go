package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func consumeEvent(e *engine, value event, at int64) {
	value.Node = "test"
	value.At = time.Unix(at, 0).UTC().Format(time.RFC3339Nano)
	data, _ := json.Marshal(value)
	e.consume(data, at)
}

func TestSSHUsesServerAuthoredAddress(t *testing.T) {
	for _, tc := range []struct {
		message string
		failure bool
	}{
		{"Failed password for invalid user name from 1.1.1.1 port 1234 ssh2 from 8.8.8.8 port 4567 ssh2", true},
		{"Failed password [redacted] invalid user name from 1.1.1.1 port 1234 ssh2 from 8.8.8.8 port 4567 ssh2", true},
		{"Invalid user name from 1.1.1.1 from 8.8.8.8 port 4567", true},
		{"Connection closed by invalid user name 1.1.1.1 8.8.8.8 port 4567 [preauth]", false},
		{"Accepted publickey for Invalid user from 1.1.1.1 port 999 ssh2 from 8.8.8.8 port 4567 ssh2: RSA test", false},
		{"Unable to negotiate with 8.8.8.8 port 4567: no matching key exchange method found. Their offer: from 1.1.1.1", true},
		{"Bad protocol version identification 'from 1.1.1.1 port 333' from 8.8.8.8 port 4567", true},
	} {
		src, failure, ok := sshSource("sshd.service", tc.message)
		if !ok || src != "8.8.8.8" || failure != tc.failure {
			t.Errorf("message=%q src=%q failure=%v accepted=%v", tc.message, src, failure, ok)
		}
	}
	for _, tc := range []struct{ unit, message string }{
		{"xray.service", "Failed password for invalid user test from 1.1.1.1 port 4567 ssh2"},
		{"", "Failed password for invalid user test from 1.1.1.1 port 4567 ssh2"},
		{"sshd.service", "arbitrary text from 1.1.1.1"},
		{"sshd.service", "Invalid user test from 1.1.1.1 port 99999"},
		{"sshd.service", "pam_unix(sshd:auth): authentication failure; rhost=1.1.1.1 user=attacker rhost=8.8.8.8"},
	} {
		if _, _, ok := sshSource(tc.unit, tc.message); ok {
			t.Errorf("accepted unstructured or unrelated service record: %+v", tc)
		}
	}
}

func TestSSHInjectedSourceNeverBansVictim(t *testing.T) {
	e := fixture()
	for i := 0; i < 8; i++ {
		consumeEvent(e, event{Event: "service", Unit: "sshd.service", Src: "1.1.1.1", Message: "Invalid user name from 1.1.1.1 from 8.8.8.8 port 4567"}, 100000+int64(i))
	}
	if e.isBanned(netip.MustParseAddr("1.1.1.1")) || !e.isBanned(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("SSH identity came from username or event src instead of server-authored tuple")
	}
}

func TestSensitivePathsAreCanonicalAndNested(t *testing.T) {
	for raw, want := range map[string]string{
		"/admin/.env":                        "/admin/.env",
		"/api/%2eenv?anything=value":         "/api/.env",
		"/a/../.git/config":                  "/.git/config",
		"/a//.git/config":                    "/a/.git/config",
		"https://example.invalid/admin/.env": "/admin/.env",
		"/.env.production":                   "/.env.production",
		"/documentation/environment":         "",
		"/help/.environment":                 "",
		"/foo.git/config":                    "",
		"/%zz/.env":                          "",
	} {
		if got := sensitivePath("GET "+raw+" HTTP/1.1", ""); got != want {
			t.Errorf("path=%q got=%q want=%q", raw, got, want)
		}
	}
	e := fixture()
	for _, target := range []string{"/api/.env", "/api/%2eenv", "/x/../api/.env"} {
		consumeEvent(e, event{Event: "http", Src: "8.8.8.8", Request: "GET " + target}, 100000)
	}
	if e.Bans != 0 {
		t.Fatal("aliases of one sensitive path counted as distinct paths")
	}
	consumeEvent(e, event{Event: "http", Src: "8.8.8.8", URI: "/admin/.git/config"}, 100001)
	if e.Bans != 1 {
		t.Fatal("nested sensitive path discovery missed")
	}
}

func TestSYNSourceRemainsUnprovedAfterRealHTTP(t *testing.T) {
	e := fixture()
	consumeEvent(e, event{Event: "http", Src: "8.8.8.8", Request: "GET /"}, 100000)
	for i := 0; i < 32; i++ {
		syn(e, "8.8.8.8", 10000+i, 100001, "0x0002")
	}
	if e.Bans != 0 || e.SYNObservations == 0 {
		t.Fatal("unrelated HTTP connection authenticated spoofable SYN tuples")
	}
}

func TestSYNWindowSprayCannotExcludeHTTP(t *testing.T) {
	e := fixture()
	consumeEvent(e, event{Event: "http", Src: "8.8.8.8", Request: "GET /.env"}, 100000)
	for i := 0; i < 6000; i++ {
		syn(e, fmt.Sprintf("11.%d.%d.%d", i>>16, (i>>8)&255, i&255), 10000, 100000, "0x0002")
	}
	if len(e.B) != 5000 || e.WindowEvictions != 1001 {
		t.Fatalf("windows=%d evictions=%d", len(e.B), e.WindowEvictions)
	}
	consumeEvent(e, event{Event: "http", Src: "8.8.8.8", Request: "GET /.git/config"}, 100001)
	if !e.isBanned(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("SYN spray erased HTTP evidence")
	}
	for _, target := range []string{"/.env", "/.git/config"} {
		consumeEvent(e, event{Event: "http", Src: "1.1.1.1", Request: "GET " + target}, 100002)
	}
	if !e.isBanned(netip.MustParseAddr("1.1.1.1")) || len(e.B) > 5000 {
		t.Fatal("SYN spray excluded new HTTP source or exceeded memory bound")
	}
}

func TestFailedReleaseSurvivesRestart(t *testing.T) {
	e := fixture()
	e.Dry = false
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	ip := netip.MustParseAddr("8.8.8.8")
	e.Banned[ip] = 0
	e.History[ip] = banHistory{Last: 99900, Strikes: 1}
	fail := func(netip.Addr) error { return fmt.Errorf("synthetic nft failure") }
	if err := e.releaseSource(ip, 100000, fail); err == nil {
		t.Fatal("release reported success after failed kernel removal")
	}
	restarted := fixture()
	restarted.StatePath = e.StatePath
	if err := restarted.loadState(100001); err != nil {
		t.Fatal(err)
	}
	if restarted.isBanned(ip) || restarted.PendingReleases[ip] != 100000 || restarted.Released[ip] != 100000 {
		t.Fatal("failed release lost durable intent")
	}
	if err := restarted.adoptKernelJSON([]byte(`{"nftables":[{"set":{"name":"permanent_v4","elem":["8.8.8.8"]}}]}`), 100001); err != nil {
		t.Fatal(err)
	}
	if restarted.isBanned(ip) {
		t.Fatal("old kernel element undid unfinished release")
	}
	called := 0
	remove := func(got netip.Addr) error {
		if got != ip {
			t.Fatalf("removed wrong source %s", got)
		}
		called++
		return nil
	}
	if err := restarted.finishReleases(remove); err != nil || called != 0 {
		t.Fatal("dry-run touched kernel release")
	}
	restarted.Dry = false
	if err := restarted.finishReleases(fail); err == nil {
		t.Fatal("startup accepted failed pending removal")
	}
	if err := restarted.finishReleases(remove); err != nil || called != 1 {
		t.Fatalf("retry failed: %v calls=%d", err, called)
	}
	final := fixture()
	final.StatePath = e.StatePath
	if err := final.loadState(100002); err != nil {
		t.Fatal(err)
	}
	if final.isBanned(ip) || len(final.PendingReleases) != 0 || final.Released[ip] != 100000 {
		t.Fatal("completed release not committed")
	}
}

func TestReleasePersistenceFailureLeavesKernelUntouched(t *testing.T) {
	e := fixture()
	e.Dry = false
	// A directory cannot be replaced with the state file.
	e.StatePath = t.TempDir()
	called := false
	err := e.releaseSource(netip.MustParseAddr("8.8.8.8"), 100000, func(netip.Addr) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("kernel removal ran before durable release intent")
	}
}

func TestLegacyWindowAliasesPreserveBoundsAndQueue(t *testing.T) {
	e := fixture()
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	windows := map[string]savedWindow{}
	for offset, ip := range []string{"8.8.8.8", "::ffff:8.8.8.8"} {
		ports := map[int]int64{}
		for port := 10000; port < 10064; port++ {
			ports[port+offset*100] = 100000
		}
		windows[ip] = savedWindow{Ports: ports, Last: 100000 + int64(offset*999999)}
	}
	state := savedState{Version: 2, Node: "test", Windows: windows}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(e.StatePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.loadState(100001); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("8.8.8.8")
	if len(e.B) != 1 || len(e.B[ip].Ports) != 64 || e.SYNWindows.Len() != 1 || e.B[ip].Last != 100000 {
		t.Fatal("legacy aliases exceeded limits, duplicated queue entries or retained invalid future timestamp")
	}
	e.dropWindow(ip)
	if len(e.B) != 0 || e.SYNWindows.Len() != 0 {
		t.Fatal("legacy window removal left queue entry")
	}
}
