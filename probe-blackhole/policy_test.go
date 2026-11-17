package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() *engine {
	return newEngine(config{Node: "test", Local: []string{"198.18.0.1"}, Trusted: []string{"203.0.113.99"}, Listen: []int{22, 80, 443, 8443}}, true)
}
func syn(e *engine, ip string, port int, at int64, flags string) {
	data, _ := json.Marshal(event{Event: "tcp", Node: "test", At: time.Unix(at, 0).UTC().Format(time.RFC3339Nano), Src: ip, Dst: "198.18.0.1", Port: fmt.Sprint(port), Flags: flags})
	e.consume(data, at)
}
func TestPortSweeps(t *testing.T) {
	for _, tc := range []struct {
		name           string
		count, spacing int
		want           bool
	}{{"fast", 8, 1, true}, {"slow", 12, 65, true}, {"very_slow", 32, 400, true}, {"below_fast", 7, 1, false}, {"below_slow", 11, 65, false}, {"too_sparse", 32, 800, false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture()
			for i := 0; i < tc.count; i++ {
				syn(e, "8.8.8.8", 10000+i, 100000+int64(i*tc.spacing), "0x0002")
			}
			if (e.SYNObservations > 0) != tc.want || e.Bans != 0 {
				t.Fatalf("observations=%d bans=%d", e.SYNObservations, e.Bans)
			}
		})
	}
}
func TestLegitimateAndRetransmits(t *testing.T) {
	t.Run("retransmits", func(t *testing.T) {
		e := fixture()
		for i := 0; i < 100; i++ {
			syn(e, "8.8.8.8", 10000, 100000+int64(i), "0x0002")
		}
		if e.Bans != 0 {
			t.Fatal("retransmits counted as ports")
		}
	})
	t.Run("service_ports", func(t *testing.T) {
		e := fixture()
		for i := 1; i <= 40; i++ {
			e.Listen[i] = true
			syn(e, "8.8.8.8", i, 100000, "0x0002")
		}
		if e.Bans != 0 || len(e.B) != 0 {
			t.Fatal("advertised ports included")
		}
	})
	t.Run("trusted", func(t *testing.T) {
		e := fixture()
		for i := 0; i < 50; i++ {
			syn(e, "203.0.113.99", 10000+i, 100000, "0x0002")
		}
		if e.Bans != 0 {
			t.Fatal("trusted source banned")
		}
	})
	t.Run("no_port_inventory", func(t *testing.T) {
		e := fixture()
		e.PortReady = false
		for i := 0; i < 50; i++ {
			syn(e, "8.8.8.8", 10000+i, 100000, "0x0002")
		}
		if e.Bans != 0 {
			t.Fatal("ban with unavailable port inventory")
		}
	})
	t.Run("syn_ack_outbound", func(t *testing.T) {
		e := fixture()
		for i := 0; i < 50; i++ {
			syn(e, "8.8.8.8", 10000+i, 100000, "0x0012")
		}
		if e.Bans != 0 {
			t.Fatal("reply counted")
		}
	})
	t.Run("ecn_syn", func(t *testing.T) {
		e := fixture()
		for i := 0; i < 8; i++ {
			syn(e, "8.8.8.8", 10000+i, 100000, "0x00c2")
		}
		if e.SYNObservations != 1 || e.Bans != 0 {
			t.Fatal("ECN SYN observation missed or unproved source banned")
		}
	})
}
func TestPermanentLifetime(t *testing.T) {
	e := fixture()
	ip := netip.MustParseAddr("8.8.8.8")
	e.ban(ip, 100000, "test")
	e.gc(100000 + 365*86400)
	e.ban(ip, 100000+365*86400, "test")
	if !e.isBanned(ip) || e.Bans != 1 {
		t.Fatal("permanent ban expired or was counted twice")
	}
}
func TestStateAndRestart(t *testing.T) {
	e := fixture()
	ip := netip.MustParseAddr("8.8.8.8")
	e.Dry = false
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	e.History[ip] = banHistory{Last: 100000, Strikes: 2}
	e.Banned[ip] = 0
	e.B[ip] = &bucket{Ports: map[int]int64{12345: 100000}, Last: 100000}
	e.Dirty = true
	if err := e.saveState(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(e.StatePath)
	if st.Mode().Perm() != 0600 {
		t.Fatal("state mode")
	}
	other := fixture()
	other.StatePath = e.StatePath
	if err := other.loadState(100100); err != nil {
		t.Fatal(err)
	}
	if other.History[ip].Strikes != 2 || !other.isBanned(ip) || other.B[ip].Ports[12345] != 100000 {
		t.Fatal("restart state lost")
	}
	// A changed role must immediately exempt newly advertised ports.
	other.Listen[12345] = true
	if other.portReason(other.B[ip], 100100) != "" {
		t.Fatal("role change not respected")
	}
}
func TestKernelBanAdoption(t *testing.T) {
	e := fixture()
	data := []byte(`{"nftables":[{"set":{"name":"sources_v4","elem":[{"elem":{"val":"8.8.8.8","timeout":120000}},"203.0.113.99"]}},{"set":{"name":"sources_v6","elem":[{"elem":{"val":"2001:4860:4860::8888"}}]}}]}`)
	if err := e.adoptKernelJSON(data, 100000); err != nil {
		t.Fatal(err)
	}
	if e.Bans != 2 {
		t.Fatalf("adoption bans=%d", e.Bans)
	}
	if err := e.adoptKernelJSON(data, 100005); err != nil {
		t.Fatal(err)
	}
	if e.Bans != 2 {
		t.Fatal("adopted repeatedly")
	}
	if err := e.adoptKernelJSON([]byte(`{"nftables":[{"set":{"name":"sources_v4","elem":[{"elem":{"val":"8.8.4.4","expires":0}}]}}]}`), 100000); err != nil {
		t.Fatal(err)
	}
	if e.Bans != 3 {
		t.Fatal("legacy expired decision was not imported permanently")
	}
}
func TestHTTPAndSSHStillWork(t *testing.T) {
	e := fixture()
	for _, path := range []string{"/.env", "/.git/config"} {
		data, _ := json.Marshal(event{Event: "http", Node: "test", At: time.Unix(100000, 0).UTC().Format(time.RFC3339), Src: "8.8.8.8", Request: "GET " + path + " HTTP/1.1"})
		e.consume(data, 100000)
	}
	if e.Bans != 1 {
		t.Fatal("HTTP detection lost")
	}
	e = fixture()
	for i := 0; i < 8; i++ {
		data, _ := json.Marshal(event{Event: "service", Unit: "sshd.service", Node: "test", At: time.Unix(100000+int64(i), 0).UTC().Format(time.RFC3339), Message: fmt.Sprintf("Failed password for invalid user test%d from 8.8.8.8 port 999 ssh2", i)})
		e.consume(data, 100000+int64(i))
	}
	if e.Bans != 1 {
		t.Fatal("SSH detection lost")
	}
}
func TestNFTNamespace(t *testing.T) {
	if os.Getenv("QNTW_NFT_NETNS_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	// Always create the namespace here: setting the opt-in environment flag
	// alone must never allow this fixture to modify the caller's firewall.
	if os.Getenv("QNTW_NFT_NETNS_TEST_CHILD") != "1" {
		parentNS, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "--net", "--", binary, "-test.run=^TestNFTNamespace$", "-test.v")
		cmd.Env = append(os.Environ(), "QNTW_NFT_NETNS_TEST_CHILD=1", "QNTW_NFT_NETNS_TEST_PARENT_NS="+parentNS)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated nft test: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parentNS := os.Getenv("QNTW_NFT_NETNS_TEST_PARENT_NS")
	if parentNS == "" || currentNS == parentNS {
		t.Fatal("nft fixture refused: namespace transition not independently verified")
	}
	init := "table inet qntw_probe_blackhole {\nset sources_v4 {type ipv4_addr;flags dynamic,timeout;timeout 120s;size 2048;}\nset sources_v6 {type ipv6_addr;flags dynamic,timeout;timeout 120s;size 2048;}\nset permanent_v4 {type ipv4_addr;flags dynamic;size 65536;}\nset permanent_v6 {type ipv6_addr;flags dynamic;size 65536;}\nset tls_sources_v4 {type ipv4_addr;flags dynamic;size 65536;}\nset tls_sources_v6 {type ipv6_addr;flags dynamic;size 65536;}\n}\n"
	if _, err := runNft([]string{"-f", "-"}, init); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		ip := netip.MustParseAddr(src)
		if err := applyBan(ip); err != nil {
			t.Fatal(err)
		}
		if err := applyBan(ip); err != nil {
			t.Fatal(err)
		}
	}
	data, err := runNft([]string{"-j", "list", "table", "inet", "qntw_probe_blackhole"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"timeout":900`) {
		t.Fatal("unexpected expiration")
	}
	if !strings.Contains(string(data), "8.8.8.8") || !strings.Contains(string(data), "2001:4860:4860::8888") {
		t.Fatal("permanent addresses missing")
	}
	e := fixture()
	if err = e.adoptKernelJSON(data, 100000); err != nil {
		t.Fatal(err)
	}
	if e.Bans != 2 {
		t.Fatalf("real nft JSON adoption: bans=%d", e.Bans)
	}
	// Exercise an audited move, independent general promotion, and operator
	// release against real nft sets, not only in-memory maps.
	e.Dry = false
	e.C.TLSGateEnabled = true
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	ip := netip.MustParseAddr("8.8.8.8")
	if err := e.migrateTLSSource(ip, 100010); err != nil {
		t.Fatal(err)
	}
	if _, err := runNft([]string{"get", "element", "inet", "qntw_probe_blackhole", "tls_sources_v4", "{ 8.8.8.8 }"}, ""); err != nil {
		t.Fatal("TLS classification missing", err)
	}
	if _, err := runNft([]string{"get", "element", "inet", "qntw_probe_blackhole", "permanent_v4", "{ 8.8.8.8 }"}, ""); err == nil {
		t.Fatal("audited TLS source remained general-banned")
	}
	e.ban(ip, 100020, "syn_sweep_8_unadvertised_ports_60s")
	if _, err := runNft([]string{"get", "element", "inet", "qntw_probe_blackhole", "permanent_v4", "{ 8.8.8.8 }"}, ""); err != nil {
		t.Fatal("general promotion missing", err)
	}
	if err := removeBan(ip); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"permanent_v4", "tls_sources_v4"} {
		if _, err := runNft([]string{"get", "element", "inet", "qntw_probe_blackhole", name, "{ 8.8.8.8 }"}, ""); err == nil {
			t.Fatalf("manual release left address in %s", name)
		}
	}
}

func TestMigrateExpiredV2(t *testing.T) {
	e := fixture()
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	data := `{"version":2,"node":"test","history":{"8.8.8.8":{"last":100000,"strikes":2}},"banned":{"8.8.4.4":100100},"windows":{}}`
	if err := os.WriteFile(e.StatePath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.loadState(100000 + 7*86400); err != nil {
		t.Fatal(err)
	}
	if !e.isBanned(netip.MustParseAddr("8.8.8.8")) || !e.isBanned(netip.MustParseAddr("8.8.4.4")) {
		t.Fatal("expired confirmed source lost in migration")
	}
}

func TestManualReleaseIgnoresOldLogReplay(t *testing.T) {
	e := fixture()
	ip := netip.MustParseAddr("8.8.8.8")
	e.Released[ip] = 100100
	for i := 0; i < 8; i++ {
		syn(e, ip.String(), 20000+i, 100090+int64(i), "0x0002")
	}
	if e.Bans != 0 {
		t.Fatal("manual release undone by old log replay")
	}
	for i := 0; i < 8; i++ {
		syn(e, ip.String(), 20000+i, 100200+int64(i), "0x0002")
	}
	if e.Bans != 0 || e.SYNObservations != 1 {
		t.Fatal("new SYN series after manual release was not observed safely")
	}
}

func TestTLSOnlySourcesCanPromoteToGeneralScannerBans(t *testing.T) {
	e := fixture()
	ip := netip.MustParseAddr("8.8.8.8")
	if err := e.addTLSSource(ip, 100000, 100000); err != nil {
		t.Fatal(err)
	}
	if e.isBanned(ip) || len(e.History) != 0 || e.Bans != 0 {
		t.Fatal("TLS-only source became a general ban")
	}
	for i := 0; i < 8; i++ {
		syn(e, ip.String(), 20000+i, 100001+int64(i), "0x0002")
	}
	if e.isBanned(ip) || e.Bans != 0 || e.SYNObservations != 1 {
		t.Fatal("spoofable SYNs promoted TLS source to a permanent general ban")
	}
	for _, path := range []string{"/.env", "/.git/config"} {
		data, _ := json.Marshal(event{Event: "http", Node: "test", At: time.Unix(100010, 0).UTC().Format(time.RFC3339), Src: ip.String(), Request: "GET " + path + " HTTP/1.1"})
		e.consume(data, 100010)
	}
	if !e.isBanned(ip) || e.Bans != 1 {
		t.Fatal("independent HTTP scanning did not promote TLS source")
	}
}

func TestTLSGateDocumentValidationAndTrustedExclusions(t *testing.T) {
	e := fixture()
	doc := `{"version":1,"node":"test","sources":{"8.8.8.8":100000,"203.0.113.99":100000,"198.18.0.1":100000,"127.0.0.1":100000,"10.1.2.3":100000}}`
	if err := e.importTLSGateSources([]byte(doc), 100010); err != nil {
		t.Fatal(err)
	}
	if len(e.TLSSources) != 1 || e.TLSSources[netip.MustParseAddr("8.8.8.8")] != 100000 {
		t.Fatal("trusted/local/private address imported")
	}
	for _, invalid := range []string{
		`{"version":1,"node":"other","sources":{"1.1.1.1":100000}}`,
		`{"version":2,"node":"test","sources":{"1.1.1.1":100000}}`,
		`{"version":1,"node":"test","sources":{"1.1.1.1":100020}}`,
		`{"version":1,"node":"test","sources":{"not-an-ip":100000}}`,
	} {
		if err := e.importTLSGateSources([]byte(invalid), 100010); err == nil {
			t.Fatal("invalid document accepted")
		}
		if len(e.TLSSources) != 1 {
			t.Fatal("partially imported invalid document")
		}
	}
}

func TestTLSManualReleaseIgnoresGateReplayButAllowsNewDetection(t *testing.T) {
	e := fixture()
	ip := netip.MustParseAddr("8.8.8.8")
	e.Released[ip] = 100100
	if err := e.importTLSGateSources([]byte(`{"version":1,"node":"test","sources":{"8.8.8.8":100000}}`), 100110); err != nil {
		t.Fatal(err)
	}
	if len(e.TLSSources) != 0 {
		t.Fatal("stale gate inventory undid manual release")
	}
	if err := e.importTLSGateSources([]byte(`{"version":1,"node":"test","sources":{"8.8.8.8":100101}}`), 100110); err != nil {
		t.Fatal(err)
	}
	if e.TLSSources[ip] != 100101 {
		t.Fatal("new post-release TLS detection was ignored")
	}
}

func TestTLSKernelAdoptionDoesNotBecomeGeneralBan(t *testing.T) {
	e := fixture()
	data := []byte(`{"nftables":[{"set":{"name":"tls_sources_v4","elem":["8.8.8.8","203.0.113.99"]}},{"set":{"name":"permanent_v4","elem":["1.1.1.1"]}}]}`)
	if err := e.adoptKernelJSON(data, 100000); err != nil {
		t.Fatal(err)
	}
	if e.isBanned(netip.MustParseAddr("8.8.8.8")) || len(e.TLSSources) != 1 || !e.isBanned(netip.MustParseAddr("1.1.1.1")) || e.Bans != 1 {
		t.Fatal("kernel TLS and general inventories mixed")
	}
}

func TestTLSNewKernelClassificationAfterManualRelease(t *testing.T) {
	e := fixture()
	ip := netip.MustParseAddr("8.8.8.8")
	e.Released[ip] = 100100
	// The unban command removed the old TLS element. An inline match on a
	// different port can subsequently add it again, without going via gate443.
	data := []byte(`{"nftables":[{"set":{"name":"tls_sources_v4","elem":["8.8.8.8"]}}]}`)
	if err := e.adoptKernelJSON(data, 100101); err != nil {
		t.Fatal(err)
	}
	if e.TLSSources[ip] != 100101 || e.isBanned(ip) {
		t.Fatal("new inline TLS detection was not persisted separately")
	}
}

func TestTLSStateSurvivesRestartWithoutHistoryPromotion(t *testing.T) {
	e := fixture()
	e.StatePath = filepath.Join(t.TempDir(), "state.json")
	ip := netip.MustParseAddr("8.8.8.8")
	e.TLSSources[ip] = 100000
	e.Dry, e.Dirty = false, true
	if err := e.saveState(); err != nil {
		t.Fatal(err)
	}
	other := fixture()
	other.StatePath = e.StatePath
	if err := other.loadState(100010); err != nil {
		t.Fatal(err)
	}
	if other.TLSSources[ip] != 100000 || other.isBanned(ip) || len(other.History) != 0 {
		t.Fatal("TLS source lost or promoted on restart")
	}
}

func TestTLSGateSourceFileIsOptInAndPrivate(t *testing.T) {
	e := fixture()
	e.C.TLSGateSourcesPath = filepath.Join(t.TempDir(), "sources.json")
	if err := e.syncTLSGateSources(100000); err != nil {
		t.Fatal("disabled feature attempted source read")
	}
	e.C.TLSGateEnabled = true
	doc := []byte(`{"version":1,"node":"test","sources":{"8.8.8.8":100000}}`)
	if err := os.WriteFile(e.C.TLSGateSourcesPath, doc, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.syncTLSGateSources(100000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.C.TLSGateSourcesPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := e.syncTLSGateSources(100000); err == nil {
		t.Fatal("publicly readable source file accepted")
	}
	link := e.C.TLSGateSourcesPath + ".link"
	if err := os.Symlink(e.C.TLSGateSourcesPath, link); err != nil {
		t.Fatal(err)
	}
	e.C.TLSGateSourcesPath = link
	if err := e.syncTLSGateSources(100000); err == nil {
		t.Fatal("symlink source file accepted")
	}
}

func TestTLSMigrationRequiresOptInAndLeavesOtherGeneralBans(t *testing.T) {
	e := fixture()
	ip, other := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")
	e.Banned[ip], e.Banned[other] = 0, 0
	e.History[ip] = banHistory{Last: 100000, Strikes: 1}
	e.History[other] = banHistory{Last: 100000, Strikes: 1}
	if err := e.migrateTLSSource(ip, 100010); err == nil || !e.isBanned(ip) {
		t.Fatal("migration without explicit gate opt-in")
	}
	e.C.TLSGateEnabled = true
	if err := e.migrateTLSSource(ip, 100010); err != nil {
		t.Fatal(err)
	}
	if e.isBanned(ip) || e.History[ip].Strikes != 0 || e.TLSSources[ip] != 100000 || !e.isBanned(other) {
		t.Fatal("audited migration changed wrong classification")
	}
	if err := e.migrateTLSSource(ip, 100010); err != nil {
		t.Fatal("migration not idempotent")
	}
}
