// probe-blackhole follows local sanitized logs. No network listener or remote credentials.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type config struct {
	Node               string   `json:"node"`
	Local              []string `json:"local_ips"`
	Trusted            []string `json:"trusted_ips"`
	Listen             []int    `json:"listen_ports"`
	TLSGateEnabled     bool     `json:"tls_gate_enabled,omitempty"`
	TLSGateReadyPath   string   `json:"tls_gate_ready_path,omitempty"`
	TLSGateSourcesPath string   `json:"tls_gate_sources_path,omitempty"`
}
type event struct {
	Event   string `json:"event"`
	Node    string `json:"node"`
	At      string `json:"observed_utc"`
	Src     string `json:"src"`
	Client  string `json:"client"`
	Dst     string `json:"dst"`
	Port    string `json:"dport"`
	Flags   string `json:"flags"`
	Unit    string `json:"unit"`
	Message string `json:"message"`
	Request string `json:"request_line"`
	URI     string `json:"uri"`
}
type bucket struct {
	Ports      map[int]int64
	Paths      map[string]int64
	Fail       map[[32]byte]int64
	Last       int64
	Transport  bool
	Order      *list.Element
	ScanReason string
}
type engine struct {
	C                                                        config
	Trusted                                                  map[netip.Addr]bool
	Local                                                    map[string]bool
	Listen                                                   map[int]bool
	B                                                        map[netip.Addr]*bucket
	Banned                                                   map[netip.Addr]int64
	Released                                                 map[netip.Addr]int64
	Dry                                                      bool
	Events, Bans, NFTErrors, ReadErrors, Rotations, Capacity uint64
	History                                                  map[netip.Addr]banHistory
	TLSSources                                               map[netip.Addr]int64
	PendingReleases                                          map[netip.Addr]int64
	StatePath                                                string
	Dirty, PortReady                                         bool
	LastGC                                                   int64
	PersistenceErrors, PortConfigErrors                      uint64
	TLSSourceErrors                                          uint64
	SYNObservations, WindowEvictions                         uint64
	SYNWindows, TransportWindows                             *list.List
}

func newEngine(c config, dry bool) *engine {
	e := &engine{
		C: c, Dry: dry, PortReady: true,
		Trusted: map[netip.Addr]bool{}, Local: map[string]bool{}, Listen: map[int]bool{},
		B: map[netip.Addr]*bucket{}, Banned: map[netip.Addr]int64{},
		Released: map[netip.Addr]int64{}, PendingReleases: map[netip.Addr]int64{},
		History: map[netip.Addr]banHistory{}, TLSSources: map[netip.Addr]int64{},
		SYNWindows: list.New(), TransportWindows: list.New(),
	}
	for _, s := range append(c.Trusted, c.Local...) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			panic(err)
		}
		e.Trusted[a.Unmap()] = true
	}
	for _, s := range c.Local {
		e.Local[s] = true
	}
	for _, p := range c.Listen {
		e.Listen[p] = true
	}
	return e
}
func (e *engine) isBanned(ip netip.Addr) bool { _, ok := e.Banned[ip]; return ok }
func (e *engine) ban(ip netip.Addr, now int64, reason string) {
	if e.isBanned(ip) || !e.permittedSource(ip) {
		return
	}
	if len(e.Banned) >= 65536 {
		e.Capacity++
		return
	}
	if !e.Dry {
		if err := applyBan(ip); err != nil {
			e.NFTErrors++
			fmt.Fprintf(os.Stderr, "nft update failed: %v\n", err)
			return
		}
	}
	e.History[ip] = banHistory{Last: now, Strikes: 1}
	delete(e.Released, ip)
	e.Banned[ip] = 0
	e.Dirty = true
	e.Bans++
	// Persist the decision before returning to the event loop. The kernel entry
	// already has no timeout; journal/bootstrap also preserve migration evidence.
	if err := e.saveState(); err != nil {
		e.PersistenceErrors++
		fmt.Fprintf(os.Stderr, "state save failed: %v\n", err)
	}
	b, _ := json.Marshal(map[string]any{"at_utc": time.Unix(now, 0).UTC().Format(time.RFC3339), "ip": ip.String(), "reason": reason, "permanent": true, "expires_utc": nil, "duration_seconds": nil, "policy_version": 4, "dry_run": e.Dry})
	fmt.Println(string(b))
}
func (e *engine) consume(line []byte, now int64) {
	var v event
	if json.Unmarshal(line, &v) != nil {
		e.ReadErrors++
		return
	}
	if v.Node != e.C.Node {
		return
	}
	stamp, err := time.Parse(time.RFC3339Nano, v.At)
	if err != nil {
		return
	}
	t := stamp.Unix()
	if t < now-60 || t > now+5 {
		return
	}
	src := v.Src
	sshFailure := false
	if v.Event == "service" {
		var ok bool
		src, sshFailure, ok = sshSource(v.Unit, v.Message)
		if !ok {
			return
		}
	} else if src == "" {
		src = v.Client
	}
	ip, err := netip.ParseAddr(src)
	if err != nil {
		return
	}
	ip = ip.Unmap()
	if t <= e.Released[ip] {
		return
	}
	if e.Trusted[ip] || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return
	}
	if v.Event == "tcp" && !e.Local[v.Dst] {
		return
	}
	if v.Event != "tcp" && v.Event != "http" && v.Event != "service" {
		return
	}
	e.Events++
	if v.Event == "tcp" {
		flags, err := strconv.ParseUint(strings.TrimPrefix(v.Flags, "0x"), 16, 16)
		if err != nil || flags&2 == 0 || flags&0x15 != 0 {
			return
		}
		p, err := strconv.Atoi(v.Port)
		if err != nil || p < 1 || p > 65535 || e.Listen[p] || !e.PortReady {
			return
		}
	}
	b := e.window(ip, v.Event != "tcp")
	if b == nil {
		return
	}
	if t > b.Last {
		b.Last = t
	}
	for p, at := range b.Ports {
		if at < now-21600 || e.Listen[p] {
			delete(b.Ports, p)
		}
	}
	for p, at := range b.Paths {
		if at < now-60 {
			delete(b.Paths, p)
		}
	}
	for p, at := range b.Fail {
		if at < now-60 {
			delete(b.Fail, p)
		}
	}
	switch v.Event {
	case "tcp":
		p, err := strconv.Atoi(v.Port)
		_, tracked := b.Ports[p]
		if err == nil && p > 0 && p <= 65535 && (len(b.Ports) < 64 || tracked) {
			b.Ports[p] = t
			e.Dirty = true
		}
	case "http":
		path := sensitivePath(v.Request, v.URI)
		if path != "" && len(b.Paths) < 8 {
			b.Paths[path] = t
		}
	case "service":
		if sshFailure && len(b.Fail) < 16 {
			b.Fail[sha256.Sum256(append([]byte(v.At), []byte(v.Message)...))] = t
		}
	}
	if len(b.Paths) >= 2 {
		e.ban(ip, now, "multiple_sensitive_http_paths")
	} else if len(b.Fail) >= 8 {
		e.ban(ip, now, "repeated_ssh_failures")
	} else if e.PortReady {
		if reason := e.portReason(b, now); reason != "" {
			// Raw SYN source addresses have no return-path proof. A valid HTTP or
			// SSH connection from this IP cannot authenticate separate SYN tuples.
			// Retain the series as evidence without creating an IP-wide ban.
			if reason != b.ScanReason {
				b.ScanReason = reason
				e.SYNObservations++
				data, _ := json.Marshal(map[string]any{"event": "syn_sweep_observed", "at_utc": time.Unix(now, 0).UTC().Format(time.RFC3339), "ip": ip.String(), "reason": reason, "enforced": false})
				fmt.Println(string(data))
			}
		}
	}
}
func (e *engine) gc(now int64) {
	if now-e.LastGC < 5 {
		return
	}
	e.LastGC = now
	for ip, b := range e.B {
		for p, at := range b.Ports {
			if at < now-21600 {
				delete(b.Ports, p)
				e.Dirty = true
			}
		}
		if b.Last < now-60 && len(b.Ports) == 0 {
			e.dropWindow(ip)
			e.Dirty = true
		}
	}
}
func (e *engine) metrics(now int64) {
	s := fmt.Sprintf("qntw_probe_blackhole_heartbeat_seconds %d\nqntw_probe_blackhole_events_total %d\nqntw_probe_blackhole_bans_total %d\nqntw_probe_blackhole_nft_errors_total %d\nqntw_probe_blackhole_read_errors_total %d\nqntw_probe_blackhole_rotations_total %d\nqntw_probe_blackhole_capacity_dropped_total %d\nqntw_probe_blackhole_source_windows %d\n", now, e.Events, e.Bans, e.NFTErrors, e.ReadErrors, e.Rotations, e.Capacity, len(e.B))
	ready := 0
	if e.PortReady {
		ready = 1
	}
	s += fmt.Sprintf("qntw_probe_blackhole_policy_version 4\nqntw_probe_blackhole_port_policy_ready %d\nqntw_probe_blackhole_persistence_errors_total %d\nqntw_probe_blackhole_port_config_errors_total %d\nqntw_probe_blackhole_active_bans %d\n", ready, e.PersistenceErrors, e.PortConfigErrors, len(e.Banned))
	s += fmt.Sprintf("qntw_probe_blackhole_syn_observations_total %d\nqntw_probe_blackhole_window_evictions_total %d\n", e.SYNObservations, e.WindowEvictions)
	gate := 0
	if e.C.TLSGateEnabled {
		gate = 1
	}
	s += fmt.Sprintf("qntw_probe_blackhole_tls_gate_configured %d\nqntw_probe_blackhole_tls_sources %d\nqntw_probe_blackhole_tls_source_errors_total %d\n", gate, len(e.TLSSources), e.TLSSourceErrors)
	p := "/var/lib/node_exporter/textfile/probe_blackhole.prom"
	if err := os.WriteFile(p+".tmp", []byte(s), 0644); err == nil {
		_ = os.Rename(p+".tmp", p)
	}
}
func scan(r io.Reader, consume func([]byte), limit int) (int64, error) {
	b := bufio.NewReaderSize(r, 65536)
	var n int64
	for i := 0; i < limit; i++ {
		line, err := b.ReadBytes('\n')
		if err != nil {
			return n, err
		}
		n += int64(len(line))
		consume(line)
	}
	return n, nil
}
func recoverTail(path string, marker []byte, offset int64, e *engine, now int64) {
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "events-*.jsonl.gz"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	for i, p := range files {
		if i >= 6 {
			break
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			continue
		}
		head := make([]byte, len(marker))
		_, err = io.ReadFull(gz, head)
		if err != nil || !bytes.Equal(head, marker) {
			gz.Close()
			f.Close()
			continue
		}
		if offset >= int64(len(head)) {
			_, err = io.CopyN(io.Discard, gz, offset-int64(len(head)))
			if err == nil {
				_, _ = scan(gz, func(b []byte) { e.consume(b, now) }, 1000000)
			}
		}
		gz.Close()
		f.Close()
		return
	}
	e.ReadErrors++
}
func main() {
	cfgFile := flag.String("config", "/etc/vpnshop-security/probe-blackhole.json", "config")
	replay := flag.String("replay", "", "offline JSONL replay, requires -dry-run")
	dry := flag.Bool("dry-run", false, "never change nftables")
	unban := flag.String("unban", "", "remove one source; daemon must be stopped")
	importFile := flag.String("import", "", "one-time historical source list; daemon must be stopped")
	migrateTLS := flag.String("migrate-tls-sources", "", "explicit root-audited TLS-only JSON source list; daemon must be stopped")
	syncTLS := flag.Bool("sync-tls-sources", false, "one-time private gate source synchronization; daemon must be stopped")
	flag.Parse()
	if *syncTLS && (*dry || *replay != "" || *unban != "" || *importFile != "" || *migrateTLS != "") {
		panic("TLS source synchronization is a separate maintenance operation; daemon must be stopped")
	}
	data, err := os.ReadFile(*cfgFile)
	if err != nil {
		panic(err)
	}
	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	if c.Node == "shop-pl" {
		panic("shop-pl is excluded from probe blackhole")
	}
	if c.Node == "" || len(c.Local) == 0 || len(c.Trusted) == 0 {
		panic("incomplete config")
	}
	e := newEngine(c, *dry)
	if *replay != "" {
		if !*dry {
			panic("replay requires dry-run")
		}
		f, err := os.Open(*replay)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		_, err = scan(f, func(b []byte) {
			var v event
			if json.Unmarshal(b, &v) != nil {
				return
			}
			t, err := time.Parse(time.RFC3339Nano, v.At)
			if err == nil {
				e.consume(b, t.Unix())
				e.gc(t.Unix())
			}
		}, 10000000)
		if err != nil && err != io.EOF {
			panic(err)
		}
		return
	}
	e.refreshListen()
	e.StatePath = "/var/lib/vpnshop-probe-blackhole/state.json"
	if err := e.loadState(time.Now().Unix()); err != nil {
		panic(err)
	}
	if err := e.finishReleases(removeBan); err != nil {
		panic(err)
	}
	if *syncTLS {
		// Like import/migration/unban, this explicit maintenance operation must
		// run with the daemon stopped to avoid concurrent state replacement.
		if !c.TLSGateEnabled {
			panic("TLS source synchronization requires opted-in node")
		}
		if err := e.syncTLSGateSources(time.Now().Unix()); err != nil {
			panic(err)
		}
		if err := e.saveState(); err != nil {
			panic(err)
		}
		fmt.Printf("tls_sources=%d\n", len(e.TLSSources))
		return
	}
	if *migrateTLS != "" {
		if !c.TLSGateEnabled || *dry || *replay != "" || *unban != "" || *importFile != "" {
			panic("TLS-only migration requires opted-in node and a separate maintenance operation")
		}
		data, err := os.ReadFile(*migrateTLS)
		if err != nil {
			panic(err)
		}
		var sources []string
		if len(data) > 8*1024*1024 || json.Unmarshal(data, &sources) != nil || len(sources) > 65536 {
			panic("invalid audited TLS source list")
		}
		for _, src := range sources {
			ip, err := netip.ParseAddr(src)
			if err != nil || !e.permittedSource(ip.Unmap()) {
				panic("invalid audited TLS source")
			}
		}
		for _, src := range sources {
			if err := e.migrateTLSSource(netip.MustParseAddr(src).Unmap(), time.Now().Unix()); err != nil {
				panic(err)
			}
		}
		fmt.Printf("tls_sources=%d\n", len(e.TLSSources))
		return
	}
	if *importFile != "" {
		if *dry || *replay != "" || *unban != "" {
			panic("import is a separate maintenance operation")
		}
		data, err := os.ReadFile(*importFile)
		if err != nil {
			panic(err)
		}
		var ips []string
		if err = json.Unmarshal(data, &ips); err != nil {
			panic(err)
		}
		for _, src := range ips {
			ip, err := netip.ParseAddr(src)
			if err != nil {
				panic(err)
			}
			ip = ip.Unmap()
			if e.permittedSource(ip) {
				if len(e.Banned) >= 65536 && !e.isBanned(ip) {
					panic("permanent source capacity")
				}
				e.Banned[ip] = 0
				if _, ok := e.History[ip]; !ok {
					e.History[ip] = banHistory{Last: time.Now().Unix(), Strikes: 1}
				}
			}
		}
		e.Dirty = true
		if err = e.saveState(); err != nil {
			panic(err)
		}
		fmt.Printf("permanent_sources=%d\n", len(e.Banned))
		return
	}
	if *unban != "" {
		if *dry || *replay != "" {
			panic("unban is separate from dry-run/replay")
		}
		ip, err := netip.ParseAddr(*unban)
		if err != nil {
			panic(err)
		}
		ip = ip.Unmap()
		if ip.Zone() != "" {
			panic("zone identifiers are not supported")
		}
		if err = e.releaseSource(ip, time.Now().Unix(), removeBan); err != nil {
			panic(err)
		}
		fmt.Printf("removed %s\n", ip)
		return
	}
	path := "/var/log/vpnshop-probes/events.jsonl"

	var offset int64
	var marker []byte
	lastMetrics := int64(0)
	lastListen := int64(0)
	for {
		now := time.Now().Unix()
		if now-lastListen >= 30 {
			e.refreshListen()
			lastListen = now
		}
		f, err := os.Open(path)
		if err != nil {
			e.ReadErrors++
			time.Sleep(time.Second)
			continue
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			time.Sleep(time.Second)
			continue
		}
		size := st.Size()
		headSize := int64(256)
		if size < headSize {
			headSize = size
		}
		head := make([]byte, headSize)
		_, _ = f.ReadAt(head, 0)
		if len(marker) > 0 && (size < offset || (len(head) >= len(marker) && !bytes.Equal(marker, head[:len(marker)]))) {
			recoverTail(path, marker, offset, e, now)
			offset = 0
			marker = nil
			e.Rotations++
		}
		if len(marker) == 0 && len(head) > 0 {
			marker = head
		}
		_, err = f.Seek(offset, io.SeekStart)
		if err == nil {
			n, readErr := scan(f, func(b []byte) { e.consume(b, time.Now().Unix()) }, 5000)
			offset += n
			if readErr != nil && readErr != io.EOF {
				e.ReadErrors++
			}
		}
		f.Close()
		e.gc(now)
		if now-lastMetrics >= 5 {
			if err := e.syncTLSGateSources(now); err != nil {
				e.TLSSourceErrors++
				fmt.Fprintf(os.Stderr, "TLS source synchronization failed: %v\n", err)
			}
			e.adoptKernelBans(now)
			if err := e.saveState(); err != nil {
				e.PersistenceErrors++
				fmt.Fprintf(os.Stderr, "state save failed: %v\n", err)
			}
			e.metrics(now)
			lastMetrics = now
		}
		time.Sleep(250 * time.Millisecond)
	}
}
