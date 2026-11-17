package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type banHistory struct {
	Last    int64 `json:"last"`
	Strikes int   `json:"strikes"`
}
type savedWindow struct {
	Ports map[int]int64 `json:"ports"`
	Last  int64         `json:"last"`
}
type savedState struct {
	Version    int                    `json:"version"`
	Node       string                 `json:"node"`
	History    map[string]banHistory  `json:"history"`
	Banned     map[string]int64       `json:"banned"`
	Windows    map[string]savedWindow `json:"windows"`
	Released   map[string]int64       `json:"released_at,omitempty"`
	TLSSources map[string]int64       `json:"tls_sources,omitempty"`
}

func (e *engine) portReason(b *bucket, now int64) string {
	fast, slow, long := 0, 0, 0
	for p, at := range b.Ports {
		if e.Listen[p] || at > now+5 {
			continue
		}
		if at >= now-60 {
			fast++
		}
		if at >= now-900 {
			slow++
		}
		if at >= now-21600 {
			long++
		}
	}
	if fast >= 8 {
		return "syn_sweep_8_unadvertised_ports_60s"
	}
	if slow >= 12 {
		return "syn_sweep_12_unadvertised_ports_15m"
	}
	if long >= 32 {
		return "syn_sweep_32_unadvertised_ports_6h"
	}
	return ""
}
func runNft(args []string, input string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w (%d output bytes)", err, len(out))
	}
	return out, nil
}
func applyBan(ip netip.Addr) error { return applyBans([]netip.Addr{ip}) }
func applyBans(ips []netip.Addr) error {
	for start := 0; start < len(ips); start += 512 {
		end := start + 512
		if end > len(ips) {
			end = len(ips)
		}
		var b strings.Builder
		for _, ip := range ips[start:end] {
			family := "permanent_v4"
			if ip.Is6() {
				family = "permanent_v6"
			}
			fmt.Fprintf(&b, "add element inet qntw_probe_blackhole %s { %s }\n", family, ip)
		}
		if _, err := runNft([]string{"-f", "-"}, b.String()); err != nil {
			return err
		}
	}
	return nil
}
func removeBan(ip netip.Addr) error {
	var b strings.Builder
	families := []string{"sources_v4", "permanent_v4", "tls_sources_v4"}
	if ip.Is6() {
		families = []string{"sources_v6", "permanent_v6", "tls_sources_v6"}
	}
	for _, family := range families {
		fmt.Fprintf(&b, "add element inet qntw_probe_blackhole %s { %s }\ndelete element inet qntw_probe_blackhole %s { %s }\n", family, ip, family, ip)
	}
	_, err := runNft([]string{"-f", "-"}, b.String())
	return err
}

func applyTLSSources(ips []netip.Addr) error {
	for start := 0; start < len(ips); start += 512 {
		end := start + 512
		if end > len(ips) {
			end = len(ips)
		}
		var b strings.Builder
		for _, ip := range ips[start:end] {
			family := "tls_sources_v4"
			if ip.Is6() {
				family = "tls_sources_v6"
			}
			fmt.Fprintf(&b, "add element inet qntw_probe_blackhole %s { %s }\n", family, ip)
		}
		if _, err := runNft([]string{"-f", "-"}, b.String()); err != nil {
			return err
		}
	}
	return nil
}

// A TLS-only classification never implies a general scanner ban. The latter
// can still be established independently by port, HTTP or SSH evidence.
func (e *engine) addTLSSource(ip netip.Addr, first, now int64) error {
	ip = ip.Unmap()
	if !e.permittedSource(ip) || first <= 0 || first > now+5 || first <= e.Released[ip] {
		return nil
	}
	if previous, ok := e.TLSSources[ip]; ok {
		if first < previous {
			e.TLSSources[ip] = first
			e.Dirty = true
		}
		return nil
	}
	if len(e.TLSSources) >= 65536 {
		e.Capacity++
		return fmt.Errorf("TLS source capacity")
	}
	if !e.Dry {
		if err := applyTLSSources([]netip.Addr{ip}); err != nil {
			return err
		}
	}
	e.TLSSources[ip] = first
	e.Dirty = true
	return nil
}

func (e *engine) importTLSGateSources(data []byte, now int64) error {
	var state struct {
		Version int              `json:"version"`
		Node    string           `json:"node"`
		Sources map[string]int64 `json:"sources"`
	}
	if len(data) > 8*1024*1024 || json.Unmarshal(data, &state) != nil || state.Version != 1 || state.Node != e.C.Node || len(state.Sources) > 65536 {
		return fmt.Errorf("invalid TLS source metadata")
	}
	// Validate the complete document before mutating the current inventory.
	for src, first := range state.Sources {
		ip, err := netip.ParseAddr(src)
		if err != nil || ip.Zone() != "" || first <= 0 || first > now+5 {
			return fmt.Errorf("invalid TLS source entry")
		}
	}
	for src, first := range state.Sources {
		if err := e.addTLSSource(netip.MustParseAddr(src), first, now); err != nil {
			return err
		}
	}
	return nil
}

func (e *engine) syncTLSGateSources(now int64) error {
	if !e.C.TLSGateEnabled {
		return nil
	}
	path := e.C.TLSGateSourcesPath
	if path == "" {
		path = "/var/lib/vpnshop-tls-alert/known-sources.json"
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("TLS source path must be absolute")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ok || int(owner.Uid) != os.Geteuid() || owner.Nlink != 1 {
		return fmt.Errorf("unsafe TLS source file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 8*1024*1024+1))
	if err != nil {
		return err
	}
	return e.importTLSGateSources(data, now)
}

// Only an explicit operator-audited source list may move old general bans.
// The command does not infer provenance from a fingerprint or kernel state.
func (e *engine) migrateTLSSource(ip netip.Addr, now int64) error {
	if !e.C.TLSGateEnabled || !e.permittedSource(ip) {
		return fmt.Errorf("TLS migration not permitted")
	}
	if _, exists := e.TLSSources[ip]; exists && !e.isBanned(ip) {
		return nil
	}
	if !e.isBanned(ip) {
		return fmt.Errorf("audited source has no general ban")
	}
	first := e.History[ip].Last
	if first <= 0 {
		first = now
	}
	if first <= e.Released[ip] {
		return fmt.Errorf("audited source predates manual release")
	}
	if len(e.TLSSources) >= 65536 {
		if _, ok := e.TLSSources[ip]; !ok {
			return fmt.Errorf("TLS source capacity")
		}
	}
	if !e.Dry {
		family := "v4"
		if ip.Is6() {
			family = "v6"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "add element inet qntw_probe_blackhole tls_sources_%s { %s }\n", family, ip)
		for _, name := range []string{"permanent_", "sources_"} {
			fmt.Fprintf(&b, "add element inet qntw_probe_blackhole %s%s { %s }\ndelete element inet qntw_probe_blackhole %s%s { %s }\n", name, family, ip, name, family, ip)
		}
		if _, err := runNft([]string{"-f", "-"}, b.String()); err != nil {
			return err
		}
	}
	delete(e.Banned, ip)
	delete(e.History, ip)
	e.TLSSources[ip] = first
	e.Dirty = true
	return e.saveState()
}
func (e *engine) permittedSource(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() && !e.Trusted[ip.Unmap()]
}
func (e *engine) adoptKernelJSON(data []byte, now int64) error {
	var root struct {
		NFTables []struct {
			Set *struct {
				Name     string            `json:"name"`
				Elements []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	seen := map[netip.Addr]bool{}
	seenTLS := map[netip.Addr]bool{}
	for _, entry := range root.NFTables {
		if entry.Set == nil {
			continue
		}
		name := entry.Set.Name
		if name != "sources_v4" && name != "sources_v6" && name != "permanent_v4" && name != "permanent_v6" && name != "tls_sources_v4" && name != "tls_sources_v6" {
			continue
		}
		for _, raw := range entry.Set.Elements {
			var value string
			if json.Unmarshal(raw, &value) != nil {
				var w struct {
					Elem struct {
						Val string `json:"val"`
					} `json:"elem"`
				}
				if json.Unmarshal(raw, &w) != nil {
					continue
				}
				value = w.Elem.Val
			}
			ip, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			if strings.HasPrefix(name, "tls_sources_") {
				seenTLS[ip] = true
				// Successful manual unban atomically removes this kernel entry.
				// Its later presence is a new inline classification, not replay of
				// the gate's old timestamped source file.
				if e.permittedSource(ip) {
					if err := e.addTLSSource(ip, now, now); err != nil {
						return err
					}
				}
				continue
			}
			if strings.HasPrefix(name, "permanent_") {
				seen[ip] = true
			}
			if e.permittedSource(ip) && !e.isBanned(ip) {
				e.ban(ip, now, "kernel_blackhole_import")
			}
		}
	}
	if !e.Dry {
		missing := []netip.Addr{}
		for ip := range e.Banned {
			if !seen[ip] {
				missing = append(missing, ip)
			}
		}
		if err := applyBans(missing); err != nil {
			return err
		}
		missing = missing[:0]
		for ip := range e.TLSSources {
			if !seenTLS[ip] {
				missing = append(missing, ip)
			}
		}
		if err := applyTLSSources(missing); err != nil {
			return err
		}
	}
	return nil
}
func (e *engine) adoptKernelBans(now int64) {
	if e.Dry {
		return
	}
	data, err := runNft([]string{"-j", "list", "table", "inet", "qntw_probe_blackhole"}, "")
	if err == nil {
		err = e.adoptKernelJSON(data, now)
	}
	if err != nil {
		e.NFTErrors++
		fmt.Fprintf(os.Stderr, "kernel ban read failed: %v\n", err)
	}
}
func (e *engine) refreshListen() {
	// Decode only public metadata; never log or copy collector HMAC/config data.
	data, err := os.ReadFile("/etc/vpnshop-probe-logging.json")
	var c config
	if err == nil {
		err = json.Unmarshal(data, &c)
	}
	if err != nil || c.Node != e.C.Node || len(c.Listen) == 0 {
		e.PortReady = false
		e.PortConfigErrors++
		return
	}
	ports := map[int]bool{}
	for _, p := range append(append([]int{}, e.C.Listen...), c.Listen...) {
		if p > 0 && p <= 65535 {
			ports[p] = true
		}
	}
	// Include live TCP listeners, including SSH ports changed outside VPN config.
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			e.PortReady = false
			e.PortConfigErrors++
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			p, err := strconv.ParseUint(parts[1], 16, 16)
			if err == nil {
				ports[int(p)] = true
			}
		}
	}
	e.Listen = ports
	e.PortReady = true
	for _, b := range e.B {
		for p := range b.Ports {
			if ports[p] {
				delete(b.Ports, p)
				e.Dirty = true
			}
		}
	}
}
func (e *engine) saveState() error {
	if e.Dry || e.StatePath == "" || !e.Dirty {
		return nil
	}
	s := savedState{Version: 3, Node: e.C.Node, History: map[string]banHistory{}, Banned: map[string]int64{}, Windows: map[string]savedWindow{}, Released: map[string]int64{}, TLSSources: map[string]int64{}}
	for ip, first := range e.TLSSources {
		s.TLSSources[ip.String()] = first
	}
	for ip, at := range e.Released {
		s.Released[ip.String()] = at
	}
	for ip, h := range e.History {
		s.History[ip.String()] = h
	}
	for ip, until := range e.Banned {
		s.Banned[ip.String()] = until
	}
	for ip, b := range e.B {
		if len(b.Ports) > 0 {
			s.Windows[ip.String()] = savedWindow{Ports: b.Ports, Last: b.Last}
		}
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(e.StatePath), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(e.StatePath+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(e.StatePath+".tmp", e.StatePath); err != nil {
		return err
	}
	e.Dirty = false
	return nil
}
func (e *engine) loadState(now int64) error {
	f, err := os.Open(e.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
	if err != nil {
		return err
	}
	if len(data) > 64*1024*1024 {
		return fmt.Errorf("state too large")
	}
	var s savedState
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	if (s.Version != 2 && s.Version != 3) || s.Node != e.C.Node || len(s.History) > 65536 || len(s.Banned) > 65536 || len(s.Windows) > 5000 || len(s.TLSSources) > 65536 {
		return fmt.Errorf("invalid state metadata")
	}
	for src, h := range s.History {
		ip, err := netip.ParseAddr(src)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		if e.permittedSource(ip) && h.Strikes > 0 && h.Last <= now+5 {
			e.History[ip] = h
			// Import expired v2 decisions as permanently confirmed, too.
			e.Banned[ip] = 0
		}
	}
	for src := range s.Banned {
		ip, err := netip.ParseAddr(src)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		if e.permittedSource(ip) {
			e.Banned[ip] = 0
		}
	}
	e.Dirty = s.Version != 3
	if len(s.Released) > 65536 {
		return fmt.Errorf("release history capacity")
	}
	for src, at := range s.Released {
		ip, err := netip.ParseAddr(src)
		if err != nil {
			return err
		}
		if at > 0 && at <= now+5 {
			e.Released[ip.Unmap()] = at
		}
	}
	for src, first := range s.TLSSources {
		ip, err := netip.ParseAddr(src)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		if e.permittedSource(ip) && first > e.Released[ip] && first > 0 && first <= now+5 {
			e.TLSSources[ip] = first
		}
	}
	for src, w := range s.Windows {
		ip, err := netip.ParseAddr(src)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		if !e.permittedSource(ip) || len(w.Ports) > 64 {
			continue
		}
		b := &bucket{Ports: map[int]int64{}, Paths: map[string]int64{}, Fail: map[[32]byte]int64{}, Last: w.Last}
		for p, at := range w.Ports {
			if p > 0 && p <= 65535 && !e.Listen[p] && at >= now-21600 && at <= now+5 {
				b.Ports[p] = at
			}
		}
		if len(b.Ports) > 0 {
			e.B[ip] = b
		}
	}
	return nil
}
