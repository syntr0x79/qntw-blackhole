package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
)

type config struct {
	Node                 string   `json:"node"`
	BehaviorEnabled      bool     `json:"behavior_enabled"`
	ListenV4             string   `json:"listen_v4"`
	ListenV6             string   `json:"listen_v6"`
	BackendV4            string   `json:"backend_v4"`
	BackendV6            string   `json:"backend_v6"`
	BackendMark          int      `json:"backend_mark"`
	InspectTimeoutMS     int      `json:"inspect_timeout_ms"`
	DialTimeoutMS        int      `json:"dial_timeout_ms"`
	MaxConnections       int      `json:"max_connections"`
	MaxPending           int      `json:"max_pending"`
	MaxPendingPerIP      int      `json:"max_pending_per_ip"`
	MaxHelloBytes        int      `json:"max_hello_bytes"`
	ExpectedOriginalPort int      `json:"expected_original_port"`
	TrustedIPs           []string `json:"trusted_ips"`
	ProfilesPath         string   `json:"profiles_path"`
	KnownSourcesPath     string   `json:"known_sources_path"`
	BlackholeStatePath   string   `json:"blackhole_state_path"`
	SummaryPath          string   `json:"summary_path"`
}

func defaults() config {
	return config{ListenV4: "0.0.0.0:14443", ListenV6: "[::]:14443", BackendV4: "10.254.254.1:443", BackendV6: "[fd51:4e::1]:443", BackendMark: 0x514e02, InspectTimeoutMS: 3000, DialTimeoutMS: 3000, MaxConnections: 2048, MaxPending: 512, MaxPendingPerIP: 64, MaxHelloBytes: 16384, ExpectedOriginalPort: 443, ProfilesPath: "/etc/vpnshop-security/probe-blackhole/profiles.json", KnownSourcesPath: "/var/lib/vpnshop-tls-alert/known-sources.json", BlackholeStatePath: "/var/lib/vpnshop-probe-blackhole/state.json", SummaryPath: "/var/lib/vpnshop-tls-alert/summary.json"}
}
func readConfig(path string) (config, error) {
	c := defaults()
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	return c, validateConfig(c)
}
func validateConfig(c config) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(c.Node) || c.BackendMark <= 0 || c.MaxConnections < 1 || c.MaxConnections > 16384 || c.MaxHelloBytes < 5 || c.MaxHelloBytes > 16384 || c.InspectTimeoutMS < 100 || c.InspectTimeoutMS > 10000 || c.DialTimeoutMS < 100 || c.DialTimeoutMS > 10000 || c.ExpectedOriginalPort < 1 || c.ExpectedOriginalPort > 65535 || c.MaxPending < 1 || c.MaxPending > c.MaxConnections || c.MaxPendingPerIP < 1 || c.MaxPendingPerIP > c.MaxPending {
		return errors.New("invalid gate bounds")
	}
	for index, v := range []string{c.BackendV4, c.BackendV6} {
		if v == "" && ((index == 0 && c.ListenV4 == "") || (index == 1 && c.ListenV6 == "")) {
			continue
		}
		a, e := netip.ParseAddrPort(v)
		if e != nil || a.Port() == 0 {
			return errors.New("invalid backend")
		}
		ip := a.Addr()
		if !ip.IsLoopback() && !netip.MustParsePrefix("10.254.254.0/24").Contains(ip) && !netip.MustParsePrefix("fd51:4e::/64").Contains(ip) {
			return errors.New("backend must use loopback or owned alias range")
		}
	}
	if c.ListenV4 == "" && c.ListenV6 == "" {
		return errors.New("no listener")
	}
	for _, v := range []string{c.ListenV4, c.ListenV6} {
		if v == "" {
			continue
		}
		a, e := netip.ParseAddrPort(v)
		if e != nil || a.Port() == 0 {
			return errors.New("invalid numeric listener")
		}
	}
	for _, v := range []string{c.ProfilesPath, c.SummaryPath, c.KnownSourcesPath} {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v {
			return errors.New("paths must be absolute and clean")
		}
	}
	if c.BlackholeStatePath != "" && (!filepath.IsAbs(c.BlackholeStatePath) || filepath.Clean(c.BlackholeStatePath) != c.BlackholeStatePath) {
		return errors.New("invalid blackhole state path")
	}
	for _, v := range c.TrustedIPs {
		if _, e := netip.ParseAddr(v); e != nil {
			return errors.New("invalid trusted address")
		}
	}
	return nil
}
