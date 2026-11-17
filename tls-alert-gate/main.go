// Bounded ClientHello gate: ordinary TLS/VPN streams remain opaque end to end.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type counters struct {
	Accepted, Active, Forwarded, Rejected, Capacity, DialErrors, InspectPartial, PersistenceErrors, ReleaseReadErrors, AlertWriteErrors, RejectedNonTLS, LogSuppressed, LogErrors, AcceptErrors atomic.Uint64
}
type gate struct {
	cfg          config
	profiles     []profile
	trusted      map[string]bool
	known        *sourceMemory
	behavior     *detector
	counts       counters
	slots        chan struct{}
	logMu        sync.Mutex
	logSecond    int64
	logCount     int
	pendingMu    sync.Mutex
	pending      map[string]int
	pendingTotal int
	listeners    []net.Listener
}

func newGate(c config) (*gate, error) {
	if e := validateConfig(c); e != nil {
		return nil, e
	}
	f, e := os.Open(c.ProfilesPath)
	if e != nil {
		return nil, e
	}
	ps, e := loadProfiles(f)
	f.Close()
	if e != nil {
		return nil, e
	}
	known, e := loadSources(c.Node, c.KnownSourcesPath, c.BlackholeStatePath)
	if e != nil {
		return nil, e
	}
	g := &gate{cfg: c, profiles: ps, known: known, behavior: newDetector(), trusted: map[string]bool{}, slots: make(chan struct{}, c.MaxConnections), pending: map[string]int{}}
	for _, s := range c.TrustedIPs {
		a, _ := netip.ParseAddr(s)
		g.trusted[a.Unmap().String()] = true
	}
	return g, nil
}
func (g *gate) emit(event map[string]any) {
	g.logMu.Lock()
	defer g.logMu.Unlock()
	now := time.Now()
	if event["event"] != "tls_alert_gate_start" {
		if now.Unix() != g.logSecond {
			g.logSecond = now.Unix()
			g.logCount = 0
		}
		if g.logCount >= 20 {
			g.counts.LogSuppressed.Add(1)
			return
		}
		g.logCount++
	}
	event["node"] = g.cfg.Node
	event["at_utc"] = now.UTC().Format(time.RFC3339Nano)
	if json.NewEncoder(os.Stdout).Encode(event) != nil {
		g.counts.LogErrors.Add(1)
	}
}
func (g *gate) beginPending(ip string) bool {
	g.pendingMu.Lock()
	defer g.pendingMu.Unlock()
	if g.pendingTotal >= g.cfg.MaxPending || g.pending[ip] >= g.cfg.MaxPendingPerIP {
		return false
	}
	g.pendingTotal++
	g.pending[ip]++
	return true
}
func (g *gate) endPending(ip string) {
	g.pendingMu.Lock()
	defer g.pendingMu.Unlock()
	g.pendingTotal--
	g.pending[ip]--
	if g.pending[ip] == 0 {
		delete(g.pending, ip)
	}
}
func endpoint(addr net.Addr) (string, int, error) {
	a, ok := addr.(*net.TCPAddr)
	if !ok || a.IP == nil {
		return "", 0, errors.New("non-TCP endpoint")
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return "", 0, errors.New("invalid TCP endpoint")
	}
	return ip.Unmap().String(), a.Port, nil
}
func clientHelloRecord(record []byte) bool {
	if len(record) < 44 || record[0] != 22 || record[5] != 1 {
		return false
	}
	n := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	return int(binary.BigEndian.Uint16(record[3:5]))+5 == len(record) && n+9 == len(record)
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (g *gate) reject(conn *net.TCPConn, prefix []byte, src string, sport int, dst string, dport int, profileID string, known bool, reason string) {
	g.counts.Rejected.Add(1)
	persistenceOK := true
	if !known {
		if _, e := g.known.remember(src); e != nil {
			g.counts.PersistenceErrors.Add(1)
			persistenceOK = false
		}
	}
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	err := writeAll(conn, fatalAlert(prefix))
	if err != nil {
		g.counts.AlertWriteErrors.Add(1)
	}
	g.emit(map[string]any{"event": "tls_alert_gate_reject", "src": src, "sport": sport, "dst": dst, "dport": dport, "profile": profileID, "reason": reason, "remembered_source": known, "alert_level": 2, "alert_description": 40, "alert_write_complete": err == nil, "persistence_ok": persistenceOK})
	conn.CloseWrite()
	conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	io.Copy(io.Discard, io.LimitReader(conn, 4096))
}
func (g *gate) handle(conn *net.TCPConn) {
	defer conn.Close()
	defer func() { <-g.slots; g.counts.Active.Add(^uint64(0)) }()
	src, sport, e := endpoint(conn.RemoteAddr())
	if e != nil {
		return
	}
	dst, dport, e := endpoint(conn.LocalAddr())
	if e != nil {
		return
	}
	if dport != g.cfg.ExpectedOriginalPort {
		return
	} // Never expose a direct high-port responder.
	var prefix []byte
	if !g.trusted[src] {
		if !g.beginPending(src) {
			g.counts.Capacity.Add(1)
			return
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(g.cfg.InspectTimeoutMS) * time.Millisecond))
		prefix, e = inspectPrefix(conn, g.cfg.MaxHelloBytes)
		conn.SetReadDeadline(time.Time{})
		g.endPending(src)
		if e != nil {
			g.counts.InspectPartial.Add(1)
		}
		if g.known.contains(src) {
			if clientHelloRecord(prefix) {
				g.reject(conn, prefix, src, sport, dst, dport, "", true, "remembered_tls_scanner")
			} else {
				g.counts.RejectedNonTLS.Add(1)
			}
			return
		}
		if e == nil && clientHelloRecord(prefix) {
			for _, p := range g.profiles {
				if p.matches(prefix) {
					g.reject(conn, prefix, src, sport, dst, dport, p.ID, false, "known_tls_profile")
					return
				}
			}
			if g.cfg.BehaviorEnabled {
				if f, ok := featureFromRecord(prefix); ok {
					if decision, hit := g.behavior.observe(src, f, time.Now().Unix()); hit {
						g.reject(conn, prefix, src, sport, dst, dport, "", false, decision.Reason)
						return
					}
				}
			}
		}
	}
	backend := g.cfg.BackendV4
	if ip, _ := netip.ParseAddr(src); ip.Is6() {
		backend = g.cfg.BackendV6
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.cfg.DialTimeoutMS)*time.Millisecond)
	upstream, e := transparentDial(ctx, src, sport, backend, g.cfg.BackendMark)
	cancel()
	if e != nil {
		g.counts.DialErrors.Add(1)
		return
	}
	defer upstream.Close()
	g.counts.Forwarded.Add(1)
	if e = writeAll(upstream, prefix); e != nil {
		return
	}
	// Direct TCPConn arguments preserve Linux splice where available. Half-close
	// each direction; do not add a new idle or session lifetime for normal VPNs.
	done := make(chan struct{}, 1)
	go func() { io.Copy(upstream, conn); upstream.CloseWrite(); done <- struct{}{} }()
	io.Copy(conn, upstream)
	conn.CloseWrite()
	<-done
}
func (g *gate) summary(ready, draining bool) map[string]any {
	g.pendingMu.Lock()
	pending := g.pendingTotal
	g.pendingMu.Unlock()
	behaviorBuckets, behaviorCapacity := g.behavior.status()
	return map[string]any{"behavior_enabled": g.cfg.BehaviorEnabled, "behavior_buckets": behaviorBuckets, "behavior_capacity": behaviorCapacity, "schema": 1, "node": g.cfg.Node, "at_utc": time.Now().UTC().Format(time.RFC3339Nano), "ready": ready, "draining": draining, "known_sources": g.known.size(), "pending": pending, "listeners": len(g.listeners), "limits": map[string]any{"max_connections": g.cfg.MaxConnections, "max_pending": g.cfg.MaxPending, "max_pending_per_ip": g.cfg.MaxPendingPerIP, "max_hello_bytes": g.cfg.MaxHelloBytes, "inspect_timeout_ms": g.cfg.InspectTimeoutMS}, "counters": map[string]uint64{"accepted": g.counts.Accepted.Load(), "active": g.counts.Active.Load(), "forwarded": g.counts.Forwarded.Load(), "rejected": g.counts.Rejected.Load(), "capacity": g.counts.Capacity.Load(), "dial_errors": g.counts.DialErrors.Load(), "inspect_partial": g.counts.InspectPartial.Load(), "persistence_errors": g.counts.PersistenceErrors.Load(), "release_read_errors": g.counts.ReleaseReadErrors.Load(), "alert_write_errors": g.counts.AlertWriteErrors.Load(), "rejected_non_tls_known_source": g.counts.RejectedNonTLS.Load(), "log_suppressed": g.counts.LogSuppressed.Load(), "log_errors": g.counts.LogErrors.Load(), "accept_errors": g.counts.AcceptErrors.Load()}}
}
func (g *gate) run(ctx context.Context) error {
	if e := g.known.ensureFile(); e != nil {
		return e
	}
	seenReleases := map[string]int64{}
	g.known.releaseChanges(seenReleases)
	for _, bind := range []string{g.cfg.ListenV4, g.cfg.ListenV6} {
		if bind == "" {
			continue
		}
		listener, e := transparentListen(ctx, bind)
		if e != nil {
			for _, l := range g.listeners {
				l.Close()
			}
			return e
		}
		g.listeners = append(g.listeners, listener)
	}
	defer func() {
		for _, l := range g.listeners {
			l.Close()
		}
		privateWrite(g.cfg.SummaryPath, g.summary(false, true))
	}()
	if e := privateWrite(g.cfg.SummaryPath, g.summary(true, false)); e != nil {
		return e
	}
	g.emit(map[string]any{"event": "tls_alert_gate_start", "version": 1, "listeners": len(g.listeners)})
	errorsC := make(chan error, len(g.listeners))
	for _, listener := range g.listeners {
		go func(l net.Listener) {
			backoff := 10 * time.Millisecond
			for {
				c, e := l.Accept()
				if e != nil {
					if temporary, ok := e.(net.Error); ok && temporary.Temporary() {
						g.counts.AcceptErrors.Add(1)
						select {
						case <-ctx.Done():
							errorsC <- e
							return
						case <-time.After(backoff):
						}
						if backoff < time.Second/2 {
							backoff *= 2
						}
						continue
					}
					errorsC <- e
					return
				}
				backoff = 10 * time.Millisecond
				g.counts.Accepted.Add(1)
				select {
				case g.slots <- struct{}{}:
					g.counts.Active.Add(1)
					go g.handle(c.(*net.TCPConn))
				default:
					g.counts.Capacity.Add(1)
					c.Close()
				}
			}
		}(listener)
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	ctxDone := ctx.Done()
	draining := false
	for {
		select {
		case <-ctxDone:
			// Caller must first disable steering of NEW connections and retain routing
			// for marked old flows. Existing connections finish naturally during drain.
			draining = true
			ctxDone = nil
			for _, l := range g.listeners {
				l.Close()
			}
			privateWrite(g.cfg.SummaryPath, g.summary(false, true))
			if g.counts.Active.Load() == 0 {
				return nil
			}
		case e := <-errorsC:
			if !draining {
				return e
			}
		case <-tick.C:
			if e := g.known.refreshReleased(); e != nil {
				g.counts.ReleaseReadErrors.Add(1)
			}
			for _, ip := range g.known.releaseChanges(seenReleases) {
				g.behavior.forget(ip)
			}
			if e := privateWrite(g.cfg.SummaryPath, g.summary(!draining, draining)); e != nil {
				g.counts.PersistenceErrors.Add(1)
			}
			if draining && g.counts.Active.Load() == 0 {
				return nil
			}
		}
	}
}
func main() {
	path := flag.String("config", "/etc/vpnshop-tls-alert/config.json", "root-owned gate configuration")
	check := flag.Bool("check", false, "validate configuration/profiles/state without listeners")
	analyze := flag.String("analyze-jsonl", "", "read-only behavioral calibration of tls_hello JSONL (path or -)")
	flag.Parse()
	if *analyze != "" {
		var r io.ReadCloser = os.Stdin
		if *analyze != "-" {
			f, err := os.Open(*analyze)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			r = f
		}
		defer r.Close()
		trusted := map[string]bool{}
		provided := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "config" {
				provided = true
			}
		})
		if provided {
			c, e := readConfig(*path)
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			for _, ip := range c.TrustedIPs {
				a, _ := netip.ParseAddr(ip)
				trusted[a.Unmap().String()] = true
			}
		}
		if e := analyzeMetadata(r, os.Stdout, trusted); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	c, e := readConfig(*path)
	if e != nil {
		fmt.Fprintln(os.Stderr, "invalid gate configuration:", e)
		os.Exit(1)
	}
	g, e := newGate(c)
	if e != nil {
		fmt.Fprintln(os.Stderr, "invalid gate profiles/state:", e)
		os.Exit(1)
	}
	if *check {
		fmt.Println("configuration valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if e = g.run(ctx); e != nil {
		fmt.Fprintln(os.Stderr, "gate stopped:", e)
		os.Exit(1)
	}
}
