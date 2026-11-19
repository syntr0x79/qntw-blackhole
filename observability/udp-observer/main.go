// Passive UDP evidence, independent of all packet verdicts and VPN services.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var captureDroppedPattern = regexp.MustCompile(`(?:^|[ ,])([0-9]+) packets dropped by kernel(?:$|[ ,])`)

func captureDropped(line string) (uint64, bool) {
	match := captureDroppedPattern.FindStringSubmatch(line)
	if match == nil {
		return 0, false
	}
	value, err := strconv.ParseUint(match[1], 10, 64)
	return value, err == nil
}

type peer struct {
	MeshIP string `json:"mesh_ip"`
	Key    string `json:"key"`
}
type config struct {
	Node      string          `json:"node"`
	Interface string          `json:"interface"`
	Local     []string        `json:"local_ips"`
	Known     []string        `json:"hello_detail_exclude_sources"`
	Key       string          `json:"key"`
	Hub       string          `json:"hub_address"`
	Bind      string          `json:"hub_bind"`
	Peers     map[string]peer `json:"peers"`
}
type envelope struct {
	Node      string `json:"node"`
	Data      []byte `json:"data"`
	Signature string `json:"signature"`
}
type flow struct {
	First, Last                time.Time
	Src, Dst                   string
	Sport, Dport               int
	In, Out, InBytes, OutBytes uint64
	Samples                    [2]int
	Decodes                    int
	Dirty                      bool
	Known                      bool
	Basis                      string
}
type observer struct {
	c                              config
	local, known                   map[string]bool
	mu                             sync.Mutex
	counts                         map[string]uint64
	sensors                        map[string]int
	received                       map[string]int64
	events                         chan obj
	decode                         chan decodePacket
	flows                          map[string]*flow
	origins                        map[string]origin
	directionReady                 bool
	directionSeed                  time.Time
	awg                            awgProfile
	budgetAt                       time.Time
	eventBudget, decodeBudget      int
	ring                           *ring
	stateDir, metricsPath, awgPath string
}

func (o *observer) inc(k string)       { o.mu.Lock(); o.counts[k]++; o.mu.Unlock() }
func (o *observer) up(k string, v int) { o.mu.Lock(); o.sensors[k] = v; o.mu.Unlock() }
func nowString() string                { return time.Now().UTC().Format(time.RFC3339Nano) }
func (o *observer) emit(d obj) {
	if d == nil {
		return
	}
	if _, ok := d["node"]; !ok {
		d["node"] = o.c.Node
	}
	if _, ok := d["observed_utc"]; !ok {
		d["observed_utc"] = nowString()
	}
	select {
	case o.events <- d:
	default:
		o.inc("queue_dropped")
	}
}
func (o *observer) allowance(decode bool) bool {
	now := time.Now()
	if now.Sub(o.budgetAt) >= time.Second {
		o.budgetAt = now
		o.eventBudget = 400
		o.decodeBudget = 50
	}
	if decode {
		if o.decodeBudget <= 0 {
			o.inc("decode_rate_limited")
			return false
		}
		o.decodeBudget--
		return true
	}
	if o.eventBudget <= 0 {
		o.inc("metadata_rate_limited")
		return false
	}
	o.eventBudget--
	return true
}

func (o *observer) refresh() {
	o.awg = loadAWG(o.awgPath)
}

func (o *observer) packet(data []byte, ci gopacket.CaptureInfo) {
	o.inc("captured_packets")
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	var src, dst string
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			o.inc("fragmented_packets")
			return
		}
	} else if l := p.Layer(layers.LayerTypeIPv6); l != nil {
		ip := l.(*layers.IPv6)
		src = ip.SrcIP.String()
		dst = ip.DstIP.String()
	}
	l := p.Layer(layers.LayerTypeUDP)
	if l == nil {
		o.inc("non_udp_or_fragment")
		return
	}
	u := l.(*layers.UDP)
	sp, dp := int(u.SrcPort), int(u.DstPort)
	if u.Length < 8 {
		o.inc("malformed_udp")
		return
	}
	wire := int(u.Length) - 8
	in := o.local[dst] && !o.local[src]
	out := o.local[src] && !o.local[dst]
	if !in && !out {
		return
	}
	source, target, sport, dport := src, dst, sp, dp
	if out {
		source, target, sport, dport = dst, src, dp, sp
	}
	k := flowKey(source, target, sport, dport)
	t := ci.Timestamp
	v, ok := o.originFor(k, in, t)
	if !ok {
		return
	}
	if !v.Inbound {
		if in {
			o.inc("excluded_reply")
		} else {
			o.inc("excluded_outgoing")
		}
		return
	}
	f := o.flows[k]
	if f != nil && t.Sub(f.First) > 5*time.Minute {
		o.flushFlow(f)
		delete(o.flows, k)
		f = nil
	}
	if f == nil {
		if len(o.flows) >= 10000 {
			o.inc("flow_capacity_dropped")
			return
		}
		f = &flow{First: t, Last: t, Src: source, Dst: target, Sport: sport, Dport: dport, Known: o.known[source], Basis: v.Basis}
		o.flows[k] = f
		o.inc("new_flows")
	}
	f.Last = t
	f.Dirty = true
	idx := 0
	direction := "ingress"
	if in {
		f.In++
		f.InBytes += uint64(wire)
	} else {
		idx = 1
		direction = "egress_reply"
		f.Out++
		f.OutBytes += uint64(wire)
	}
	limit := 8
	if f.Known {
		limit = 2
	}
	if f.Samples[idx] >= limit {
		o.inc("packets_aggregated_only")
		return
	}
	f.Samples[idx]++
	if !o.allowance(false) {
		return
	}
	d := obj{"event": "udp_observation", "epoch": fmt.Sprintf("%.6f", float64(t.UnixNano())/1e9), "src": src, "dst": dst, "sport": sp, "dport": dp, "direction": direction, "udp_payload_length": wire, "captured_payload_length": len(u.Payload), "capture_truncated": len(data) < ci.Length, "sample_index": f.Samples[idx], "known_source": f.Known, "capture_point": "af_packet_before_netfilter_drop", "authentication_checked": false}
	d["direction_schema"] = 2
	d["flow_origin"] = "inbound"
	d["origin_basis"] = f.Basis
	q := quicHeader(u.Payload)
	if q != nil {
		d["quic"] = q
	}
	if dport == o.awg.Port {
		d["awg"] = awgShape(u.Payload, wire, o.awg)
	}
	o.emit(d)
	// Only QUIC Initials enter the isolated dissector. No established QUIC
	// data, AWG ciphertext, or arbitrary UDP is passed to it.
	if !f.Known && q != nil && q["packet_type"] == "initial" && f.Decodes < 16 && o.allowance(true) {
		f.Decodes++
		cp := decodePacket{Info: ci, Data: append([]byte(nil), data...)}
		select {
		case o.decode <- cp:
		default:
			o.inc("decoder_queue_dropped")
		}
	}
}
func (o *observer) flushFlow(f *flow) {
	if !f.Dirty {
		return
	}
	f.Dirty = false
	o.emit(obj{"event": "udp_flow_summary", "first_utc": f.First.UTC().Format(time.RFC3339Nano), "last_utc": f.Last.UTC().Format(time.RFC3339Nano), "src": f.Src, "dst": f.Dst, "sport": f.Sport, "dport": f.Dport, "ingress_packets": f.In, "egress_packets": f.Out, "ingress_payload_bytes": f.InBytes, "egress_payload_bytes": f.OutBytes, "known_source": f.Known, "cumulative": true, "egress_scope": "reply_to_inbound_flow", "authentication_checked": false, "direction_schema": 2, "flow_origin": "inbound", "origin_basis": f.Basis})
}
func (o *observer) sweep() {
	now := time.Now()
	for k, f := range o.flows {
		if f.Dirty {
			o.flushFlow(f)
		}
		if now.Sub(f.Last) > 120*time.Second {
			delete(o.flows, k)
		}
	}
	o.refresh()
	for k, v := range o.origins {
		if now.Sub(v.Last) > 120*time.Second {
			delete(o.origins, k)
		}
	}
}

func captureFilter(local []string) string {
	hosts := []string{}
	for _, s := range local {
		if net.ParseIP(s) != nil {
			hosts = append(hosts, "host "+s)
		}
	}
	return "((ip and ip proto 17) or (ip6 and (ip6[6] = 17 or ip6[6] = 0 or ip6[6] = 43 or ip6[6] = 44 or ip6[6] = 60 or ip6[6] = 51))) and (" + strings.Join(hosts, " or ") + ")"
}
func (o *observer) capture(ctx context.Context) {
	for ctx.Err() == nil {
		cctx, cancel := context.WithCancel(ctx)
		o.directionReady = false
		o.up("direction", 0)
		o.origins = map[string]origin{}
		loss := make(chan struct{}, 1)
		// AF_PACKET taps precede netfilter. Include IPv6 extension-header
		// candidates and discard non-UDP in memory. No pcap files are created.
		cmd := exec.CommandContext(cctx, "tcpdump", "-n", "-p", "-U", "-i", o.c.Interface, "-B", "4096", "-s", "4096", "-w", "-", captureFilter(o.c.Local))
		stdout, e := cmd.StdoutPipe()
		if e != nil {
			cancel()
			return
		}
		stderr, e := cmd.StderrPipe()
		if e != nil {
			cancel()
			return
		}
		if e = cmd.Start(); e != nil {
			o.inc("capture_errors")
			cancel()
			time.Sleep(time.Second)
			continue
		}
		go func() {
			s := bufio.NewScanner(stderr)
			var prev uint64
			for s.Scan() {
				line := s.Text()
				n, ok := captureDropped(line)
				if ok && n >= prev {
					o.mu.Lock()
					o.counts["capture_kernel_dropped"] += n - prev
					o.mu.Unlock()
					if n > prev {
						select {
						case loss <- struct{}{}:
						default:
						}
					}
					prev = n
				}
			}
		}()
		go func() {
			tick := time.NewTicker(15 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-cctx.Done():
					return
				case <-tick.C:
					cmd.Process.Signal(syscall.SIGUSR1)
				}
			}
		}()
		r, e := pcapgo.NewReader(stdout)
		if e != nil || r.LinkType() != layers.LinkTypeEthernet {
			o.inc("capture_format_errors")
			cancel()
			cmd.Wait()
			continue
		}
		o.up("capture", 1)
		seeds := make(chan originSnapshot, 1)
		seedBusy, seedAgain := false, false
		requestSeed := func() {
			if seedBusy {
				return
			}
			seedBusy = true
			go func() {
				qctx, qcancel := context.WithTimeout(cctx, 5*time.Second)
				defer qcancel()
				entries, err := readOrigins(qctx, o.local)
				select {
				case seeds <- originSnapshot{entries: entries, err: err}:
				case <-cctx.Done():
				}
			}()
		}
		requestSeed()
		packets := make(chan decodePacket, 256)
		go func() {
			defer close(packets)
			for {
				b, ci, e := r.ReadPacketData()
				if e != nil {
					return
				}
				select {
				case packets <- decodePacket{Info: ci, Data: b}:
				case <-cctx.Done():
					return
				}
			}
		}()
		tick := time.NewTicker(60 * time.Second)
	readLoop:
		for {
			select {
			case <-cctx.Done():
				break readLoop
			case <-tick.C:
				o.sweep()
				requestSeed()
			case <-loss:
				o.directionReady = false
				o.origins = map[string]origin{}
				o.up("direction", 0)
				o.inc("direction_capture_gaps")
				if seedBusy {
					seedAgain = true
				} else {
					requestSeed()
				}
			case seed := <-seeds:
				seedBusy = false
				if seedAgain {
					seedAgain = false
					requestSeed()
				} else {
					o.applyOrigins(seed)
				}
			case p, ok := <-packets:
				if !ok {
					break readLoop
				}
				o.packet(p.Data, p.Info)
			}
		}
		tick.Stop()
		o.up("capture", 0)
		cancel()
		cmd.Wait()
		o.inc("capture_restarts")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

type ring struct {
	dir          string
	f            *os.File
	size, budget int64
	since        time.Time
}

func newRing(dir string, budget int64) (*ring, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	os.Chmod(dir, 0700)
	r := &ring{dir: dir, budget: budget}
	e := r.open()
	return r, e
}
func (r *ring) open() error {
	f, e := os.OpenFile(filepath.Join(r.dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	r.f = f
	os.Chmod(f.Name(), 0600)
	st, e := f.Stat()
	if e != nil {
		return e
	}
	r.size = st.Size()
	r.since = time.Now()
	return nil
}
func (r *ring) trim() {
	files, _ := filepath.Glob(filepath.Join(r.dir, "events-*.jsonl.gz"))
	sort.Strings(files)
	size := r.size
	for _, p := range files {
		st, e := os.Stat(p)
		if e == nil {
			size += st.Size()
		}
	}
	for _, p := range files {
		st, e := os.Stat(p)
		if e != nil {
			continue
		}
		if size > r.budget || time.Since(st.ModTime()) > 7*24*time.Hour {
			if os.Remove(p) == nil {
				size -= st.Size()
			}
		}
	}
}
func (r *ring) write(b []byte) error {
	if r.size > 16<<20 || time.Since(r.since) > time.Hour {
		r.f.Close()
		old := filepath.Join(r.dir, "events.jsonl")
		name := filepath.Join(r.dir, "events-"+time.Now().UTC().Format("20060102T150405.000000000")+".jsonl.gz")
		f, e := os.Open(old)
		if e != nil {
			return e
		}
		out, e := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			f.Close()
			return e
		}
		z := gzip.NewWriter(out)
		_, e = io.Copy(z, f)
		e2 := z.Close()
		out.Close()
		f.Close()
		if e != nil {
			return e
		}
		if e2 != nil {
			return e2
		}
		if e = os.Truncate(old, 0); e != nil {
			return e
		}
		if e = r.open(); e != nil {
			return e
		}
		r.trim()
	}
	n, e := r.f.Write(append(b, '\n'))
	r.size += int64(n)
	return e
}
func atomicJSON(path string, d any) error {
	b, e := json.Marshal(d)
	if e != nil {
		return e
	}
	if e = os.WriteFile(path+".tmp", append(b, '\n'), 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}

func sign(key string, b []byte) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (o *observer) hub(ctx context.Context) {
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(o.c.Bind), Port: 19015})
	if e != nil {
		o.inc("hub_errors")
		return
	}
	defer c.Close()
	c.SetReadBuffer(8 << 20)
	o.up("hub", 1)
	defer o.up("hub", 0)
	b := make([]byte, 16384)
	for ctx.Err() == nil {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, e := c.ReadFromUDP(b)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			o.inc("hub_errors")
			continue
		}
		var env envelope
		if json.Unmarshal(b[:n], &env) != nil {
			o.inc("hub_rejected")
			continue
		}
		p, ok := o.c.Peers[env.Node]
		if !ok || addr.IP.String() != p.MeshIP || !hmac.Equal([]byte(sign(p.Key, env.Data)), []byte(env.Signature)) {
			o.inc("hub_rejected")
			continue
		}
		var d obj
		if json.Unmarshal(env.Data, &d) != nil || d["node"] != env.Node {
			o.inc("hub_rejected")
			continue
		}
		d["received_utc"] = nowString()
		o.mu.Lock()
		o.received[env.Node] = time.Now().Unix()
		o.mu.Unlock()
		o.emit(d)
	}
}
func (o *observer) snapshots() {
	o.mu.Lock()
	counts := map[string]uint64{}
	for k, v := range o.counts {
		counts[k] = v
	}
	sensors := map[string]int{}
	for k, v := range o.sensors {
		sensors[k] = v
	}
	received := map[string]int64{}
	for k, v := range o.received {
		received[k] = v
	}
	o.mu.Unlock()
	d := obj{"at_utc": nowString(), "node": o.c.Node, "version": 2, "interval_seconds": 15, "sensors": sensors, "counters": counts, "last_remote_seconds": received, "expected_remote_nodes": len(o.c.Peers), "passive_only": true, "limits": obj{"flows": 10000, "samples_per_direction": 8, "known_samples_per_direction": 2, "metadata_per_second": 400, "quic_packets_per_second": 50, "capture_bytes": 4096, "flow_idle_seconds": 120, "flow_max_seconds": 300}}
	if e := atomicJSON(filepath.Join(o.stateDir, "summary.json"), d); e != nil {
		o.inc("summary_errors")
	}
	lines := []string{fmt.Sprintf("qntw_udp_observer_heartbeat_seconds %d", time.Now().Unix()), "qntw_udp_observer_version 2"}
	for k, v := range sensors {
		lines = append(lines, fmt.Sprintf("qntw_udp_observer_sensor_up{sensor=%q} %d", k, v))
	}
	for k, v := range counts {
		lines = append(lines, fmt.Sprintf("qntw_udp_observer_events_total{kind=%q} %d", k, v))
	}
	for k, v := range received {
		lines = append(lines, fmt.Sprintf("qntw_udp_observer_last_remote_seconds{node=%q} %d", k, v))
	}
	sort.Strings(lines)
	path := o.metricsPath
	if e := os.WriteFile(path+".tmp", []byte(strings.Join(lines, "\n")+"\n"), 0644); e == nil {
		os.Chmod(path+".tmp", 0644)
		os.Rename(path+".tmp", path)
	} else {
		o.inc("metrics_errors")
	}
	o.emit(obj{"event": "udp_heartbeat", "version": 2, "sensors": sensors, "counters": counts, "passive_only": true})
}
func (o *observer) writer(ctx context.Context) {
	var remote *net.UDPConn
	if o.c.Hub != "" {
		addr, e := net.ResolveUDPAddr("udp", net.JoinHostPort(o.c.Hub, "19015"))
		if e == nil {
			remote, e = net.DialUDP("udp", nil, addr)
		}
		if e != nil {
			o.inc("forward_errors")
		}
		if remote != nil {
			defer remote.Close()
		}
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	diskOK := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var st syscall.Statfs_t
			if syscall.Statfs(o.ring.dir, &st) == nil {
				diskOK = st.Bavail*uint64(st.Bsize) > 1<<30
			}
			o.up("disk", btoi(diskOK))
			o.ring.trim()
			o.snapshots()
		case d := <-o.events:
			b, e := json.Marshal(d)
			if e != nil {
				o.inc("json_errors")
				continue
			}
			if diskOK {
				if e = o.ring.write(b); e != nil {
					o.inc("disk_errors")
				}
			} else {
				o.inc("disk_dropped")
			}
			if remote != nil {
				env := envelope{Node: o.c.Node, Data: b, Signature: sign(o.c.Key, b)}
				raw, _ := json.Marshal(env)
				if len(raw) > 16000 {
					o.inc("forward_oversize")
					continue
				}
				retried, err := deliver(remote, raw)
				if retried {
					o.inc("forward_retries")
				}
				if err != nil {
					o.inc("forward_errors")
					reason := forwardReason(err)
					o.inc("forward_" + reason)
					if d["event"] != "udp_forward_error" {
						o.emit(obj{"event": "udp_forward_error", "reason": reason, "bytes": len(raw), "local_record_retained": diskOK && e == nil})
					}
				} else if retried {
					o.inc("forward_retry_success")
				}
			}
		}
	}
}

type evidenceWriter interface {
	SetWriteDeadline(time.Time) error
	Write([]byte) (int, error)
}

func deliver(c evidenceWriter, b []byte) (bool, error) {
	var err error
	for i := 0; i < 2; i++ {
		if err = c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return i > 0, err
		}
		var n int
		n, err = c.Write(b)
		if err == nil && n == len(b) {
			return i > 0, nil
		}
		if err == nil {
			err = io.ErrShortWrite
		}
		if errors.Is(err, syscall.EMSGSIZE) {
			return i > 0, err
		}
	}
	return true, err
}
func forwardReason(e error) string {
	var n net.Error
	if errors.As(e, &n) && n.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(e, syscall.EMSGSIZE):
		return "message_too_long"
	case errors.Is(e, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(e, syscall.ENOBUFS):
		return "no_buffer"
	case errors.Is(e, syscall.ENETUNREACH) || errors.Is(e, syscall.EHOSTUNREACH):
		return "unreachable"
	}
	return "other_error"
}
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
func main() {
	cfg := flag.String("config", "/etc/vpnshop-probe-logging.json", "existing local collector configuration")
	logDir := flag.String("log-dir", "/var/log/vpnshop-udp", "private evidence directory")
	stateDir := flag.String("state-dir", "/var/lib/vpnshop-udp-observer", "private summary directory")
	metricsPath := flag.String("metrics-path", "/var/lib/node_exporter/textfile/udp_observer.prom", "textfile metrics")
	awgPath := flag.String("awg-profile", "/etc/amneziawg/awg0.conf", "local AWG public-parameter source")
	flag.Parse()
	syscall.Umask(0077)
	b, e := os.ReadFile(*cfg)
	if e != nil {
		panic("configuration unavailable")
	}
	var c config
	if json.Unmarshal(b, &c) != nil || c.Node == "" || c.Interface == "" || len(c.Local) == 0 {
		panic("invalid configuration")
	}
	budget := int64(512 << 20)
	if c.Bind != "" {
		budget = 2 << 30
	}
	r, e := newRing(*logDir, budget)
	if e != nil {
		panic("evidence directory unavailable")
	}
	defer func() { r.f.Close() }()
	if e = os.MkdirAll(*stateDir, 0700); e != nil {
		panic("state directory unavailable")
	}
	o := &observer{c: c, local: map[string]bool{}, known: map[string]bool{}, counts: map[string]uint64{}, sensors: map[string]int{}, received: map[string]int64{}, events: make(chan obj, 8192), decode: make(chan decodePacket, 128), flows: map[string]*flow{}, ring: r, stateDir: *stateDir, metricsPath: *metricsPath, awgPath: *awgPath}
	for _, s := range c.Local {
		o.local[s] = true
	}
	for _, s := range c.Known {
		o.known[s] = true
	}
	o.refresh()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); o.writer(ctx) }()
	go o.decoder(ctx)
	if c.Bind != "" {
		go o.hub(ctx)
	}
	o.emit(obj{"event": "udp_collector_start", "version": 2, "passive_only": true})
	o.capture(ctx)
	cancel()
	<-writerDone
}
