package main

// Conntrack data is read-only, held in bounded memory, and never persisted or
// forwarded. In particular, customer egress destinations are not evidence.
import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const originLimit = 50000

type origin struct {
	Inbound bool
	Basis   string
	Last    time.Time
}
type originSnapshot struct {
	entries map[string]origin
	err     error
}

func flowKey(remote, local string, remotePort, localPort int) string {
	return net.JoinHostPort(remote, strconv.Itoa(remotePort)) + ">" + net.JoinHostPort(local, strconv.Itoa(localPort))
}

func conntrackOrigin(line string, local map[string]bool, now time.Time) (string, origin, bool) {
	var tuples [2]map[string]string
	tuples[0] = map[string]string{}
	tuples[1] = map[string]string{}
	idx := -1
	udp := false
	for _, f := range strings.Fields(line) {
		if f == "udp" {
			udp = true
		}
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		if k == "src" {
			idx++
		}
		if idx < 0 || idx > 1 {
			continue
		}
		if k == "src" || k == "dst" || k == "sport" || k == "dport" {
			tuples[idx][k] = v
		}
	}
	if !udp || idx != 1 {
		return "", origin{}, false
	}
	for _, t := range tuples {
		if net.ParseIP(t["src"]) == nil || net.ParseIP(t["dst"]) == nil {
			return "", origin{}, false
		}
		for _, k := range []string{"sport", "dport"} {
			n, e := strconv.Atoi(t[k])
			if e != nil || n < 1 || n > 65535 {
				return "", origin{}, false
			}
		}
	}
	a, b := tuples[0], tuples[1]
	sp, _ := strconv.Atoi(a["sport"])
	dp, _ := strconv.Atoi(a["dport"])
	if local[a["dst"]] && !local[a["src"]] {
		return flowKey(a["src"], a["dst"], sp, dp), origin{Inbound: true, Basis: "conntrack_original", Last: now}, true
	}
	// Use the reply tuple for outgoing/SNAT flows: it describes the incoming
	// wire packet before reverse NAT, including the translated local port.
	if local[b["dst"]] && !local[b["src"]] {
		rsp, _ := strconv.Atoi(b["sport"])
		rdp, _ := strconv.Atoi(b["dport"])
		return flowKey(b["src"], b["dst"], rsp, rdp), origin{Inbound: false, Basis: "conntrack_reply", Last: now}, true
	}
	return "", origin{}, false
}

func readOrigins(ctx context.Context, local map[string]bool) (map[string]origin, error) {
	entries := map[string]origin{}
	for _, family := range []string{"ipv4", "ipv6"} {
		cmd := exec.CommandContext(ctx, "conntrack", "-L", "-f", family, "-p", "udp", "-o", "extended")
		pipe, e := cmd.StdoutPipe()
		if e != nil {
			return nil, e
		}
		cmd.Stderr = io.Discard
		if e = cmd.Start(); e != nil {
			return nil, e
		}
		s := bufio.NewScanner(pipe)
		s.Buffer(make([]byte, 4096), 65536)
		var parseErr error
		for s.Scan() {
			k, v, ok := conntrackOrigin(s.Text(), local, time.Now())
			if !ok {
				continue
			}
			if _, exists := entries[k]; !exists && len(entries) >= originLimit {
				parseErr = errors.New("direction cache capacity")
				cmd.Process.Kill()
				break
			}
			entries[k] = v
		}
		e = s.Err()
		waitErr := cmd.Wait()
		if parseErr != nil {
			return nil, parseErr
		}
		if e != nil {
			return nil, e
		}
		if waitErr != nil {
			return nil, waitErr
		}
	}
	return entries, nil
}

func (o *observer) applyOrigins(s originSnapshot) {
	if s.err != nil {
		o.directionReady = false
		o.up("direction", 0)
		o.inc("direction_snapshot_errors")
		return
	}
	if o.origins == nil {
		o.origins = map[string]origin{}
	}
	for k, v := range s.entries {
		if _, ok := o.origins[k]; !ok && len(o.origins) >= originLimit {
			o.directionReady = false
			o.up("direction", 0)
			o.inc("direction_capacity_dropped")
			return
		}
		o.origins[k] = v
		if f := o.flows[k]; f != nil {
			if !v.Inbound {
				delete(o.flows, k)
				o.inc("flow_reclassified_outgoing")
			} else {
				f.Basis = v.Basis
			}
		}
	}
	o.directionReady = true
	o.directionSeed = time.Now()
	o.up("direction", 1)
	o.inc("direction_snapshots")
}

func (o *observer) originFor(k string, in bool, t time.Time) (origin, bool) {
	if o.origins == nil {
		o.origins = map[string]origin{}
	}
	v, ok := o.origins[k]
	if ok && t.Sub(v.Last) > 120*time.Second {
		delete(o.origins, k)
		ok = false
	}
	if ok {
		if t.After(v.Last) {
			v.Last = t
		}
		o.origins[k] = v
		return v, true
	}
	if len(o.origins) >= originLimit {
		o.directionReady = false
		o.up("direction", 0)
		o.inc("direction_capacity_dropped")
		return origin{}, false
	}
	// Learn all outgoing tuples even when no evidence is emitted, including
	// source ports appearing in ss -lun. A bound UDP socket is not a service.
	if !in {
		v = origin{Inbound: false, Basis: "first_seen_outgoing", Last: t}
		o.origins[k] = v
		return v, true
	}
	if !o.directionReady || time.Since(o.directionSeed) > 120*time.Second {
		o.up("direction", 0)
		o.inc("direction_wait_packets")
		return origin{}, false
	}
	v = origin{Inbound: true, Basis: "first_seen_incoming", Last: t}
	o.origins[k] = v
	return v, true
}
