package main

// Only public structure is returned. Packet contents, connection IDs, tokens,
// sender indices, MACs and key material never become event fields.
import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type obj = map[string]any

func varint(p []byte, at *int) (uint64, bool) {
	if *at >= len(p) {
		return 0, false
	}
	n := 1 << (p[*at] >> 6)
	if len(p)-*at < n {
		return 0, false
	}
	v := uint64(p[*at] & 63)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(p[*at+i])
	}
	*at += n
	return v, true
}

func quicHeader(p []byte) obj {
	if len(p) < 7 || p[0]&0x80 == 0 {
		return nil
	}
	v := binary.BigEndian.Uint32(p[1:5])
	d := obj{"version": fmt.Sprintf("0x%08x", v), "fixed_bit": p[0]&64 != 0, "complete_header": false}
	at := 5
	dcil := int(p[at])
	at++
	if dcil > 20 || len(p) < at+dcil+1 {
		d["error"] = "invalid_or_truncated_dcid"
		return d
	}
	at += dcil
	scil := int(p[at])
	at++
	if scil > 20 || len(p) < at+scil {
		d["error"] = "invalid_or_truncated_scid"
		return d
	}
	at += scil
	d["dcid_length"] = dcil
	d["scid_length"] = scil
	if v == 0 {
		d["packet_type"] = "version_negotiation"
		d["complete_header"] = (len(p)-at)%4 == 0
		versions := []string{}
		for len(p)-at >= 4 && len(versions) < 32 {
			versions = append(versions, fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(p[at:at+4])))
			at += 4
		}
		d["supported_versions"] = versions
		return d
	}
	t := int((p[0] >> 4) & 3)
	names := []string{"initial", "0rtt", "handshake", "retry"}
	if v == 0x6b3343cf {
		names = []string{"retry", "initial", "0rtt", "handshake"}
	}
	if v != 1 && v != 0x6b3343cf {
		d["packet_type"] = "unknown_version"
		return d
	}
	d["packet_type"] = names[t]
	if names[t] == "retry" {
		d["complete_header"] = len(p)-at >= 16
		d["token_length"] = max(0, len(p)-at-16)
		return d
	}
	if names[t] == "initial" {
		n, ok := varint(p, &at)
		if !ok || n > uint64(len(p)-at) {
			d["error"] = "invalid_or_truncated_token"
			return d
		}
		d["token_length"] = n
		at += int(n)
	}
	n, ok := varint(p, &at)
	if !ok {
		d["error"] = "truncated_length"
		return d
	}
	d["protected_length"] = n
	d["complete_header"] = true
	d["packet_truncated"] = n > uint64(len(p)-at)
	return d
}

type awgProfile struct {
	Port                int
	S                   [4]int
	H                   [4][2]uint32
	Protected, Trailers bool
	Valid               bool
}

func loadAWG(path string) awgProfile {
	a := awgProfile{}
	f, err := os.Open(path)
	if err != nil {
		return a
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 65536)
	// Read only Interface, discard all fields other than public sizing/header
	// parameters. Never run showconf/dump or log configuration text.
	section := ""
	seen := map[string]bool{}
	for s.Scan() {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Interface]" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "listenport" {
			a.Port, _ = strconv.Atoi(v)
		}
		if k == "headerprotectionkey" {
			a.Protected = v != "" && strings.Trim(v, "0=") != ""
		}
		if k == "randomtrailers" {
			a.Trailers = v == "true" || v == "1"
		}
		for i := 0; i < 4; i++ {
			if k == fmt.Sprint("s", i+1) {
				n, e := strconv.Atoi(v)
				if e == nil && n >= 0 && n <= 4096 {
					a.S[i] = n
					seen[k] = true
				}
			}
			if k == fmt.Sprint("h", i+1) {
				lo, hi, rangeOK := strings.Cut(v, "-")
				if !rangeOK {
					hi = lo
				}
				x, e := strconv.ParseUint(lo, 10, 32)
				y, e2 := strconv.ParseUint(hi, 10, 32)
				if e == nil && e2 == nil && x <= y {
					a.H[i] = [2]uint32{uint32(x), uint32(y)}
					seen[k] = true
				}
			}
		}
	}
	a.Valid = s.Err() == nil && a.Port > 0
	for i := 0; i < 4; i++ {
		a.Valid = a.Valid && seen[fmt.Sprint("h", i+1)] && seen[fmt.Sprint("s", i+1)]
	}
	return a
}

func awgShape(p []byte, wireLen int, a awgProfile) obj {
	d := obj{"profile_available": a.Valid, "authentication_checked": false}
	if !a.Valid {
		return d
	}
	d["header_protected"] = a.Protected
	d["random_trailers"] = a.Trailers
	sizes := []int{148, 92, 64, 32}
	names := []string{"initiation", "response", "cookie", "transport"}
	matches := []string{}
	lengths := []string{}
	for i := 0; i < 4; i++ {
		n := a.S[i] + sizes[i]
		ok := wireLen == n || (a.Trailers || i == 3) && wireLen >= n
		if !ok {
			continue
		}
		lengths = append(lengths, names[i])
		if !a.Protected && len(p) >= a.S[i]+4 {
			h := binary.LittleEndian.Uint32(p[a.S[i]:])
			if h >= a.H[i][0] && h <= a.H[i][1] {
				matches = append(matches, names[i])
			}
		}
	}
	d["length_candidates"] = lengths
	d["header_length_candidates"] = matches
	if a.Protected {
		d["assessment"] = "length_only_header_protected"
	} else {
		d["assessment"] = "structural_candidate_not_authenticated"
	}
	// Plain WireGuard probes are useful even on a masked AWG listener.
	if len(p) >= 4 {
		h := binary.LittleEndian.Uint32(p)
		if h >= 1 && h <= 4 && wireLen >= sizes[h-1] && (h == 4 || wireLen == sizes[h-1]) {
			d["plain_wireguard_candidate"] = names[h-1]
		}
	}
	return d
}
