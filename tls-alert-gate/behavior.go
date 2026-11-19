package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type capabilities struct {
	Versions   []int    `json:"versions"`
	Ciphers    []int    `json:"ciphers"`
	Groups     []int    `json:"groups"`
	Signatures []int    `json:"signatures"`
	Extensions []int    `json:"extensions"`
	ALPN       []string `json:"alpn"`
}
type feature struct{ SNI, ID, VersionMode string }

func grease(n int) bool { return n >= 0 && n <= 65535 && n&0x0f0f == 0x0a0a && byte(n>>8) == byte(n) }
func canonicalIDs(values []int, extensions bool) []int {
	seen := map[int]bool{}
	for _, v := range values {
		if v < 0 || v > 65535 || grease(v) {
			continue
		}
		if extensions {
			switch v {
			case 21, 35, 41, 42, 44, 45:
				continue
			}
		}
		seen[v] = true
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}
func normalizedFeature(sni string, c capabilities) feature {
	c.Versions = canonicalIDs(c.Versions, false)
	c.Ciphers = canonicalIDs(c.Ciphers, false)
	c.Groups = canonicalIDs(c.Groups, false)
	c.Signatures = canonicalIDs(c.Signatures, false)
	c.Extensions = canonicalIDs(c.Extensions, true)
	seen := map[string]bool{}
	for _, s := range c.ALPN {
		if len(s) <= 255 && s != "" {
			seen[s] = true
		}
	}
	c.ALPN = make([]string, 0, len(seen))
	for s := range seen {
		c.ALPN = append(c.ALPN, s)
	}
	sort.Strings(c.ALPN)
	encoded, _ := json.Marshal(c)
	sum := sha256.Sum256(encoded)
	v, _ := json.Marshal(c.Versions)
	vs := sha256.Sum256(v)
	return feature{SNI: strings.ToLower(strings.TrimSuffix(sni, ".")), ID: hex.EncodeToString(sum[:]), VersionMode: hex.EncodeToString(vs[:])}
}
func vector16(data []byte) ([]int, bool) {
	if len(data) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(data))
	if n != len(data)-2 || n%2 != 0 {
		return nil, false
	}
	out := make([]int, 0, n/2)
	for i := 2; i < len(data); i += 2 {
		out = append(out, int(binary.BigEndian.Uint16(data[i:])))
	}
	return out, true
}
func featureFromRecord(record []byte) (feature, bool) {
	if !clientHelloRecord(record) {
		return feature{}, false
	}
	b := record[9:]
	if len(b) < 35 {
		return feature{}, false
	}
	legacy := int(binary.BigEndian.Uint16(b))
	pos := 34
	sid := int(b[pos])
	pos++
	if sid > 32 || pos+sid+2 > len(b) {
		return feature{}, false
	}
	pos += sid
	cipherBytes := int(binary.BigEndian.Uint16(b[pos:]))
	if cipherBytes == 0 || cipherBytes%2 != 0 || pos+2+cipherBytes+1 > len(b) {
		return feature{}, false
	}
	c := capabilities{Versions: []int{legacy}}
	var ok bool
	c.Ciphers, ok = vector16(b[pos : pos+2+cipherBytes])
	if !ok {
		return feature{}, false
	}
	pos += 2 + cipherBytes
	compression := int(b[pos])
	pos++
	if compression == 0 || pos+compression > len(b) {
		return feature{}, false
	}
	pos += compression
	sni := ""
	if pos == len(b) {
		return normalizedFeature(sni, c), true
	}
	if pos+2 > len(b) {
		return feature{}, false
	}
	extLen := int(binary.BigEndian.Uint16(b[pos:]))
	pos += 2
	if pos+extLen != len(b) {
		return feature{}, false
	}
	for pos < len(b) {
		if pos+4 > len(b) {
			return feature{}, false
		}
		typ := int(binary.BigEndian.Uint16(b[pos:]))
		n := int(binary.BigEndian.Uint16(b[pos+2:]))
		pos += 4
		if pos+n > len(b) {
			return feature{}, false
		}
		data := b[pos : pos+n]
		pos += n
		c.Extensions = append(c.Extensions, typ)
		switch typ {
		case 0:
			if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
				return feature{}, false
			}
			for at := 2; at < len(data); {
				if at+3 > len(data) {
					return feature{}, false
				}
				kind := data[at]
				length := int(binary.BigEndian.Uint16(data[at+1:]))
				at += 3
				if at+length > len(data) {
					return feature{}, false
				}
				if kind == 0 {
					if length == 0 || length > 253 {
						return feature{}, false
					}
					sni = string(data[at : at+length])
				}
				at += length
			}
		case 10:
			c.Groups, ok = vector16(data)
			if !ok {
				return feature{}, false
			}
		case 13, 50:
			var signatures []int
			signatures, ok = vector16(data)
			if !ok {
				return feature{}, false
			}
			c.Signatures = append(c.Signatures, signatures...)
		case 43:
			if len(data) < 1 || int(data[0]) != len(data)-1 || int(data[0])%2 != 0 {
				return feature{}, false
			}
			c.Versions = nil
			for at := 1; at < len(data); at += 2 {
				c.Versions = append(c.Versions, int(binary.BigEndian.Uint16(data[at:])))
			}
		case 16:
			if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
				return feature{}, false
			}
			for at := 2; at < len(data); {
				length := int(data[at])
				at++
				if length == 0 || at+length > len(data) {
					return feature{}, false
				}
				c.ALPN = append(c.ALPN, string(data[at:at+length]))
				at += length
			}
		}
	}
	return normalizedFeature(sni, c), true
}

// Same normalized schema is used for retrospective, read-only calibration of
// existing metadata journals; neither analysis nor the detector stores payloads.
func featureFromMetadata(sni string, hello map[string]json.RawMessage) (feature, bool) {
	var complete bool
	if json.Unmarshal(hello["complete"], &complete) != nil || !complete {
		return feature{}, false
	}
	var c capabilities
	for key, dst := range map[string]*[]int{"supported_versions": &c.Versions, "cipher_suites": &c.Ciphers, "supported_groups": &c.Groups, "signature_algorithms": &c.Signatures, "extension_types": &c.Extensions} {
		if raw := hello[key]; len(raw) > 0 && json.Unmarshal(raw, dst) != nil {
			return feature{}, false
		}
	}
	if len(c.Versions) == 0 {
		var legacy string
		if json.Unmarshal(hello["legacy_version"], &legacy) != nil {
			return feature{}, false
		}
		v, e := strconv.ParseUint(legacy, 0, 16)
		if e != nil {
			return feature{}, false
		}
		c.Versions = []int{int(v)}
	}
	if raw := hello["alpn_protocols"]; len(raw) > 0 && json.Unmarshal(raw, &c.ALPN) != nil {
		return feature{}, false
	}
	if len(c.Ciphers) == 0 {
		return feature{}, false
	}
	return normalizedFeature(sni, c), true
}

type observation struct {
	At      int64
	Version string
}
type behaviorBucket struct {
	IP       string
	Last     int64
	Profiles map[string]observation
}
type decision struct {
	Reason               string `json:"reason"`
	DistinctProfiles     int    `json:"distinct_profiles"`
	DistinctVersionModes int    `json:"distinct_version_modes"`
	Profiles15s          int    `json:"profiles_15s"`
}
type detector struct {
	mu        sync.Mutex
	buckets   map[string]*behaviorBucket
	perSource map[string]int
	lastSweep int64
	capacity  uint64
}

func newDetector() *detector {
	return &detector{buckets: map[string]*behaviorBucket{}, perSource: map[string]int{}}
}

// The caller holds d.mu, so the global and per-source inventories stay aligned.
func (d *detector) removeBucket(key string, b *behaviorBucket) {
	delete(d.buckets, key)
	d.perSource[b.IP]--
	if d.perSource[b.IP] == 0 {
		delete(d.perSource, b.IP)
	}
}
func (d *detector) observe(ip string, f feature, now int64) (decision, bool) {
	addr, e := netip.ParseAddr(ip)
	if e != nil || len(f.SNI) > 253 {
		return decision{}, false
	}
	ip = addr.Unmap().String()
	keyHash := sha256.Sum256([]byte(ip + "\x00" + f.SNI))
	key := string(keyHash[:])
	d.mu.Lock()
	defer d.mu.Unlock()
	if now > d.lastSweep {
		for k, b := range d.buckets {
			if b.Last < now-60 {
				d.removeBucket(k, b)
			}
		}
		d.lastSweep = now
	}
	b := d.buckets[key]
	if b == nil {
		if len(d.buckets) >= 4096 || d.perSource[ip] >= 64 {
			d.capacity++
			return decision{}, false
		}
		b = &behaviorBucket{IP: ip, Profiles: map[string]observation{}}
		d.buckets[key] = b
		d.perSource[ip]++
	}
	if now < b.Last-60 {
		return decision{}, false
	}
	if now > b.Last {
		b.Last = now
	}
	for id, o := range b.Profiles {
		if o.At < now-60 {
			delete(b.Profiles, id)
		}
	}
	if _, ok := b.Profiles[f.ID]; !ok && len(b.Profiles) >= 16 {
		d.capacity++
		return decision{}, false
	}
	b.Profiles[f.ID] = observation{At: now, Version: f.VersionMode}
	versions := map[string]bool{}
	recent := 0
	for _, o := range b.Profiles {
		versions[o.Version] = true
		if o.At >= now-15 {
			recent++
		}
	}
	r := decision{DistinctProfiles: len(b.Profiles), DistinctVersionModes: len(versions), Profiles15s: recent}
	switch {
	case len(b.Profiles) >= 4 && len(versions) >= 3:
		r.Reason = "tls_version_sweep_4_profiles_3_modes_60s"
	case recent >= 6:
		r.Reason = "tls_capability_sweep_6_profiles_15s"
	case len(b.Profiles) >= 8:
		r.Reason = "tls_capability_sweep_8_profiles_60s"
	default:
		return r, false
	}
	return r, true
}
func (d *detector) status() (int, uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.buckets), d.capacity
}

func (d *detector) forget(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, bucket := range d.buckets {
		if bucket.IP == ip {
			d.removeBucket(key, bucket)
		}
	}
}
