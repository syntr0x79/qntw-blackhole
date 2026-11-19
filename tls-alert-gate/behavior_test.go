package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func genericCH(c capabilities, sni string) []byte {
	word := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	vector := func(ns []int) []byte { v, _ := words(ns); return append(word(len(v)), v...) }
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{0x54}, 32)...)
	body = append(body, 0)
	body = append(body, vector(c.Ciphers)...)
	body = append(body, 1, 0)
	ext := []byte{}
	for _, typ := range c.Extensions {
		data := []byte{}
		switch typ {
		case 0:
			entry := append([]byte{0}, word(len(sni))...)
			entry = append(entry, []byte(sni)...)
			data = append(word(len(entry)), entry...)
		case 10:
			data = vector(c.Groups)
		case 13:
			data = vector(c.Signatures)
		case 43:
			v, _ := words(c.Versions)
			data = append([]byte{byte(len(v))}, v...)
		case 16:
			v := []byte{}
			for _, s := range c.ALPN {
				v = append(v, byte(len(s)))
				v = append(v, []byte(s)...)
			}
			data = append(word(len(v)), v...)
		case 21:
			data = bytes.Repeat([]byte{0x77}, 14)
		case 35:
			data = []byte("opaque-ticket")
		case 41:
			data = []byte("opaque-psk")
		case 44:
			data = []byte("opaque-cookie")
		}
		ext = append(ext, word(typ)...)
		ext = append(ext, word(len(data))...)
		ext = append(ext, data...)
	}
	body = append(body, word(len(ext))...)
	body = append(body, ext...)
	hand := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hand = append(hand, body...)
	rec := []byte{22, 3, 1, byte(len(hand) >> 8), byte(len(hand))}
	return append(rec, hand...)
}
func baselineCaps() capabilities {
	return capabilities{Versions: []int{0x0304, 0x0303}, Ciphers: []int{4865, 4866, 4867, 49199}, Groups: []int{29, 23}, Signatures: []int{0x0403, 0x0804}, Extensions: []int{0, 43, 10, 13, 16, 51}, ALPN: []string{"h2", "http/1.1"}}
}
func TestChromeOrderGREASEAndResumptionNormalizeOut(t *testing.T) {
	a := baselineCaps()
	first, ok := featureFromRecord(genericCH(a, "Example.COM."))
	if !ok {
		t.Fatal("baseline parse")
	}
	b := baselineCaps()
	b.Ciphers = []int{0x0a0a, 49199, 4867, 4866, 4865}
	b.Groups = []int{0x1a1a, 23, 29}
	b.Signatures = []int{0x0804, 0x0403, 0x2a2a}
	b.Versions = []int{0x4a4a, 0x0303, 0x0304}
	b.Extensions = []int{51, 16, 13, 0x3a3a, 43, 0, 10, 21, 35, 41, 42, 44, 45}
	b.ALPN = []string{"http/1.1", "h2"}
	second, ok := featureFromRecord(genericCH(b, "example.com"))
	if !ok {
		t.Fatal("resumption/GREASE parse")
	}
	if first.ID != second.ID || first.VersionMode != second.VersionMode || first.SNI != second.SNI {
		t.Fatal("volatile fields caused new capability profile")
	}
	d := newDetector()
	for n := 0; n < 100; n++ {
		f := first
		if n%2 == 1 {
			f = second
		}
		if _, hit := d.observe("192.0.2.20", f, 1000+int64(n/20)); hit {
			t.Fatal("ordinary reconnects classified as scan")
		}
	}
}
func TestVersionAndCipherSweepsAreRecognized(t *testing.T) {
	d := newDetector()
	versions := [][]int{{0x0304}, {0x0303}, {0x0302}, {0x0301}}
	for i, v := range versions {
		c := baselineCaps()
		c.Versions = v
		f, _ := featureFromRecord(genericCH(c, "site.example"))
		r, hit := d.observe("192.0.2.20", f, 1000+int64(i))
		if hit != (i == 3) {
			t.Fatalf("version threshold at%d: %v", i, hit)
		}
		if hit && r.Reason != "tls_version_sweep_4_profiles_3_modes_60s" {
			t.Fatal(r)
		}
	}
	d = newDetector()
	for i := 0; i < 6; i++ {
		c := baselineCaps()
		c.Ciphers = append(c.Ciphers, 600+i)
		f, _ := featureFromRecord(genericCH(c, "site.example"))
		r, hit := d.observe("192.0.2.20", f, 2000+int64(i))
		if hit != (i == 5) {
			t.Fatalf("cipher threshold at%d: %v", i, hit)
		}
		if hit && r.Reason != "tls_capability_sweep_6_profiles_15s" {
			t.Fatal(r)
		}
	}
}
func TestSharedNATDifferentSNIStaysSeparatedAndALPNVariationCounts(t *testing.T) {
	d := newDetector()
	for i := 0; i < 10; i++ {
		c := baselineCaps()
		c.Ciphers = append(c.Ciphers, 600+i)
		f, _ := featureFromRecord(genericCH(c, fmt.Sprintf("node%d.example", i)))
		if _, hit := d.observe("192.0.2.20", f, 1000+int64(i)); hit {
			t.Fatal("different mask SNIs mixed")
		}
	}
	d = newDetector()
	for i := 0; i < 6; i++ {
		c := baselineCaps()
		c.ALPN = []string{fmt.Sprintf("protocol%d", i)}
		f, _ := featureFromRecord(genericCH(c, "one.example"))
		_, hit := d.observe("192.0.2.20", f, 1000+int64(i))
		if hit != (i == 5) {
			t.Fatal("ALPN used as bucket instead of capability")
		}
	}
}
func TestBehaviorWindowsAndBounds(t *testing.T) {
	d := newDetector()
	for i := 0; i < 8; i++ {
		c := baselineCaps()
		c.Ciphers = append(c.Ciphers, 600+i)
		f := normalizedFeature("one.example", c)
		r, hit := d.observe("192.0.2.20", f, 1000+int64(i*7))
		if hit != (i == 7) {
			t.Fatalf("60s threshold at%d: %v", i, hit)
		}
		if hit && r.Reason != "tls_capability_sweep_8_profiles_60s" {
			t.Fatal(r)
		}
	}
	d = newDetector()
	for i := 0; i < 20; i++ {
		c := baselineCaps()
		c.Ciphers = append(c.Ciphers, 600+i)
		if _, hit := d.observe("192.0.2.20", normalizedFeature("one.example", c), 1000+int64(i*61)); hit {
			t.Fatal("expired profiles accumulated")
		}
	}
	for i := 0; i < 4100; i++ {
		d.observe(fmt.Sprintf("2001:db8::%x", i+1), normalizedFeature("a", baselineCaps()), 3000)
	}
	n, capacity := d.status()
	if n != 4096 || capacity == 0 {
		t.Fatalf("unbounded buckets n=%d cap=%d", n, capacity)
	}
}
func TestMetadataAndWireShareTheSameFingerprint(t *testing.T) {
	c := baselineCaps()
	wire, _ := featureFromRecord(genericCH(c, "one.example"))
	raw := map[string]any{"complete": true, "supported_versions": c.Versions, "cipher_suites": c.Ciphers, "supported_groups": c.Groups, "signature_algorithms": c.Signatures, "extension_types": c.Extensions, "alpn_protocols": c.ALPN, "legacy_version": "0x0303"}
	encoded, _ := json.Marshal(raw)
	var metadata map[string]json.RawMessage
	json.Unmarshal(encoded, &metadata)
	meta, ok := featureFromMetadata("one.example", metadata)
	if !ok || wire != meta {
		t.Fatal("offline calibration differs from wire detector")
	}
}

func TestRotatingSNICannotExhaustBehaviorCapacityForAnotherSource(t *testing.T) {
	d := newDetector()
	f := normalizedFeature("", baselineCaps())
	for i := 0; i < 4100; i++ {
		f.SNI = fmt.Sprintf("name%d.example", i)
		d.observe("192.0.2.1", f, 1000)
	}
	n, capacity := d.status()
	if n != 64 || capacity != 4036 || d.perSource["192.0.2.1"] != 64 {
		t.Fatalf("per-source SNI inventory is unbounded: %d buckets, %d rejected", n, capacity)
	}
	for i := 0; i < 6; i++ {
		c := baselineCaps()
		c.Ciphers = append(c.Ciphers, 600+i)
		_, hit := d.observe("192.0.2.2", normalizedFeature("other.example", c), 1000+int64(i))
		if hit != (i == 5) {
			t.Fatalf("another source lost behavior detection at profile %d", i)
		}
	}
	d.forget("192.0.2.1")
	if _, exists := d.perSource["192.0.2.1"]; exists {
		t.Fatal("release retained the source's behavior capacity")
	}
	for i := 0; i < 64; i++ {
		f.SNI = fmt.Sprintf("new%d.example", i)
		d.observe("192.0.2.1", f, 1006)
	}
	if d.perSource["192.0.2.1"] != 64 {
		t.Fatal("released behavior capacity could not be reused")
	}
	d.observe("192.0.2.3", f, 1067)
	if len(d.perSource) != 1 || d.perSource["192.0.2.3"] != 1 || len(d.buckets) != 1 {
		t.Fatal("expiration retained per-source behavior capacity")
	}
}
func TestCalibrationNeverWritesStateOrLeaksOpaqueData(t *testing.T) {
	var input strings.Builder
	for i := 0; i < 6; i++ {
		c := baselineCaps()
		c.Ciphers = append(c.Ciphers, 600+i)
		r := map[string]any{"event": "tls_hello", "src": "192.0.2.20", "sni": "one.example", "epoch": fmt.Sprint(1000 + i), "client_hello": map[string]any{"complete": true, "supported_versions": c.Versions, "cipher_suites": c.Ciphers, "supported_groups": c.Groups, "signature_algorithms": c.Signatures, "extension_types": c.Extensions, "alpn_protocols": c.ALPN, "random": "secret-random", "session_id": "secret-session", "key_share": "secret-key"}}
		b, _ := json.Marshal(r)
		input.Write(b)
		input.WriteByte('\n')
	}
	var output bytes.Buffer
	if e := analyzeMetadata(strings.NewReader(input.String()), &output, map[string]bool{}); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(output.String(), "tls_behavior_candidate") || strings.Contains(output.String(), "secret-") {
		t.Fatal("invalid calibration output")
	}
	var trusted bytes.Buffer
	if e := analyzeMetadata(strings.NewReader(input.String()), &trusted, map[string]bool{"192.0.2.20": true}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(trusted.String(), "tls_behavior_candidate") {
		t.Fatal("trusted source counted")
	}
}
func TestParserMalformedAndBounded(t *testing.T) {
	c := baselineCaps()
	good := genericCH(c, "a.example")
	for i := 0; i < len(good); i++ {
		if _, ok := featureFromRecord(good[:i]); ok {
			t.Fatalf("truncation%d accepted", i)
		}
	}
	bad := bytes.Clone(good)
	binary.BigEndian.PutUint16(bad[3:5], 65535)
	if _, ok := featureFromRecord(bad); ok {
		t.Fatal("bad framing accepted")
	}
	p, e := inspectPrefix(bytes.NewReader(bad), 16384)
	if e != nil && e != io.EOF {
		t.Fatal(e)
	}
	if len(p) > 5 {
		t.Fatal("unbounded inspection")
	}
}
