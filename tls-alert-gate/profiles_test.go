package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func referenceProfiles(t *testing.T) []profile {
	t.Helper()
	f, e := os.Open("../probe-blackhole/profiles.json")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ps, e := loadProfiles(f)
	if e != nil {
		t.Fatal(e)
	}
	return ps
}
func TestPublicNFTRubyFixturesMatchExactProfiles(t *testing.T) {
	if _, e := exec.LookPath("ruby"); e != nil {
		t.Skip("independent Ruby nft fixture builder unavailable")
	}
	dir := t.TempDir()
	cmd := exec.Command("ruby", "../probe-blackhole/build-profiles.rb", "../probe-blackhole/profiles.json", dir)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture builder: %v %s", e, b)
	}
	for _, p := range referenceProfiles(t) {
		t.Run(p.ID, func(t *testing.T) {
			data, e := os.ReadFile(filepath.Join(dir, p.ID+".hello"))
			if e != nil {
				t.Fatal(e)
			}
			if !p.matches(data) {
				t.Fatal("Go classifier disagrees with deployed nft fixture")
			}
			if !clientHelloRecord(data) {
				t.Fatal("valid fixture not a ClientHello")
			}
			// Opaque random/session/key data must not be part of structural matching.
			mutated := bytes.Clone(data)
			for i := range mutated {
				if p.mask[i] == 0 {
					mutated[i] ^= 0xa5
				}
			}
			if !p.matches(mutated) {
				t.Fatal("opaque material altered classification")
			}
			for i := range data {
				if p.mask[i] != 0 {
					changed := bytes.Clone(data)
					changed[i] ^= 1
					if p.matches(changed) {
						t.Fatalf("changed matched byte%d accepted", i)
					}
				}
			}
			if p.matches(append(bytes.Clone(data), 0)) || p.matches(data[:len(data)-1]) {
				t.Fatal("wrong record lengths accepted")
			}
		})
	}
}
func TestIndependentSSL3FixtureAndAlert(t *testing.T) {
	prefix, _ := hex.DecodeString("160300004d010000490300")
	body := append(prefix, bytes.Repeat([]byte{0x5a}, 32)...)
	tail, _ := hex.DecodeString("000022003900380088008700330032009a00990045004400350084002f00960041000700ff0100")
	body = append(body, tail...)
	var target profile
	for _, p := range referenceProfiles(t) {
		if p.ID == "80eada7719bbed095130efee745e89e2" {
			target = p
		}
	}
	if len(body) != 82 || !target.matches(body) {
		t.Fatalf("independent SSL3 probe not matched, len=%d", len(body))
	}
	if !bytes.Equal(fatalAlert(body), []byte{21, 3, 0, 0, 2, 2, 40}) {
		t.Fatal("incorrect fatal SSL3-compatible alert")
	}
	modern := bytes.Clone(body)
	modern[9] = 3
	modern[10] = 3
	if !bytes.Equal(fatalAlert(modern), []byte{21, 3, 3, 0, 2, 2, 40}) {
		t.Fatal("incorrect standard TLS alert")
	}
}

// Force TCP reads smaller than a TLS header/record to exercise stream framing.
type smallReader struct{ r io.Reader }

func (s smallReader) Read(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return s.r.Read(p)
}
func TestInspectSplitTCPRecordPreservesFollowingData(t *testing.T) {
	p := referenceProfiles(t)[0]
	input := append(bytes.Clone(p.value), []byte("not-part-of-ClientHello")...)
	r := bytes.NewReader(input)
	prefix, e := inspectPrefix(smallReader{r}, 16384)
	if e != nil || !p.matches(prefix) {
		t.Fatalf("split read failed: %v", e)
	}
	remaining, _ := io.ReadAll(r)
	if string(remaining) != "not-part-of-ClientHello" {
		t.Fatal("reader consumed following application data")
	}
}
func TestInspectNonTLSOversizedAndTruncatedRemainOpaque(t *testing.T) {
	for _, in := range [][]byte{[]byte("SSH-2.0-test\r\n"), {22, 3, 3, 0xff, 0xff}, referenceProfiles(t)[0].value[:15]} {
		reader := bytes.NewReader(in)
		prefix, e := inspectPrefix(reader, 16384)
		if e != nil && !errors.Is(e, io.ErrUnexpectedEOF) {
			t.Fatal(e)
		}
		rest, _ := io.ReadAll(reader)
		combined := append(prefix, rest...)
		if !bytes.Equal(combined, in) {
			t.Fatal("passthrough lost bytes")
		}
		if clientHelloRecord(prefix) {
			t.Fatal("incomplete/non-TLS classified as ClientHello")
		}
	}
}
func TestInspectionLimitAndMalformedProfileAreRejected(t *testing.T) {
	for _, limit := range []int{0, 4, 16385} {
		if _, e := inspectPrefix(strings.NewReader("x"), limit); e == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	for _, text := range []string{"[]", "{}", "[null]"} {
		if _, e := loadProfiles(strings.NewReader(text)); e == nil {
			t.Fatal("malformed profile set accepted")
		}
	}
	source, _ := os.ReadFile("../probe-blackhole/profiles.json")
	var ps []profileSource
	if e := json.Unmarshal(source, &ps); e != nil {
		t.Fatal(e)
	}
	ps[0].Hello.RecordLengths[0]++
	b, _ := json.Marshal(ps)
	if _, e := loadProfiles(bytes.NewReader(b)); e == nil {
		t.Fatal("inconsistent profile accepted")
	}
}
