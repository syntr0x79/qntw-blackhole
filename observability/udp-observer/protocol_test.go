package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func TestQUICVersionsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		v uint32
		b byte
	}{{1, 0xc0}, {0x6b3343cf, 0xd0}} {
		p := []byte{tc.b, 0, 0, 0, 0, 2, 1, 2, 0, 0, 5, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(p[1:5], tc.v)
		q := quicHeader(p)
		if q["packet_type"] != "initial" || q["token_length"] != uint64(0) || q["packet_truncated"] != false {
			t.Fatal(q)
		}
		b, _ := json.Marshal(q)
		if strings.Contains(string(b), "0102") {
			t.Fatal("CID leaked")
		}
	}
	for n := 0; n < 128; n++ {
		for b := 0; b < 256; b++ {
			p := make([]byte, n)
			for i := range p {
				p[i] = byte(b)
			}
			quicHeader(p)
		}
	}
	q := quicHeader([]byte{0xc0, 0, 0, 0, 1, 40, 0})
	if q["complete_header"] != false {
		t.Fatal(q)
	}
}

type fakeForward struct {
	calls         int
	first, second error
}

func (f *fakeForward) SetWriteDeadline(t time.Time) error { return nil }
func (f *fakeForward) Write(b []byte) (int, error) {
	f.calls++
	e := f.first
	if f.calls > 1 {
		e = f.second
	}
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
func TestForwardRetryAndErrorClassification(t *testing.T) {
	f := &fakeForward{first: syscall.ECONNREFUSED}
	retry, e := deliver(f, []byte("metadata-only"))
	if !retry || e != nil || f.calls != 2 {
		t.Fatal(retry, e, f.calls)
	}
	f = &fakeForward{first: syscall.EMSGSIZE}
	retry, e = deliver(f, []byte("metadata-only"))
	if retry || forwardReason(e) != "message_too_long" || f.calls != 1 {
		t.Fatal(retry, e)
	}
	f = &fakeForward{first: syscall.ENOBUFS, second: syscall.ENOBUFS}
	retry, e = deliver(f, nil)
	if !retry || forwardReason(e) != "no_buffer" {
		t.Fatal(retry, e)
	}
}
func TestAWGProtectionAndNoSecretFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "awg.conf")
	os.WriteFile(p, []byte("[Interface]\nPrivateKey = NEVER_COPY_PRIVATE\nHeaderProtectionKey = NEVER_COPY_HEADER_KEY\nListenPort = 51821\nS1 = 33\nS2 = 48\nS3 = 45\nS4 = 51\nH1 = 99-100\nH2 = 101\nH3 = 102\nH4 = 103\n[Peer]\nPresharedKey = NEVER_COPY_PSK\n"), 0600)
	a := loadAWG(p)
	if !a.Valid || !a.Protected {
		t.Fatal(a)
	}
	b := make([]byte, 181)
	binary.LittleEndian.PutUint32(b[33:], 99)
	d := awgShape(b, len(b), a)
	if len(d["header_length_candidates"].([]string)) != 0 {
		t.Fatal("protected header falsely classified")
	}
	a.Protected = false
	d = awgShape(b, len(b), a)
	if len(d["header_length_candidates"].([]string)) != 1 {
		t.Fatal(d)
	}
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "NEVER_COPY") {
		t.Fatal("secret retained")
	}
}
func udpPacket(src, dst string, sp, dp uint16, payload []byte, v6 bool) []byte {
	e := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	u := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
	b := gopacket.NewSerializeBuffer()
	var ip gopacket.SerializableLayer
	if v6 {
		e.EthernetType = layers.EthernetTypeIPv6
		i := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
		ip = i
		u.SetNetworkLayerForChecksum(i)
	} else {
		i := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
		ip = i
		u.SetNetworkLayerForChecksum(i)
	}
	gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, e, ip, u, gopacket.Payload(payload))
	return b.Bytes()
}
func TestSamplingAggregationDirectionAndIPv6(t *testing.T) {
	o := &observer{local: map[string]bool{"192.0.2.1": true, "2001:db8::1": true}, known: map[string]bool{}, counts: map[string]uint64{}, events: make(chan obj, 64), decode: make(chan decodePacket, 1), flows: map[string]*flow{}, directionReady: true, directionSeed: time.Now()}
	for i := 0; i < 20; i++ {
		b := udpPacket("198.51.100.2", "192.0.2.1", 1234, 443, []byte("PAYLOAD_SECRET"), false)
		o.packet(b, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(b), Length: len(b)})
	}
	if len(o.events) != 8 {
		t.Fatal("sampling", len(o.events))
	}
	for _, f := range o.flows {
		if f.In != 20 {
			t.Fatal(f)
		}
	}
	b := udpPacket("192.0.2.1", "198.51.100.99", 55555, 53, nil, false)
	o.packet(b, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(b), Length: len(b)})
	if len(o.flows) != 1 {
		t.Fatal("customer egress recorded")
	}
	b = udpPacket("2001:db8::2", "2001:db8::1", 1234, 443, nil, true)
	o.packet(b, gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(b), Length: len(b)})
	if len(o.flows) != 2 {
		t.Fatal("IPv6 missing")
	}
	close(o.events)
	for e := range o.events {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "PAYLOAD_SECRET") {
			t.Fatal("payload leaked")
		}
	}
}
func TestDecodedClientHelloWhitelist(t *testing.T) {
	r := make([]string, len(decodeFields))
	for i, k := range decodeFields {
		if k == "tls.handshake.type" {
			r[i] = "1"
		}
		if k == "tls.handshake.ciphersuite" {
			r[i] = "0x1301,0x1302"
		}
	}
	d := decoded(r)
	if d == nil {
		t.Fatal("hello missing")
	}
	h := d["client_hello"].(obj)
	if len(h["cipher_suites"].([]uint64)) != 2 {
		t.Fatal(h)
	}
	for _, f := range decodeFields {
		if strings.Contains(f, "random") || strings.Contains(f, "payload") || strings.HasSuffix(f, ".dcid") {
			t.Fatal("unsafe dissector field", f)
		}
	}
}
