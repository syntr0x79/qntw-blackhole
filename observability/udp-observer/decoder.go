package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Explicit allowlist: no raw payload, IDs, tokens, randoms, keys, tickets,
// MACs, PSK identity/binder, or ECH ciphertext can leave the dissector.
var decodeFields = []string{"frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "udp.srcport", "udp.dstport", "quic.version", "quic.long.packet_type", "quic.decryption_failed", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str", "tls.handshake.ja3", "tls.handshake.ja3_full", "tls.handshake.version", "tls.handshake.length", "tls.handshake.ciphersuite", "tls.handshake.extension.type", "tls.handshake.extension.len", "tls.handshake.extensions_supported_group", "tls.handshake.sig_hash_alg", "tls.handshake.extensions.supported_version", "tls.handshake.extensions_key_share_group", "tls.handshake.extensions_ec_point_format", "tls.quic.parameter.type", "tls.quic.parameter.length"}

type decodePacket struct {
	Info gopacket.CaptureInfo
	Data []byte
}

func numbers(s string) []uint64 {
	out := []uint64{}
	for _, v := range strings.Split(s, ",") {
		n, e := strconv.ParseUint(strings.TrimSpace(v), 0, 64)
		if e == nil && len(out) < 512 {
			out = append(out, n)
		}
	}
	return out
}
func safe(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}
func decoded(row []string) obj {
	if len(row) != len(decodeFields) {
		return nil
	}
	r := map[string]string{}
	for i, k := range decodeFields {
		r[k] = row[i]
	}
	if !strings.Contains(","+r["tls.handshake.type"]+",", ",1,") {
		return nil
	}
	src, dst := r["ip.src"], r["ip.dst"]
	if src == "" {
		src = r["ipv6.src"]
	}
	if dst == "" {
		dst = r["ipv6.dst"]
	}
	h := obj{"schema": 1, "transport": "quic", "scope": "decoded_client_hello_structure", "sni": safe(r["tls.handshake.extensions_server_name"], 255), "alpn": safe(r["tls.handshake.extensions_alpn_str"], 128), "ja3": safe(r["tls.handshake.ja3"], 64), "ja3_full": safe(r["tls.handshake.ja3_full"], 4096)}
	for out, in := range map[string]string{"legacy_version": "tls.handshake.version", "handshake_lengths": "tls.handshake.length", "cipher_suites": "tls.handshake.ciphersuite", "extension_types": "tls.handshake.extension.type", "extension_lengths": "tls.handshake.extension.len", "supported_groups": "tls.handshake.extensions_supported_group", "signature_algorithms": "tls.handshake.sig_hash_alg", "supported_versions": "tls.handshake.extensions.supported_version", "key_share_groups": "tls.handshake.extensions_key_share_group", "ec_point_formats": "tls.handshake.extensions_ec_point_format", "quic_parameter_types": "tls.quic.parameter.type", "quic_parameter_lengths": "tls.quic.parameter.length"} {
		h[out] = numbers(r[in])
	}
	// Wireshark may have reassembled CRYPTO across sampled Initials. We do
	// not promise a complete handshake or identify an application/tool.
	h["sampling_limited"] = true
	return obj{"event": "udp_quic_hello", "epoch": r["frame.time_epoch"], "src": src, "dst": dst, "sport": r["udp.srcport"], "dport": r["udp.dstport"], "client_hello": h, "quic_version": safe(r["quic.version"], 64), "authentication_checked": false, "direction_schema": 2, "direction": "ingress", "flow_origin": "inbound", "origin_basis": "selected_inbound_flow"}
}

func (o *observer) decoder(ctx context.Context) {
	for ctx.Err() == nil {
		args := []string{"--reuid=65534", "--regid=65534", "--clear-groups", "tshark", "-n", "-l", "-r", "-", "-M", "5000", "-d", "udp.port==1-65535,quic", "-T", "fields", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"}
		for _, f := range decodeFields {
			args = append(args, "-e", f)
		}
		cctx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(cctx, "setpriv", args...)
		in, e := cmd.StdinPipe()
		if e != nil {
			cancel()
			return
		}
		out, e := cmd.StdoutPipe()
		if e != nil {
			cancel()
			return
		}
		cmd.Stderr = io.Discard
		if e = cmd.Start(); e != nil {
			o.inc("decoder_errors")
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		o.up("decoder", 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			s := bufio.NewScanner(out)
			s.Buffer(make([]byte, 8192), 262144)
			for s.Scan() {
				r := csv.NewReader(strings.NewReader(s.Text()))
				r.Comma = '\t'
				r.FieldsPerRecord = -1
				row, e := r.Read()
				if e != nil {
					o.inc("decoder_parse_errors")
					continue
				}
				o.inc("decoder_records")
				if len(row) > 9 && row[9] != "" {
					o.inc("quic_decryption_failed")
				}
				if d := decoded(row); d != nil {
					o.emit(d)
					o.inc("quic_client_hellos")
				}
			}
			if s.Err() != nil {
				o.inc("decoder_read_errors")
			}
			cancel()
		}()
		w := pcapgo.NewWriter(in)
		e = w.WriteFileHeader(4096, layers.LinkTypeEthernet)
	loop:
		for e == nil {
			select {
			case <-cctx.Done():
				break loop
			case p := <-o.decode:
				e = w.WritePacket(p.Info, p.Data)
				if e == nil {
					o.inc("decoder_packets_written")
				}
			}
		}
		in.Close()
		cancel()
		cmd.Wait()
		<-done
		o.up("decoder", 0)
		o.inc("decoder_restarts")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
