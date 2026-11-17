package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

type helloSpec struct {
	Complete           bool   `json:"complete"`
	JA3Matches         bool   `json:"ja3_matches"`
	RecordVersions     []int  `json:"record_versions"`
	RecordLengths      []int  `json:"record_lengths"`
	HandshakeLengths   []int  `json:"handshake_lengths"`
	LegacyVersion      string `json:"legacy_version"`
	SessionIDLength    int    `json:"session_id_length"`
	CipherSuites       []int  `json:"cipher_suites"`
	CompressionMethods []int  `json:"compression_methods"`
	ExtensionsLength   *int   `json:"extensions_length"`
	ExtensionTypes     []int  `json:"extension_types"`
	ExtensionLengths   []int  `json:"extension_lengths"`
	SupportedGroups    []int  `json:"supported_groups"`
	ECPointFormats     []int  `json:"ec_point_formats"`
	SupportedVersions  []int  `json:"supported_versions"`
}
type profileSource struct {
	JA3   string    `json:"ja3"`
	Hello helloSpec `json:"hello"`
}
type profile struct {
	ID          string
	value, mask []byte
}

// Match exactly the existing nft structural-byte profiles. Randoms, session
// identifiers and opaque extension/key-share content are deliberately ignored.
func (p profile) matches(record []byte) bool {
	if len(record) != len(p.value) {
		return false
	}
	for i, b := range record {
		if p.mask[i] != 0 && b != p.value[i] {
			return false
		}
	}
	return true
}
func u16(n int) ([]byte, error) {
	if n < 0 || n > 65535 {
		return nil, errors.New("invalid uint16")
	}
	return []byte{byte(n >> 8), byte(n)}, nil
}
func words(ns []int) ([]byte, error) {
	out := make([]byte, 0, len(ns)*2)
	for _, n := range ns {
		v, e := u16(n)
		if e != nil {
			return nil, e
		}
		out = append(out, v...)
	}
	return out, nil
}
func compileProfile(src profileSource) (profile, error) {
	h := src.Hello
	fail := func() (profile, error) { return profile{}, fmt.Errorf("invalid public profile %s", src.JA3) }
	if len(src.JA3) != 32 || !h.Complete || !h.JA3Matches || len(h.RecordVersions) != 1 || len(h.RecordLengths) != 1 || len(h.HandshakeLengths) != 1 || h.SessionIDLength < 0 || h.SessionIDLength > 32 || len(h.ExtensionTypes) != len(h.ExtensionLengths) {
		return fail()
	}
	for _, ch := range src.JA3 {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return fail()
		}
	}
	legacy, err := strconv.ParseUint(h.LegacyVersion, 0, 16)
	if err != nil {
		return fail()
	}
	suites, err := words(h.CipherSuites)
	if err != nil {
		return fail()
	}
	if len(h.CompressionMethods) > 255 {
		return fail()
	}
	body := []byte{byte(legacy >> 8), byte(legacy)}
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(h.SessionIDLength))
	body = append(body, make([]byte, h.SessionIDLength)...)
	prefix := []byte{byte(len(suites) >> 8), byte(len(suites))}
	prefix = append(prefix, suites...)
	prefix = append(prefix, byte(len(h.CompressionMethods)))
	for _, n := range h.CompressionMethods {
		if n < 0 || n > 255 {
			return fail()
		}
		prefix = append(prefix, byte(n))
	}
	body = append(body, prefix...)
	ext := []byte{}
	extMask := []byte{}
	for i, typ := range h.ExtensionTypes {
		length := h.ExtensionLengths[i]
		head, e := words([]int{typ, length})
		if e != nil {
			return fail()
		}
		ext = append(ext, head...)
		extMask = append(extMask, 1, 1, 1, 1)
		data := make([]byte, length)
		masked := false
		switch typ {
		case 10:
			vals, e := words(h.SupportedGroups)
			if e != nil {
				return fail()
			}
			data = append([]byte{byte(len(vals) >> 8), byte(len(vals))}, vals...)
			masked = true
		case 11:
			if len(h.ECPointFormats) > 255 {
				return fail()
			}
			data = []byte{byte(len(h.ECPointFormats))}
			for _, v := range h.ECPointFormats {
				if v < 0 || v > 255 {
					return fail()
				}
				data = append(data, byte(v))
			}
			masked = true
		case 43:
			vals, e := words(h.SupportedVersions)
			if e != nil || len(vals) > 255 {
				return fail()
			}
			data = append([]byte{byte(len(vals))}, vals...)
			masked = true
		}
		if len(data) != length {
			return fail()
		}
		ext = append(ext, data...)
		for range data {
			if masked {
				extMask = append(extMask, 1)
			} else {
				extMask = append(extMask, 0)
			}
		}
	}
	if h.ExtensionsLength != nil {
		if *h.ExtensionsLength != len(ext) {
			return fail()
		}
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
	} else if len(ext) != 0 {
		return fail()
	}
	extOffset := 5 + 4 + len(body)
	body = append(body, ext...)
	if len(body) != h.HandshakeLengths[0] || len(body)+4 != h.RecordLengths[0] || h.RecordLengths[0] > 16384 {
		return fail()
	}
	rv, e := u16(h.RecordVersions[0])
	if e != nil {
		return fail()
	}
	record := []byte{22, rv[0], rv[1], byte(h.RecordLengths[0] >> 8), byte(h.RecordLengths[0]), 1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	record = append(record, body...)
	mask := make([]byte, len(record))
	for i := 0; i < 11; i++ {
		mask[i] = 1
	}
	mask[43] = 1
	fixedOffset := 44 + h.SessionIDLength
	for i := fixedOffset; i < extOffset; i++ {
		mask[i] = 1
	}
	copy(mask[extOffset:], extMask)
	return profile{ID: src.JA3, value: record, mask: mask}, nil
}
func loadProfiles(r io.Reader) ([]profile, error) {
	var source []profileSource
	raw, e := io.ReadAll(io.LimitReader(r, 1<<20))
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(raw, &source); e != nil {
		return nil, e
	}
	if len(source) != 6 {
		return nil, errors.New("expected six public profiles")
	}
	result := make([]profile, 0, 6)
	seen := map[string]bool{}
	for _, s := range source {
		p, e := compileProfile(s)
		if e != nil {
			return nil, e
		}
		if seen[p.ID] {
			return nil, errors.New("duplicate public profile")
		}
		seen[p.ID] = true
		result = append(result, p)
	}
	return result, nil
}

// inspectPrefix consumes only a bounded initial TLS record. TCP segmentation
// is handled by the stream reader; a different TLS-record layout passes through.
// On partial/slow/malformed data, all bytes read are returned for opaque proxying.
func inspectPrefix(r io.Reader, limit int) ([]byte, error) {
	if limit < 5 || limit > 16384 {
		return nil, errors.New("invalid inspection limit")
	}
	first := make([]byte, 1)
	n, err := io.ReadFull(r, first)
	first = first[:n]
	if err != nil || first[0] != 22 {
		return first, err
	}
	tail := make([]byte, 4)
	n, err = io.ReadFull(r, tail)
	prefix := append(first, tail[:n]...)
	if err != nil {
		return prefix, err
	}
	length := int(binary.BigEndian.Uint16(prefix[3:5]))
	if length < 4 || length+5 > limit {
		return prefix, nil
	}
	body := make([]byte, length)
	n, err = io.ReadFull(r, body)
	prefix = append(prefix, body[:n]...)
	return prefix, err
}
func fatalAlert(record []byte) []byte {
	version := uint16(0x0303)
	if len(record) >= 11 {
		v := binary.BigEndian.Uint16(record[9:11])
		if v >= 0x0300 && v <= 0x0303 {
			version = v
		}
	}
	return []byte{21, byte(version >> 8), byte(version), 0, 2, 2, 40}
}
