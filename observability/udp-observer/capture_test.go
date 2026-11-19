package main

import "testing"

func TestCaptureDroppedStatisticsFormats(t *testing.T) {
	for _, row := range []struct {
		line  string
		value uint64
		valid bool
	}{
		{"9809 packets dropped by kernel", 9809, true},
		{"tcpdump: 49 packets captured, 10000 packets received by filter, 9809 packets dropped by kernel", 9809, true},
		{"tcpdump: 49 packets captured, 49 packets received by filter, 0 packets dropped by kernel", 0, true},
		{"tcpdump: listening on eth0", 0, false},
		{"18446744073709551616 packets dropped by kernel", 0, false},
	} {
		actual, valid := captureDropped(row.line)
		if valid != row.valid || (valid && actual != row.value) {
			t.Errorf("captureDropped(%q) = %d,%t; want %d,%t", row.line, actual, valid, row.value, row.valid)
		}
	}
}
