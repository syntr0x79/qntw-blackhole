package main

import (
	"bufio"
	"encoding/json"
	"io"
	"strconv"
	"time"
)

func analyzeMetadata(r io.Reader, w io.Writer, trusted map[string]bool) error {
	d := newDetector()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var records, complete int
	for scanner.Scan() {
		var e struct {
			Event, Src, SNI string
			Epoch           json.RawMessage
			Observed        string                     `json:"observed_utc"`
			Hello           map[string]json.RawMessage `json:"client_hello"`
		}
		if json.Unmarshal(scanner.Bytes(), &e) != nil || e.Event != "tls_hello" || trusted[e.Src] || seen[e.Src] {
			continue
		}
		records++
		f, ok := featureFromMetadata(e.SNI, e.Hello)
		if !ok {
			continue
		}
		complete++
		var epoch string
		if json.Unmarshal(e.Epoch, &epoch) != nil {
			epoch = string(e.Epoch)
		}
		at, err := strconv.ParseFloat(epoch, 64)
		if err != nil {
			v, e := time.Parse(time.RFC3339Nano, e.Observed)
			if e != nil {
				continue
			}
			at = float64(v.UnixNano()) / 1e9
		}
		decision, hit := d.observe(e.Src, f, int64(at))
		if !hit {
			continue
		}
		seen[e.Src] = true
		v := map[string]any{"event": "tls_behavior_candidate", "src": e.Src, "at_utc": time.Unix(int64(at), 0).UTC().Format(time.RFC3339), "reason": decision.Reason, "distinct_profiles": decision.DistinctProfiles, "distinct_version_modes": decision.DistinctVersionModes, "profiles_15s": decision.Profiles15s, "sni": f.SNI}
		if err = json.NewEncoder(w).Encode(v); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	buckets, capacity := d.status()
	return json.NewEncoder(w).Encode(map[string]any{"event": "tls_behavior_analysis_summary", "records": records, "complete_hellos": complete, "candidate_sources": len(seen), "buckets": buckets, "capacity": capacity, "read_only": true, "policy": "4profiles+3versions/60s or6profiles/15s or8profiles/60s"})
}
