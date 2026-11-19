# Ingress observation and analysis

This directory is self-contained. The Python collector supplies `events.jsonl`
to the blackhole policy engine. The analyzer and UDP observer provide additional
evidence and health reports. Their runtime paths and `vpnshop-*` service names
remain compatible with existing installations.

| Component | Input | Output |
| --- | --- | --- |
| `probe-logging.py` | Interface capture, original-destination conntrack events, local nginx syslog, selected service journals | Private rotated JSONL and Prometheus textfile |
| `probe-analysis.py` | Collector JSONL and rotations | Candidate findings, retained evidence, rolling summaries and reader state |
| `udp-observer/` | UDP before firewall DROP, read-only conntrack direction snapshots | Separate UDP JSONL, summary and Prometheus textfile |

The observer code does not change firewall rules, conntrack entries, VPN
configuration or routing. It observes selected metadata, including addresses,
SNI, HTTP paths and fingerprint parameters. Store its journals as sensitive
operational data. URL queries, credential-bearing path segments and selected
secret fields are redacted or excluded before persistence; arbitrary service
log text cannot be assumed to be free of sensitive information.

## Requirements

The collector uses Python 3's standard library plus Linux `tcpdump`, `tshark`,
`setpriv` and `journalctl`, and the `libnetfilter_conntrack` shared library. The
provided services require systemd. Capture and conntrack access need the
capabilities in the service units. The analyzer uses only Python's standard
library and reads files; it needs no network access.

Tshark must expose every field requested by `FIELDS` in `probe-logging.py`.
Fields vary across Wireshark releases; missing fields produce sensor failures
rather than complete handshake evidence. The dissector runs as uid/gid 65534
and consumes an anonymous pipe. No packet capture file is created.

## Local collector

Copy `probe-logging.example.json` to a private configuration file and replace
the documentation addresses, interface, node name and listening ports. Keep
`log_dir` consistent with the blackhole input path. The example deliberately
has no remote destination or credentials and works without an analyzer or hub.

The supplied service expects:

- Script: `/usr/local/libexec/vpnshop-probe-logging`
- Config: `/etc/vpnshop-probe-logging.json`, mode `0600`
- Unit name: `vpnshop-probe-logging.service`
- Writable directories: `/var/log/vpnshop-probes`, `/run/vpnshop-probes`,
  `/var/lib/node_exporter/textfile`

The runtime directory is created by systemd. Create the log directory privately
(mode `0700`) and the metrics directory before starting the unit. For a direct
foreground run, also create `/run/vpnshop-probes` first:

```sh
python3 probe-logging.py /path/to/private-collector.json
```

The nginx Unix socket is mode `0660`, owned by root and the `www-data` group
(`nginx` is the fallback group when `www-data` is absent). For a custom worker
group, set `nginx_socket_gid` in the private collector configuration. The receiver
uses Linux `SCM_CREDENTIALS` and accepts root or a worker whose parent is a root
nginx master running the trusted executable. The executable defaults to
`/usr/sbin/nginx`; set `nginx_executable` for a custom installation. A process
sharing the web worker UID cannot supply enforcement evidence solely by knowing
the socket path. Proven root masters remain valid across an executable package
replacement. Their PID, start time, executable inode and root ownership are
rechecked, with a bounded cache of 256 identities. After a collector restart,
an old master can be recognized through the exact trusted executable path
marked deleted by the kernel. Rootless nginx masters require an operator-reviewed trusted
forwarding arrangement. Sender identity, node and observation time cannot be
overridden by fields inside an HTTP log object.

The optional `probe-logging-nginx.conf` defines an nginx `http`-context format
and syslog destination. Integrate it into the existing nginx configuration and
validate that configuration before reloading nginx. It does not configure
listeners, TLS certificates or proxy trust. The receiver redacts the request
before writing it. The journal sensor retains its legacy unit selection
(`ssh`, `sshd`, `xray`, `vpnshop-tinc`, `vpnshop-nodeagent`); absent units need no
replacement service.

Collector logs use mode `0600` in a `0700` directory, with gzip rotation at
16 MiB or roughly one hour and retention bounded by seven days and
`budget_bytes` (default 512 MiB). Logging pauses below 1 GiB free space and
reports drops. Capture loss statistics are requested every 15 seconds, including while the
capture process is running. The metrics file is
`/var/lib/node_exporter/textfile/probe_logging.prom`.

## Central collection

The complete `probe-logging-edge.example.json` and
`probe-logging-hub.example.json` demonstrate sender and receiver roles. Their
`10.200.0.x` addresses are fictional private-network examples. Generate a new
per-node shared secret and replace every placeholder before use.

Remote collection is optional and uses authenticated UDP. It is best effort;
local journals remain the primary copy. There is no encryption in this
transport. Use an operator-managed private or encrypted network and restrict
access to the configured peers.

For each sender, add `hub_address` and a newly generated random `key` to its
private collector config. For the receiver, add `hub_bind` and a `peers` map:

```json
{
  "hub_bind": "10.200.0.2",
  "peers": {
    "edge-01": {
      "mesh_ip": "10.200.0.10",
      "key": "REPLACE_WITH_A_NEW_RANDOM_SHARED_SECRET"
    }
  }
}
```

Merge these fields into a complete collector config; the snippet is not a
standalone configuration. Every sender uses its own key, matching that node's
receiver entry. `mesh_ip` must match the sender address seen by the receiver.
The collector listens on UDP port `19014`; the UDP observer uses port `19015`
with the same config fields and a distinct wire format. Do not expose these
receivers publicly. Omit `hub_address` on a hub unless its own local evidence
must go to another receiver. Received evidence is never forwarded again.
Large TLS ClientHello details stay in the local journal and are forwarded by
hash reference instead of silent truncation. The receiver accepts authenticated
records from the preceding 90 seconds with at most five seconds of future clock
skew. Keep peer clocks synchronized. Authenticated duplicate datagrams are
rejected while retained in a bounded 95-second replay cache. At capacity, its
oldest entry is evicted and counted while new authenticated evidence continues
to be accepted. Replay detection is best effort under high volume; replay and
schema drops and cache evictions have separate counters. A malformed datagram cannot terminate the receiver;
socket failures clear its health and trigger a retry.

## Analyzer

Use `probe-analysis.example.json` as a complete local example and
`probe-analysis-hub.example.json` for the two-node central example. For a central
analyzer, `local_ips` must contain all observed server addresses and
`expected_nodes` all participating node names. `known_sources` excludes trusted
monitor addresses; private and non-global source addresses are excluded by the
preserved normalization policy. The documentation-address fixtures in unit
tests simulate public sources without changing that runtime policy.

```sh
python3 probe-analysis.py --config /path/to/private-analysis.json
```

The service expects the analyzer at
`/usr/local/libexec/vpnshop-probe-analysis`, config at
`/etc/vpnshop-probe-analysis.json`, and a writable private
`/var/lib/vpnshop-probe-analysis` directory. The unit name is
`vpnshop-probe-analysis.service`. It needs read access to the collector log
directory.

Every 15 seconds, the analyzer writes `summary.json`, bounded hourly JSONL for
findings/evidence/windows, and cursor/window state. It recovers unread records
from gzip rotations and carries its correlation window across restarts.
Heuristics report candidates; they do not establish identity or intent, and
the analyzer does not issue firewall actions. UTC timestamps are accompanied
by legacy UTC+07:00 display fields.

The analyzer consumes collector events, including conntrack UDP `NEW` events.
It does **not** ingest the separate UDP observer's `udp_*` stream. UDP packet
samples, QUIC metadata and direction health are available in that observer's
own journals, summary and metrics.

## Verification

Run from the repository root:

```sh
python3 -m unittest discover -s observability -p 'test_*.py'
```

The TLS integration test additionally needs Linux root, disposable network
namespaces, OpenSSL, iproute2, nftables, tcpdump, tshark and util-linux:

```sh
sudo bash observability/test-tls-responses-netns.sh "$(pwd)/observability"
```

It tests TLS 1.2/1.3 ServerHello, a plaintext protocol alert, and a negative
control with ServerHello dropped in isolated postrouting. Packet bytes travel
only through pipes. The script runs its test networking and firewall rules in
fresh namespaces and removes temporary certificates and logs on exit.

See [UDP observer](udp-observer/README.md) for its builds, tests and limits.
