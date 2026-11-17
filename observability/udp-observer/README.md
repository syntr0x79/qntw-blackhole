# Passive UDP observer

This standalone Go module records bounded UDP metadata before an ingress
firewall DROP. It does not set packet verdicts or modify traffic services.
It is separate from the TCP/TLS collector and analyzer, while retaining the
shared config schema and legacy `vpnshop-*` runtime paths.

## Build and run

Go 1.25 or newer builds the module without the application backend. Runtime
requires Linux, `tcpdump`, `tshark`, `conntrack` and `setpriv`. The module's
pinned QUIC dependency is used by the integration client; the observer uses
`gopacket` to decode the capture pipe. No libpcap development headers are needed.

```sh
go test ./...
go vet ./...
go test -race ./...
go build -o /tmp/vpnshop-udp-observer .
```

Use the parent directory's `probe-logging.example.json` after replacing its
node name, interface and documentation addresses. `log_dir`, `listen_ports`
and `budget_bytes` in that shared file apply to the Python collector; this
observer takes its own paths from flags:

```sh
/tmp/vpnshop-udp-observer \
  -config /path/to/private-collector.json \
  -log-dir /var/log/vpnshop-udp \
  -state-dir /var/lib/vpnshop-udp-observer \
  -metrics-path /var/lib/node_exporter/textfile/udp_observer.prom \
  -awg-profile /path/to/optional-local-awg.conf
```

The `observer.service` example expects the binary at
`/usr/local/libexec/vpnshop-udp-observer` and reads
`/etc/vpnshop-probe-logging.json`. Install it as
`vpnshop-udp-observer.service`. systemd creates its log and state directories;
create the metrics directory before starting it. The default optional AWG
source is `/etc/amneziawg/awg0.conf`. A missing or invalid AWG profile disables
AWG classification while packet metadata continues.

`hub_address`, `hub_bind`, `key` and `peers` have the same roles as in the
collector config. UDP evidence uses port `19015`, HMAC authentication, a source
address allowlist, and a separate envelope. It is not encrypted; use a private
or encrypted operator network. Local-only operation omits all hub fields and
needs no HMAC key. See the parent README for central configuration.

## Evidence and limits

Direction schema 2 seeds a bounded direction cache from read-only IPv4/IPv6
conntrack snapshots and learns outgoing tuples from observed packets. Replies
to outgoing traffic are excluded. For inbound flows, records use
`direction=ingress` and `egress_reply`, with a stated `origin_basis`.
`first_seen_incoming` is an observation, not authentication or kernel proof.
Before initial direction synchronization succeeds, uncertain incoming traffic
is counted as waiting rather than labelled a probe. Snapshot failures, capture
loss and capacity limits are visible in counters and sensor health.

`udp_observation` contains addresses, ports, lengths, truncation, sample index,
direction and structural protocol candidates. `udp_flow_summary` is cumulative
for each flow; repeated summaries must not be summed as independent traffic.
Only QUIC Initial candidates enter a bounded unprivileged tshark decoder.
`udp_quic_hello` retains allowlisted public handshake parameters such as SNI,
ALPN, ciphers, extension types/lengths and fingerprint inputs. It excludes raw
payload, connection ID values, tokens, key bytes, randoms, tickets, PSKs and
application data. Truncated or fragmented traffic may not yield a complete
ClientHello. Structural resemblance does not prove protocol identity or intent.

AWG handling reads only public interface parameters and whether header
protection is configured. It neither retains keys nor decrypts traffic.
Protected headers yield length-only candidates. Customer outgoing destinations
and conntrack snapshots stay in bounded memory and are not persisted.

Bounds include 10,000 detailed flows, 50,000 direction tuples, an 8,192-event
queue, a 128-packet decoder queue, 400 detailed events/second and 50 decoded
Initial candidates/second. A tuple yields at most eight packet samples per
direction (two for configured known sources) and sixteen decoder candidates.
This is sampled evidence under load, not a complete capture.

Outputs are private `events.jsonl` and gzip rotations, a 15-second
`summary.json`, and Prometheus textfile metrics. Local retention is bounded by
seven days/512 MiB (2 GiB with `hub_bind`), and writing pauses below 1 GiB free.
Forwarding has one bounded retry and no receiver acknowledgment; loss and
duplicate delivery remain possible. Deduplicate on node, event time and event
content while excluding `received_utc`. Received events are not forwarded again.
The Python analyzer does not read these UDP journals.

## Isolated integration tests

On Linux with root and the runtime packages above, plus Go, iproute2,
nftables, util-linux and jq:

```sh
sudo bash test-netns.sh
sudo bash test-direction-netns.sh
```

Each test builds its own observer and fixtures, creates a temporary directory,
then runs in fresh mount and network namespaces. It creates no named host
network namespaces, listeners or host firewall rules. The first checks IPv4,
IPv6, QUIC ClientHello and AWG metadata before DROP. The second checks that
replies to locally initiated DNS/QUIC-port traffic are excluded while unsolicited
packets remain visible. All processes and temporary evidence are removed on
exit. Unit tests and builds can run on macOS; namespace integration requires
Linux and is not replaced by those unit tests.
