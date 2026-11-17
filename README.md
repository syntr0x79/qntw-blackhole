# QNTW Blackhole

Standalone Linux tools for observing unsolicited connections, reviewing scan
patterns, and filtering sources that meet explicit local rules. Extracted from
the Quantway backend; no backend checkout, database, VPN account service, fleet
inventory, or operator credentials are required to build the project.

## Components

| Component | Purpose |
| --- | --- |
| [probe-blackhole](probe-blackhole/) | Local TCP-port, HTTP-path and SSH classifiers, persistent source state, isolated nftables table and manual release. |
| [tls-alert-gate](tls-alert-gate/) | Transparent TCP443 forwarding; known TLS profiles and capability sweeps receive a fatal TLS Alert 40. |
| [TCP/TLS observation](observability/) | Bounded metadata from packets, conntrack, nginx and service journals, including ClientHello structure and visible TLS replies. |
| [Passive analysis](observability/probe-analysis.py) | Periodic cross-node triage, findings and selected evidence with stable evidence IDs. It does not block sources. |
| [UDP observation](observability/udp-observer/) | Direction-aware metadata before firewall DROP, QUIC ClientHello decoding and structural AWG candidates, with its own hub, summaries and metrics. |

TCP/TLS observation feeds the local blackhole daemon and, when configured, a
central passive analyzer. UDP observation is a separate evidence stream; the
current analyzer does not correlate its `udp_*` events. Neither observer nor the
central analyzer adds new UDP bans. TLS source bans can nevertheless drop that
source's UDP traffic under the existing source policy.

## Build and verify

Use Go 1.27 for the complete build, Python 3.10+, Bash and Ruby. Each Go component
has an independent module and a checked-in dependency manifest. The two core
modules use only the standard library; the UDP decoder has external modules.

```sh
make test
make vet
make race
make build                    # Linux, host CPU architecture
make build TARGET_ARCH=amd64
make stage DESTDIR="$PWD/dist/rootfs"
```

`make stage` creates a reviewable installation tree. It does not install packages,
start services, change firewall rules, or contact deployment servers. Its build
prerequisite may download Go modules or a toolchain. Configure the example
files before activating anything. [Linux integration tests](tools/test-integration.sh)
exercise nftables, transparent forwarding, source preservation, TLS responses,
permanent state and release in disposable namespaces. `make test-integration`
requires Linux root and the test dependencies; use a disposable test VM or the
provided test container.

## Edge setup

Runtime dependencies on Debian/Ubuntu are `python3`, `nftables`, `iproute2`, `jq`,
`util-linux`, `tcpdump`, `tshark`, `conntrack` and `libnetfilter-conntrack3`.
Network namespace tests also use `ruby`, `openssl`, `netcat-openbsd` and
`coreutils`. Building the source does not install these packages.

The staged tree contains executables under `/usr/local/libexec`, units under
`/etc/systemd/system`, and configuration templates with `.example` suffixes.
On a fresh Linux host, copy the reviewed tree, then create actual configurations:

| Actual path | Template |
| --- | --- |
| `/etc/vpnshop-probe-logging.json` | An edge or hub example from `observability/` |
| `/etc/vpnshop-security/probe-blackhole/config.json` | `examples/probe-blackhole/config.json.example` |
| `/etc/vpnshop-security/probe-blackhole/public-ifaces` | `examples/probe-blackhole/public-ifaces.example` |
| `/etc/vpnshop-security/tls-alert-gate/gate.json` | `examples/tls-alert-gate/gate.json.example` |
| `/etc/vpnshop-security/tls-alert-gate/routing.json` | `examples/tls-alert-gate/routing.json.example` |
| `/etc/vpnshop-probe-analysis.json` | The analyzer example from `observability/`, on the analysis host |

Examples use documentation addresses. Replace the node name, interface, local
addresses, trusted operator/monitor addresses, and service port inventory. The
collector and blackhole node identities must agree. The SYN classifier also
reads the shared collector inventory and current Linux TCP listeners; missing or
inconsistent inventory disables that classifier and raises a metric.

The collector writes local JSONL at `/var/log/vpnshop-probes/events.jsonl`, which
the blackhole daemon reads; nginx
metadata needs the provided nginx log configuration in its `http` context and
appropriate server logging. Review existing logging before enabling it. The
UDP observer shares the node configuration and writes separately under
`/var/log/vpnshop-udp`. See [observation setup](observability/README.md).

For a fresh, configured edge, service activation is explicit:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now vpnshop-probe-logging.service
sudo systemctl enable --now vpnshop-udp-observer.service
sudo systemctl enable --now vpnshop-probe-blackhole-filter.service
sudo systemctl enable --now vpnshop-probe-blackhole.service
```

The transparent TLS gate additionally needs a working TCP443 backend, its owned
loopback aliases and policy routes, matching trusted sources, and
`tls_gate_enabled: true` in blackhole configuration. Review the routing preflight
in the [gate README](tls-alert-gate/README.md), create its explicit `enabled`
marker only after configuration, and then enable `vpnshop-tls-alert-gate.service`.
Readiness is proven from the listener and owned routing state. Merely setting a
configuration flag does not bypass DROP.

All supplied edge examples protect IPv4 only. IPv6 support requires declaring
every protected IPv6 address consistently in collector, blackhole and gate
routing configuration, and enabling the corresponding listener/backend. Do not
enable TLS-only TCP443 exceptions for an address family that the gate does not
serve.

Budget memory for observer subprocesses as well as the Go daemons; systemd
memory limits are ceilings, not a capacity plan. Monitor available memory and
memory/IO pressure: file-cache thrashing on small disk-backed hosts can delay
probes and services even when CPU computation is low.

The staged `nftables.service.d` example is an optional reapply hook. Review and
merge it with the existing firewall lifecycle only after configuring blackhole.
If another manager flushes its tables, a still-active oneshot unit does not
prove rules remain installed. Recheck/reapply the filter and verify TLS routing
readiness after firewall reloads.

Existing deployments retain their `vpnshop-*` executable, service, metric and
state paths, plus the `qntw_*` nft table names. Extraction does not migrate or
restart an existing installation. The legacy `shop-pl` guard remains in the
local blocking component; use a generic node identity for new deployments and
keep public web shops outside automatic blackhole unless explicitly designed
otherwise.

## Central observation and analysis

Configure the collector and UDP observer on a central host with explicit peer
identities, private addresses and a distinct HMAC secret per peer. The TCP/TLS hub
uses UDP19014; the UDP evidence hub uses UDP19015. Generate keys locally, keep
configuration root-only, and use a private trusted network or encrypted tunnel:
HMAC authenticates delivery but does not encrypt metadata. The local-only edge
example requires no forwarding key.

Point the analyzer at the central TCP/TLS log directory, set `expected_nodes`,
`known_sources` and `local_ips`, then explicitly enable
`vpnshop-probe-analysis.service`. It processes existing events every 15 seconds
and produces `summary.json`, `findings-*.jsonl`, `evidence-*.jsonl` and errors.
Check freshness (normally within 45 seconds), sensor health, delivery losses,
capacity counters and raw local logs when evidence may be incomplete. UDP
evidence remains available in its separate summaries and journals.

## Preserved rules and limits

* SYN sweeps count distinct unadvertised TCP ports: 8/60 seconds, 12/15 minutes,
  or 32/6 hours. Retransmitted SYNs do not increase the port count.
* HTTP classification requires two recognized sensitive paths; SSH requires
  repeated relevant failures. Current HTTP expressions recognize root-level
  `.env` and `.git`, but not nested paths such as `/admin/.env`. This known gap
  is preserved in this extraction.
* TLS classification uses six complete structural templates or capability
  variation grouped by IP and SNI: 4 profiles plus 3 version modes/60 seconds,
  6 profiles/15 seconds, or 8 profiles/60 seconds. GREASE, random values and
  extension order alone are not scanning evidence.
* Confirmed sources remain stored until an explicit release. General bans take
  priority over TLS-only treatment. Shared public IPs/CGNAT can affect multiple
  users; review authenticated client evidence before attributing a source.
* The gate inspects one complete initial TLS record up to 16 KiB. Fragmentation
  across records is forwarded unless the source is already classified. Initial
  connections can pass before a behavioral threshold is reached.
* Opaque forwarding preserves original source IP/port and connection half-close.
  It does not decrypt TLS or introduce an ordinary-session lifetime limit.

## Evidence handling

Runtime journals can contain source/destination IPs, SNI, user agents, paths and
service messages. Redaction is bounded and pattern-based, not a guarantee that
every secret is removed. Never commit runtime configurations, HMAC keys, state,
packet captures or real connection journals. Profiles and test fixtures here are
structural/synthetic; deployment inventories and incident datasets are excluded.

A matching fingerprint, source subnet, or timestamp does not identify a scanner
operator or prove why a network route became unavailable. Seeing packets before
DROP is not evidence of a successful connection.
