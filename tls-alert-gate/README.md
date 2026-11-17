# TLS Alert gate

Optional Linux transparent TCP gate for the defensive policy described in the
[repository README](../README.md). This directory is an independent,
standard-library-only Go module. It reads the sanitized structural profiles in
the sibling `probe-blackhole` directory; keep the repository layout intact when
running its tests.

Build and run the existing tests from this directory:

```sh
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/qntw-tls-alert-gate .
```

The gate accepts `-config FILE`. `-check` validates configuration, profiles, and
state without opening listeners. `-analyze-jsonl FILE` performs read-only
behavioral calibration on sanitized `tls_hello` JSONL metadata; use `-` for stdin.
Installation, configuration examples, and readiness checks live at the
repository root. Compatibility installation paths and service names retain their
`vpnshop` prefix.

Recognized structural probes and remembered TLS sources receive a fatal TLS
alert. Unknown traffic is forwarded to the local backend with its original
source tuple. Optional behavior analysis is disabled unless configured. The
gate does not terminate ordinary TLS, inspect encrypted application traffic, or
use SNI alone as a rejection decision. It bounds pending inspections and active
connections; source state and release markers coordinate with the blackhole
analyzer. Classification does not establish the identity or intent of a remote
operator.

Transparent sockets, packet marks, policy routing, and nftables are Linux
requirements. The non-Linux build exists for unit testing and does not provide
transparent forwarding. `routing.sh` owns the `inet qntw_tls_gate` table and
specific routing state. `control.sh` coordinates listener readiness and draining.
Their apply/start/remove operations change the local machine; do not run them to
perform an offline check.

`test-routing-netns.sh STAGE_DIR` and `test-alert-netns.sh STAGE_DIR` are existing isolated
Linux fixtures. They require root, nftables, iproute2, util-linux, jq, Python 3,
OpenSSL, and GNU coreutils. The alert stage includes the gate binary, routing
script, profiles, generated synthetic ClientHello fixtures, and optionally the
blackhole binary and filter for integration coverage when
`QNTW_TLS_GATE_TEST_BLACKHOLE=1` is set. These fixtures cannot run on macOS. See
the root validation instructions for stage construction.

## Configure and activate on an edge

Use the root examples for `gate.json` and `routing.json`, replacing documentation
addresses and trusted sources. The backend must accept the owned alias address
(`10.254.254.1:443` in the IPv4 example); a listener bound only to the public IP
will not accept the gate's backend connection. A wildcard TCP443 listener can
serve both addresses. The gate does not create TLS certificates or configure
that backend.

Set `tls_gate_enabled` to `true` in the blackhole configuration and keep node,
addresses and trusted sources consistent. For IPv6, configure the IPv6 gate
listener and backend and include every protected address in routing. Supplied
examples are deliberately IPv4-only; do not grant TCP443 exceptions for an
address family that has no functioning gate.

Validate before activation; these commands do not divert traffic:

```sh
sudo /usr/local/libexec/vpnshop-tls-alert-gate \
  -config /etc/vpnshop-security/tls-alert-gate/gate.json -check
sudo /usr/local/libexec/vpnshop-tls-alert-routing check \
  /etc/vpnshop-security/tls-alert-gate/routing.json
```

After reviewing the configuration, explicitly opt in and start the service:

```sh
sudo install -m 0600 /dev/null /etc/vpnshop-security/tls-alert-gate/enabled
sudo systemctl enable --now vpnshop-tls-alert-gate.service
sudo systemctl is-active vpnshop-tls-alert-gate.service
sudo /usr/local/libexec/vpnshop-tls-alert-routing status \
  /etc/vpnshop-security/tls-alert-gate/routing.json
```

Review `/var/lib/vpnshop-tls-alert/summary.json` and
`/run/qntw-tls-alert-gate/routing-ready.json`. The unit activates steering only
after proving listener ownership and readiness, and restores blackhole fallback
when new diversion is disabled.

For maintenance, stopping the unit first disables new diversion and drains
existing streams, retaining their return routes and aliases. The unit has a
finite stop timeout, so a forced stop can interrupt remaining streams. Once the
gate has stopped and no owned streams remain, explicit resource removal is:

```sh
sudo systemctl stop vpnshop-tls-alert-gate.service
# Verify that draining is complete before removing return routing.
sudo /usr/local/libexec/vpnshop-tls-alert-routing remove \
  /etc/vpnshop-security/tls-alert-gate/routing.json
```

These activation and removal commands change the local machine. They are not
part of building, staging or extracting this repository.
