# Probe blackhole

Linux nftables filter and local log analyzer for the defensive policy described in
the [repository README](../README.md). This directory is an independent,
standard-library-only Go module. Installation and configuration examples live at
the repository root.

Build and run the existing unit tests from this directory:

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/qntw-probe-blackhole .
```

The analyzer accepts `-config FILE`. Offline event replay requires both
`-dry-run` and `-replay FILE`; it does not change nftables. Events must use the
same `node` value as the configuration. The daemon reads local sanitized JSONL
events and has no network listener or remote credentials.

`filter.sh` owns only `inet qntw_probe_blackhole`. It supports `check`, `render`,
`apply`, and `remove`; the latter two change the local firewall. `unban.sh`
coordinates the analyzer while removing one source from persistent and kernel
state. Import and TLS migration flags are explicit maintenance operations and
require the analyzer to be stopped. Compatibility installation paths and service
names retain their `vpnshop` prefix.

The current policy uses permanent general bans, bounded source windows, and six
complete structural ClientHello profiles. TLS-only source state remains separate
when the optional TLS gate is configured. Trusted and local addresses are exempt.
Port inventory must be available and consistent for new SYN decisions. HTTP path
matching is deliberately unchanged, including its known gap for nested `.env`
paths. Inline matching does not reassemble TCP streams, so fragmented or unknown
ClientHello messages can pass. Classification does not establish the identity or
intent of a remote operator.

`profiles.json` contains sanitized structural fields. Ruby is needed only to
regenerate the nftables rules and synthetic ClientHello fixtures:

```sh
ruby build-profiles.rb profiles.json /tmp/qntw-profile-fixtures
```

Existing shell fixtures require an isolated Linux environment with root,
nftables, iproute2, util-linux, jq, Python 3, OpenSSL, netcat, and GNU coreutils.
`test-permanent-netns.sh STAGE_DIR` exercises the current permanent policy using
a stage directory containing `filter.sh`, the generated profile rules and
synthetic `.hello` files. The older `test-netns.sh` fixture assumes legacy timed
source sets. `test-capacity.sh` and `test-expiry.sh` test nftables set properties.
The Go nftables integration test is opt-in through `QNTW_NFT_NETNS_TEST=1` and
creates and verifies its own network namespace. These checks cannot run on
macOS. See the root validation instructions before using any namespace fixture.
