#!/bin/bash
# Every firewall, listener, capture, and hardcoded path is private to these tests.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bin=${QNTW_TEST_BIN_DIR:-$repo/bin}

if [[ ${1:-} != --isolated ]]; then
  [[ $# == 0 && $(uname -s) == Linux && $EUID == 0 ]] || {
    echo 'requires Linux root; use make docker-integration for a disposable container' >&2
    exit 2
  }
  for command in ip nsenter unshare mount nft jq python3 ruby openssl nc timeout tcpdump tshark conntrack setpriv; do
    command -v "$command" >/dev/null
  done
  for executable in vpnshop-probe-blackhole vpnshop-tls-alert-gate vpnshop-udp-observer blackhole.test udp-test-client udp-test-peer; do
    [[ -x "$bin/$executable" ]] || { echo "missing test executable: $executable; run make integration-build" >&2; exit 2; }
  done
  work=$(mktemp -d /tmp/qntw-integration.XXXXXX)
  trap 'rm -rf -- "$work"' EXIT
  parent_ns=$(readlink /proc/self/ns/net)
  QNTW_TEST_BIN_DIR="$bin" unshare --net --mount --fork bash "$0" --isolated "$work" "$parent_ns"
  exit $?
fi

[[ $# == 3 && $EUID == 0 && -d $2 ]] || exit 2
work=$2
[[ $(readlink /proc/self/ns/net) != "$3" ]] || { echo 'network namespace isolation failed' >&2; exit 1; }
mount --make-rprivate /
umask 077

# Debian's nc/awk launchers use /etc/alternatives. Resolve the executables
# before replacing /etc, without carrying any caller configuration into tests.
mkdir -p "$work/runtime-bin"
for executable in nc awk; do
  ln -s "$(readlink -f "$(command -v "$executable")")" "$work/runtime-bin/$executable"
done
export PATH="$work/runtime-bin:$PATH"

# Mask the legacy absolute paths in the private mount namespace, including
# collector inventory reads. No file from the caller's /etc or state is used.
for directory in /etc /run /var/lib /var/log; do
  mount -t tmpfs -o mode=0755 qntw-test-private "$directory"
done
printf 'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\ntcpdump:x:65533:65533:tcpdump:/:/usr/sbin/nologin\n' > /etc/passwd
printf 'root:x:0:\nnogroup:x:65534:\ntcpdump:x:65533:\n' > /etc/group
printf 'passwd: files\ngroup: files\nhosts: files\n' > /etc/nsswitch.conf
printf 'icmp 1 ICMP\ntcp 6 TCP\nudp 17 UDP\nipv6-icmp 58 IPv6-ICMP\n' > /etc/protocols
printf '{"node":"alert-test","listen_ports":[22,443,7443,7444]}\n' > /etc/vpnshop-probe-logging.json
mkdir -p /run/lock /var/lib/vpnshop-probe-blackhole /var/lib/node_exporter/textfile /var/log/vpnshop-probes
mkdir -m755 "$work/decoder-home"
chmod 711 "$work"
mkdir -m700 "$work/decoder-home/config" "$work/decoder-home/cache" "$work/decoder-home/wireshark"
chown -R 65534:65534 "$work/decoder-home"
# tshark -G folders confirms WIRESHARK_CONFIG_DIR selects this private location.
export WIRESHARK_CONFIG_DIR="$work/decoder-home/wireshark"
export XDG_CONFIG_HOME="$work/decoder-home/config" XDG_CACHE_HOME="$work/decoder-home/cache"
export OPENSSL_CONF=/dev/null PYTHONDONTWRITEBYTECODE=1 LC_ALL=C
export QNTW_PROBE_BLACKHOLE_STATE="$work/no-persistent-state.json"

stage=$work/stage
mkdir -p "$stage"
ruby "$repo/probe-blackhole/build-profiles.rb" "$repo/probe-blackhole/profiles.json" "$stage"
cp "$repo/probe-blackhole/profiles.json" "$stage/"
install -m755 "$repo/probe-blackhole/filter.sh" "$stage/filter.sh"
install -m755 "$repo/probe-blackhole/filter.sh" "$stage/bh-filter.sh"
install -m755 "$repo/tls-alert-gate/routing.sh" "$stage/routing.sh"
install -m755 "$repo/observability/probe-logging.py" "$stage/probe-logging.py"
install -m755 "$bin/vpnshop-probe-blackhole" "$stage/blackhole"
install -m755 "$bin/vpnshop-tls-alert-gate" "$stage/vpnshop-tls-alert-gate"

printf '\n%s\n' 'Checking nftables operations in a verified child network namespace'
QNTW_NFT_NETNS_TEST=1 "$bin/blackhole.test" -test.run='^TestNFTNamespace$' -test.v
printf '\n%s\n' 'Checking permanent blackhole profiles, IPv4/IPv6 and trusted bypass'
bash "$repo/probe-blackhole/test-permanent-netns.sh" "$stage"
printf '\n%s\n' 'Checking transparent routing, source preservation and draining'
bash "$repo/tls-alert-gate/test-routing-netns.sh" "$stage"
printf '\n%s\n' 'Checking TLS alerts with blackhole state coordination'
QNTW_TLS_GATE_TEST_BLACKHOLE=1 bash "$repo/tls-alert-gate/test-alert-netns.sh" "$stage"
printf '\n%s\n' 'Checking visible TLS responses and the postrouting DROP negative control'
bash "$repo/observability/test-tls-responses-netns.sh" "$stage"
printf '\n%s\n' 'Checking bounded nftables set capacity and legacy timeout behavior'
bash "$repo/probe-blackhole/test-capacity.sh"
bash "$repo/probe-blackhole/test-expiry.sh"

for fixture in test-netns.sh test-direction-netns.sh; do
  udp_stage=$work/udp-${fixture%.sh}
  mkdir -p "$udp_stage"
  install -m755 "$bin/vpnshop-udp-observer" "$udp_stage/observer"
  install -m755 "$bin/udp-test-client" "$udp_stage/client"
  install -m755 "$bin/udp-test-peer" "$udp_stage/peer"
  printf '\n%s\n' "Checking UDP fixture: $fixture"
  unshare --net --mount --fork bash "$repo/observability/udp-observer/$fixture" --isolated "$udp_stage"
done
printf '\n%s\n' 'All isolated integration tests passed'
