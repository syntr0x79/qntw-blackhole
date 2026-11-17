#!/bin/bash
# Shared setup for disposable Linux UDP integration fixtures.
set -euo pipefail
umask 077
source_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

prepare_integration() {
  if [[ ${1:-} != --isolated ]]; then
    [[ $# == 0 ]] || { echo "usage: $(basename "$0")" >&2; exit 2; }
    [[ $(uname -s) == Linux && $EUID == 0 ]] || {
      echo 'requires Linux root for disposable network namespaces' >&2; exit 2;
    }
    for command in go ip nsenter unshare mount tcpdump tshark conntrack nft setpriv jq; do
      command -v "$command" >/dev/null
    done
    stage=$(mktemp -d /tmp/qntw-udp-test.XXXXXX)
    trap 'rm -rf -- "$stage"' EXIT
    (cd "$source_dir" && go build -o "$stage/observer" .)
    (cd "$source_dir" && go build -o "$stage/client" ./test-client)
    (cd "$source_dir" && go build -o "$stage/peer" ./test-peer)
    unshare --net --mount --fork bash "$source_dir/$(basename "$0")" --isolated "$stage"
    exit $?
  fi
  [[ $# == 2 && -d $2 ]] || exit 2
  stage=$2
  mount --make-rprivate /
  install -d -m700 "$stage/log" "$stage/state"
  pids=()
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  cat > "$stage/awg.conf" <<'CONF'
[Interface]
ListenPort = 51821
S1 = 33
S2 = 48
S3 = 45
S4 = 51
H1 = 99
H2 = 101
H3 = 102
H4 = 103
HeaderProtectionKey = test-not-a-real-key
CONF
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  if ((status)); then
    echo 'UDP namespace integration failed; observer diagnostics:' >&2
    [[ ! -f "$stage/process.log" ]] || tail -n 20 "$stage/process.log" >&2
  fi
  exit "$status"
}

setup_network() {
  local server_interface=$1 client_interface=$2 outer_ns
  outer_ns=$(readlink /proc/self/ns/net)
  unshare --net sleep 300 &
  client_pid=$!
  pids+=("$client_pid")
  for _ in $(seq 1 50); do
    kill -0 "$client_pid"
    [[ $(readlink "/proc/$client_pid/ns/net") == "$outer_ns" ]] || break
    sleep .05
  done
  [[ $(readlink "/proc/$client_pid/ns/net") != "$outer_ns" ]]
  ip link add "$server_interface" type veth peer name "$client_interface"
  ip link set "$client_interface" netns "$client_pid"
  ip address add 192.0.2.1/24 dev "$server_interface"
  ip -6 address add 2001:db8:ad::1/64 dev "$server_interface" nodad
  ip link set lo up
  ip link set "$server_interface" up
  client ip address add 192.0.2.2/24 dev "$client_interface"
  client ip -6 address add 2001:db8:ad::2/64 dev "$client_interface" nodad
  client ip link set lo up
  client ip link set "$client_interface" up
  cat > "$stage/config.json" <<JSON
{"node":"udp-isolated-test","interface":"$server_interface","local_ips":["192.0.2.1","2001:db8:ad::1"],"hello_detail_exclude_sources":[]}
JSON
}

client() { nsenter -t "$client_pid" -n "$@"; }

start_observer() {
  "$stage/observer" -config "$stage/config.json" -log-dir "$stage/log" \
    -state-dir "$stage/state" -metrics-path "$stage/state/metrics.prom" \
    -awg-profile "$stage/awg.conf" > "$stage/process.log" 2>&1 &
  observer_pid=$!
  pids+=("$observer_pid")
  for _ in $(seq 1 25); do
    kill -0 "$observer_pid"
    if [[ -f "$stage/state/summary.json" ]] && \
       jq -e '.sensors.direction==1 and .sensors.capture==1 and .sensors.decoder==1 and .version==2' \
         "$stage/state/summary.json" >/dev/null; then return; fi
    sleep 1
  done
  echo 'observer sensors did not become ready' >&2
  return 1
}
