#!/bin/bash
# Isolated positive TLS responses and a real postrouting-DROP negative control.
# Packet bytes only traverse anonymous pipes. No host listener/firewall changes.
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
  [[ $# == 1 ]] || { echo 'usage: test-tls-responses-netns.sh STAGE_DIRECTORY' >&2; exit 2; }
  stage=$(cd "$1" && pwd)
  [[ -f "$stage/probe-logging.py" ]] || { echo 'stage lacks probe-logging.py' >&2; exit 2; }
  [[ $EUID == 0 ]] || { echo 'requires root for disposable namespaces' >&2; exit 2; }
  exec unshare --net --mount --fork bash "$0" --isolated "$stage"
fi

stage=$2
mount --make-rprivate /
umask 077
work=$(mktemp -d /tmp/qntw-tls-response-test.XXXXXX)
client_pid=''; capture_pid=''; server12=''; server13=''
cleanup() {
  status=$?
  trap - EXIT INT TERM
  for pid in "$capture_pid" "$server12" "$server13" "$client_pid"; do
    [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true
  done
  for pid in "$capture_pid" "$server12" "$server13" "$client_pid"; do
    [[ -z "$pid" ]] || wait "$pid" 2>/dev/null || true
  done
  if ((status)); then
    echo 'TLS namespace integration failed; decoder diagnostics:' >&2
    for f in "$work/capture.err" "$work/tshark.err"; do
      [[ ! -f "$f" ]] || tail -n 12 "$f" >&2
    done
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for executable in ip nsenter unshare openssl tcpdump tshark nft setpriv python3 ss; do
  command -v "$executable" >/dev/null
done

# Keep the second network namespace alive without named /run/netns mounts.
outer_ns=$(readlink /proc/self/ns/net)
unshare --net sleep 300 &
client_pid=$!
for _ in $(seq 1 50); do
  kill -0 "$client_pid"
  [[ $(readlink "/proc/$client_pid/ns/net") == "$outer_ns" ]] || break
  sleep .05
done
[[ $(readlink "/proc/$client_pid/ns/net") != "$outer_ns" ]]
ip link add qtls-server type veth peer name qtls-client
ip link set qtls-client netns "$client_pid"
ip address add 192.0.2.10/24 dev qtls-server
ip link set qtls-server up
ip link set lo up
nsenter -t "$client_pid" -n ip address add 192.0.2.20/24 dev qtls-client
nsenter -t "$client_pid" -n ip link set qtls-client up
nsenter -t "$client_pid" -n ip link set lo up

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=tls-observer.example.test \
  -keyout "$work/test.key" -out "$work/test.crt" >"$work/certificate.log" 2>&1
openssl s_server -quiet -www -accept 192.0.2.10:443 -tls1_2 \
  -cert "$work/test.crt" -key "$work/test.key" >"$work/server12.log" 2>&1 &
server12=$!
openssl s_server -quiet -www -accept 192.0.2.10:7444 -tls1_3 \
  -cert "$work/test.crt" -key "$work/test.key" >"$work/server13.log" 2>&1 &
server13=$!
for _ in $(seq 1 50); do
  kill -0 "$server12"; kill -0 "$server13"
  if ss -Hln sport = :443 | grep -q . && ss -Hln sport = :7444 | grep -q .; then break; fi
  sleep .1
done
ss -Hln sport = :443 | grep -q .
ss -Hln sport = :7444 | grep -q .

cat > "$work/capture.py" <<'PY'
import importlib.util
import json
import os
import signal
import subprocess
import sys

stage, directory = sys.argv[1:]
spec = importlib.util.spec_from_file_location('tested_probe_logging', os.path.join(stage, 'probe-logging.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.Collector.__new__(m.Collector)
c.local = {'192.0.2.10'}
c.cfg = {'listen_ports': [443, 7444]}
children = []

def stop(*_):
    for child in children:
        if child.poll() is None:
            child.terminate()

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    with open(os.path.join(directory, 'capture.err'), 'wb') as capture_error, \
         open(os.path.join(directory, 'tshark.err'), 'wb') as tshark_error:
        capture = subprocess.Popen([
            'tcpdump', '-n', '-p', '-U', '-i', 'qtls-server', '-s', '16384',
            '-w', '-', m.packet_filter(c.local)], stdout=subprocess.PIPE, stderr=capture_error)
        children.append(capture)
        fields = sum((['-e', name] for name in m.FIELDS), [])
        decoder = subprocess.Popen([
            'setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
            'tshark', '-n', '-l', '-r', '-', '-M', '20000',
            '-o', 'tcp.desegment_tcp_streams:FALSE',
            '-o', 'tls.desegment_ssl_records:FALSE',
            '-T', 'fields', '-E', 'quote=d', '-E', 'occurrence=a', '-E', 'aggregator=,',
            *fields], stdin=capture.stdout, stdout=subprocess.PIPE, stderr=tshark_error,
            text=True, bufsize=1)
        children.append(decoder)
        capture.stdout.close()
        for line in decoder.stdout:
            event = c.packet(line)
            if event:
                print(json.dumps(event, separators=(',', ':')), flush=True)
finally:
    stop()
    for child in children:
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
PY
python3 -u "$work/capture.py" "$stage" "$work" >"$work/events.jsonl" &
capture_pid=$!
for _ in $(seq 1 50); do
  kill -0 "$capture_pid"
  if grep -q 'listening on' "$work/capture.err" 2>/dev/null; then break; fi
  sleep .1
done
grep -q 'listening on' "$work/capture.err"

request() {
  local version=$1 port=$2 source_port=$3
  printf 'GET / HTTP/1.0\r\n\r\n' | timeout 7 nsenter -t "$client_pid" -n \
    openssl s_client -quiet -connect "192.0.2.10:$port" \
      -bind "192.0.2.20:$source_port" -servername tls-observer.example.test \
      -groups X25519 "-$version" >/dev/null 2>"$work/client-$source_port.log"
}
request tls1_2 443 46001
request tls1_3 7444 46002
# Unsupported protocol: the TLS1.2-only listener must emit a plaintext alert.
if request tls1_3 443 46003; then
  echo 'version mismatch unexpectedly completed' >&2; exit 1
fi

# Only the namespace's TLS ServerHello packets are dropped. TCP SYN-ACK and
# incoming ClientHello still pass, proving an egress capture is after this hook.
nft -f - <<'NFT'
table inet qntw_tls_test {
  chain after {
    type filter hook postrouting priority 110; policy accept;
    ip saddr 192.0.2.10 tcp sport 443 @ih,0,8 22 @ih,40,8 2 counter drop
  }
}
NFT
if request tls1_2 443 46004; then
  echo 'postrouting-DROP connection unexpectedly completed' >&2; exit 1
fi
nft -j list table inet qntw_tls_test >"$work/drop-counter.json"
sleep .5
kill "$capture_pid"
wait "$capture_pid"
capture_pid=''

python3 - "$work" <<'PY'
import json
import os
import sys

directory = sys.argv[1]
with open(os.path.join(directory, 'events.jsonl')) as f:
    events = [json.loads(line) for line in f if line.strip()]

def selected(port, kind):
    return [e for e in events if e.get('event') == kind
            and e.get('connection', {}).get('client_port') == str(port)]

def server_hellos(port):
    return [e for e in selected(port, 'tls_response')
            if 2 in e['response']['handshake_types']]

tls12, tls13 = server_hellos(46001), server_hellos(46002)
assert tls12 and any(e['response']['selected_version'] == '0x0303' for e in tls12), 'TLS1.2 ServerHello missing'
assert tls13 and any(e['response']['selected_version'] == '0x0304' for e in tls13), 'TLS1.3 ServerHello missing'
alerts = [e for e in selected(46003, 'tls_response') if 21 in e['response']['record_types']]
assert alerts and any(e['response']['alert_descriptions'] for e in alerts), 'plaintext TLS alert missing'
assert selected(46004, 'tls_hello'), 'negative control has no incoming ClientHello'
assert not server_hellos(46004), 'dropped ServerHello appeared in public-interface egress capture'
for event in events:
    if event.get('event') == 'tls_response':
        assert event['direction'] == 'egress'
        assert event['capture_point'] == 'public_interface_egress_after_netfilter'
        assert event['remote_receipt_confirmed'] is False
        assert 'certificate' not in event['response']

with open(os.path.join(directory, 'drop-counter.json')) as f:
    rule_set = json.load(f)
def dropped(value):
    if isinstance(value, dict):
        own = value.get('counter', {}).get('packets', 0) if isinstance(value.get('counter'), dict) else 0
        return own + sum(dropped(child) for key, child in value.items() if key != 'counter')
    return sum(dropped(child) for child in value) if isinstance(value, list) else 0
drop_count = dropped(rule_set)
assert drop_count > 0, 'negative-control DROP rule did not execute'
print(json.dumps({'verdict': 'pass', 'tls12_serverhello': len(tls12),
                  'tls13_serverhello': len(tls13), 'plaintext_alert': len(alerts),
                  'postrouting_serverhello_drops': drop_count,
                  'dropped_serverhello_egress_observed': 0,
                  'packet_files_written': False, 'host_network_changes': False}))
PY
