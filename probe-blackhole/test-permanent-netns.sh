set -euo pipefail
stage=$1
unshare --net bash -s -- "$stage" <<'INNER'
set -euo pipefail
stage=$1
testdir=$(mktemp -d /run/qntw-probe-test.XXXXXX)
client=''; listener=''; tlsserver=''; reverse=''
cleanup(){ result=$?; if ((result));then for log in "$testdir"/*.log;do [[ ! -f "$log" ]] || { echo "$log";cat "$log"; };done;fi;for p in "$listener" "$tlsserver" "$reverse" "$client"; do [[ -z "$p" ]] || kill "$p" 2>/dev/null || true; done; rm -rf "$testdir"; }
trap cleanup EXIT
cp "$stage/profiles.nft" "$stage/counters.nft" "$testdir/"
printf 'qntwtest0\n' > "$testdir/public-ifaces"
printf '{"node":"test-node","local_ips":["198.18.0.1"],"trusted_ips":["203.0.113.99"]}\n' > "$testdir/config.json"
export QNTW_PROBE_BLACKHOLE_CONFIG_DIR="$testdir" QNTW_PROBE_BLACKHOLE_STATE="$testdir/no-state"
unshare --net sleep 120 & client=$!
sleep 0.3
ip link set lo up
ip link add qntwtest0 type veth peer name qntwtest1
ip link set qntwtest1 netns "$client"
ip addr add 198.18.0.1/24 dev qntwtest0
ip -6 addr add fd00:151::1/64 dev qntwtest0 nodad
ip link set qntwtest0 up
nsenter -t "$client" -n ip link set lo up
nsenter -t "$client" -n ip addr add 198.18.0.2/24 dev qntwtest1
nsenter -t "$client" -n ip -6 addr add fd00:151::2/64 dev qntwtest1 nodad
nsenter -t "$client" -n ip link set qntwtest1 up
"$stage/filter.sh" apply
counter(){ nft -j list table inet qntw_probe_blackhole | jq -r --arg name "$1" '.nftables[].counter? // empty|select(.name==$name)|.packets'; }
clear_sources(){ nft flush set inet qntw_probe_blackhole sources_v4; nft flush set inet qntw_probe_blackhole sources_v6; nft flush set inet qntw_probe_blackhole permanent_v4; nft flush set inet qntw_probe_blackhole permanent_v6; }
profile_index=10
for family in 4 6; do
 if [[ "$family" == 4 ]]; then dest=198.18.0.1; else dest=fd00:151::1; fi
 for hello in "$stage/"*.hello; do
  clear_sources
  profile_index=$((profile_index+1))
  if [[ "$family" == 4 ]];then source="198.18.0.$profile_index"; nsenter -t "$client" -n ip addr add "$source/24" dev qntwtest1;else source="fd00:151::$profile_index"; nsenter -t "$client" -n ip -6 addr add "$source/64" dev qntwtest1 nodad;fi
  hash=$(basename "$hello" .hello)
  previous=$(counter "p_$hash")
  : > "$testdir/received"
  nc -"$family" -l -p 18080 > "$testdir/received" & listener=$!
  sleep 0.08
  timeout 0.6 nsenter -t "$client" -n nc -"$family" -s "$source" -N -w 1 "$dest" 18080 < "$hello" >/dev/null 2>&1 || true
  [[ $(counter "p_$hash") -gt "$previous" ]]
  [[ ! -s "$testdir/received" ]]
  kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true; listener=''
  printf 'PASS profile %s IPv%s payload withheld\n' "$hash" "$family"
 done
done
[[ $(counter reply_dropped) -gt 0 ]]
printf 'PASS server close packets suppressed\n'
clear_sources
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=qntw-test.invalid -addext subjectAltName=DNS:qntw-test.invalid -keyout "$testdir/key.pem" -out "$testdir/cert.pem" -days 1 >/dev/null 2>&1
openssl s_server -quiet -accept 18443 -cert "$testdir/cert.pem" -key "$testdir/key.pem" > "$testdir/server.log" 2>&1 & tlsserver=$!
sleep 0.1
for family in 4 6; do
 if [[ "$family" == 4 ]]; then dest=198.18.0.1:18443; else dest='[fd00:151::1]:18443'; fi
 for version in tls1_2 tls1_3; do
  timeout 4 nsenter -t "$client" -n openssl s_client -"$family" -connect "$dest" -servername qntw-test.invalid -CAfile "$testdir/cert.pem" -verify_return_error -verify_hostname qntw-test.invalid -"$version" -brief < /dev/null > "$testdir/client.log" 2>&1
  grep -q 'Verification: OK' "$testdir/client.log"
  printf 'PASS normal %s IPv%s\n' "$version" "$family"
 done
done
nft add element inet qntw_probe_blackhole permanent_v4 '{ 198.18.0.2 }'
nsenter -t "$client" -n openssl s_server -quiet -accept 18444 -cert "$testdir/cert.pem" -key "$testdir/key.pem" > "$testdir/reverse.log" 2>&1 & reverse=$!
sleep 0.1
timeout 4 openssl s_client -4 -connect 198.18.0.2:18444 -servername qntw-test.invalid -CAfile "$testdir/cert.pem" -verify_return_error -brief </dev/null > "$testdir/reverse-client.log" 2>&1
grep -q 'Verification: OK' "$testdir/reverse-client.log"
printf 'PASS outbound connection to blackholed source\n'
nft add element inet qntw_probe_blackhole trusted_v4 '{ 198.18.0.2 }'
: > "$testdir/trusted-received"
nc -4 -l -p 18081 > "$testdir/trusted-received" & listener=$!
sleep 0.1
timeout 0.5 nsenter -t "$client" -n nc -4 -N -w 1 198.18.0.1 18081 < "$(find "$stage" -name '*.hello' | head -1)" >/dev/null 2>&1 || true
[[ -s "$testdir/trusted-received" ]]
kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true; listener=''
printf 'PASS management allowlist overrides dynamic block\n'
"$stage/filter.sh" remove
if nft list table inet qntw_probe_blackhole >/dev/null 2>&1; then exit 1; fi
printf 'PASS own-table rollback\n'
INNER
