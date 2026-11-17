set -euo pipefail
unshare --net bash -s <<'INNER'
set -euo pipefail
tmp=$(mktemp -d /run/qntw-capacity.XXXXXX)
listener=''
trap '[[ -z "$listener" ]] || kill "$listener" 2>/dev/null || true; rm -rf "$tmp"' EXIT
ip link set lo up
nft -f - <<'NFT'
table inet capacity_test {
set ips { type ipv4_addr; flags dynamic,timeout; timeout 120s; size 1; elements = { 198.18.0.123 }; }
counter dropped { }
chain quarantine {
 add @ips { ip saddr timeout 120s }
 counter name dropped drop
}
chain ingress {
 type filter hook prerouting priority -151; policy accept;
 udp dport 19000 jump quarantine
}
}
NFT
nc -u -l -p 19000 > "$tmp/received" & listener=$!
sleep 0.1
printf capacity-test > /dev/udp/127.0.0.1/19000
sleep 0.1
nft -j list table inet capacity_test | jq -e '[.nftables[].counter? // empty|select(.name=="dropped")|.packets]|.[0]==1' >/dev/null
[[ ! -s "$tmp/received" ]]
if nft get element inet capacity_test ips '{ 127.0.0.1 }' >/dev/null 2>&1; then exit 1; fi
printf 'PASS full dynamic set still drops matched packet\n'
INNER
