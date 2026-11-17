set -euo pipefail
unshare --net bash -s <<'INNER'
set -euo pipefail
nft -f - <<'NFT'
table inet test_bounded { set ips { type ipv4_addr; flags dynamic,timeout; timeout 120s; gc-interval 100ms; size 1; }
}
add element inet test_bounded ips { 198.18.2.1 timeout 1s }
NFT
nft get element inet test_bounded ips '{ 198.18.2.1 }' >/dev/null
sleep 1.2
if nft get element inet test_bounded ips '{ 198.18.2.1 }' >/dev/null 2>&1; then exit 1; fi
printf 'PASS dynamic set expiry\n'
INNER
