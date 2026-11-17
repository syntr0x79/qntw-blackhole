#!/bin/bash
# Distinguish incoming probes from replies to locally initiated IPv4/IPv6 UDP.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/integration-common.sh"
prepare_integration "$@"
setup_network uq2-server uq2-client
nft -f - <<'NFT'
table inet udp_validation {
 chain input {
  type filter hook input priority filter; policy accept;
  ct state established,related accept
  meta l4proto udp counter drop
 }
}
NFT
for address in '192.0.2.2:53' '192.0.2.2:443' '[2001:db8:ad::2]:443'; do
  nsenter -t "$client_pid" -n "$stage/peer" echo "$address" >/dev/null 2>&1 &
  pids+=("$!")
done
sleep 2
"$stage/peer" query 192.0.2.1:55100 192.0.2.2:53 120 > "$stage/dns-replies.json" & pids+=("$!")
"$stage/peer" query 192.0.2.1:55101 192.0.2.2:443 120 > "$stage/quic-port-replies.json" & pids+=("$!")
"$stage/peer" query '[2001:db8:ad::1]:55100' '[2001:db8:ad::2]:443' 120 > "$stage/v6-replies.json" & pids+=("$!")
sleep 2
start_observer
"$stage/peer" query 192.0.2.1:55102 192.0.2.2:443 20 > "$stage/new-outgoing-replies.json" & pids+=("$!")
client "$stage/client" 192.0.2.1:443
client "$stage/client" '[2001:db8:ad::1]:443'
client "$stage/peer" once 192.0.2.2:49999 192.0.2.1:55103
client bash -c 'head -c181 /dev/zero > /dev/udp/192.0.2.1/51821'
# Wait for all successful echo-query fixtures, including their final output.
for _ in $(seq 1 45); do
  complete=1
  for result in "$stage"/*replies.json; do [[ -s $result ]] || complete=0; done
  ((complete)) && break
  sleep 1
done
for result in "$stage"/*replies.json; do jq -e '.sent==.replies' "$result" >/dev/null; done
jq -se 'all(.[]|select(.event=="udp_observation");.dport!=55100 and .dport!=55101 and .dport!=55102) and any(.[];.event=="udp_observation" and .dport==55103 and .direction=="ingress" and .origin_basis=="first_seen_incoming") and any(.[];.event=="udp_quic_hello" and .client_hello.sni=="udp-observer.example.test" and .src=="192.0.2.2") and any(.[];.event=="udp_quic_hello" and .src=="2001:db8:ad::2") and any(.[];.event=="udp_observation" and .dport==51821)' "$stage/log/events.jsonl"
echo 'UDP direction integration passed'
