#!/bin/bash
# Capture IPv4/IPv6 UDP and QUIC ClientHello before an isolated ingress DROP.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/integration-common.sh"
prepare_integration "$@"
setup_network uq-server uq-client
nft -f - <<'NFT'
table inet udp_validation {
 chain input {
  type filter hook input priority filter; policy accept;
  meta l4proto udp counter drop
 }
}
NFT
start_observer
client "$stage/client" 192.0.2.1:443
client bash -c 'for n in 1 2 3; do head -c181 /dev/zero > /dev/udp/192.0.2.1/51821; done'
client "$stage/client" '[2001:db8:ad::1]:443'
sleep 5
jq -se 'any(.[];.event=="udp_quic_hello" and .client_hello.sni=="udp-observer.example.test") and any(.[];.event=="udp_observation" and .src=="2001:db8:ad::2") and any(.[];.awg.header_protected==true and .awg.assessment=="length_only_header_protected")' "$stage/log/events.jsonl"
nft -j list table inet udp_validation | jq -e 'any(.nftables[]|.rule.expr[]?; .counter.packets? > 0)'
echo 'UDP before-DROP integration passed'
