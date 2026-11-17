#!/bin/bash
# Isolated table; no flush ruleset, no changes to managed inet filter.
set -euo pipefail
exec 9>/run/lock/vpnshop-probe-blackhole.lock
flock -x 9
case "${1:-apply}" in
 remove) if nft list table inet qntw_probe_blackhole >/dev/null 2>&1; then nft delete table inet qntw_probe_blackhole; fi; exit 0 ;;
 apply|check|render) ;;
 *) exit 2 ;;
esac
conf=${QNTW_PROBE_BLACKHOLE_CONFIG_DIR:-/etc/vpnshop-security/probe-blackhole}
[[ $(jq -r .node "$conf/config.json") != shop-pl ]]
gate_configured=$(jq -r '.tls_gate_enabled // false' "$conf/config.json")
gate_ready=false
gate_iface=''
gate_mark=0
gate_v4=''
gate_v6=''
if [[ "$gate_configured" == true ]]; then
 ready=$(jq -r '.tls_gate_ready_path // "/run/qntw-tls-alert-gate/routing-ready.json"' "$conf/config.json")
 node=$(jq -r .node "$conf/config.json")
 # A configured feature is not enough. The routing owner creates this marker
 # only after the listener and owned transparent-routing rules are active.
 if python3 - "$ready" "$node" <<'PY'
import ipaddress, json, os, re, stat, sys
try:
 path, node = sys.argv[1:]
 info = os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 8192:
  raise ValueError('unsafe marker')
 with open(path) as f: marker = json.load(f)
 if marker.get('version') != 2 or marker.get('node') != node or marker.get('listener_port') != 14443 or marker.get('routing_table') != 'qntw_tls_gate':
  raise ValueError('invalid marker')
 if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', marker['interface']) or not re.fullmatch(r'0x[0-9a-fA-F]{1,8}', marker['ingress_mark']):
  raise ValueError('invalid routing scope')
 if int(marker['ingress_mark'], 16) == 0 or not 1 <= len(marker['local_ips']) <= 64:
  raise ValueError('invalid routing scope')
 for address in marker['local_ips']:
  if str(ipaddress.ip_address(address)) != address: raise ValueError('noncanonical gate address')
 with open('/proc/%d/stat' % int(marker['pid'])) as f: fields = f.read().rpartition(') ')[2].split()
 if int(fields[19]) != int(marker['procstart_ticks']): raise ValueError('replaced listener')
except (OSError, ValueError, TypeError, KeyError, IndexError):
 sys.exit(1)
PY
 then
  if nft list table inet qntw_tls_gate >/dev/null 2>&1 && ss -Hltn '( sport = :14443 )' | grep -q .; then
   gate_ready=true
   gate_iface=$(jq -r '.interface' "$ready")
   gate_mark=$(jq -r '.ingress_mark' "$ready")
   gate_v4=$(jq -r '[.local_ips[]|select(contains(":")|not)]|join(",")' "$ready")
   gate_v6=$(jq -r '[.local_ips[]|select(contains(":"))]|join(",")' "$ready")
  fi
 fi
fi
interfaces=()
while IFS= read -r iface; do [[ "$iface" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]]; interfaces+=("\"$iface\""); done < "$conf/public-ifaces"
(( ${#interfaces[@]} > 0 && ${#interfaces[@]} <= 16 ))
tmp=$(mktemp /run/qntw-probe-blackhole.XXXXXX)
trap 'rm -f "$tmp"' EXIT
{
 printf 'table inet qntw_probe_blackhole\ndelete table inet qntw_probe_blackhole\ntable inet qntw_probe_blackhole {\n'
 printf 'set public_interfaces { type ifname; elements = { %s }; }\n' "$(IFS=,; echo "${interfaces[*]}")"
 for family in 4 6; do
  if [[ "$family" == 4 ]]; then kind=ipv4_addr; else kind=ipv6_addr; fi
  addresses=$(jq -r --arg family "$family" '[.trusted_ips[],.local_ips[]]|unique|map(select(if $family=="4" then (contains(":")|not) else contains(":") end))|join(",")' "$conf/config.json")
  printf 'set trusted_v%s { type %s;' "$family" "$kind"
  [[ -z "$addresses" ]] || printf ' elements = { %s };' "$addresses"
  printf ' }\n'
 done
 cat <<'NFT'
set sources_v4 { type ipv4_addr; flags dynamic,timeout; timeout 120s; gc-interval 10s; size 2048; }
set sources_v6 { type ipv6_addr; flags dynamic,timeout; timeout 120s; gc-interval 10s; size 2048; }
counter inbound_dropped { }
counter reply_dropped { }
NFT
 # Rehydrate persistent addresses in the same atomic transaction as the table.
 state=${QNTW_PROBE_BLACKHOLE_STATE:-/var/lib/vpnshop-probe-blackhole/state.json}
 if [[ -f "$state" ]]; then
  jq -e --arg node "$(jq -r .node "$conf/config.json")" '(.version==2 or .version==3) and .node==$node' "$state" >/dev/null
 fi
 for family in 4 6; do
  addresses=''
  if [[ -f "$state" ]]; then
   addresses=$(jq -r --argjson family "$family" --slurpfile cfg "$conf/config.json" '[((.banned//{})|keys[]),((.history//{})|keys[])]|unique|map(select((contains(":"))==($family==6)))|map(. as $ip|select(([$cfg[0].trusted_ips[],$cfg[0].local_ips[]]|index($ip))==null))|join(",")' "$state")
  fi
  [[ "$addresses" =~ ^[0-9a-fA-F:.,]*$ ]]
  kind=ipv4_addr;[[ "$family" == 4 ]] || kind=ipv6_addr
  printf 'set permanent_v%s { type %s; flags dynamic; size 65536;' "$family" "$kind"
  [[ -z "$addresses" ]] || printf ' elements = { %s };' "$addresses"
  printf ' }\n'
 done
 # TLS-only sources never enter the general ban/history inventory. Their
 # traffic may reach TCP443 only when the transparent gate is proven ready.
 for family in 4 6; do
  addresses=''
  if [[ -f "$state" ]]; then
   addresses=$(jq -r --argjson family "$family" --slurpfile cfg "$conf/config.json" '(.released_at//{}) as $released|(.tls_sources//{})|to_entries|map(select(.value>($released[.key]//0)))|map(.key)|map(select((contains(":"))==($family==6)))|map(. as $ip|select(([$cfg[0].trusted_ips[],$cfg[0].local_ips[]]|index($ip))==null))|join(",")' "$state")
  fi
  [[ "$addresses" =~ ^[0-9a-fA-F:.,]*$ ]]
  kind=ipv4_addr;[[ "$family" == 4 ]] || kind=ipv6_addr
  printf 'set tls_sources_v%s { type %s; flags dynamic; size 65536;' "$family" "$kind"
  [[ -z "$addresses" ]] || printf ' elements = { %s };' "$addresses"
  printf ' }\n'
 done
 printf 'set tls_gate_ports { type inet_service;'
 [[ "$gate_ready" != true ]] || printf ' elements = { 443 };'
 printf ' }\n'
 for family in 4 6;do
  kind=ipv4_addr;addresses=$gate_v4
  if [[ "$family" == 6 ]];then kind=ipv6_addr;addresses=$gate_v6;fi
  printf 'set tls_gate_v%s { type %s;' "$family" "$kind"
  [[ -z "$addresses" ]] || printf ' elements = { %s };' "$addresses"
  printf ' }\n'
 done
 printf 'set tls_gate_interfaces { type ifname;'
 [[ "$gate_ready" != true ]] || printf ' elements = { "%s" };' "$gate_iface"
 printf ' }\n'
 cat "$conf/counters.nft"
 cat <<'NFT'
chain quarantine {
    # Separate add/drop statements: a full set must never allow a matched probe.
NFT
 if [[ "$gate_configured" == true ]]; then
  printf '    meta nfproto ipv4 add @tls_sources_v4 { ip saddr }\n    meta nfproto ipv6 add @tls_sources_v6 { ip6 saddr }\n'
 else
  cat <<'NFT'
    meta nfproto ipv4 add @permanent_v4 { ip saddr }
    meta nfproto ipv6 add @permanent_v6 { ip6 saddr }
NFT
 fi
 cat <<'NFT'
    counter name inbound_dropped drop
}
chain profiles {
NFT
 cat "$conf/profiles.nft"
 cat <<'NFT'
}
chain ingress {
    # Routing assigns both marks at -149 only to traffic actually steered to
    # the gate. Evaluate the exception after that decision, before DNAT.
    type filter hook prerouting priority -148; policy accept;
    iifname != @public_interfaces return
    ct direction reply return
    ct state related return
    ip saddr @trusted_v4 return
    ip6 saddr @trusted_v6 return
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 return
    ip saddr @permanent_v4 counter name inbound_dropped drop
    ip6 saddr @permanent_v6 counter name inbound_dropped drop
    ip saddr @sources_v4 counter name inbound_dropped drop
    ip6 saddr @sources_v6 counter name inbound_dropped drop
NFT
 printf '    iifname @tls_gate_interfaces ip daddr @tls_gate_v4 tcp dport @tls_gate_ports ct mark %s meta mark %s return\n' "$gate_mark" "$gate_mark"
 printf '    iifname @tls_gate_interfaces ip6 daddr @tls_gate_v6 tcp dport @tls_gate_ports ct mark %s meta mark %s return\n' "$gate_mark" "$gate_mark"
 cat <<'NFT'
    ip saddr @tls_sources_v4 counter name inbound_dropped drop
    ip6 saddr @tls_sources_v6 counter name inbound_dropped drop
    meta l4proto tcp ct state established tcp flags & (syn | ack) == ack jump profiles
}
chain egress {
    # After SNAT: covers host services and published container ports.
    type filter hook postrouting priority 110; policy accept;
    oifname != @public_interfaces return
    ct direction original return
    ip daddr @trusted_v4 return
    ip6 daddr @trusted_v6 return
    ip daddr @permanent_v4 counter name reply_dropped drop
    ip6 daddr @permanent_v6 counter name reply_dropped drop
    ip daddr @sources_v4 counter name reply_dropped drop
    ip6 daddr @sources_v6 counter name reply_dropped drop
NFT
 printf '    oifname @tls_gate_interfaces ip saddr @tls_gate_v4 tcp sport @tls_gate_ports ct mark %s return\n' "$gate_mark"
 printf '    oifname @tls_gate_interfaces ip6 saddr @tls_gate_v6 tcp sport @tls_gate_ports ct mark %s return\n' "$gate_mark"
 cat <<'NFT'
    ip daddr @tls_sources_v4 counter name reply_dropped drop
    ip6 daddr @tls_sources_v6 counter name reply_dropped drop
}
}
NFT
} > "$tmp"
if [[ "${1:-apply}" == render ]]; then cat "$tmp"; exit 0; fi
nft -c -f "$tmp"
[[ "${1:-apply}" != check ]] || exit 0
nft -f "$tmp"
