#!/bin/bash
# Own only the TLS gate's table, policy routes, loopback aliases and readiness.
# Disable-new keeps return routes for existing transparent proxy connections.
set -euo pipefail
mode=${1:-status}
cfg=${2:-/etc/vpnshop-security/tls-alert-gate/config.json}
[[ $EUID == 0 ]] || { echo 'root required' >&2; exit 1; }
case "$mode" in apply|check|disable-new|remove|status) ;; *) exit 2 ;; esac
for cmd in jq nft ip ss sha256sum;do command -v "$cmd" >/dev/null;done
[[ -f "$cfg" && ! -L "$cfg" ]] || { echo 'regular config required' >&2;exit 1; }
node=$(jq -er '.node' "$cfg")
iface=$(jq -er '.interface' "$cfg")
port=$(jq -r '.listen_port // 14443' "$cfg")
ig=$(jq -r '.ingress_mark // "0x514e01"' "$cfg")
bg=$(jq -r '.backend_mark // "0x514e02"' "$cfg")
table=$(jq -r '.route_table // 151' "$cfg")
pref_ig=$(jq -r '.rule_priority_ingress // 15100' "$cfg")
pref_bg=$(jq -r '.rule_priority_backend // 15101' "$cfg")
backend4=$(jq -r '.backend_ipv4 // "10.254.254.1"' "$cfg")
backend6=$(jq -r '.backend_ipv6 // "fd51:4e::1"' "$cfg")
ready=${QNTW_TLS_GATE_READY:-/run/qntw-tls-alert-gate/routing-ready.json}
state=${QNTW_TLS_GATE_ROUTING_STATE:-/var/lib/vpnshop-tls-alert/routing-state.json}
bh=${QNTW_TLS_GATE_BH_FILTER:-/usr/local/libexec/vpnshop-probe-blackhole-filter}
[[ "$node" =~ ^[a-zA-Z0-9_-]{1,64}$ && "$iface" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]]
[[ "$port" =~ ^[0-9]+$ && "$table" =~ ^[0-9]+$ && "$pref_ig" =~ ^[0-9]+$ && "$pref_bg" =~ ^[0-9]+$ ]]
((port>1024 && port<65536 && table>=128 && table<253 && pref_ig>1000 && pref_bg>1000 && pref_ig!=pref_bg))
[[ "$ig" =~ ^0x[0-9a-fA-F]{1,8}$ && "$bg" =~ ^0x[0-9a-fA-F]{1,8}$ && "$ig" != "$bg" ]]
[[ "$backend4" =~ ^[0-9.]+$ && "$backend6" =~ ^[0-9a-fA-F:]+$ ]]
[[ "$backend4" != 127.* && "$backend4" != 0.* ]]
v4=();v6=()
while IFS= read -r address;do
 if [[ "$address" == *:* ]];then [[ "$address" =~ ^[0-9a-fA-F:]+$ ]];v6+=("$address");else [[ "$address" =~ ^[0-9.]+$ ]];v4+=("$address");fi
done < <(jq -er '.local_ips[]' "$cfg")
((${#v4[@]}+${#v6[@]}>0))
fingerprint=$(jq -cS '{node,interface,local_ips,listen_port:(.listen_port//14443),ingress_mark:(.ingress_mark//"0x514e01"),backend_mark:(.backend_mark//"0x514e02"),route_table:(.route_table//151),rule_priority_ingress:(.rule_priority_ingress//15100),rule_priority_backend:(.rule_priority_backend//15101),backend_ipv4:(.backend_ipv4//"10.254.254.1"),backend_ipv6:(.backend_ipv6//"fd51:4e::1")}' "$cfg"|sha256sum|awk '{print $1}')
owned=0
if [[ -e "$state" ]];then
 [[ -f "$state" && ! -L "$state" ]]
 jq -e --arg node "$node" --arg fingerprint "$fingerprint" '.version==1 and .node==$node and .config_fingerprint==$fingerprint' "$state" >/dev/null || { echo 'routing ownership/config mismatch' >&2;exit 1; }
 owned=1
fi
join(){ local IFS=,;echo "$*"; }
render(){
 local new=$1
 printf 'table inet qntw_tls_gate\ndelete table inet qntw_tls_gate\ntable inet qntw_tls_gate {\n'
 printf 'comment "Quantway TLS gate owned routing v1"\n'
 printf 'chain divert { type filter hook prerouting priority -149; policy accept;\n'
 if ((new));then
  ((${#v4[@]}==0)) || printf 'iifname "%s" ip daddr { %s } tcp dport 443 ct mark 0 ct state new tcp flags & (syn | ack) == syn ct mark set %s\n' "$iface" "$(join "${v4[@]}")" "$ig"
  ((${#v6[@]}==0)) || printf 'iifname "%s" ip6 daddr { %s } tcp dport 443 ct mark 0 ct state new tcp flags & (syn | ack) == syn ct mark set %s\n' "$iface" "$(join "${v6[@]}")" "$ig"
 fi
 ((${#v4[@]}==0)) || printf 'iifname "%s" ip daddr { %s } tcp dport 443 ct mark %s meta mark set %s tproxy ip to :%s accept\n' "$iface" "$(join "${v4[@]}")" "$ig" "$ig" "$port"
 ((${#v6[@]}==0)) || printf 'iifname "%s" ip6 daddr { %s } tcp dport 443 ct mark %s meta mark set %s tproxy ip6 to :%s accept\n' "$iface" "$(join "${v6[@]}")" "$ig" "$ig" "$port"
 printf '}\nchain backend_output { type route hook output priority -149; policy accept;\n'
 ((${#v4[@]}==0)) || printf 'ip daddr %s tcp dport 443 meta mark %s ct mark set %s\nip saddr %s tcp sport 443 ct mark %s ct direction reply meta mark set %s\n' "$backend4" "$bg" "$bg" "$backend4" "$bg" "$bg"
 ((${#v6[@]}==0)) || printf 'ip6 daddr %s tcp dport 443 meta mark %s ct mark set %s\nip6 saddr %s tcp sport 443 ct mark %s ct direction reply meta mark set %s\n' "$backend6" "$bg" "$bg" "$backend6" "$bg" "$bg"
 printf '}\nchain guard { type filter hook input priority -149; policy accept;\niifname "%s" tcp dport %s counter drop\n' "$iface" "$port"
 ((${#v4[@]}==0)) || printf 'iifname "%s" ip daddr %s counter drop\n' "$iface" "$backend4"
 ((${#v6[@]}==0)) || printf 'iifname "%s" ip6 daddr %s counter drop\n' "$iface" "$backend6"
 printf '}\n}\n'
}
write_state(){
 local phase=$1
 mkdir -p "$(dirname "$state")";chmod 700 "$(dirname "$state")"
 jq -n --arg node "$node" --arg f "$fingerprint" --arg phase "$phase" '{version:1,node:$node,config_fingerprint:$f,phase:$phase}' > "$state.tmp"
 chmod 600 "$state.tmp";mv "$state.tmp" "$state"
}
fail_closed(){
 rm -f "$ready"
 if [[ -x "$bh" && -f "${QNTW_PROBE_BLACKHOLE_CONFIG_DIR:-/etc/vpnshop-security/probe-blackhole}/config.json" ]];then "$bh" apply;fi
}
remove_resources(){
 nft delete table inet qntw_tls_gate 2>/dev/null || true
 for family in 4 6;do
  if [[ "$family" == 4 && ${#v4[@]} == 0 || "$family" == 6 && ${#v6[@]} == 0 ]];then continue;fi
  ip -"$family" rule del priority "$pref_ig" fwmark "$ig" lookup "$table" 2>/dev/null || true
  ip -"$family" rule del priority "$pref_bg" fwmark "$bg" lookup "$table" 2>/dev/null || true
  ip -"$family" route del local default dev lo table "$table" 2>/dev/null || true
 done
 ((${#v4[@]}==0)) || ip -4 address del "$backend4/32" dev lo 2>/dev/null || true
 ((${#v6[@]}==0)) || ip -6 address del "$backend6/128" dev lo 2>/dev/null || true
 rm -f "$state"
}
check_conflicts(){
 local family line priority rulemark rulemask candidate number
 if ((owned)) && nft list table inet qntw_tls_gate >/dev/null 2>&1;then
  nft -j list table inet qntw_tls_gate |jq -e '.nftables[]|.table? // empty|select(.name=="qntw_tls_gate" and .comment=="Quantway TLS gate owned routing v1")' >/dev/null || { echo 'gate table ownership marker mismatch' >&2;return 1; }
 fi
 for family in 4 6;do
  while IFS= read -r line;do
   priority=${line%%:*}
   if [[ "$line" =~ fwmark[[:space:]]+([^[:space:]]+) ]];then
    candidate=${BASH_REMATCH[1]};rulemark=${candidate%%/*};rulemask=0xffffffff
    [[ "$candidate" != */* ]] || rulemask=${candidate#*/}
    [[ "$rulemark" =~ ^0x[0-9a-fA-F]+$ && "$rulemask" =~ ^0x[0-9a-fA-F]+$ ]] || { echo 'unrecognized policy mark rule' >&2;return 1; }
    for number in "$ig" "$bg";do
     if (((number & rulemask)==(rulemark & rulemask)));then
      if ((owned)) && ((rulemask==0xffffffff)) &&
         { { ((priority==pref_ig && number==ig)); } || { ((priority==pref_bg && number==bg)); }; } &&
         [[ "$line" =~ lookup[[:space:]]+$table([[:space:]]|$) ]];then continue;fi
      echo 'policy mark collision' >&2;return 1
     fi
    done
   fi
   if [[ "$priority" == "$pref_ig" || "$priority" == "$pref_bg" ]];then
    [[ "$line" == *"fwmark "* ]] || { echo 'policy priority collision' >&2;return 1; }
    if (( !owned || rulemask!=0xffffffff )) ||
       { [[ "$priority" == "$pref_ig" ]] && ((rulemark!=ig)); } ||
       { [[ "$priority" == "$pref_bg" ]] && ((rulemark!=bg)); } ||
       [[ ! "$line" =~ lookup[[:space:]]+$table([[:space:]]|$) ]];then
     echo 'policy priority collision' >&2;return 1
    fi
   fi
  done < <(ip -"$family" rule show)
  if ((owned)) && [[ "$family" == 4 && ${#v4[@]} != 0 || "$family" == 6 && ${#v6[@]} != 0 ]];then
   ip -j -"$family" route show table "$table" 2>/dev/null |jq -e 'all(.[]; .type=="local" and .dst=="default" and .dev=="lo")' >/dev/null || { echo 'owned routing table contains unexpected routes' >&2;return 1; }
  fi
 done
 if (( !owned ));then
  ! nft list table inet qntw_tls_gate >/dev/null 2>&1 || { echo 'unowned gate table exists' >&2;return 1; }
  ! ip -j -4 address show |jq -e --arg a "$backend4" '.[].addr_info[]|select(.local==$a)' >/dev/null || { echo 'backend IPv4 alias already exists' >&2;return 1; }
  ! ip -j -6 address show |jq -e --arg a "$backend6" '.[].addr_info[]|select(.local==$a)' >/dev/null || { echo 'backend IPv6 alias already exists' >&2;return 1; }
  ip -j -4 route show match "$backend4/32" |jq -e '[.[]|select(.dst!="default")]|length==0' >/dev/null || { echo 'backend IPv4 conflicts with an existing route' >&2;return 1; }
  ip -j -6 route show match "$backend6/128" |jq -e '[.[]|select(.dst!="default")]|length==0' >/dev/null || { echo 'backend IPv6 conflicts with an existing route' >&2;return 1; }
  for family in 4 6;do
   [[ -z $(ip -"$family" route show table "$table" 2>/dev/null) ]] || { echo 'unowned routing table is nonempty' >&2;return 1; }
   ! ip -"$family" rule show |grep -Eq "^($pref_ig|$pref_bg):" || { echo 'policy priority collision' >&2;return 1; }
  done
 fi
}
if [[ "$mode" == status ]];then
 jq -n --arg node "$node" --argjson owned "$owned" --argjson ready "$([[ -f "$ready" ]]&&echo true||echo false)" '{node:$node,owned:($owned==1),ready:$ready}'
 exit
fi
if [[ "$mode" == check || "$mode" == apply ]];then
 check_conflicts
 ip link show "$iface" >/dev/null
 tmp=$(mktemp /run/qntw-tls-gate-rules.XXXXXX);trap 'rm -f "$tmp"' EXIT
 render 1 > "$tmp";nft -c -f "$tmp"
 [[ "$mode" != check ]] || { echo 'routing preflight passed';exit; }
 listener=$(ss -Hlnpt "sport = :$port")
 pid=$(grep -o 'pid=[0-9]*' <<< "$listener"|head -n1|cut -d= -f2)
 [[ -n "$pid" ]] && kill -0 "$pid" || { echo 'gate listener absent' >&2;exit 1; }
 fail_closed
 initial=$owned
 write_state applying
 rollback_apply(){ status=$?;rm -f "$tmp";if ((status && !initial));then fail_closed||true;remove_resources;fi;exit "$status"; }
 trap rollback_apply EXIT
 if ((${#v4[@]}));then
  ip -4 address show dev lo |grep -Fq "inet $backend4/32 " || ip -4 address add "$backend4/32" dev lo label lo:qntwtls
  ip -4 route replace local default dev lo table "$table"
  ip -4 rule show |grep -Eq "^$pref_ig:" || ip -4 rule add priority "$pref_ig" fwmark "$ig" lookup "$table"
  ip -4 rule show |grep -Eq "^$pref_bg:" || ip -4 rule add priority "$pref_bg" fwmark "$bg" lookup "$table"
 fi
 if ((${#v6[@]}));then
  ip -6 address show dev lo |grep -Fq "inet6 $backend6/128 " || ip -6 address add "$backend6/128" dev lo nodad
  ip -6 route replace local default dev lo table "$table"
  ip -6 rule show |grep -Eq "^$pref_ig:" || ip -6 rule add priority "$pref_ig" fwmark "$ig" lookup "$table"
  ip -6 rule show |grep -Eq "^$pref_bg:" || ip -6 rule add priority "$pref_bg" fwmark "$bg" lookup "$table"
 fi
 nft -f "$tmp"
 mkdir -p "$(dirname "$ready")";chmod 700 "$(dirname "$ready")"
 ticks=$(sed 's/.*) //' "/proc/$pid/stat" |awk '{print $20}')
 jq -n --arg node "$node" --argjson pid "$pid" --argjson ticks "$ticks" --argjson port "$port" '{version:1,node:$node,pid:$pid,procstart_ticks:$ticks,listener_port:$port,routing_table:"qntw_tls_gate"}' > "$ready.tmp"
 chmod 600 "$ready.tmp";mv "$ready.tmp" "$ready"
 write_state active
 echo 'routing active'
 exit
fi
((owned)) || { echo 'routing is not owned';exit; }
fail_closed
check_conflicts
tmp=$(mktemp /run/qntw-tls-gate-rules.XXXXXX);trap 'rm -f "$tmp"' EXIT
render 0 > "$tmp";nft -c -f "$tmp";nft -f "$tmp";write_state draining
if [[ "$mode" == disable-new ]];then echo 'new diversion disabled; existing marked flows retained';exit;fi
command -v conntrack >/dev/null
for mark in "$ig" "$bg";do
 if conntrack -L -p tcp --mark "$mark" -o extended 2>/dev/null |grep -Eq '\b(ESTABLISHED|SYN_SENT|SYN_RECV|FIN_WAIT|CLOSE_WAIT|LAST_ACK)\b';then
  echo 'active marked connections remain; retained draining routing' >&2;exit 1
 fi
done
remove_resources
echo 'owned routing removed'
