#!/bin/bash
# Start steering only after this systemd unit owns fresh, ready gate listeners.
# Stop is intentionally a NEW-flow disable, never a route/alias removal or kill.
set -euo pipefail
mode=${1:-}
case "$mode" in start|disable-new) ;; *) echo 'usage: control.sh start|disable-new' >&2;exit 2;;esac
[[ $EUID == 0 ]] || { echo 'root required' >&2;exit 1; }
unit=${QNTW_TLS_ALERT_UNIT:-vpnshop-tls-alert-gate.service}
gate_cfg=${QNTW_TLS_ALERT_CONFIG:-/etc/vpnshop-security/tls-alert-gate/gate.json}
routing_cfg=${QNTW_TLS_ALERT_ROUTING_CONFIG:-/etc/vpnshop-security/tls-alert-gate/routing.json}
router=${QNTW_TLS_ALERT_ROUTER:-/usr/local/libexec/vpnshop-tls-alert-routing}
bh=${QNTW_TLS_ALERT_BH_FILTER:-/usr/local/libexec/vpnshop-probe-blackhole-filter}
enabled=${QNTW_TLS_ALERT_ENABLED_FILE:-/etc/vpnshop-security/tls-alert-gate/enabled}
export QNTW_TLS_GATE_BH_FILTER="$bh"
[[ "$unit" =~ ^[a-zA-Z0-9_.@-]+\.service$ ]] || { echo 'invalid gate unit' >&2;exit 1; }

# routing.sh performs ownership checks and keeps its established-flow return
# routes while deleting the readiness marker / restoring blackhole fallback.
if [[ "$mode" == disable-new ]];then
 # Routing may be only partially installed, with no owned state yet. Always
 # withdraw readiness and re-apply blackhole fallback, even on that path or
 # when the routing driver itself fails. Do not remove any return resources.
 rm -f "${QNTW_TLS_GATE_READY:-/run/qntw-tls-alert-gate/routing-ready.json}"
 status=0
 if [[ -f "$routing_cfg" && ! -L "$routing_cfg" && -x "$router" ]];then
  "$router" disable-new "$routing_cfg" || status=$?
 else
  echo 'gate routing is unavailable during disable-new' >&2
  status=1
 fi
 if [[ -x "$bh" ]];then
  "$bh" apply || status=$?
 else
  echo 'blackhole driver unavailable during disable-new' >&2
  status=1
 fi
 exit "$status"
fi

[[ -f "$routing_cfg" && ! -L "$routing_cfg" && -x "$router" ]] || { echo 'gate routing is unavailable' >&2;exit 1; }
for program in jq python3 systemctl ss;do command -v "$program" >/dev/null;done
[[ -f "$gate_cfg" && ! -L "$gate_cfg" ]] || { echo 'regular gate config required' >&2;exit 1; }
summary=$(jq -er '.summary_path // "/var/lib/vpnshop-tls-alert/summary.json"' "$gate_cfg")
node=$(jq -er '.node' "$gate_cfg")
port=$(jq -er '.listen_port // 14443' "$routing_cfg")
[[ "$node" =~ ^[a-zA-Z0-9_-]{1,64}$ && "$port" =~ ^[0-9]+$ && "$summary" == /* ]] || { echo 'invalid readiness configuration' >&2;exit 1; }
((port>1024 && port<65536))
expected_listeners=$(jq '[.listen_v4 // "0.0.0.0:14443",.listen_v6 // "[::]:14443"]|map(select(length>0))|length' "$gate_cfg")
((expected_listeners>=1 && expected_listeners<=2))
jq -e --argjson port "$port" '[.listen_v4 // "0.0.0.0:14443",.listen_v6 // "[::]:14443"]|map(select(length>0))|all(.[]; (split(":")[-1]|tonumber)==$port)' "$gate_cfg" >/dev/null || { echo 'gate/routing listener ports differ' >&2;exit 1; }
# Demand a new summary write AFTER this ExecStartPost invocation. A readiness
# file left by a killed previous process can therefore never activate routing.
started_ns=$(python3 -c 'import time;print(time.time_ns())')
ready=0
for _ in $(seq 1 175);do
 pid=$(systemctl show "$unit" -p MainPID --value)
 if [[ "$pid" =~ ^[0-9]+$ ]] && ((pid>1)) && kill -0 "$pid" 2>/dev/null;then
  listeners=$(ss -Hlnpt "sport = :$port")
  if grep -Eq "pid=$pid([,)]|$)" <<< "$listeners" &&
   python3 - "$summary" "$node" "$started_ns" "$expected_listeners" <<'PY'
import datetime,json,os,stat,sys,time
path,node,started,expected=sys.argv[1:]
try:
    st=os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_mode&0o077 or st.st_uid!=0 or st.st_mtime_ns<int(started):
        raise ValueError('unsafe or stale summary')
    with open(path) as source:
        record=json.load(source)
    at=datetime.datetime.fromisoformat(record['at_utc'].replace('Z','+00:00')).timestamp()
    age=time.time()-at
    assert record['schema']==1 and record['node']==node and record['ready'] is True
    assert record.get('draining') is False and record['listeners']==int(expected)
    assert -1<=age<=15
except (OSError,ValueError,KeyError,TypeError,AssertionError):
    raise SystemExit(1)
PY
  then
   ready=1
   break
  fi
 fi
 sleep .2
done
((ready)) || { echo 'gate readiness/PID/listener check timed out' >&2;exit 1; }

# Installation can validate a live listener before enabling any traffic change.
if [[ ! -e "$enabled" ]];then
 echo 'gate listener ready; diversion remains disabled'
 exit
fi
[[ -f "$enabled" && ! -L "$enabled" ]] || { echo 'regular enable marker required' >&2;exit 1; }
[[ -x "$bh" ]] || { echo 'blackhole driver unavailable' >&2;exit 1; }

rollback_new(){
 status=$?
 trap - EXIT
 if ((status));then "$router" disable-new "$routing_cfg" || true;fi
 exit "$status"
}
trap rollback_new EXIT
"$router" apply "$routing_cfg"
# The ready marker is created by routing apply. Re-render the owned blackhole
# policy only now, so it can distinguish TLS response mode from general bans.
"$bh" apply
trap - EXIT
echo 'gate ready; new diversion and TLS blackhole coordination active'
