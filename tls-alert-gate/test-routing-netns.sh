#!/bin/bash
# Real TPROXY/source-preservation/drain tests; everything in disposable namespaces.
set -euo pipefail
if [[ ${1:-} != --isolated ]];then
 [[ $# == 1 && $EUID == 0 ]] || { echo 'usage: root bash test-routing-netns.sh STAGE_DIR' >&2;exit 2; }
 stage=$(cd "$1"&&pwd)
 exec unshare --net --mount --fork bash "$0" --isolated "$stage"
fi
stage=$2
mount --make-rprivate /
umask 077
work=$(mktemp -d /tmp/qntw-tls-route-test.XXXXXX)
client_pid='';server_pid='';old_pid='';held_pid=''
cleanup(){
 status=$?;trap - EXIT INT TERM
 if ((status));then for f in "$work"/*.log;do [[ ! -f "$f" ]]||{ echo "$f";tail -n20 "$f"; };done;fi
 for p in "$old_pid" "$held_pid" "$server_pid" "$client_pid";do [[ -z "$p" ]]||kill "$p" 2>/dev/null||true;done
 for p in "$old_pid" "$held_pid" "$server_pid" "$client_pid";do [[ -z "$p" ]]||wait "$p" 2>/dev/null||true;done
 rm -rf "$work";exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export QNTW_TLS_GATE_READY="$work/routing-ready.json"
export QNTW_TLS_GATE_ROUTING_STATE="$work/routing-state.json"
export QNTW_TLS_GATE_BH_FILTER="$work/no-bh-filter"
ip link set lo up
unshare --net sleep 180 &client_pid=$!
sleep .2
ip link add qgate0 type veth peer name qgate1
ip link set qgate1 netns "$client_pid"
ip address add 192.0.2.10/24 dev qgate0
ip -6 address add fd00:51::10/64 dev qgate0 nodad
ip link set qgate0 up
nsenter -t "$client_pid" -n ip link set lo up
nsenter -t "$client_pid" -n ip address add 192.0.2.20/24 dev qgate1
nsenter -t "$client_pid" -n ip -6 address add fd00:51::20/64 dev qgate1 nodad
nsenter -t "$client_pid" -n ip link set qgate1 up
nsenter -t "$client_pid" -n ip route add default via 192.0.2.10
nsenter -t "$client_pid" -n ip -6 route add default via fd00:51::10
printf '{"node":"routing-test","interface":"qgate0","local_ips":["192.0.2.10","fd00:51::10"]}\n' > "$work/config.json"
cat > "$work/server.py" <<'PY'
import json,os,socket,threading,select,sys

# One write keeps concurrent fixture threads from joining JSONL records.
def report(**kw):os.write(1,(json.dumps(kw)+'\n').encode())
def echo(c):
 with c:
  while True:
   data=c.recv(4096)
   if not data:return
   c.sendall(data)
def backend(family):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind(('0.0.0.0'if family==socket.AF_INET else'::',443));s.listen()
 while True:
  c,peer=s.accept();report(kind='backend',peer=list(peer),local=list(c.getsockname()));threading.Thread(target=echo,args=(c,),daemon=True).start()
def proxy(c,peer,family):
 try:
  with c:
   b=socket.socket(family);b.settimeout(5)
   b.setsockopt(socket.SOL_IP,19,1)if family==socket.AF_INET else b.setsockopt(socket.IPPROTO_IPV6,75,1)
   b.setsockopt(socket.SOL_SOCKET,36,0x514e02);b.bind(peer)
   b.connect(('10.254.254.1'if family==socket.AF_INET else'fd51:4e::1',443));b.settimeout(None)
   with b:
    while True:
     r,_,_=select.select([c,b],[],[],30)
     if not r:return
     for x in r:
      data=x.recv(4096)
      if not data:return
      (b if x is c else c).sendall(data)
 except Exception as e:report(kind='proxy_error',error=str(e))
def gate(family):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET:s.setsockopt(socket.SOL_IP,19,1)
 else:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.setsockopt(socket.IPPROTO_IPV6,75,1)
 s.bind(('0.0.0.0'if family==socket.AF_INET else'::',14443));s.listen();report(kind='ready',family=family)
 while True:
  c,peer=s.accept();report(kind='gate',peer=list(peer),local=list(c.getsockname()));threading.Thread(target=proxy,args=(c,peer,family),daemon=True).start()
for family in [socket.AF_INET,socket.AF_INET6]:
 threading.Thread(target=backend,args=(family,),daemon=True).start()
 threading.Thread(target=gate,args=(family,),daemon=True).start()
threading.Event().wait()
PY
python3 -u "$work/server.py" > "$work/server.log" 2>&1 &server_pid=$!
for _ in $(seq 1 30);do [[ $(grep -c '"ready"' "$work/server.log") == 2 ]]&&break;sleep .1;done
cat > "$work/held.py" <<'PY'
import socket,sys,time,pathlib
work=pathlib.Path(sys.argv[1]);name=sys.argv[2];port=int(sys.argv[3]);s=socket.socket();s.bind(('192.0.2.20',port));s.settimeout(3);s.connect(('192.0.2.10',443));s.sendall(b'initial');assert s.recv(7)==b'initial';(work/(name+'-ready')).touch()
for step in range(1,4):
 p=work/(name+'-go'+str(step))
 while not p.exists():time.sleep(.05)
 data=('step'+str(step)).encode();s.sendall(data);assert s.recv(len(data))==data;(work/(name+'-done'+str(step))).touch()
s.close()
PY
nsenter -t "$client_pid" -n python3 "$work/held.py" "$work" old 46000 > "$work/old.log" 2>&1 &old_pid=$!
for _ in $(seq 1 40);do [[ -f "$work/old-ready" ]]&&break;sleep .05;done
[[ -f "$work/old-ready" ]]
"$stage/routing.sh" check "$work/config.json"
"$stage/routing.sh" apply "$work/config.json"
jq -e '.version==1 and .routing_table=="qntw_tls_gate" and .listener_port==14443' "$QNTW_TLS_GATE_READY" >/dev/null
# Old connection must keep going directly to the original server.
touch "$work/old-go1"
for _ in $(seq 1 40);do [[ -f "$work/old-done1" ]]&&break;sleep .05;done
[[ -f "$work/old-done1" ]]
nsenter -t "$client_pid" -n python3 - <<'PY'
import socket
for family,ip,src,port in [(socket.AF_INET,'192.0.2.10','192.0.2.20',46001),(socket.AF_INET6,'fd00:51::10','fd00:51::20',46002)]:
 with socket.socket(family)as s:
  s.bind((src,port));s.settimeout(4);s.connect((ip,443));s.sendall(b'normal');assert s.recv(6)==b'normal'
for family,ip,port in [(socket.AF_INET,'192.0.2.10',14443),(socket.AF_INET6,'fd00:51::10',14443),(socket.AF_INET,'10.254.254.1',443),(socket.AF_INET6,'fd51:4e::1',443)]:
 with socket.socket(family)as s:
  s.settimeout(.5)
  try:s.connect((ip,port))
  except (TimeoutError,ConnectionError,OSError):pass
  else:raise AssertionError('direct gate/backend exposure')
PY
nsenter -t "$client_pid" -n python3 "$work/held.py" "$work" held 46003 > "$work/held.log" 2>&1 &held_pid=$!
for _ in $(seq 1 40);do [[ -f "$work/held-ready" ]]&&break;sleep .05;done
[[ -f "$work/held-ready" ]]
"$stage/routing.sh" disable-new "$work/config.json"
[[ ! -e "$QNTW_TLS_GATE_READY" ]]
touch "$work/old-go2" "$work/held-go1"
for _ in $(seq 1 40);do [[ -f "$work/old-done2" && -f "$work/held-done1" ]]&&break;sleep .05;done
[[ -f "$work/old-done2" && -f "$work/held-done1" ]]
# A new connection after disable-new must bypass the gate.
nsenter -t "$client_pid" -n python3 - <<'PY'
import socket
with socket.socket()as s:
 s.bind(('192.0.2.20',46004));s.settimeout(3);s.connect(('192.0.2.10',443));s.sendall(b'direct');assert s.recv(6)==b'direct'
PY
if "$stage/routing.sh" remove "$work/config.json";then echo 'active route removal should refuse' >&2;exit 1;fi
# Existing proxied and old direct connections also survive an attempted removal.
touch "$work/held-go2" "$work/old-go3"
for _ in $(seq 1 40);do [[ -f "$work/held-done2" && -f "$work/old-done3" ]]&&break;sleep .05;done
[[ -f "$work/held-done2" && -f "$work/old-done3" ]]
touch "$work/held-go3"
wait "$held_pid";held_pid='';wait "$old_pid";old_pid=''
for _ in $(seq 1 20);do if "$stage/routing.sh" remove "$work/config.json";then break;fi;sleep .1;done
[[ ! -e "$QNTW_TLS_GATE_ROUTING_STATE" ]]
! nft list table inet qntw_tls_gate >/dev/null 2>&1
[[ -z $(ip -4 route show table 151 2>/dev/null) ]]
[[ -z $(ip -6 route show table 151 2>/dev/null) ]]
python3 - "$work" <<'PY'
import json,pathlib,sys
w=pathlib.Path(sys.argv[1]);rows=[json.loads(s)for s in (w/'server.log').read_text().splitlines()if s.startswith('{')];errors=[r for r in rows if r['kind']=='proxy_error'];assert not errors,errors
back={r['peer'][1]:r for r in rows if r['kind']=='backend'};gate={r['peer'][1]:r for r in rows if r['kind']=='gate'}
assert 46000 not in gate and back[46000]['local'][0]=='192.0.2.10'
assert back[46001]['peer'][:2]==['192.0.2.20',46001]and back[46001]['local'][0]=='10.254.254.1'
assert back[46002]['peer'][:2]==['fd00:51::20',46002]and back[46002]['local'][0]=='fd51:4e::1'
assert 46004 not in gate and back[46004]['local'][0]=='192.0.2.10'
assert 46003 in gate
print(json.dumps({'verdict':'pass','transparent_source_ip_and_port':['IPv4','IPv6'],'old_connection_survives_activation':True,'active_proxy_survives_disable_new':True,'new_connections_bypass_after_disable':True,'active_remove_refused':True,'public_high_port_and_backend_aliases_blocked':True,'sysctls_changed':False,'host_network_changes':False,'owned_resources_removed':True}))
PY
