#!/bin/bash
# Actual gate + ordinary TLS backend. No production listener/rules/sysctl changes.
set -euo pipefail
if [[ ${1:-} != --isolated ]];then
 [[ $# == 1 && $EUID == 0 ]]||{ echo 'usage: root bash test-alert-netns.sh STAGE_DIR' >&2;exit 2; }
 stage=$(cd "$1"&&pwd)
 exec unshare --net --mount --fork bash "$0" --isolated "$stage"
fi
stage=$2
mount --make-rprivate /
umask 077
work=$(mktemp -d /tmp/qntw-tls-alert-test.XXXXXX)
cpid='';bpid='';gpid='';oldpid='';heldpid='';bhpid=''
cleanup(){
 status=$?;trap - EXIT INT TERM
 if ((status));then for f in "$work"/*.log;do [[ ! -f "$f" || "$f" == */certificate.log ]]||{ echo "$f";tail -n25 "$f"; };done;fi
 for p in "$bhpid" "$oldpid" "$heldpid" "$gpid" "$bpid" "$cpid";do [[ -z "$p" ]]||kill "$p" 2>/dev/null||true;done
 for p in "$bhpid" "$oldpid" "$heldpid" "$gpid" "$bpid" "$cpid";do [[ -z "$p" ]]||wait "$p" 2>/dev/null||true;done
 rm -rf "$work";exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export QNTW_TLS_GATE_READY="$work/routing-ready.json" QNTW_TLS_GATE_ROUTING_STATE="$work/routing-state.json" QNTW_TLS_GATE_BH_FILTER="$work/no-bh"
ip link set lo up
unshare --net sleep 240 &cpid=$!
sleep .2
ip link add qgate0 type veth peer name qgate1
ip link set qgate1 netns "$cpid"
ip address add 192.0.2.10/24 dev qgate0
ip -6 address add fd00:51::10/64 dev qgate0 nodad
ip link set qgate0 up
nsenter -t "$cpid" -n ip link set lo up
nsenter -t "$cpid" -n ip address add 192.0.2.20/24 dev qgate1
nsenter -t "$cpid" -n ip -6 address add fd00:51::20/64 dev qgate1 nodad
for last in 31 32 33 34 35 36 40 41 42 50 51;do nsenter -t "$cpid" -n ip address add "192.0.2.$last/24" dev qgate1;done
nsenter -t "$cpid" -n ip link set qgate1 up
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=tls-gate-test.invalid -addext subjectAltName=DNS:tls-gate-test.invalid -keyout "$work/test.key" -out "$work/test.crt" >"$work/certificate.log" 2>&1
cat > "$work/backend.py" <<'PY'
import hashlib,json,os,socket,ssl,threading,sys
w=sys.argv[1];ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.maximum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(w+'/test.crt',w+'/test.key')
# One write keeps concurrent fixture threads from joining JSONL records.
def report(**r):os.write(1,(json.dumps(r)+'\n').encode())
def bulk(c,peer):
 size=32*1024*1024;block=bytes((i*7)%251 for i in range(65536));sent=[0]
 header=b''
 while not header.endswith(b'\n'):header+=c.recv(1)
 assert header==b'BULK32\n'
 def send():
  for _ in range(size//len(block)):c.sendall(block);sent[0]+=len(block)
  c.shutdown(socket.SHUT_WR)
 writer=threading.Thread(target=send);writer.start();digest=hashlib.sha256();received=0
 while True:
  data=c.recv(65536)
  if not data:break
  received+=len(data);digest.update(data)
 writer.join();expected=hashlib.sha256(bytes(i%251 for i in range(65536))*(size//65536)).hexdigest();assert received==size and digest.hexdigest()==expected and sent[0]==size
 report(kind='bulk',peer=list(peer),received=received,sent=sent[0],hashes_verified=True);c.close()
def handle(c,peer):
 try:
  if c.recv(1,socket.MSG_PEEK)==b'B':bulk(c,peer);return
  with ctx.wrap_socket(c,server_side=True)as s:
   report(kind='tls',peer=list(peer),version=s.version())
   buf=b''
   while True:
    data=s.recv(4096)
    if not data:return
    buf+=data
    while b'\r\n\r\n' in buf:
     request,buf=buf.split(b'\r\n\r\n',1)
     s.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK')
 except (ssl.SSLError,OSError):c.close()
def listen(family):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind(('0.0.0.0'if family==socket.AF_INET else'::',443));s.listen();report(kind='ready',family=family)
 while True:
  c,peer=s.accept();report(kind='accept',peer=list(peer),local=list(c.getsockname()));threading.Thread(target=handle,args=(c,peer),daemon=True).start()
for f in [socket.AF_INET,socket.AF_INET6]:threading.Thread(target=listen,args=(f,),daemon=True).start()
threading.Event().wait()
PY
python3 -u "$work/backend.py" "$work" >"$work/backend.log" 2>&1 &bpid=$!
for _ in $(seq 1 40);do [[ $(grep -c '"ready"' "$work/backend.log") == 2 ]]&&break;sleep .05;done
cat > "$work/client.py" <<'PY'
import hashlib,json,socket,ssl,sys,time,pathlib,struct,os,threading
w=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
def context(version):
 c=ssl.create_default_context(cafile=str(w/'test.crt'));c.minimum_version=version;c.maximum_version=version;return c
def request(s):
 s.sendall(b'GET / HTTP/1.1\r\nHost: tls-gate-test.invalid\r\n\r\n');buf=b''
 while b'\r\n\r\n' not in buf:buf+=s.recv(4096)
 h,b=buf.split(b'\r\n\r\n',1)
 while len(b)<2:b+=s.recv(2-len(b))
 assert h.startswith(b'HTTP/1.1 200')and b==b'OK'
def tls(src,dst,port,version):
 f=socket.AF_INET6 if ':'in src else socket.AF_INET;s=socket.socket(f);s.settimeout(4);s.bind((src,port));s.connect((dst,443));return context(version).wrap_socket(s,server_hostname='tls-gate-test.invalid')
if mode=='held':
 name=sys.argv[3];port=int(sys.argv[4]);s=tls('192.0.2.20','192.0.2.10',port,ssl.TLSVersion.TLSv1_3);request(s);(w/(name+'-ready')).touch()
 for step in range(1,4):
  p=w/(name+'-go'+str(step))
  while not p.exists():time.sleep(.05)
  request(s);(w/(name+'-done'+str(step))).touch()
 s.close();sys.exit()
if mode=='normal':
 for src,dst,base in [('192.0.2.20','192.0.2.10',46100),('fd00:51::20','fd00:51::10',46110)]:
  for n,version in enumerate([ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3]):
   with tls(src,dst,base+n,version)as s:request(s)
 sys.exit()
if mode=='bulk':
 size=32*1024*1024;block=bytes(i%251 for i in range(65536));expected=hashlib.sha256(bytes((i*7)%251 for i in range(65536))*(size//65536)).hexdigest();started=time.monotonic()
 with socket.socket()as s:
  s.settimeout(20);s.bind(('192.0.2.20',46500));s.connect(('192.0.2.10',443));s.sendall(b'BULK32\n')
  def send():
   for _ in range(size//len(block)):s.sendall(block)
   s.shutdown(socket.SHUT_WR)
  writer=threading.Thread(target=send);writer.start();digest=hashlib.sha256();received=0
  while True:
   data=s.recv(65536)
   if not data:break
   received+=len(data);digest.update(data)
  writer.join();assert received==size and digest.hexdigest()==expected
 print(json.dumps({'bidirectional_bytes':size*2,'hashes_verified':True,'half_close_preserved':True,'elapsed_seconds':time.monotonic()-started}));sys.exit()
def fixture(h):
 u16=lambda n:struct.pack('!H',n);suites=b''.join(u16(n)for n in h['cipher_suites']);prefix=u16(len(suites))+suites+bytes([len(h['compression_methods'])])+bytes(h['compression_methods']);ext=b''
 for typ,length in zip(h['extension_types'],h['extension_lengths']):
  data=bytes(length)
  if typ==10:
   vals=b''.join(u16(n)for n in h['supported_groups']);data=u16(len(vals))+vals
  elif typ==11:data=bytes([len(h['ec_point_formats'])])+bytes(h['ec_point_formats'])
  elif typ==43:
   vals=b''.join(u16(n)for n in h['supported_versions']);data=bytes([len(vals)])+vals
  assert len(data)==length;ext+=u16(typ)+u16(length)+data
 if h['extensions_length'] is not None:prefix+=u16(len(ext))
 body=u16(int(h['legacy_version'],16))+os.urandom(32)+bytes([h['session_id_length']])+os.urandom(h['session_id_length'])+prefix+ext
 handshake=bytes([1])+len(body).to_bytes(3,'big')+body;return bytes([22])+u16(h['record_versions'][0])+u16(len(handshake))+handshake
def send(src,port,data,expect=False):
 with socket.socket()as s:
  s.settimeout(3);s.bind((src,port));s.connect(('192.0.2.10',443));s.sendall(data[:3]);time.sleep(.01);s.sendall(data[3:]);buf=b''
  try:
   while len(buf)<7:
    data=s.recv(7-len(buf))
    if not data:break
    buf+=data
  except (TimeoutError,OSError):pass
  if expect:
   assert len(buf)==7 and buf[0]==21 and buf[3:]==b'\x00\x02\x02\x28',buf
   assert s.recv(1)==b'','Alert did not close TCP'
  return buf
profiles=json.load(open(sys.argv[3]))
if mode=='exact':
 for i,p in enumerate(profiles):send('192.0.2.'+str(31+i),46200+i,fixture(p['hello']),True)
 # A remembered source switches to a normal TLS client, still gets Alert40.
 try:
  with tls('192.0.2.31','192.0.2.10',46220,ssl.TLSVersion.TLSv1_3)as s:raise AssertionError('remembered source completed TLS')
 except ssl.SSLError as e:assert 'HANDSHAKE_FAILURE'in str(e),str(e)
 sys.exit()
base=fixture(next(p['hello']for p in profiles if p['hello']['legacy_version']=='0x0300'))
# Change a cipher byte to avoid every exact template while remaining parseable.
offset=44+base[43]+2
if mode=='generic':
 for n in range(6):
  data=bytearray(base);data[offset+1]=(data[offset+1]+n+17)%256;send('192.0.2.40',46300+n,bytes(data),n==5)
 sys.exit()
if mode=='versions':
 for n,v in enumerate([0x0300,0x0301,0x0302,0x0303]):
  data=bytearray(base);data[9:11]=struct.pack('!H',v);data[offset+1]=(data[offset+1]+n+33)%256;send('192.0.2.41',46400+n,bytes(data),n==3)
 sys.exit()
raise AssertionError('unknown mode')
PY
bh_enabled=false
if [[ ${QNTW_TLS_GATE_TEST_BLACKHOLE:-0} == 1 ]];then
 bh_enabled=true
 mkdir -p "$work/bh-conf" "$work/bh-state" "$work/bh-logs" "$work/bh-metrics" "$work/bh-locks"
 # Private mount namespace hides every hardcoded daemon write path. These
 # mounts never propagate to the real production mounts.
 for pair in "$work/bh-state /var/lib/vpnshop-probe-blackhole" "$work/bh-logs /var/log/vpnshop-probes" "$work/bh-metrics /var/lib/node_exporter/textfile" "$work/bh-locks /run/lock";do
  read -r from to <<< "$pair";[[ -d "$to" ]];mount --bind "$from" "$to"
 done
 : > "$work/bh-logs/events.jsonl"
 cp "$stage/profiles.nft" "$stage/counters.nft" "$work/bh-conf/"
 printf 'qgate0\n' > "$work/bh-conf/public-ifaces"
 export QNTW_PROBE_BLACKHOLE_CONFIG_DIR="$work/bh-conf" QNTW_PROBE_BLACKHOLE_STATE="$work/bh-state/state.json" QNTW_TLS_GATE_BH_FILTER="$stage/bh-filter.sh"
 python3 - "$work" <<'PY'
import json,pathlib,sys,time
w=pathlib.Path(sys.argv[1]);now=int(time.time());cfg={'node':'alert-test','local_ips':['192.0.2.10','fd00:51::10'],'trusted_ips':['198.51.100.99'],'listen_ports':[22,443,7443,7444],'tls_gate_enabled':True,'tls_gate_ready_path':str(w/'routing-ready.json'),'tls_gate_sources_path':str(w/'known.json')};(w/'bh-conf/config.json').write_text(json.dumps(cfg));state={'version':3,'node':'alert-test','history':{'192.0.2.51':{'last':now-3600,'strikes':1}},'banned':{'192.0.2.50':0,'192.0.2.51':0},'windows':{},'released_at':{},'tls_sources':{}};(w/'bh-state/state.json').write_text(json.dumps(state));(w/'audit-tls-migrate.json').write_text(json.dumps(['192.0.2.51']))
PY
 "$stage/bh-filter.sh" apply
 nft -j list set inet qntw_probe_blackhole tls_gate_ports |jq -e 'all(.nftables[]|.set? // empty; (.elem//[])|length==0)' >/dev/null
fi
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" held old 46000 >"$work/old.log" 2>&1 &oldpid=$!
for _ in $(seq 1 40);do [[ -f "$work/old-ready" ]]&&break;sleep .05;done
[[ -f "$work/old-ready" ]]
python3 - "$work" "$stage" <<'PY'
import json,pathlib,sys
w=pathlib.Path(sys.argv[1]);stage=pathlib.Path(sys.argv[2]);bh='/var/lib/vpnshop-probe-blackhole/state.json'if(w/'bh-state/state.json').exists()else'';(w/'gate.json').write_text(json.dumps({'node':'alert-test','behavior_enabled':True,'trusted_ips':[],'profiles_path':str(stage/'profiles.json'),'known_sources_path':str(w/'known.json'),'blackhole_state_path':bh,'summary_path':str(w/'summary.json')}));(w/'routing.json').write_text(json.dumps({'node':'alert-test','interface':'qgate0','local_ips':['192.0.2.10','fd00:51::10']}))
PY
"$stage/vpnshop-tls-alert-gate" -config "$work/gate.json" >"$work/gate.log" 2>&1 &gpid=$!
for _ in $(seq 1 50);do if [[ -f "$work/summary.json" ]]&&jq -e '.ready==true' "$work/summary.json" >/dev/null;then break;fi;sleep .05;done
jq -e '.ready==true' "$work/summary.json" >/dev/null
"$stage/routing.sh" apply "$work/routing.json"
if [[ "$bh_enabled" == true ]];then
 "$stage/bh-filter.sh" apply
 nft -j list set inet qntw_probe_blackhole tls_gate_ports |jq -e '.nftables[]|.set? // empty|(.elem//[])|index(443)!=null' >/dev/null
 "$stage/blackhole" -config "$work/bh-conf/config.json" -migrate-tls-sources "$work/audit-tls-migrate.json"
 nft get element inet qntw_probe_blackhole tls_sources_v4 '{ 192.0.2.51 }' >/dev/null
 ! nft get element inet qntw_probe_blackhole permanent_v4 '{ 192.0.2.51 }' >/dev/null 2>&1
 "$stage/blackhole" -config "$work/bh-conf/config.json" >"$work/bh.log" 2>&1 &bhpid=$!
fi
touch "$work/old-go1"
for _ in $(seq 1 40);do [[ -f "$work/old-done1" ]]&&break;sleep .05;done
[[ -f "$work/old-done1" ]]
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" normal
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" bulk >"$work/bulk.log" 2>&1
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" exact "$stage/profiles.json"
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" generic "$stage/profiles.json"
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" versions "$stage/profiles.json"
if [[ "$bh_enabled" == true ]];then
 for _ in $(seq 1 80);do if nft get element inet qntw_probe_blackhole tls_sources_v4 '{ 192.0.2.41 }' >/dev/null 2>&1&&jq -e '.sources["192.0.2.51"]!=null' "$work/known.json" >/dev/null;then break;fi;sleep .1;done
 nft get element inet qntw_probe_blackhole tls_sources_v4 '{ 192.0.2.31,192.0.2.40,192.0.2.41,192.0.2.51 }' >/dev/null
 # A wildcard backend also accepts secondary public addresses. Only connections
 # actually diverted through the gate may use the TLS-only 443 exception.
 ip address add 192.0.2.11/24 dev qgate0
 nsenter -t "$cpid" -n python3 - <<'PY'
import socket
with socket.socket() as s:
 s.bind(('192.0.2.31', 0)); s.settimeout(.6)
 try: s.connect(('192.0.2.11', 443))
 except TimeoutError: pass
 else: raise AssertionError('TLS source reached an unprotected public alias')
PY
 nft -f - <<'NFT'
table inet qntw_test_qos {
 chain assign_qos { type filter hook prerouting priority -155; policy accept;
  ip saddr 192.0.2.31 tcp dport 443 ct state new ct mark set 1234
 }
}
NFT
 nsenter -t "$cpid" -n python3 - <<'PY'
import socket
with socket.socket() as s:
 s.bind(('192.0.2.31', 0)); s.settimeout(.6)
 try: s.connect(('192.0.2.10', 443))
 except TimeoutError: pass
 else: raise AssertionError('TLS source bypassed diversion with another conntrack mark')
PY
 nft delete table inet qntw_test_qos
 nsenter -t "$cpid" -n python3 - "$work" <<'PY'
import socket,ssl,sys
for ip,port in [('192.0.2.50',443),('192.0.2.31',22)]:
 with socket.socket()as s:
  s.bind((ip,0));s.settimeout(.6)
  try:s.connect(('192.0.2.10',port))
  except TimeoutError:pass
  else:raise AssertionError('general/TLS other-port ban did not DROP')
s=socket.socket();s.settimeout(2);s.bind(('192.0.2.51',46251));s.connect(('192.0.2.10',443));c=ssl.create_default_context(cafile=sys.argv[1]+'/test.crt')
try:c.wrap_socket(s,server_hostname='tls-gate-test.invalid')
except ssl.SSLError as e:assert 'HANDSHAKE_FAILURE'in str(e)
else:raise AssertionError('migrated TLS source completed TLS')
PY
 kill "$bhpid";wait "$bhpid" 2>/dev/null||true;bhpid=''
 "$stage/blackhole" -config "$work/bh-conf/config.json" -unban 192.0.2.31
 # Gate retains the first-seen inventory for audit; released_at overrides its
 # active decision and prevents the BH daemon importing the old entry again.
 for _ in $(seq 1 80);do if jq -e '.known_sources==8' "$work/summary.json" >/dev/null;then break;fi;sleep .1;done
 jq -e '.known_sources==8' "$work/summary.json" >/dev/null
 nsenter -t "$cpid" -n python3 - "$work" <<'PY'
import socket,ssl,sys
s=socket.socket();s.settimeout(3);s.bind(('192.0.2.31',46221));s.connect(('192.0.2.10',443));c=ssl.create_default_context(cafile=sys.argv[1]+'/test.crt')
with c.wrap_socket(s,server_hostname='tls-gate-test.invalid')as s:
 s.sendall(b'GET / HTTP/1.1\r\nHost: tls-gate-test.invalid\r\n\r\n');assert b'200 OK'in s.recv(4096)
PY
 "$stage/blackhole" -config "$work/bh-conf/config.json" >"$work/bh.log" 2>&1 &bhpid=$!
fi
nsenter -t "$cpid" -n python3 "$work/client.py" "$work" held held 46003 >"$work/held.log" 2>&1 &heldpid=$!
for _ in $(seq 1 40);do [[ -f "$work/held-ready" ]]&&break;sleep .05;done
[[ -f "$work/held-ready" ]]
"$stage/routing.sh" disable-new "$work/routing.json"
if [[ "$bh_enabled" == true ]];then
 nft -j list set inet qntw_probe_blackhole tls_gate_ports |jq -e 'all(.nftables[]|.set? // empty; (.elem//[])|length==0)' >/dev/null
fi
kill -TERM "$gpid"
touch "$work/old-go2" "$work/held-go1"
for _ in $(seq 1 40);do [[ -f "$work/old-done2" && -f "$work/held-done1" ]]&&break;sleep .05;done
[[ -f "$work/old-done2" && -f "$work/held-done1" ]]
touch "$work/old-go3" "$work/held-go2"
for _ in $(seq 1 40);do [[ -f "$work/held-done2" ]]&&break;sleep .05;done
[[ -f "$work/held-done2" ]]
touch "$work/held-go3"
wait "$heldpid";heldpid='';wait "$oldpid";oldpid=''
for _ in $(seq 1 80);do kill -0 "$gpid" 2>/dev/null||break;sleep .1;done
wait "$gpid";gpid=''
mkdir -p "$work/failing-bin"
printf '#!/bin/sh\nexit 1\n' > "$work/failing-bin/conntrack"
chmod 755 "$work/failing-bin/conntrack"
if PATH="$work/failing-bin:$PATH" "$stage/routing.sh" remove "$work/routing.json";then
 echo 'routing removed despite a failed conntrack dump' >&2;exit 1
fi
[[ -e "$QNTW_TLS_GATE_ROUTING_STATE" ]]
ip -4 address show dev lo |grep -Fq 'inet 10.254.254.1/32 '
for _ in $(seq 1 20);do if "$stage/routing.sh" remove "$work/routing.json";then break;fi;sleep .1;done
[[ ! -e "$QNTW_TLS_GATE_ROUTING_STATE" ]]
python3 - "$work" <<'PY'
import json,pathlib,sys
w=pathlib.Path(sys.argv[1]);backend=[json.loads(l)for l in(w/'backend.log').read_text().splitlines()if l.startswith('{')];accept=[e for e in backend if e['kind']=='accept'];ports={e['peer'][1]for e in accept};events=[json.loads(l)for l in(w/'gate.log').read_text().splitlines()if l.startswith('{')];rejects=[e for e in events if e['event']=='tls_alert_gate_reject'];exact=[e for e in rejects if e['reason']=='known_tls_profile'];assert len(exact)==6,exact
assert not ports.intersection(set(range(46200,46206))|{46220,46305,46403}),ports
assert any(e['reason']=='remembered_tls_scanner'and e['sport']==46220 for e in rejects)
assert any(e['reason']=='tls_capability_sweep_6_profiles_15s'and e['sport']==46305 for e in rejects)
assert any(e['reason']=='tls_version_sweep_4_profiles_3_modes_60s'and e['sport']==46403 for e in rejects)
assert all(e['alert_write_complete']and e['alert_description']==40 and e['persistence_ok']for e in rejects)
for port,ip in [(46100,'192.0.2.20'),(46101,'192.0.2.20'),(46110,'fd00:51::20'),(46111,'fd00:51::20')]:assert any(e['peer'][0]==ip and e['peer'][1]==port for e in accept)
state=json.loads((w/'known.json').read_text())
bh_enabled=(w/'bh-state/state.json').exists()
if bh_enabled:
 bh=json.loads((w/'bh-state/state.json').read_text());assert '192.0.2.50'in bh['banned']and'192.0.2.51'not in bh['banned'];assert '192.0.2.51'in bh['tls_sources'];assert bh['released_at']['192.0.2.31']>=state['sources']['192.0.2.31']and'192.0.2.31'not in bh['tls_sources'];assert any(e['peer'][0]=='192.0.2.31'and e['peer'][1]==46221 for e in accept);assert len(state['sources'])==9,state
else:assert len(state['sources'])==8,state
bulk=[e for e in backend if e['kind']=='bulk'];assert len(bulk)==1 and bulk[0]['hashes_verified']
summary=json.loads((w/'summary.json').read_text());assert summary['counters']['dial_errors']==0,summary;assert summary['counters']['persistence_errors']==0,summary;assert summary['known_sources']==8,summary
print(json.dumps({'verdict':'pass','exact_profiles_alert40':len(exact),'all_rejects_closed_without_backend':True,'remembered_source_different_hello_rejected':True,'generic_capability_sweep_detected':True,'generic_version_sweep_detected':True,'normal_TLS12_TLS13_HTTP_v4_v6':True,'source_ip_and_port_preserved':True,'old_TLS_session_survives_activation':True,'active_TLS_proxy_survives_disable_and_SIGTERM':True,'gate_drained_cleanly':True,'active_sources':summary['known_sources'],'private_source_inventory':len(state['sources']),'bulk':json.loads((w/'bulk.log').read_text()),'blackhole_full_integration':bh_enabled,'host_network_changes':False}))
PY
